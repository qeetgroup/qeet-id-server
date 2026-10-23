package directory

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

type Mapping struct {
	ID        uuid.UUID `json:"id"`
	Source    string    `json:"source_attribute"`
	Target    string    `json:"target_field"`
	ValueType string    `json:"value_type"`
	Transform string    `json:"transform"`
	Pattern   string    `json:"pattern"`
	Enabled   bool      `json:"enabled"`
	Required  bool      `json:"required"`
	Version   int       `json:"version"`
}

// MappingIssue is a problem a preview found. Field is the target_field of the
// mapping at fault (empty for the size limit), and Code one of
// mappingIssueCodes.
type MappingIssue struct {
	MappingID uuid.UUID `json:"mapping_id"`
	Field     string    `json:"field"`
	Code      string    `json:"code"`
	Message   string    `json:"message"`
}

// Codes a MappingIssue carries.
const (
	CodeMappingPreviewTooLarge      = "directory.mapping_preview_too_large"     // the source or the mapping set is over its size limit
	CodeMappingSourceInvalid        = "directory.mapping_source_invalid"        // source_attribute is empty, padded, over 128 characters or, for LDAP, not an attribute name
	CodeMappingSourceCredential     = "directory.mapping_source_credential"     // source_attribute names a credential
	CodeMappingTargetUnsupported    = "directory.mapping_target_unsupported"    // target_field is not a profile field
	CodeMappingTargetDuplicate      = "directory.mapping_target_duplicate"      // another active mapping has the same target_field
	CodeMappingValueTypeMismatch    = "directory.mapping_value_type_mismatch"   // value_type is not the one target_field takes
	CodeMappingTransformUnsupported = "directory.mapping_transform_unsupported" // transform is not a supported transform
	CodeMappingPatternUnexpected    = "directory.mapping_pattern_unexpected"    // pattern is set on a transform other than extract
	CodeMappingPatternInvalid       = "directory.mapping_pattern_invalid"       // the extract pattern is not 1 to 256 characters with one capture group
	CodeMappingSourceMissing        = "directory.mapping_source_missing"        // a required source attribute is absent
	CodeMappingSourceEmpty          = "directory.mapping_source_empty"          // a required source attribute maps to an empty value
	CodeMappingValueNotString       = "directory.mapping_value_not_string"      // the source value is not a string
	CodeMappingValueNotArray        = "directory.mapping_value_not_array"       // the source value is not an array of strings
	CodeMappingValueTooLong         = "directory.mapping_value_too_long"        // a source value is over 2048 characters
	CodeMappingValueTooMany         = "directory.mapping_value_too_many"        // the source array has over 100 entries
	CodeMappingValueUnmatched       = "directory.mapping_value_unmatched"       // the source value does not match the extract pattern
	CodeMappingEmailInvalid         = "directory.mapping_email_invalid"         // the mapped email is not a valid address
	CodeMappingDisplayNameTooLong   = "directory.mapping_display_name_too_long" // the mapped display name is over 200 characters
)

// mappingIssueCodes is every code a MappingIssue can carry.
var mappingIssueCodes = []string{
	CodeMappingPreviewTooLarge, CodeMappingSourceInvalid, CodeMappingSourceCredential,
	CodeMappingTargetUnsupported, CodeMappingTargetDuplicate, CodeMappingValueTypeMismatch,
	CodeMappingTransformUnsupported, CodeMappingPatternUnexpected, CodeMappingPatternInvalid,
	CodeMappingSourceMissing, CodeMappingSourceEmpty, CodeMappingValueNotString,
	CodeMappingValueNotArray, CodeMappingValueTooLong, CodeMappingValueTooMany,
	CodeMappingValueUnmatched, CodeMappingEmailInvalid, CodeMappingDisplayNameTooLong,
}

// mappingProblem is why a mapping or a mapped value was refused: a code from
// mappingIssueCodes, the Mapping property at fault (empty for a value) and
// the message the issue reports.
type mappingProblem struct {
	code    string
	field   string
	message string
}

// refuse is a problem a preview finds outside the mapping's own fields.
func refuse(code, message string) *mappingProblem {
	return &mappingProblem{code: code, message: message}
}

// invalid is a problem with the mapping's own field, named by its JSON key.
func invalid(field, code, message string) *mappingProblem {
	return &mappingProblem{code: code, field: field, message: message}
}

// validationError is the validation_failed error a save answers with.
func (problem *mappingProblem) validationError() error {
	return errs.ErrValidationFailed.WithFields([]errs.FieldError{{Field: problem.field, Code: problem.code, Message: problem.message}})
}

type MappingPreview struct {
	Profile map[string]any `json:"profile"`
	Values  map[string]any `json:"values"`
	Issues  []MappingIssue `json:"issues"`
	Valid   bool           `json:"valid"`
}

var profileTargets = map[string]string{
	"email": "string", "display_name": "string", "first_name": "string", "last_name": "string",
	"department": "string", "title": "string", "manager_id": "string", "groups": "array",
}

// ValidateMapping returns nil if mapping can be saved, or else a
// validation_failed error naming the field at fault and its mapping code.
func ValidateMapping(mapping Mapping) error {
	if problem := checkMapping(mapping); problem != nil {
		return problem.validationError()
	}
	return nil
}

func checkMapping(mapping Mapping) *mappingProblem {
	if len(mapping.Source) == 0 || len(mapping.Source) > 128 || strings.TrimSpace(mapping.Source) != mapping.Source {
		return invalid("source_attribute", CodeMappingSourceInvalid, "source attribute must contain 1 to 128 characters")
	}
	lower := strings.ToLower(mapping.Source)
	for _, secret := range []string{"password", "passwd", "token", "secret", "credential", "privatekey", "private_key"} {
		if strings.Contains(lower, secret) {
			return invalid("source_attribute", CodeMappingSourceCredential, "credential attributes cannot be mapped")
		}
	}
	kind, exists := profileTargets[mapping.Target]
	if !exists {
		return invalid("target_field", CodeMappingTargetUnsupported, "target is not a supported profile field")
	}
	if mapping.ValueType != kind {
		return invalid("value_type", CodeMappingValueTypeMismatch, fmt.Sprintf("target requires a %s value", kind))
	}
	switch mapping.Transform {
	case "none", "trim", "lowercase", "uppercase":
		if mapping.Pattern != "" {
			return invalid("pattern", CodeMappingPatternUnexpected, "patterns are only used by extract transforms")
		}
	case "extract":
		if len(mapping.Pattern) == 0 || len(mapping.Pattern) > 256 {
			return invalid("pattern", CodeMappingPatternInvalid, "extract pattern must contain 1 to 256 characters")
		}
		pattern, err := regexp.Compile(mapping.Pattern)
		if err != nil || pattern.NumSubexp() != 1 {
			return invalid("pattern", CodeMappingPatternInvalid, "extract pattern must be valid and contain one capture group")
		}
	default:
		return invalid("transform", CodeMappingTransformUnsupported, "unsupported transform")
	}
	return nil
}

func sourceAttribute(source map[string]any, path string) (any, bool) {
	if value, exists := source[path]; exists {
		return value, true
	}
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 8 {
		return nil, false
	}
	var current any = source
	for _, part := range parts {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		key := strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		current, ok = object[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func transformValue(mapping Mapping, value any) (any, *mappingProblem) {
	transform := func(value string) (string, *mappingProblem) {
		if len(value) > 2048 {
			return "", refuse(CodeMappingValueTooLong, "attribute exceeds the supported length")
		}
		switch mapping.Transform {
		case "trim":
			value = strings.TrimSpace(value)
		case "lowercase":
			value = strings.ToLower(strings.TrimSpace(value))
		case "uppercase":
			value = strings.ToUpper(strings.TrimSpace(value))
		case "extract":
			matches := regexp.MustCompile(mapping.Pattern).FindStringSubmatch(value)
			if len(matches) != 2 {
				return "", refuse(CodeMappingValueUnmatched, "attribute does not match the extraction rule")
			}
			value = matches[1]
		}
		return value, nil
	}
	if mapping.ValueType == "array" {
		var values []any
		switch input := value.(type) {
		case []any:
			values = input
		case []string:
			for _, item := range input {
				values = append(values, item)
			}
		default:
			return nil, refuse(CodeMappingValueNotArray, "attribute must be an array of strings")
		}
		if len(values) > 100 {
			return nil, refuse(CodeMappingValueTooMany, "attribute exceeds 100 entries")
		}
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, refuse(CodeMappingValueNotArray, "attribute must be an array of strings")
			}
			output, problem := transform(text)
			if problem != nil {
				return nil, problem
			}
			result = append(result, output)
		}
		return result, nil
	}
	if values, ok := value.([]string); ok && len(values) == 1 {
		value = values[0]
	}
	if values, ok := value.([]any); ok && len(values) == 1 {
		value = values[0]
	}
	text, ok := value.(string)
	if !ok {
		return nil, refuse(CodeMappingValueNotString, "attribute must be a string")
	}
	result, problem := transform(text)
	if problem != nil {
		return nil, problem
	}
	if mapping.Target == "email" {
		result = strings.TrimSpace(result)
		address, err := mail.ParseAddress(result)
		if err != nil || address.Address != result {
			return nil, refuse(CodeMappingEmailInvalid, "email must be a valid address")
		}
	}
	if mapping.Target == "display_name" && len(result) > 200 {
		return nil, refuse(CodeMappingDisplayNameTooLong, "display name exceeds 200 characters")
	}
	return result, nil
}

func PreviewMappings(mappings []Mapping, source map[string]any, partial bool) MappingPreview {
	result := MappingPreview{Profile: map[string]any{}, Values: map[string]any{}, Issues: []MappingIssue{}, Valid: true}
	encoded, err := json.Marshal(source)
	if err != nil || len(encoded) > 65536 || len(mappings) > 50 {
		result.Valid = false
		result.Issues = append(result.Issues, MappingIssue{Code: CodeMappingPreviewTooLarge, Message: "Source or mapping set exceeds the supported size"})
		return result
	}
	targets := map[string]bool{}
	for _, mapping := range mappings {
		if !mapping.Enabled {
			continue
		}
		issue := func(problem *mappingProblem) {
			result.Valid = false
			result.Issues = append(result.Issues, MappingIssue{MappingID: mapping.ID, Field: mapping.Target, Code: problem.code, Message: problem.message})
		}
		if problem := checkMapping(mapping); problem != nil {
			issue(problem)
			continue
		}
		if targets[mapping.Target] {
			issue(refuse(CodeMappingTargetDuplicate, "Multiple active mappings target the same field"))
			continue
		}
		targets[mapping.Target] = true
		value, exists := sourceAttribute(source, mapping.Source)
		if partial && exists && value == nil {
			result.Profile[mapping.Target] = nil
			result.Values[mapping.ID.String()] = nil
			continue
		}
		if !exists || value == nil {
			if mapping.Required && !partial {
				issue(refuse(CodeMappingSourceMissing, "Required source attribute is missing"))
			}
			continue
		}
		transformed, problem := transformValue(mapping, value)
		if problem != nil {
			issue(problem)
			continue
		}
		if mapping.Required && transformed == "" {
			issue(refuse(CodeMappingSourceEmpty, "Required source attribute is empty"))
			continue
		}
		result.Profile[mapping.Target] = transformed
		result.Values[mapping.ID.String()] = transformed
	}
	return result
}
