package directory

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/google/uuid"
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

type MappingIssue struct {
	MappingID uuid.UUID `json:"mapping_id"`
	Field     string    `json:"field"`
	Message   string    `json:"message"`
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

func ValidateMapping(mapping Mapping) error {
	if len(mapping.Source) == 0 || len(mapping.Source) > 128 || strings.TrimSpace(mapping.Source) != mapping.Source {
		return fmt.Errorf("source attribute must contain 1 to 128 characters")
	}
	lower := strings.ToLower(mapping.Source)
	for _, secret := range []string{"password", "passwd", "token", "secret", "credential", "privatekey", "private_key"} {
		if strings.Contains(lower, secret) {
			return fmt.Errorf("credential attributes cannot be mapped")
		}
	}
	kind, exists := profileTargets[mapping.Target]
	if !exists {
		return fmt.Errorf("target is not a supported profile field")
	}
	if mapping.ValueType != kind {
		return fmt.Errorf("target requires a %s value", kind)
	}
	switch mapping.Transform {
	case "none", "trim", "lowercase", "uppercase":
		if mapping.Pattern != "" {
			return fmt.Errorf("patterns are only used by extract transforms")
		}
	case "extract":
		if len(mapping.Pattern) == 0 || len(mapping.Pattern) > 256 {
			return fmt.Errorf("extract pattern must contain 1 to 256 characters")
		}
		pattern, err := regexp.Compile(mapping.Pattern)
		if err != nil || pattern.NumSubexp() != 1 {
			return fmt.Errorf("extract pattern must be valid and contain one capture group")
		}
	default:
		return fmt.Errorf("unsupported transform")
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

func transformValue(mapping Mapping, value any) (any, error) {
	transform := func(value string) (string, error) {
		if len(value) > 2048 {
			return "", fmt.Errorf("attribute exceeds the supported length")
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
				return "", fmt.Errorf("attribute does not match the extraction rule")
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
			return nil, fmt.Errorf("attribute must be an array of strings")
		}
		if len(values) > 100 {
			return nil, fmt.Errorf("attribute exceeds 100 entries")
		}
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("attribute must be an array of strings")
			}
			output, err := transform(text)
			if err != nil {
				return nil, err
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
		return nil, fmt.Errorf("attribute must be a string")
	}
	result, err := transform(text)
	if err != nil {
		return nil, err
	}
	if mapping.Target == "email" {
		result = strings.TrimSpace(result)
		address, err := mail.ParseAddress(result)
		if err != nil || address.Address != result {
			return nil, fmt.Errorf("email must be a valid address")
		}
	}
	if mapping.Target == "display_name" && len(result) > 200 {
		return nil, fmt.Errorf("display name exceeds 200 characters")
	}
	return result, nil
}

func PreviewMappings(mappings []Mapping, source map[string]any, partial bool) MappingPreview {
	result := MappingPreview{Profile: map[string]any{}, Values: map[string]any{}, Issues: []MappingIssue{}, Valid: true}
	encoded, err := json.Marshal(source)
	if err != nil || len(encoded) > 65536 || len(mappings) > 50 {
		result.Valid = false
		result.Issues = append(result.Issues, MappingIssue{Message: "Source or mapping set exceeds the supported size"})
		return result
	}
	targets := map[string]bool{}
	for _, mapping := range mappings {
		if !mapping.Enabled {
			continue
		}
		issue := func(message string) {
			result.Valid = false
			result.Issues = append(result.Issues, MappingIssue{MappingID: mapping.ID, Field: mapping.Target, Message: message})
		}
		if err := ValidateMapping(mapping); err != nil {
			issue(err.Error())
			continue
		}
		if targets[mapping.Target] {
			issue("Multiple active mappings target the same field")
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
				issue("Required source attribute is missing")
			}
			continue
		}
		transformed, err := transformValue(mapping, value)
		if err != nil {
			issue(err.Error())
			continue
		}
		if mapping.Required && transformed == "" {
			issue("Required source attribute is empty")
			continue
		}
		result.Profile[mapping.Target] = transformed
		result.Values[mapping.ID.String()] = transformed
	}
	return result
}
