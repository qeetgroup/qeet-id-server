package directory

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
