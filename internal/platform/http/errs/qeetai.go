package errs

// Qeet AI error codes. They predate the domain.reason form and are kept as
// shipped.
const (
	CodeQeetAIUnconfigured         = "qeetai_unconfigured"
	CodeQeetAIProviderUnreachable  = "qeetai_provider_unreachable"
	CodeQeetAIProviderKeyInvalid   = "qeetai_provider_key_invalid"
	CodeQeetAIProviderModelInvalid = "qeetai_provider_model_invalid"
	CodeQeetAIProviderError        = "qeetai_provider_error"
)

// Qeet AI errors. The provider errors answer a test of a tenant's provider
// settings.
var (
	ErrQeetAIUnconfigured         = New(CodeQeetAIUnconfigured, "Qeet AI is not configured for this organization")
	ErrQeetAIProviderUnreachable  = New(CodeQeetAIProviderUnreachable, "could not reach the provider endpoint")
	ErrQeetAIProviderKeyInvalid   = New(CodeQeetAIProviderKeyInvalid, "the provider rejected the API key")
	ErrQeetAIProviderModelInvalid = New(CodeQeetAIProviderModelInvalid, "the key authenticated but the model was rejected — check the model id")
	ErrQeetAIProviderError        = New(CodeQeetAIProviderError, "the provider returned an error")
)
