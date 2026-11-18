package qeetai

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeUnconfigured         = "qeetai_unconfigured"
	CodeProviderUnreachable  = "qeetai_provider_unreachable"
	CodeProviderKeyInvalid   = "qeetai_provider_key_invalid"
	CodeProviderModelInvalid = "qeetai_provider_model_invalid"
	CodeProviderError        = "qeetai_provider_error"
	CodeTurnInProgress       = "qeetai.turn_in_progress"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrUnconfigured         = errs.New(CodeUnconfigured, errs.KindConflict, "Qeet AI is not configured for this organization")
	ErrProviderUnreachable  = errs.New(CodeProviderUnreachable, errs.KindInvalid, "could not reach the provider endpoint")
	ErrProviderKeyInvalid   = errs.New(CodeProviderKeyInvalid, errs.KindInvalid, "the provider rejected the API key")
	ErrProviderModelInvalid = errs.New(CodeProviderModelInvalid, errs.KindInvalid, "the key authenticated but the model was rejected — check the model id")
	ErrProviderError        = errs.New(CodeProviderError, errs.KindInvalid, "the provider returned an error")
	// ErrQeetAITurnInProgress refuses a message to a conversation whose previous
	// turn is still running: a conversation answers one turn at a time.
	ErrTurnInProgress = errs.New(CodeTurnInProgress, errs.KindConflict, "Qeet AI is still answering in this conversation. Wait for it to finish, then try again.").AsRetryable()
)
