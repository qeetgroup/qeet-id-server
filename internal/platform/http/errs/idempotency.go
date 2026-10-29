package errs

// Idempotency-Key error codes.
const (
	CodeIdempotencyKeyInvalid     = "idempotency.key_invalid"
	CodeIdempotencyKeyReused      = "idempotency.key_reused"
	CodeIdempotencyKeyInProgress  = "idempotency.in_progress"
	CodeIdempotencyOutcomeUnknown = "idempotency.outcome_unknown"
)

// Idempotency-Key errors.
var (
	ErrIdempotencyKeyInvalid     = New(CodeIdempotencyKeyInvalid, "The Idempotency-Key header must be 1 to 255 printable characters.")
	ErrIdempotencyKeyReused      = New(CodeIdempotencyKeyReused, "This Idempotency-Key was already used for a different request.")
	ErrIdempotencyKeyInProgress  = New(CodeIdempotencyKeyInProgress, "A request with this Idempotency-Key is still being processed; retry shortly.")
	ErrIdempotencyOutcomeUnknown = New(CodeIdempotencyOutcomeUnknown, "The request first sent with this Idempotency-Key was interrupted, so whether it took effect is unknown. Check the outcome, then retry with a new key if it did not.")
)
