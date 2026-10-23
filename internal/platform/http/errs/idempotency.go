package errs

// Idempotency-Key error codes.
const (
	CodeIdempotencyKeyInvalid    = "idempotency.key_invalid"
	CodeIdempotencyKeyReused     = "idempotency.key_reused"
	CodeIdempotencyKeyInProgress = "idempotency.in_progress"
)

// Idempotency-Key errors.
var (
	ErrIdempotencyKeyInvalid    = New(CodeIdempotencyKeyInvalid, "The Idempotency-Key header must be 1 to 255 printable characters.")
	ErrIdempotencyKeyReused     = New(CodeIdempotencyKeyReused, "This Idempotency-Key was already used for a different request.")
	ErrIdempotencyKeyInProgress = New(CodeIdempotencyKeyInProgress, "A request with this Idempotency-Key is still being processed; retry shortly.")
)
