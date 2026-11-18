package idempotency

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrKeyInvalid     = errs.New("idempotency.key_invalid", errs.KindInvalid, "The Idempotency-Key header must be 1 to 255 printable characters.")
	ErrKeyReused      = errs.New("idempotency.key_reused", errs.KindUnprocessable, "This Idempotency-Key was already used for a different request.")
	ErrKeyInProgress  = errs.New("idempotency.in_progress", errs.KindConflict, "A request with this Idempotency-Key is still being processed; retry shortly.")
	ErrOutcomeUnknown = errs.New("idempotency.outcome_unknown", errs.KindConflict, "The request first sent with this Idempotency-Key was interrupted, so whether it took effect is unknown. Check the outcome, then retry with a new key if it did not.")
)
