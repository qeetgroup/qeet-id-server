package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the Idempotency-Key error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeIdempotencyKeyInvalid:    http.StatusBadRequest,
		errs.CodeIdempotencyKeyReused:     http.StatusUnprocessableEntity,
		errs.CodeIdempotencyKeyInProgress: http.StatusConflict,
	})
}
