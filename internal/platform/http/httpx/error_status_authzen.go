package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// AuthZEN code→status mappings. Registered from this bounded context's own file
// so the shared error_status.go stays free of per-domain entries. Statuses
// mirror the generic sentinels these codes replaced.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAuthZENSubjectIDRequired:  http.StatusUnprocessableEntity,
		errs.CodeAuthZENActionNameRequired: http.StatusUnprocessableEntity,
		errs.CodeAuthZENSubjectIDInvalid:   http.StatusUnprocessableEntity,
		errs.CodeAuthZENResourceRequired:   http.StatusUnprocessableEntity,
	})
}
