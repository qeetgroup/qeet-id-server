package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// RBAC code→status mappings. Registered from this bounded context's own file so
// the shared error_status.go stays free of per-domain entries. Statuses mirror
// the generic sentinels these codes replaced.
func init() {
	registerStatuses(map[string]int{
		errs.CodeRBACRoleNameExists:      http.StatusConflict,
		errs.CodeRBACGroupOrRoleNotFound: http.StatusNotFound,
		errs.CodeRBACPermissionDenied:    http.StatusForbidden,
		errs.CodeRBACPermissionRequired:  http.StatusBadRequest,
	})
}
