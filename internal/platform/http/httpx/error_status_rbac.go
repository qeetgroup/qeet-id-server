package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the RBAC error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeRBACRoleNameExists:      http.StatusConflict,
		errs.CodeRBACGroupOrRoleNotFound: http.StatusNotFound,
		errs.CodeRBACUserOrRoleNotFound:  http.StatusNotFound,
		errs.CodeRBACPermissionDenied:    http.StatusForbidden,
		errs.CodeRBACGrantExceedsCaller:  http.StatusForbidden,
		errs.CodeRBACOwnerOnly:           http.StatusForbidden,
		errs.CodeRBACPermissionRequired:  http.StatusBadRequest,
	})
}
