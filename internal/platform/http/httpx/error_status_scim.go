package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// SCIM provisioning code→status mappings, registered from this per-domain file
// so the scim bounded context owns its own transport mapping.
func init() {
	registerStatuses(map[string]int{
		errs.CodeSCIMTenantIDInvalid: http.StatusBadRequest,
		errs.CodeSCIMTenantMismatch:  http.StatusForbidden,
	})
}
