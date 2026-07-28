package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Verifiable-credential code→status mappings. Registered from init() so this
// bounded context owns its own statuses without editing the shared
// error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodeVCSubjectTypeRequired: http.StatusUnprocessableEntity,
		errs.CodeVCClaimsInvalid:       http.StatusUnprocessableEntity,
		errs.CodeVCCredentialRequired:  http.StatusUnprocessableEntity,
		errs.CodeVCCredentialNotFound:  http.StatusNotFound,
	})
}
