package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// LDAP code→status mappings. Registered from this bounded context's own file so
// the shared error_status.go stays free of per-domain entries. Statuses mirror
// the generic sentinels these codes replaced.
func init() {
	registerStatuses(map[string]int{
		errs.CodeLDAPDialFailed:               http.StatusUnprocessableEntity,
		errs.CodeLDAPServiceBindFailed:        http.StatusUnprocessableEntity,
		errs.CodeLDAPCredentialsRequired:      http.StatusBadRequest,
		errs.CodeLDAPDirectoryUnreachable:     http.StatusUnprocessableEntity,
		errs.CodeLDAPInvalidCredentials:       http.StatusUnauthorized,
		errs.CodeLDAPEmailAttributeMissing:    http.StatusUnprocessableEntity,
		errs.CodeLDAPConnectionDisabled:       http.StatusForbidden,
		errs.CodeLDAPConnectionFieldsRequired: http.StatusUnprocessableEntity,
		errs.CodeLDAPServerURLInvalid:         http.StatusUnprocessableEntity,
		errs.CodeLDAPStatusInvalid:            http.StatusUnprocessableEntity,
	})
}
