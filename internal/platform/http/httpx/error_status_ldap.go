package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the LDAP error codes.
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
		errs.CodeLDAPAccountNotInTenant:       http.StatusForbidden,
		errs.CodeLDAPStatusInvalid:            http.StatusUnprocessableEntity,
	})
}
