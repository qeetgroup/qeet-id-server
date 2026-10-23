package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the verifiable-credential error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeVCSubjectTypeRequired: http.StatusUnprocessableEntity,
		errs.CodeVCClaimsInvalid:       http.StatusUnprocessableEntity,
		errs.CodeVCCredentialRequired:  http.StatusUnprocessableEntity,
		errs.CodeVCCredentialNotFound:  http.StatusNotFound,
	})
}
