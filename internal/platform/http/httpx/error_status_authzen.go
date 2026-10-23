package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the AuthZEN error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAuthZENSubjectIDRequired:  http.StatusUnprocessableEntity,
		errs.CodeAuthZENActionNameRequired: http.StatusUnprocessableEntity,
		errs.CodeAuthZENSubjectIDInvalid:   http.StatusUnprocessableEntity,
		errs.CodeAuthZENResourceRequired:   http.StatusUnprocessableEntity,
	})
}
