package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the SAML identity-provider error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeSAMLNameIDFormatInvalid:    http.StatusUnprocessableEntity,
		errs.CodeSAMLNameIDAttributeInvalid: http.StatusUnprocessableEntity,
		errs.CodeSAMLAttributesInvalid:      http.StatusUnprocessableEntity,
		errs.CodeSAMLNameIDUnavailable:      http.StatusForbidden,
		errs.CodeSAMLSPNotAssigned:          http.StatusForbidden,
		errs.CodeSAMLAssigneeNotFound:       http.StatusNotFound,
	})
}
