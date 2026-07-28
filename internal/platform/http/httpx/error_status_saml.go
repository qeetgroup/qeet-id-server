package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// SAML federation code→status mappings. Registered from this per-domain file so
// the saml bounded context owns its own transport mapping without editing the
// shared statusByCode table.
func init() {
	registerStatuses(map[string]int{
		errs.CodeSAMLTenantIDInvalid:          http.StatusBadRequest,
		errs.CodeSAMLTenantMismatch:           http.StatusForbidden,
		errs.CodeSAMLIDInvalid:                http.StatusBadRequest,
		errs.CodeSAMLLoginCodeRequired:        http.StatusBadRequest,
		errs.CodeSAMLLoginCodeInvalid:         http.StatusUnauthorized,
		errs.CodeSAMLLoginCodeUsed:            http.StatusUnauthorized,
		errs.CodeSAMLLoginCodeExpired:         http.StatusUnauthorized,
		errs.CodeSAMLConnectionFieldsRequired: http.StatusUnprocessableEntity,
		errs.CodeSAMLCertificateInvalid:       http.StatusUnprocessableEntity,
		errs.CodeSAMLStatusInvalid:            http.StatusUnprocessableEntity,
		errs.CodeSAMLConnectionDisabled:       http.StatusForbidden,
		errs.CodeSAMLConnectionMisconfigured:  http.StatusInternalServerError,
		errs.CodeSAMLRequestInvalid:           http.StatusBadRequest,
		errs.CodeSAMLResponseMissing:          http.StatusBadRequest,
		errs.CodeSAMLAssertionInvalid:         http.StatusUnauthorized,
		errs.CodeSAMLAssertionConditions:      http.StatusUnauthorized,
		errs.CodeSAMLAssertionNoEmail:         http.StatusBadRequest,
		errs.CodeSAMLIdPNotConfigured:         http.StatusNotImplemented,
		errs.CodeSAMLAuthnRequestInvalid:      http.StatusBadRequest,
		errs.CodeSAMLRequestParamMissing:      http.StatusBadRequest,
		errs.CodeSAMLServiceProviderDisabled:  http.StatusForbidden,
		errs.CodeSAMLACSMismatch:              http.StatusBadRequest,
		errs.CodeSAMLSPFieldsRequired:         http.StatusUnprocessableEntity,
		errs.CodeSAMLUserTenantMismatch:       http.StatusForbidden,
	})
}
