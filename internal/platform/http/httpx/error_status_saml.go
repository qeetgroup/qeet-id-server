package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the SAML error codes.
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
		errs.CodeSAMLSSOURLInvalid:            http.StatusUnprocessableEntity,
		errs.CodeSAMLStatusInvalid:            http.StatusUnprocessableEntity,
		errs.CodeSAMLConnectionDisabled:       http.StatusForbidden,
		errs.CodeSAMLConnectionMisconfigured:  http.StatusInternalServerError,
		errs.CodeSAMLRequestInvalid:           http.StatusBadRequest,
		errs.CodeSAMLResponseMissing:          http.StatusBadRequest,
		errs.CodeSAMLAssertionInvalid:         http.StatusUnauthorized,
		errs.CodeSAMLAssertionConditions:      http.StatusUnauthorized,
		errs.CodeSAMLAssertionNoEmail:         http.StatusBadRequest,
		errs.CodeSAMLRequestCorrelation:       http.StatusUnauthorized,
		errs.CodeSAMLReplayDetected:           http.StatusUnauthorized,
		errs.CodeSAMLIdPNotConfigured:         http.StatusNotImplemented,
		errs.CodeSAMLAuthnRequestInvalid:      http.StatusBadRequest,
		errs.CodeSAMLRequestParamMissing:      http.StatusBadRequest,
		errs.CodeSAMLServiceProviderDisabled:  http.StatusForbidden,
		errs.CodeSAMLACSMismatch:              http.StatusBadRequest,
		errs.CodeSAMLACSURLInvalid:            http.StatusUnprocessableEntity,
		errs.CodeSAMLSPFieldsRequired:         http.StatusUnprocessableEntity,
		errs.CodeSAMLUserTenantMismatch:       http.StatusForbidden,
		errs.CodeSAMLAccountUnverified:        http.StatusForbidden,
		errs.CodeSAMLSPEntityIDTaken:          http.StatusConflict,
	})
}
