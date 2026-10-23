package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the Admin Portal error codes.
func init() {
	registerStatuses(map[string]int{
		// Capabilities.
		errs.CodeAdminPortalCapabilitiesRequired: http.StatusUnprocessableEntity,
		errs.CodeAdminPortalCapabilityUnknown:    http.StatusUnprocessableEntity,
		errs.CodeAdminPortalCapabilityNotGranted: http.StatusForbidden,

		// Link lifecycle.
		errs.CodeAdminPortalLinkNotFound:   http.StatusNotFound,
		errs.CodeAdminPortalTokenMissing:   http.StatusUnauthorized,
		errs.CodeAdminPortalLinkInvalid:    http.StatusUnauthorized,
		errs.CodeAdminPortalLinkRevoked:    http.StatusUnauthorized,
		errs.CodeAdminPortalLinkExpired:    http.StatusUnauthorized,
		errs.CodeAdminPortalSessionMissing: http.StatusUnauthorized,
		errs.CodeAdminPortalSessionInvalid: http.StatusUnauthorized,

		// Request shape & path parameters.
		errs.CodeAdminPortalTenantIDInvalid: http.StatusBadRequest,
		errs.CodeAdminPortalTenantMismatch:  http.StatusForbidden,
		errs.CodeAdminPortalActorRequired:   http.StatusUnauthorized,
		errs.CodeAdminPortalIDInvalid:       http.StatusBadRequest,

		// SAML connection input.
		errs.CodeAdminPortalSAMLFieldsRequired: http.StatusUnprocessableEntity,
		errs.CodeAdminPortalSAMLStatusInvalid:  http.StatusUnprocessableEntity,
	})
}
