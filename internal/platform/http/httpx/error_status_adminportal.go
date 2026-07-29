package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Admin Portal code→status mappings. Registered from init() so the
// federation/adminportal bounded context owns its own mappings without editing
// the shared error_status.go. Each code maps to the SAME status as the generic
// sentinel it replaced.
func init() {
	registerStatuses(map[string]int{
		// Capabilities.
		errs.CodeAdminPortalCapabilitiesRequired: http.StatusUnprocessableEntity,
		errs.CodeAdminPortalCapabilityUnknown:    http.StatusUnprocessableEntity,
		errs.CodeAdminPortalCapabilityNotGranted: http.StatusForbidden,

		// Link lifecycle.
		errs.CodeAdminPortalLinkNotFound: http.StatusNotFound,
		errs.CodeAdminPortalTokenMissing: http.StatusUnauthorized,
		errs.CodeAdminPortalLinkInvalid:  http.StatusUnauthorized,
		errs.CodeAdminPortalLinkRevoked:  http.StatusUnauthorized,
		errs.CodeAdminPortalLinkExpired:  http.StatusUnauthorized,

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
