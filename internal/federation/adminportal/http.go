package adminportal

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
)

// Handler serves the admin portal HTTP API. PublicBaseURL is this API's
// public origin, or "" to build the addresses an IdP needs from the request's
// Host, as the SAML and SCIM handlers do.
type Handler struct {
	Service       *Service
	SAML          *saml.Service
	SAMLSignIn    *saml.Handler
	SCIM          *scim.Service
	Domains       *domainverify.Service
	PublicBaseURL string
	CookieSecure  bool
}

// Mount registers the authed link-management endpoints (generate/list/revoke)
// under the normal /v1/organizations/{organizationID} group — this is the organization admin's
// own action, gated by connection.write/connection.read like the rest of SSO
// config.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/organizations/{organizationID}/admin-portal/links", h.generate)
	r.Get("/organizations/{organizationID}/admin-portal/links", h.list)
	r.Delete("/organizations/{organizationID}/admin-portal/links/{id}", h.revoke)
}

// MountPublic registers the one-time link exchange and the cookie-authenticated,
// token-free portal endpoints used by the external IT administrator.
func (h *Handler) MountPublic(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(adminPortalHeaders)
		r.Post("/admin-portal/session", h.exchange)
		r.Delete("/admin-portal/session", h.logout)
		r.Get("/admin-portal/context", h.context)

		r.Get("/admin-portal/saml", h.samlList)
		r.Post("/admin-portal/saml", h.samlCreate)
		r.Get("/admin-portal/saml/{id}", h.samlGet)
		r.Patch("/admin-portal/saml/{id}", h.samlUpdate)
		r.Post("/admin-portal/saml/{id}/test", h.samlTest)
		r.Post("/admin-portal/saml/{id}/test-sign-ins", h.samlTestSignInBegin)
		r.Get("/admin-portal/saml/{id}/test-sign-ins/{testID}", h.samlTestSignInGet)
		r.Delete("/admin-portal/saml/{id}", h.samlDelete)

		r.Get("/admin-portal/scim", h.scimConfig)
		r.Post("/admin-portal/scim/token", h.scimRotate)
		r.Delete("/admin-portal/scim/token", h.scimRevoke)

		r.Get("/admin-portal/domains", h.domainList)
		r.Post("/admin-portal/domains", h.domainAdd)
		r.Post("/admin-portal/domains/{id}/verify", h.domainVerify)
		r.Patch("/admin-portal/domains/{id}", h.domainUpdate)
	})
}

func adminPortalHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
