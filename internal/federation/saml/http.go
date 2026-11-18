package saml

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves both SAML sides. IdP is optional: when nil, the /saml/idp/*
// endpoints fail with ErrSAMLIdPNotConfigured and the SP-registry admin routes
// aren't mounted. PublicBaseURL is this API's public origin, or "" to build SAML
// URLs from the request's Host.
type Handler struct {
	Service       *Service
	IdP           *IdP
	PublicBaseURL string
	CookieSecure  bool // the browser-binding cookie's Secure attribute; off only in development
	// ActOnCheck lets a change of what a connection trusts through only for a
	// caller who outranks every administrator linked to it (rbac CheckActOn).
	// Without it the change is refused while one is linked.
	ActOnCheck identitylink.ActOn
}

// checkTrust refuses changing what connection id of organizationID trusts unless the
// caller may act on every administrator linked to it (see ActOnCheck).
func (h *Handler) checkTrust(r *http.Request, organizationID, id uuid.UUID) error {
	return identitylink.CheckTrustChange(r.Context(), h.Service.Pool(), httpx.PrincipalFromCtx(r.Context()), h.ActOnCheck, organizationID, id, "")
}

// binding ties an SP-initiated sign-in to the browser that began it, so the ACS completes it only
// there; otherwise whoever began one could post its answer from someone else's browser and sign them in
// as themselves. SameSite=None, as the IdP posts cross-site; Lax where it can't be Secure (development).
func (h *Handler) binding() httpx.BindingCookie {
	sameSite := http.SameSiteNoneMode
	if !h.CookieSecure {
		sameSite = http.SameSiteLaxMode
	}
	return httpx.BindingCookie{Name: "qe_saml", Secure: h.CookieSecure, SameSite: sameSite, MaxAge: authnRequestTTL}
}

// Mount registers the SAML routes on r.
func (h *Handler) Mount(r chi.Router) {
	// SP side: external-IdP connections Qeet consumes.
	r.Get("/organizations/{organizationID}/saml", h.list)
	r.Post("/organizations/{organizationID}/saml", h.create)
	r.Get("/organizations/{organizationID}/saml/{id}", h.get)
	r.Patch("/organizations/{organizationID}/saml/{id}", h.update)
	r.Post("/organizations/{organizationID}/saml/{id}/test", h.test)
	r.Delete("/organizations/{organizationID}/saml/{id}", h.del)
	r.Post("/organizations/{organizationID}/saml/import", h.importConnection)
	r.Post("/organizations/{organizationID}/saml/{id}/metadata", h.applyMetadata)
	r.Post("/organizations/{organizationID}/saml/{id}/certificates", h.addCertificate)
	r.Delete("/organizations/{organizationID}/saml/{id}/certificates/{certificateID}", h.removeCertificate)

	// IdP side: downstream Service Providers that consume Qeet as their IdP.
	if h.IdP != nil {
		r.Get("/organizations/{organizationID}/saml-providers", h.listSP)
		r.Post("/organizations/{organizationID}/saml-providers", h.createSP)
		r.Get("/organizations/{organizationID}/saml-providers/{id}", h.getSP)
		r.Patch("/organizations/{organizationID}/saml-providers/{id}", h.updateSP)
		r.Delete("/organizations/{organizationID}/saml-providers/{id}", h.delSP)
		r.Get("/organizations/{organizationID}/saml-providers/{id}/assignments", h.listSPAssignments)
		r.Post("/organizations/{organizationID}/saml-providers/{id}/assignments/users/{userID}", h.assignSPUser)
		r.Delete("/organizations/{organizationID}/saml-providers/{id}/assignments/users/{userID}", h.unassignSPUser)
		r.Post("/organizations/{organizationID}/saml-providers/{id}/assignments/groups/{groupID}", h.assignSPGroup)
		r.Delete("/organizations/{organizationID}/saml-providers/{id}/assignments/groups/{groupID}", h.unassignSPGroup)
	}
}

// The public SSO routes are browser- and IdP-facing. Success returns SAML XML
// or a redirect; errors use the standard JSON error envelope (httpx.WriteError).

// MountPublic registers the browser/IdP-facing SSO ceremony (no user JWT).
func (h *Handler) MountPublic(r chi.Router) {
	// SP side (Qeet as SP): metadata, login redirect, ACS, code exchange.
	r.Get("/saml/metadata/{id}", h.metadata)
	r.Get("/saml/login/{id}", h.login)
	r.Post("/saml/acs/{id}", h.acs) // CSRF-exempt (see router.go); validated by signature
	r.Post("/saml/exchange", h.exchange)
	r.Post("/saml/session", h.session)

	// IdP side (Qeet as IdP), per organization: metadata + SingleSignOnService
	// (redirect + POST).
	r.Get("/saml/idp/{organizationID}/metadata", h.idpMetadata)
	r.Get("/saml/idp/{organizationID}/certificate", h.idpCertificate)
	r.Get("/saml/idp/{organizationID}/sso", h.idpSSO)
	r.Post("/saml/idp/{organizationID}/sso", h.idpSSO) // CSRF-exempt (see router.go); SP-initiated cross-origin POST
}
