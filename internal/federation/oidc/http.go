package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// SessionManager resolves and ends the hosted-login SSO cookie. Satisfied by
// *auth.Service; an interface keeps the dependency one-way.
type SessionManager interface {
	ResolveLoginSession(ctx context.Context, raw string) (uuid.UUID, error)
	ResolveLoginSessionWithID(ctx context.Context, raw string) (sessionID, userID uuid.UUID, err error)
	ResolveLoginSessionAt(ctx context.Context, raw string) (sessionID, userID uuid.UUID, signedInAt time.Time, err error)
	EndLoginSession(ctx context.Context, in auth.EndLoginSessionInput) (auth.LoginSessionEnded, error)
	// LoginSessionFactorShortfall says what stops a code or token being
	// issued for tenantID through the session: nil, or ErrStepUpRequired /
	// ErrMFAEnrollmentRequired while the organisation requires a second
	// factor its sign-in didn't meet.
	LoginSessionFactorShortfall(ctx context.Context, loginSessionID, userID, tenantID uuid.UUID) error
}

// ProviderLister lists a tenant's enabled social providers, so the hosted login
// app can render the right social buttons. Satisfied by *social.Service.
type ProviderLister interface {
	EnabledProviderNames(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}

// RegistrationChecker reports whether a tenant permits hosted self-registration,
// so the login-context tells the hosted app whether to show a signup link.
// Satisfied by *authpolicy.Service (optional).
type RegistrationChecker interface {
	SelfRegistrationEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

// SignInMethodsChecker reports which sign-in methods a tenant allows, so the
// login-context tells the hosted login which to offer. Satisfied by
// *authpolicy.Service (optional).
type SignInMethodsChecker interface {
	AllowedSignInMethods(ctx context.Context, tenantID uuid.UUID) (password, passkey, magicLink bool, err error)
}

// DeviceTrustChecker reports whether a tenant has opted into adaptive MFA, so
// the login-context tells the hosted app whether to offer "remember this
// device" on the MFA step. Satisfied by *authpolicy.Service (optional).
type DeviceTrustChecker interface {
	RememberDeviceEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

// BrandingLister returns a tenant's hosted-login branding (logo + brand colors)
// so the login page can render the tenant's brand on first paint. Returns empty
// strings when unset. Satisfied by *branding.Repository (optional).
type BrandingLister interface {
	LoginBranding(ctx context.Context, tenantID uuid.UUID) (logoURL, primaryColor, secondaryColor, backgroundColor string)
}

// Handler serves the OIDC provider HTTP API.
type Handler struct {
	Service *Service
	// Sessions resolves the hosted-login SSO cookie for the authorize/consent
	// flow. LoginBaseURL is the origin of the hosted login app (qeetid-login)
	// the browser is redirected to for login/consent. Providers lists a tenant's
	// social providers for the login-context endpoint (optional).
	Sessions     SessionManager
	Providers    ProviderLister
	Registration RegistrationChecker
	DeviceTrust  DeviceTrustChecker
	Methods      SignInMethodsChecker
	Branding     BrandingLister
	LoginBaseURL string
	// CookieSecure marks the hosted-login SSO cookie Secure (HTTPS-only) when
	// clearing it on logout; set from SERVICE_ENV != "dev".
	CookieSecure bool
	// PublicBaseURL is this API's public origin, the base of discovery
	// metadata and return_to URLs, or "" to build them from the request's Host.
	PublicBaseURL string
}

// Mount registers the authenticated admin/RP endpoints (require a user JWT or
// API key): client registration, userinfo (bearer access token), and grant
// administration.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/oidc/clients", h.registerClient)
	r.Get("/oauth/userinfo", h.userinfo)
	r.Post("/oauth/userinfo", h.userinfo) // OIDC Core §5.3.1 allows both
	r.Get("/oauth/bc-authorize/pending", h.pendingBackchannel)
	r.Post("/oauth/bc-authorize/decision", h.backchannelDecision)
	r.Get("/tenants/{tenantID}/oauth/grants", h.listGrants)
	r.Delete("/tenants/{tenantID}/oauth/grants/{id}", h.revokeGrant)

	// Tenant-scoped OIDC client management (admin UI). Reads/writes are confined
	// to the path tenant; create + mutate + rotate are audited.
	r.Post("/tenants/{tenantID}/oidc/clients", h.createTenantClient)
	r.Get("/tenants/{tenantID}/oidc/clients", h.listClients)
	r.Get("/tenants/{tenantID}/oidc/clients/{id}", h.getClient)
	r.Patch("/tenants/{tenantID}/oidc/clients/{id}", h.patchClient)
	r.Get("/tenants/{tenantID}/oidc/clients/{id}/auth-failures", h.clientAuthFailures)
	r.Get("/tenants/{tenantID}/oidc/resources", h.listResources)
	r.Post("/tenants/{tenantID}/oidc/resources", h.createResource)
	r.Delete("/tenants/{tenantID}/oidc/resources/{id}", h.deleteResource)
	r.Delete("/tenants/{tenantID}/oidc/clients/{id}", h.deleteClient)
	r.Post("/tenants/{tenantID}/oidc/clients/{id}/rotate-secret", h.rotateClientSecret)
	r.Get("/tenants/{tenantID}/oidc/clients/shadow-ai", h.shadowAI)
	r.Post("/tenants/{tenantID}/oidc/clients/{id}/review", h.reviewShadowAI)

	// The admin UI's list page wires Delete to the non-tenant-scoped
	// /v1/oidc/clients/{id}; the create sheet posts to /v1/oidc/clients (handled
	// by registerClient above). Tenant-scope this delete via the caller's JWT
	// tenant so it can never reach across tenants.
	r.Delete("/oidc/clients/{id}", h.deleteClientByScope)

	// Admin device-authorization visibility (RFC 8628 rows), tenant-scoped.
	r.Get("/tenants/{tenantID}/oauth/devices", h.listDevices)
	r.Delete("/tenants/{tenantID}/oauth/devices/{id}", h.revokeDevice)

	// Signing-key management (global/issuer-level, not tenant-scoped).
	r.Get("/oidc/signing-keys", h.signingKeys)
}

// MountToken registers the token endpoint, client-credential M2M traffic that
// is CSRF-exempt in the router and rate-limited apart from sign-in.
func (h *Handler) MountToken(r chi.Router) {
	r.Post("/oauth/token-code", h.tokenCode)
}

// MountBrowser registers the browser/RP-facing OAuth endpoints that authenticate
// via the SSO cookie or client credentials (not a user JWT), so they live in
// the public group. authorize (GET) and decision (cookie POST) are not
// CSRF-exempt.
func (h *Handler) MountBrowser(r chi.Router) {
	r.Get("/oauth/authorize", h.authorize)
	r.Post("/oauth/authorize/decision", h.decision)
	r.Get("/oauth/authorize/request", h.consentRequest)
	r.Get("/oauth/login-context", h.loginContext)
	r.Get("/oauth/logout", h.endSession)  // RP-Initiated Logout
	r.Post("/oauth/logout", h.endSession) // (some RPs POST)
	r.Get("/oauth/logout/continue", h.endSessionContinue)
	// Device Authorization Grant (RFC 8628). device_authorization is
	// client-authenticated M2M (CSRF-exempt in the router, like token-code);
	// the device context + decision endpoints are SSO-cookie gated like
	// authorize/decision (the hosted /device page posts the user's choice).
	r.Post("/oauth/device_authorization", h.deviceAuthorization)
	r.Get("/oauth/device", h.deviceContext)
	r.Post("/oauth/device/decision", h.deviceDecision)
	// OpenID CIBA (poll mode). bc-authorize is client-credential M2M like
	// device_authorization above (CSRF-exempt in the router); the
	// pending/decision endpoints are bearer-JWT authenticated and live in
	// Mount, not here.
	r.Post("/oauth/bc-authorize", h.backchannelAuthorize)
}

// MountPublic registers the OIDC provider routes that take no user token.
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/.well-known/openid-configuration", h.discovery)
	r.Get("/.well-known/oauth-authorization-server", h.authorizationServerMetadata) // RFC 8414
	r.Get("/.well-known/jwks.json", h.jwks)
	r.Get("/.well-known/oauth-protected-resource", h.protectedResourceMetadata) // RFC 9728
	// Client-authenticated, machine-to-machine; CSRF-exempt in the router.
	r.Post("/oauth/revoke", h.revoke)         // RFC 7009
	r.Post("/oauth/introspect", h.introspect) // RFC 7662
}

// loginContext gives the hosted login app what it needs to render itself for a
// given client_id: the client's display name, its tenant, and the tenant's
// enabled social providers.
func (h *Handler) loginContext(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	name, tenantID, err := h.Service.ClientName(r.Context(), clientID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	providers := []string{}
	if h.Providers != nil {
		if p, perr := h.Providers.EnabledProviderNames(r.Context(), tenantID); perr == nil {
			providers = p
		}
	}
	selfRegistration := false
	if h.Registration != nil {
		if enabled, rerr := h.Registration.SelfRegistrationEnabled(r.Context(), tenantID); rerr == nil {
			selfRegistration = enabled
		}
	}
	rememberDevice := false
	if h.DeviceTrust != nil {
		if enabled, derr := h.DeviceTrust.RememberDeviceEnabled(r.Context(), tenantID); derr == nil {
			rememberDevice = enabled
		}
	}
	// Which sign-in methods the tenant allows, so the hosted login offers only
	// those (each is also refused where the credential is accepted). All on when
	// no checker is wired or it cannot be read.
	methods := map[string]bool{"password": true, "passkey": true, "magic_link": true}
	if h.Methods != nil {
		if password, passkey, magic, merr := h.Methods.AllowedSignInMethods(r.Context(), tenantID); merr == nil {
			methods = map[string]bool{"password": password, "passkey": passkey, "magic_link": magic}
		}
	}
	// Per-tenant branding (logo + brand colors) so the hosted login can render
	// the tenant's brand on first paint. Omitted entirely when nothing is set.
	var brand map[string]any
	if h.Branding != nil {
		if logo, primary, secondary, background := h.Branding.LoginBranding(r.Context(), tenantID); logo != "" || primary != "" || secondary != "" || background != "" {
			brand = map[string]any{}
			if logo != "" {
				brand["logo_url"] = logo
			}
			if primary != "" {
				brand["primary_color"] = primary
			}
			if secondary != "" {
				brand["secondary_color"] = secondary
			}
			if background != "" {
				brand["background_color"] = background
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"client_name":               name,
		"tenant_id":                 tenantID,
		"providers":                 providers,
		"self_registration_enabled": selfRegistration,
		"remember_device_enabled":   rememberDevice,
		"sign_in_methods":           methods,
		"branding":                  brand,
	})
}

func (h *Handler) registerClient(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateClientInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tenantID
	ctx := r.Context()
	if err := h.Service.checkClientLimit(ctx, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	c, secret, err := h.Service.RegisterClient(ctx, tx, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var actorID *uuid.UUID
	actorType := "system"
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
		if p.ActorType != "" {
			actorType = p.ActorType
		} else {
			actorType = "user"
		}
	}
	auditTenantID := c.TenantID
	resourceID := c.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &auditTenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "oidc.client_registered",
		ResourceType: "oidc_client",
		ResourceID:   &resourceID,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata: map[string]any{
			"client_id":   c.ClientID,
			"type":        c.Type,
			"name":        c.Name,
			"grant_types": c.GrantTypes,
			"scopes":      c.Scopes,
		},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	resp := map[string]any{"client": c}
	if secret != "" {
		resp["client_secret"] = secret
		resp["warning"] = "secret shown once"
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// sessionUser resolves the hosted-login SSO cookie to a user id.
func (h *Handler) sessionUser(r *http.Request) (uuid.UUID, bool) {
	_, uid, ok := h.loginSession(r)
	return uid, ok
}

// loginSession resolves the hosted-login SSO cookie to the session's id and its
// user.
func (h *Handler) loginSession(r *http.Request) (sessionID, userID uuid.UUID, ok bool) {
	c, err := r.Cookie(auth.LoginSessionCookie)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	sessionID, userID, err = h.Sessions.ResolveLoginSessionWithID(r.Context(), c.Value)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	return sessionID, userID, true
}

// loginSessionAt is loginSession plus when the person signed in.
func (h *Handler) loginSessionAt(r *http.Request) (sessionID, userID uuid.UUID, signedInAt time.Time, ok bool) {
	c, err := r.Cookie(auth.LoginSessionCookie)
	if err != nil {
		return uuid.Nil, uuid.Nil, time.Time{}, false
	}
	sessionID, userID, signedInAt, err = h.Sessions.ResolveLoginSessionAt(r.Context(), c.Value)
	if err != nil {
		return uuid.Nil, uuid.Nil, time.Time{}, false
	}
	return sessionID, userID, signedInAt, true
}

// currentURL reconstructs the absolute URL of the current request (for the
// login redirect's return_to).
func (h *Handler) currentURL(r *http.Request) string {
	return httpx.PublicOrigin(r, h.PublicBaseURL) + r.URL.RequestURI()
}

// appendQuery appends key/value pairs (skipping empty values) to a URL that may
// already carry a query string.
func appendQuery(base string, kv ...string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	out := base
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			continue
		}
		out += sep + kv[i] + "=" + url.QueryEscape(kv[i+1])
		sep = "&"
	}
	return out
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	return httpx.PathTenantOr(r, errs.ErrOIDCTenantIDInvalid, errs.ErrOIDCTenantMismatch)
}
