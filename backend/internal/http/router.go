package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/qeetgroup/qeet-identity/internal/analytics"
	"github.com/qeetgroup/qeet-identity/internal/apikey"
	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/auth"
	"github.com/qeetgroup/qeet-identity/internal/authpolicy"
	"github.com/qeetgroup/qeet-identity/internal/billing"
	"github.com/qeetgroup/qeet-identity/internal/branding"
	"github.com/qeetgroup/qeet-identity/internal/emailtemplate"
	"github.com/qeetgroup/qeet-identity/internal/gdpr"
	"github.com/qeetgroup/qeet-identity/internal/group"
	"github.com/qeetgroup/qeet-identity/internal/invite"
	"github.com/qeetgroup/qeet-identity/internal/ipallow"
	"github.com/qeetgroup/qeet-identity/internal/ldap"
	"github.com/qeetgroup/qeet-identity/internal/mfa"
	"github.com/qeetgroup/qeet-identity/internal/oidc"
	"github.com/qeetgroup/qeet-identity/internal/passkey"
	"github.com/qeetgroup/qeet-identity/internal/platform/health"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
	"github.com/qeetgroup/qeet-identity/internal/platform/metrics"
	"github.com/qeetgroup/qeet-identity/internal/platform/outbox"
	"github.com/qeetgroup/qeet-identity/internal/platform/ratelimit"
	"github.com/qeetgroup/qeet-identity/internal/policy"
	"github.com/qeetgroup/qeet-identity/internal/principal"
	"github.com/qeetgroup/qeet-identity/internal/rbac"
	"github.com/qeetgroup/qeet-identity/internal/recovery"
	"github.com/qeetgroup/qeet-identity/internal/retention"
	"github.com/qeetgroup/qeet-identity/internal/saml"
	"github.com/qeetgroup/qeet-identity/internal/scim"
	"github.com/qeetgroup/qeet-identity/internal/secret"
	"github.com/qeetgroup/qeet-identity/internal/social"
	"github.com/qeetgroup/qeet-identity/internal/tenant"
	"github.com/qeetgroup/qeet-identity/internal/user"
	"github.com/qeetgroup/qeet-identity/internal/verification"
	"github.com/qeetgroup/qeet-identity/internal/webhook"
)

type Deps struct {
	Tenant        *tenant.Handler
	User          *user.Handler
	Auth          *auth.Handler
	AuthPolicy    *authpolicy.Handler
	RBAC          *rbac.Handler
	Verification  *verification.Handler
	Recovery      *recovery.Handler
	Retention     *retention.Handler
	Invite        *invite.Handler
	Branding      *branding.Handler
	EmailTemplate *emailtemplate.Handler
	APIKey        *apikey.Handler
	APIKeyService *apikey.Service
	Principal     *principal.Handler
	MFA           *mfa.Handler
	Webhook       *webhook.Handler
	Policy        *policy.Handler
	GDPR          *gdpr.Handler
	Audit         *audit.Handler
	Billing       *billing.Handler
	Analytics     *analytics.Handler
	Outbox        *outbox.Handler
	OIDC          *oidc.Handler
	Passkey       *passkey.Handler
	Social        *social.Handler
	Group         *group.Handler
	SCIM          *scim.Handler
	Secret        *secret.Handler
	SAML          *saml.Handler
	LDAP          *ldap.Handler
	IPAllow       *ipallow.Handler
	Health        *health.Handler
	InFlight      *httpx.InFlight

	AuthVerifier     *httpx.AuthVerifier
	AllowedOrigins   []string
	ServiceName      string
	ServiceEnv       string
	StartedAt        time.Time
	CSRFDisabled     bool
	CSRFCookieDomain string
}

func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(d.InFlight.Middleware)
	r.Use(httpx.SecurityHeaders(d.ServiceEnv != "dev"))
	r.Use(httpx.AccessLog)
	r.Use(metrics.Middleware)
	// CSRF: enforced on browser cookie-bearing requests; bearer-token
	// (Authorization: Bearer …) traffic bypasses. Lives above the route
	// groups so every mutation route inherits the check, including the
	// public auth/recovery/invite endpoints which are the most CSRF-
	// sensitive (they create sessions).
	//
	// CSRFDisabled is an explicit escape hatch for dev/Postman testing only
	// — main.go refuses to start with CSRF_DISABLED outside SERVICE_ENV=dev.
	if !d.CSRFDisabled {
		r.Use(httpx.CSRF(httpx.CSRFConfig{
			AllowedOrigins: d.AllowedOrigins,
			CookieSecure:   d.ServiceEnv != "dev",
			CookieDomain:   d.CSRFCookieDomain,
			// SAML ACS is a cross-site form-POST from the IdP, authenticated
			// by XML-signature validation rather than a CSRF cookie. The OAuth
			// revocation/introspection endpoints are machine-to-machine and
			// authenticated by client credentials (RFC 7009/7662), not a
			// browser session, so they're exempt for the same reason.
			ExemptPaths: []string{"/saml/acs/", "/oauth/revoke", "/oauth/introspect", "/v1/oauth/token-code"},
		}))
	}
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   d.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-Id", "X-Dev-User", "X-Dev-Tenant", "X-CSRF-Token"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/healthz", d.Health.Liveness)
	r.Get("/readyz", d.Health.Readiness)
	// Prometheus scrape endpoint — restrict to the scrape network in prod.
	r.Handle("/metrics", metrics.Handler())

	// OIDC well-known + JWKS live at the root, per spec.
	d.OIDC.MountPublic(r)

	// SCIM 2.0 lives at /scim/v2 with its own per-tenant bearer-token auth
	// (IdPs present a token, not a user JWT), so it mounts outside /v1.
	d.SCIM.MountPublic(r)

	// SAML SSO ceremony (metadata, login redirect, ACS, code exchange) is
	// IdP/browser-facing — no user JWT — so it also mounts at the root.
	d.SAML.MountPublic(r)

	// LDAP username/password login is end-user-facing (no JWT).
	d.LDAP.MountPublic(r)

	// Per-IP throttle on auth-burning endpoints.
	loginLimiter := ratelimit.New(5, 20)
	// Per-tenant + per-user throttles on authenticated endpoints. Rates
	// here are intentionally generous; the per-tenant bucket guards
	// against a single tenant exhausting shared resources, the per-user
	// bucket guards against a single compromised principal.
	tenantLimiter := ratelimit.New(100, 500)
	userLimiter := ratelimit.New(30, 100)
	apiKeyLimiter := ratelimit.New(50, 200)

	r.Route("/v1", func(r chi.Router) {
		// Public (no JWT required).
		r.Group(func(r chi.Router) {
			r.Use(loginLimiter.Middleware)
			d.Auth.Mount(r)            // /auth/login, /auth/refresh
			d.Recovery.Mount(r)        // forgot password, magic links
			d.Invite.MountPublic(r)    // accept-invite
			d.Principal.MountPublic(r) // /oauth/token (client_credentials)
			d.Social.MountPublic(r)    // social OAuth start/callback/exchange
			d.Passkey.MountPublic(r)   // passwordless passkey login
			d.OIDC.MountBrowser(r)     // /oauth/authorize (SSO cookie) + decision + token-code
		})

		// Authenticated. Accepts either user JWT, service JWT, or API key.
		r.Group(func(r chi.Router) {
			r.Use(d.APIKeyService.Middleware)
			r.Use(httpx.RequireAuth(d.AuthVerifier))
			r.Use(tenantLimiter.MiddlewareBy("tenant", ratelimit.PerTenant))
			r.Use(userLimiter.MiddlewareBy("user", ratelimit.PerUser))
			r.Use(apiKeyLimiter.MiddlewareBy("apikey", ratelimit.PerAPIKey))

			d.Auth.MountAuthed(r)
			d.Tenant.Mount(r)
			d.User.Mount(r)
			d.RBAC.Mount(r)
			d.Verification.Mount(r)
			d.Invite.MountAuthed(r)
			d.Branding.Mount(r)
			d.EmailTemplate.Mount(r) // /tenants/{id}/email-templates: transactional email overrides
			d.APIKey.Mount(r)
			d.Principal.Mount(r)
			d.MFA.Mount(r)
			d.Webhook.Mount(r)
			d.Policy.Mount(r)
			d.AuthPolicy.Mount(r) // /tenants/{id}/auth-policy: password rules + login methods
			d.GDPR.Mount(r)
			d.Retention.Mount(r) // /tenants/{id}/retention: auto-purge soft-deleted users
			d.Audit.Mount(r)
			d.Billing.Mount(r) // /billing/plans + /tenants/{id}/billing/*
			d.Analytics.Mount(r)
			d.Outbox.Mount(r)
			d.OIDC.Mount(r)
			d.Passkey.Mount(r)
			d.Social.Mount(r)
			d.Group.Mount(r)
			d.SCIM.Mount(r)    // /tenants/{id}/scim admin: token rotate/revoke/status
			d.Secret.Mount(r)  // /tenants/{id}/secrets: encrypted secrets vault
			d.SAML.Mount(r)    // /tenants/{id}/saml admin: connection CRUD
			d.LDAP.Mount(r)    // /tenants/{id}/ldap admin: connection CRUD + test bind
			d.IPAllow.Mount(r) // /tenants/{id}/ip-rules: allow/deny CIDR rules + check
		})
	})

	return r
}
