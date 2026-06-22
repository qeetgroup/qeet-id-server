package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/qeetgroup/qeet-id/domains/access/authentication"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/policy"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id/domains/access/mfa"
	"github.com/qeetgroup/qeet-id/domains/access/passkeys"
	"github.com/qeetgroup/qeet-id/domains/access/recovery"
	"github.com/qeetgroup/qeet-id/domains/access/risk/ipallow"
	"github.com/qeetgroup/qeet-id/domains/access/threat-detection/bot"
	"github.com/qeetgroup/qeet-id/domains/access/threat-detection/threat"
	"github.com/qeetgroup/qeet-id/domains/developer/agents"
	"github.com/qeetgroup/qeet-id/domains/developer/api-keys"
	"github.com/qeetgroup/qeet-id/domains/developer/auth-hooks"
	"github.com/qeetgroup/qeet-id/domains/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id/domains/developer/credentials/vc"
	"github.com/qeetgroup/qeet-id/domains/developer/service-accounts"
	"github.com/qeetgroup/qeet-id/domains/developer/webhooks"
	"github.com/qeetgroup/qeet-id/domains/federation/ldap"
	"github.com/qeetgroup/qeet-id/domains/federation/oidc"
	"github.com/qeetgroup/qeet-id/domains/federation/saml"
	"github.com/qeetgroup/qeet-id/domains/federation/scim"
	"github.com/qeetgroup/qeet-id/domains/federation/social"
	"github.com/qeetgroup/qeet-id/domains/identity/domains"
	"github.com/qeetgroup/qeet-id/domains/identity/groups"
	"github.com/qeetgroup/qeet-id/domains/identity/invitations"
	"github.com/qeetgroup/qeet-id/domains/identity/organizations"
	"github.com/qeetgroup/qeet-id/domains/identity/organizations/branding"
	"github.com/qeetgroup/qeet-id/domains/identity/users"
	"github.com/qeetgroup/qeet-id/domains/identity/verification"
	"github.com/qeetgroup/qeet-id/domains/operations/analytics"
	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/domains/operations/billing"
	"github.com/qeetgroup/qeet-id/domains/operations/compliance"
	"github.com/qeetgroup/qeet-id/domains/operations/email-templates"
	"github.com/qeetgroup/qeet-id/domains/operations/notifications"
	"github.com/qeetgroup/qeet-id/domains/operations/retention"
	"github.com/qeetgroup/qeet-id/domains/operations/siem"
	"github.com/qeetgroup/qeet-id/platform/health"
	"github.com/qeetgroup/qeet-id/platform/httpx"
	"github.com/qeetgroup/qeet-id/platform/metrics"
	"github.com/qeetgroup/qeet-id/platform/outbox"
	"github.com/qeetgroup/qeet-id/platform/ratelimit"
	"github.com/qeetgroup/qeet-id/platform/tracing"
)

type Deps struct {
	Tenant     *tenant.Handler
	User       *user.Handler
	Auth       *auth.Handler
	AuthPolicy *authpolicy.Handler
	RBAC       *rbac.Handler
	// RBACChecker enforces per-route permissions for end-user principals
	// (the authz policy table lives in permissionMap()). Satisfied by the
	// rbac repository.
	RBACChecker   rbac.Checker
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
	Threat        *threat.Handler
	Bot           *bot.Handler
	Notification  *notification.Handler
	DomainVerify  *domainverify.Handler
	SIEM          *siem.Handler
	AuthHook      *authhook.Handler
	ReBAC         *rebac.Handler
	Agent         *agent.Handler
	VC            *vc.Handler
	Health        *health.Handler
	InFlight      *httpx.InFlight

	AuthVerifier     *httpx.AuthVerifier
	AllowedOrigins   []string
	ServiceName      string
	ServiceEnv       string
	StartedAt        time.Time
	CSRFDisabled     bool
	CSRFCookieDomain string
	// RateLimitStore, when set, backs every limiter (shared across replicas).
	// Nil = in-process limits.
	RateLimitStore ratelimit.Store
}

func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(d.InFlight.Middleware)
	r.Use(httpx.SecurityHeaders(d.ServiceEnv != "dev"))
	r.Use(httpx.AccessLog)
	// Tracing wraps metrics so the server span spans the whole request; both
	// derive low-cardinality names from the matched chi route pattern. When no
	// OTLP endpoint is configured the global tracer is a no-op, so this is a
	// cheap pass-through.
	r.Use(tracing.Middleware)
	r.Use(metrics.Middleware)
	// CORS first (above CSRF) so that even a rejected request — e.g. a CSRF 403
	// — still carries Access-Control-* headers; otherwise the browser masks the
	// real error as a generic "blocked by CORS policy" failure.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   d.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-Id", "X-Dev-User", "X-Dev-Tenant", "X-CSRF-Token"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	// CSRF: enforced on browser cookie-bearing requests; bearer-token
	// (Authorization: Bearer …) traffic bypasses entirely. Lives above the route
	// groups so every cookie-session mutation inherits the check.
	//
	// CSRFDisabled is an explicit escape hatch for dev/Postman testing only
	// — main.go refuses to start with CSRF_DISABLED outside SERVICE_ENV=dev.
	if !d.CSRFDisabled {
		r.Use(httpx.CSRF(httpx.CSRFConfig{
			AllowedOrigins: d.AllowedOrigins,
			CookieSecure:   d.ServiceEnv != "dev",
			CookieDomain:   d.CSRFCookieDomain,
			// Exempt paths, two buckets:
			//  1. Machine/IdP-driven, authenticated by something other than a
			//     browser session: SAML ACS (XML-DSig) + IdP SSO POST binding;
			//     OAuth revoke/introspect (client creds, RFC 7009/7662); the
			//     code + device-authorization token endpoints (RFC 8628).
			//  2. Public PRE-AUTH endpoints that bootstrap a *Bearer* token (not a
			//     cookie session): signup/login/refresh, password recovery, magic
			//     link, passkey login, social, invite-accept. They carry no cookie
			//     session to forge; the token response can't be read or stored
			//     cross-origin by an attacker; and CORS origin-checks + rate limits
			//     already gate them — so the double-submit only adds friction.
			//     NB: /v1/auth/session (the cookie-session creator) is deliberately
			//     NOT exempt — it stays CSRF-protected.
			ExemptPaths: []string{
				"/saml/acs/", "/saml/idp/sso", "/oauth/revoke", "/oauth/introspect",
				"/v1/oauth/token-code", "/v1/oauth/device_authorization",
				"/v1/auth/signup", "/v1/auth/login", "/v1/auth/refresh",
				"/v1/auth/forgot-password", "/v1/auth/reset-password", "/v1/auth/magic-link/",
				"/v1/passkeys/login/", "/v1/social/", "/v1/invites/accept",
				"/v1/billing/webhooks/",  // provider-signed (Stripe/Razorpay), no cookie session
				"/v1/agents/token",       // agent-credential auth (no cookie session)
				"/v1/credentials/verify", // public JWT-VC verification (no cookie session)
			},
		}))
	}

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

	// newLimiter builds an in-process limiter, or a Redis-backed one when a
	// shared store is configured (so limits hold across replicas).
	newLimiter := func(rate float64, capacity int) *ratelimit.Limiter {
		if d.RateLimitStore != nil {
			return ratelimit.NewWithStore(d.RateLimitStore, rate, capacity)
		}
		return ratelimit.New(rate, capacity)
	}
	// Per-IP throttle on auth-burning endpoints.
	loginLimiter := newLimiter(5, 20)
	// Per-tenant + per-user throttles on authenticated endpoints. Rates
	// here are intentionally generous; the per-tenant bucket guards
	// against a single tenant exhausting shared resources, the per-user
	// bucket guards against a single compromised principal.
	tenantLimiter := newLimiter(100, 500)
	userLimiter := newLimiter(30, 100)
	apiKeyLimiter := newLimiter(50, 200)

	r.Route("/v1", func(r chi.Router) {
		// Public (no JWT required).
		r.Group(func(r chi.Router) {
			r.Use(loginLimiter.Middleware)
			d.Auth.Mount(r)            // /auth/login, /auth/refresh
			d.Recovery.Mount(r)        // forgot password, magic links
			d.Invite.MountPublic(r)    // accept-invite
			d.Principal.MountPublic(r) // /oauth/token (client_credentials)
			d.Social.MountPublic(r)    // social OAuth start/callback/exchange
			d.Billing.MountPublic(r)   // /billing/webhooks/{provider}: Stripe/Razorpay (signature-verified)
			d.Agent.MountPublic(r)     // /agents/token: AI-agent credential → ephemeral scoped token
			d.VC.MountPublic(r)        // /credentials/verify: verify a presented JWT-VC (any relying party)
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
			// RBAC permission enforcement for end-user principals. Gates the
			// routes listed in permissionMap(); API-key/service actors and
			// unmapped (self-service / public) routes pass through.
			r.Use(rbac.Enforce(d.RBACChecker, permissionMap()))

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
			d.SCIM.Mount(r)         // /tenants/{id}/scim admin: token rotate/revoke/status
			d.Secret.Mount(r)       // /tenants/{id}/secrets: encrypted secrets vault
			d.SAML.Mount(r)         // /tenants/{id}/saml admin: connection CRUD
			d.LDAP.Mount(r)         // /tenants/{id}/ldap admin: connection CRUD + test bind
			d.IPAllow.Mount(r)      // /tenants/{id}/ip-rules: allow/deny CIDR rules + check
			d.Threat.Mount(r)       // /tenants/{id}/security/anomalies: detected security events
			d.Bot.Mount(r)          // /tenants/{id}/security/bots: bot-detection telemetry + settings
			d.Notification.Mount(r) // /notifications: in-app inbox (principal-scoped)
			d.DomainVerify.Mount(r) // /tenants/{id}/domains: DNS domain verification
			d.SIEM.Mount(r)         // /tenants/{id}/log-sinks: SIEM / log streaming
			d.AuthHook.Mount(r)     // /tenants/{id}/auth-hooks: synchronous login Actions/Hooks
			d.ReBAC.Mount(r)        // /tenants/{id}/relation-tuples: fine-grained (ReBAC) authz
			d.Agent.Mount(r)        // /tenants/{id}/agents: AI-agent identity admin
			d.VC.Mount(r)           // /tenants/{id}/credentials: verifiable credential issuance
		})
	})

	return r
}
