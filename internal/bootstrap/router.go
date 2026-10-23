package bootstrap

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authzen"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/policy"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	passkey "github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	"github.com/qeetgroup/qeet-id-server/internal/access/risk/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/bot"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/threat"
	agent "github.com/qeetgroup/qeet-id-server/internal/developer/agents"
	apikey "github.com/qeetgroup/qeet-id-server/internal/developer/api-keys"
	authhook "github.com/qeetgroup/qeet-id-server/internal/developer/auth-hooks"
	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/vc"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal"
	webhook "github.com/qeetgroup/qeet-id-server/internal/developer/webhooks"
	"github.com/qeetgroup/qeet-id-server/internal/federation/adminportal"
	"github.com/qeetgroup/qeet-id-server/internal/federation/directory"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	group "github.com/qeetgroup/qeet-id-server/internal/identity/groups"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant/branding"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/identity/verification"
	"github.com/qeetgroup/qeet-id-server/internal/operations/activity"
	"github.com/qeetgroup/qeet-id-server/internal/operations/analytics"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/anomaly"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	notification "github.com/qeetgroup/qeet-id-server/internal/operations/notifications"
	"github.com/qeetgroup/qeet-id-server/internal/operations/qeetai"
	"github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention"
	"github.com/qeetgroup/qeet-id-server/internal/operations/sales"
	"github.com/qeetgroup/qeet-id-server/internal/operations/search"
	"github.com/qeetgroup/qeet-id-server/internal/operations/siem"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/idempotency"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/health"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/metrics"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/tracing"
)

// Deps is everything the router serves: each package's handler and the shared
// middleware settings.
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
	EmailTemplate *email.Handler
	EmailDelivery *email.DeliveryHandler
	SESWebhook    *delivery.Webhook
	APIKey        *apikey.Handler
	APIKeyService *apikey.Service
	Principal     *principal.Handler
	MFA           *mfa.Handler
	Webhook       *webhook.Handler
	Policy        *policy.Handler
	GDPR          *gdpr.Handler
	Audit         *audit.Handler
	AuditAnomaly  *anomaly.Handler
	Billing       *billing.Handler
	Entitlement   *entitlements.Handler
	Sales         *sales.Handler
	Analytics     *analytics.Handler
	OIDC          *oidc.Handler
	Passkey       *passkey.Handler
	Social        *social.Handler
	Group         *group.Handler
	SCIM          *scim.Handler
	Secret        *secret.Handler
	TokenVault    *tokenvault.Handler
	SAML          *saml.Handler
	AdminPortal   *adminportal.Handler
	LDAP          *ldap.Handler
	Directory     *directory.Handler
	IPAllow       *ipallow.Handler
	Threat        *threat.Handler
	Bot           *bot.Handler
	Risk          *risk.Handler
	RateLimits    *ratelimits.Handler
	Notification  *notification.Handler
	DomainVerify  *domainverify.Handler
	SIEM          *siem.Handler
	Qeetai        *qeetai.Handler
	AuthHook      *authhook.Handler
	ABAC          *abac.Handler
	ReBAC         *rebac.Handler
	AuthZEN       *authzen.Handler
	Agent         *agent.Handler
	VC            *vc.Handler
	Search        *search.Handler
	Activity      *activity.Handler
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
	// TenantLim, UserLim and APIKeyLim limit the authenticated routes per
	// organisation, user and API key, at the organisation's own limits where it
	// has set them.
	TenantLim, UserLim, APIKeyLim *ratelimit.TenantLimiter
	// Idempotency stores the answers to IdempotentRoutes requests sent with
	// an Idempotency-Key.
	Idempotency *idempotency.Store

	shutdownHooks []func() // run once the HTTP server has drained
}

// NewRouter builds the HTTP API: the middleware chain, the public routes, and
// the authenticated routes behind it.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(httpx.ClientIPContext) // the client address, for audit records written below a handler
	// chimw.RealIP is deliberately not used: it trusts X-Forwarded-For from anyone.
	// Client IPs come from httpx.ClientIP, governed by TRUSTED_PROXY_HOPS.
	r.Use(httpx.GeoCountryContext) // the trusted upstream country, for the sessions a request opens
	r.Use(d.InFlight.Middleware)
	r.Use(httpx.SecurityHeaders(d.ServiceEnv != config.EnvDev))
	r.Use(httpx.NoStore(NoStoreRoutes())) // responses carrying a token, secret or sign-in session
	// Tracing wraps metrics so the server span covers the whole request, and it sits
	// above AccessLog so log lines carry trace_id and span_id. With no OTLP endpoint
	// the tracer is a no-op.
	r.Use(tracing.Middleware)
	r.Use(httpx.AccessLog)
	r.Use(metrics.Middleware)
	// Below the logging, metrics and in-flight count, so a panic is answered
	// 500 and still logged, counted and released.
	r.Use(chimw.Recoverer)
	// CORS first (above CSRF) so that even a rejected request — e.g. a CSRF 403
	// — still carries Access-Control-* headers; otherwise the browser masks the
	// real error as a generic "blocked by CORS policy" failure.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   d.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-Id", "X-Dev-User", "X-Dev-Tenant", "X-CSRF-Token", idempotency.Header},
		ExposedHeaders:   []string{"X-Request-Id", "Idempotent-Replayed"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	// CSRF applies to cookie-bearing browser requests; bearer tokens and API keys
	// bypass it. CSRFDisabled is for dev only, and startup refuses it elsewhere.
	if !d.CSRFDisabled {
		r.Use(CSRF(d.AllowedOrigins, d.ServiceEnv != config.EnvDev, d.CSRFCookieDomain))
	}

	// newLimiter builds an in-process limiter, or a Redis-backed one when a
	// shared store is configured (so limits hold across replicas). A shared
	// store keys buckets by scope, so each limiter names its own.
	newLimiter := func(rate float64, capacity int) *ratelimit.Limiter {
		if d.RateLimitStore != nil {
			return ratelimit.NewWithStore(d.RateLimitStore, rate, capacity)
		}
		return ratelimit.New(rate, capacity)
	}
	// Per-IP throttle on auth-burning endpoints.
	loginLimiter := newLimiter(5, 20)
	// The token endpoints serve an application's code exchanges and refreshes
	// for all its users from one address, and every credential they take is
	// long and random, so they get a machine-traffic bucket.
	tokenLimiter := newLimiter(50, 200)

	// Rate limits for root-mounted protocol routes. credentialLimiter matches the /v1
	// login throttle (LDAP authenticate is a password-spray target, introspect a token
	// oracle); protocolLimiter is generous, since SCIM and SAML are legitimate machine
	// traffic.
	credentialLimiter := newLimiter(5, 20)
	protocolLimiter := newLimiter(50, 200)

	mountRootPublicRoutes(r, d, credentialLimiter, protocolLimiter)

	// Tight per-user throttle for the endpoints that dispatch an SMS/email to a
	// caller-supplied address or guess a credential (~6/min sustained, burst 5):
	// blunts SMS toll-fraud, email-bombing, and online password guessing that the
	// generous 30 rps/user bucket wouldn't. Applied per-route inside the handlers.
	sensitiveThrottle := newLimiter(0.1, 5).MiddlewareBy("sensitive", ratelimit.PerUser)
	d.Auth.Throttle = sensitiveThrottle
	d.Verification.Throttle = sensitiveThrottle
	// A phone linking with a pairing code: a wrong code is a guess, so the same
	// pace per address (the code itself is 50 bits and lives five minutes).
	d.MFA.PairingThrottle = newLimiter(0.1, 5).MiddlewareBy("pairing", ratelimit.PerIP)

	r.Route("/v1", func(r chi.Router) {
		// Public (no JWT required).
		r.Group(func(r chi.Router) {
			r.Use(loginLimiter.MiddlewareBy("login-ip", ratelimit.PerIP))
			mountV1PublicRoutes(r, d)
		})
		r.Group(func(r chi.Router) {
			r.Use(tokenLimiter.MiddlewareBy("token-ip", ratelimit.PerIP))
			mountV1TokenRoutes(r, d)
		})

		// Authenticated. Accepts either user JWT, service JWT, or API key — and,
		// on the few routes in LoginSessionRoutes only, the hosted login's
		// session cookie (CSRF-checked above like every cookie mutation).
		r.Group(func(r chi.Router) {
			r.Use(d.APIKeyService.Middleware)
			r.Use(d.Auth.Service.LoginSessionAuth(LoginSessionRoutes()))
			r.Use(httpx.RequireAuth(d.AuthVerifier))
			// A token issued to an application reaches only the routes meant for
			// applications (ApplicationTokenRoutes); everything else here is account
			// and organisation management, which only the user's own tokens may do.
			r.Use(httpx.RefuseApplicationTokens(ApplicationTokenRoutes()))
			// Cross-tenant guard: a {tenantID} path parameter must match the caller's
			// tenant. It needs the nested Route("/v1") + Group structure to see the
			// parameter; flattening these routes onto the top mux makes it fail open.
			r.Use(httpx.EnforceTenantScope)
			// Row-level security: on organisation-administration routes the
			// database shows the request only its organisation's rows.
			r.Use(scopeOrganisationRoutes(RoutePolicies()))
			// Generous per-organisation, per-user and per-key buckets: one
			// organisation can't exhaust shared resources, nor one compromised
			// principal its organisation's.
			r.Use(d.TenantLim.MiddlewareBy("tenant", ratelimit.PerTenant))
			r.Use(d.UserLim.MiddlewareBy("user", ratelimit.PerUser))
			r.Use(d.APIKeyLim.MiddlewareBy("apikey", ratelimit.PerAPIKey))
			// RBAC permission enforcement for end-user principals. Gates the
			// routes listed in permissionMap(); API-key/service actors and
			// unmapped (self-service / public) routes pass through.
			r.Use(rbac.Enforce(d.RBACChecker, RoutePolicies()))
			// Sensitive actions also need a step-up of the calling session
			// (StepUpRoutes); asked only of a caller already authorized.
			r.Use(d.MFA.Service.StepUpGate(StepUpRoutes()))
			// Last, so only a request that may run is remembered for its key.
			r.Use(d.Idempotency.Middleware(IdempotentRoutes()))

			mountAuthenticatedRoutes(r, d)
		})
	})

	return r
}

// mountRootPublicRoutes registers the protocol and operational routes outside
// /v1. Groups add rate limits without changing route patterns. Health probes are
// unlimited, so a busy pod isn't killed.
func mountRootPublicRoutes(r chi.Router, d Deps, credentialLimiter, protocolLimiter *ratelimit.Limiter) {
	r.Get("/healthz", d.Health.Liveness)
	r.Get("/readyz", d.Health.Readiness)
	r.Get("/version", d.Health.Version)
	r.Get("/metrics", metrics.Handler().ServeHTTP)

	// Directory credential verification — same throttle as /v1 login.
	r.Group(func(r chi.Router) {
		r.Use(credentialLimiter.MiddlewareBy("credential-ip", ratelimit.PerIP))
		d.LDAP.MountPublic(r)
	})

	// Protocol surfaces: machine traffic, generously bounded.
	r.Group(func(r chi.Router) {
		r.Use(protocolLimiter.MiddlewareBy("protocol-ip", ratelimit.PerIP))
		d.OIDC.MountPublic(r)
		d.SCIM.MountPublic(r)
		d.SAML.MountPublic(r)
	})
}

// mountV1PublicRoutes is the single production registration point for routes
// under /v1 that authenticate with protocol credentials, cookies, one-time
// state, or no credential rather than the API JWT/API-key middleware.
func mountV1PublicRoutes(r chi.Router, d Deps) {
	d.Auth.Mount(r)
	d.Recovery.Mount(r)
	d.Invite.MountPublic(r)
	d.Social.MountPublic(r)
	d.Billing.MountPublic(r)
	d.Agent.MountPublic(r)
	d.VC.MountPublic(r)
	d.Audit.MountPublic(r)
	d.Passkey.MountPublic(r)
	d.AdminPortal.MountPublic(r)
	d.OIDC.MountBrowser(r)
	d.TokenVault.MountPublic(r)
	d.MFA.MountPublic(r)
	d.SESWebhook.Mount(r)
}

// mountV1TokenRoutes registers the OAuth token endpoints, which applications
// call for many people from one address.
func mountV1TokenRoutes(r chi.Router, d Deps) {
	d.Principal.MountToken(r)
	d.OIDC.MountToken(r)
}

// mountAuthenticatedRoutes is the single production registration point for
// routes protected by RequireAuth and the route policy catalogue. Keeping the
// mounts in one helper lets the coverage test walk the exact production route
// set without duplicating it or changing the load-bearing middleware nesting.
func mountAuthenticatedRoutes(r chi.Router, d Deps) {
	d.Auth.MountAuthed(r)
	d.Tenant.Mount(r)
	d.User.Mount(r)
	d.RBAC.Mount(r)
	d.Verification.Mount(r)
	d.Invite.MountAuthed(r)
	d.Branding.Mount(r)
	d.EmailTemplate.Mount(r)
	d.EmailDelivery.Mount(r)
	d.APIKey.Mount(r)
	d.Principal.Mount(r)
	d.MFA.Mount(r)
	d.MFA.MountAdmin(r)
	d.Webhook.Mount(r)
	d.Policy.Mount(r)
	d.AuthPolicy.Mount(r)
	d.GDPR.Mount(r)
	d.Retention.Mount(r)
	d.Audit.Mount(r)
	d.AuditAnomaly.Mount(r)
	d.Billing.Mount(r)
	d.Entitlement.Mount(r)
	d.Sales.Mount(r)
	d.Analytics.Mount(r)
	d.OIDC.Mount(r)
	d.Passkey.Mount(r)
	d.Social.Mount(r)
	d.Group.Mount(r)
	d.Group.MountTemplates(r)
	d.SCIM.Mount(r)
	d.Secret.Mount(r)
	d.TokenVault.Mount(r)
	d.SAML.Mount(r)
	d.AdminPortal.Mount(r)
	d.LDAP.Mount(r)
	d.Directory.Mount(r)
	d.IPAllow.Mount(r)
	d.Threat.Mount(r)
	d.Bot.Mount(r)
	d.Risk.Mount(r)
	d.RateLimits.Mount(r)
	d.Notification.Mount(r)
	d.DomainVerify.Mount(r)
	d.SIEM.Mount(r)
	d.AuthHook.Mount(r)
	d.ABAC.Mount(r)
	d.ReBAC.Mount(r)
	d.AuthZEN.Mount(r)
	d.Agent.Mount(r)
	d.VC.Mount(r)
	d.Qeetai.Mount(r)
	d.Search.Mount(r)
	d.Activity.Mount(r)
}

// ApplicationTokenRoutes lists the authenticated routes that accept a token
// issued to an application. Every other authenticated route refuses it: an
// application may read who the user is, not manage their account.
func ApplicationTokenRoutes() []string {
	return []string{
		"GET /v1/oauth/userinfo",
		"POST /v1/oauth/userinfo",
	}
}

// LoginSessionRoutes lists the authenticated routes that also accept the hosted
// login's session cookie (qe_ls), because its pages hold no token. Keep it to
// user-only self-service routes that aren't CSRF-exempt.
func LoginSessionRoutes() []string {
	return []string{
		"GET /v1/auth/me",
		"GET /v1/me",
		"GET /v1/me/organizations",
		"GET /v1/passkeys",
		"PATCH /v1/passkeys/{id}",
		"POST /v1/passkeys/register/begin",
		"POST /v1/passkeys/register/finish",
	}
}

// scopeOrganisationRoutes applies row-level security (httpx.ScopeDatabase) to
// the organisation-administration routes: those whose policy needs a user
// permission or a machine scope. A person's own routes (user-only policies)
// act on their data across organisations and run unscoped.
func scopeOrganisationRoutes(policies map[string]rbac.RoutePolicy) func(http.Handler) http.Handler {
	administration := chi.NewRouter()
	for route, p := range policies {
		if p.UserPermission == "" && len(p.MachineScopes) == 0 && !p.HandlerAuthorizedMachine {
			continue
		}
		method, pattern, _ := strings.Cut(route, " ")
		administration.MethodFunc(method, pattern, func(http.ResponseWriter, *http.Request) {})
	}
	return func(next http.Handler) http.Handler {
		scoped := httpx.ScopeDatabase(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if administration.Match(chi.NewRouteContext(), r.Method, r.URL.Path) {
				scoped.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IdempotentRoutes are the create routes that honour an Idempotency-Key: one
// sent again with the same key and body gets the first answer instead of
// creating twice (see the idempotency package).
func IdempotentRoutes() []string {
	return []string{
		"POST /v1/api-keys",
		"POST /v1/groups",
		"POST /v1/invites",
		"POST /v1/service-principals",
		"POST /v1/tenants/{tenantID}/agents",
		"POST /v1/tenants/{tenantID}/billing/checkout",
		"POST /v1/users",
		"POST /v1/webhooks",
	}
}

// NoStoreRoutes lists the routes whose responses carry a token, a secret shown
// once, or a sign-in session cookie. NewRouter marks them Cache-Control:
// no-store and Pragma: no-cache (RFC 6749 §5.1).
func NoStoreRoutes() []string {
	return []string{
		// Token endpoints, the device and backchannel requests whose codes a
		// client polls them with, the consent answer carrying an authorization
		// code, and the IdP page carrying a signed SAML assertion.
		"POST /v1/oauth/token",
		"POST /v1/oauth/token-code",
		"POST /v1/oauth/device_authorization",
		"POST /v1/oauth/bc-authorize",
		"POST /v1/oauth/authorize/decision",
		"POST /v1/agents/token",
		"POST /ldap/{id}/authenticate",
		"GET /saml/idp/{tenantID}/sso",
		"POST /saml/idp/{tenantID}/sso",

		// Sign-in: a token pair, an mfa_token, or the hosted-login cookie.
		"POST /v1/auth/signup",
		"POST /v1/auth/login",
		"POST /v1/auth/mfa",
		"POST /v1/auth/mfa/enroll",
		"POST /v1/auth/refresh",
		"POST /v1/auth/session",
		"POST /v1/auth/session/mfa",
		"DELETE /v1/auth/session",
		"POST /v1/auth/register",
		"POST /v1/auth/switch-tenant",
		"POST /v1/auth/sessions/revoke-all",
		"POST /v1/auth/forgot-password",
		"POST /v1/auth/magic-link/consume",
		"POST /v1/auth/magic-link/session",
		"POST /v1/passkeys/login/finish",
		"POST /v1/passkeys/login/session",
		"POST /v1/signup/passkey/finish",
		"POST /v1/register/passkey/finish",
		"POST /v1/invites/accept",
		"POST /v1/invites/accept/passkey/finish",
		"POST /v1/me/invites/accept",
		"POST /v1/me/invites/{id}/accept",
		"POST /v1/social/exchange",
		"POST /saml/exchange",
		"POST /v1/tenants",

		// A secret, key, code or credential returned to its holder.
		"POST /v1/api-keys",
		"POST /v1/oidc/clients",
		"POST /v1/tenants/{tenantID}/oidc/clients",
		"POST /v1/tenants/{tenantID}/oidc/clients/{id}/rotate-secret",
		"POST /v1/service-principals",
		"POST /v1/tenants/{tenantID}/agents",
		"POST /v1/webhooks",
		"POST /v1/tenants/{tenantID}/webhooks/{id}/rotate-secret",
		"POST /v1/mfa/totp/enroll/start",
		"POST /v1/mfa/totp/enroll/confirm",
		"POST /v1/mfa/recovery-codes/regenerate",
		"POST /v1/mfa/push/devices",
		"POST /v1/mfa/push/pairing",
		"POST /v1/mfa/push/pairing/claim",
		"POST /v1/tenants/{tenantID}/scim/token",
		"POST /v1/tenants/{tenantID}/admin-portal/links",
		"POST /v1/tenants/{tenantID}/secrets/{id}/reveal",
		"POST /v1/tenants/{tenantID}/credentials",
		"GET /v1/vault/tokens/{provider}/access-token",
	}
}

// CSRF is the production cross-site request check (httpx.CSRF) with the
// production exemptions, as NewRouter mounts it.
func CSRF(allowedOrigins []string, cookieSecure bool, cookieDomain string) func(http.Handler) http.Handler {
	return httpx.CSRF(httpx.CSRFConfig{
		AllowedOrigins: allowedOrigins,
		CookieSecure:   cookieSecure,
		CookieDomain:   cookieDomain,
		// Exempt: machine and IdP endpoints authenticated otherwise (SAML ACS, OAuth
		// revoke, introspect and token) and public pre-auth endpoints that return bearer
		// tokens; cookie-setting endpoints stay protected. Entries are exact, end in "/"
		// (prefix) or use "*" (one segment), so keep prefixes narrow.
		ExemptPaths: csrfExemptPaths(),
	})
}

// csrfExemptPaths lists the paths that skip the double-submit/origin check.
// Extracted so TestNoAuthenticatedRouteIsCSRFExempt can assert the list never
// covers a route in the authenticated tree.
func csrfExemptPaths() []string {
	return []string{
		"/saml/acs/", "/saml/idp/*/sso", "/oauth/revoke", "/oauth/introspect",
		"/v1/oauth/token-code", "/v1/oauth/device_authorization",
		"/v1/oauth/token",        // service-principal client credentials, in the form or Basic; no cookie session
		"/ldap/*/authenticate",   // directory credentials in the body, answered with a token pair; no cookie session
		"/v1/oauth/bc-authorize", // exact: .../decision below it is authenticated
		"/v1/auth/signup", "/v1/auth/login", "/v1/auth/refresh",
		"/v1/auth/mfa",  // completes a token-flow sign-in: the mfa_token, not a cookie, is the credential
		"/v1/auth/mfa/", // its helpers (send a code, begin a passkey, send a push) — likewise
		"/v1/auth/forgot-password", "/v1/auth/reset-password",
		"/v1/auth/magic-link/start", "/v1/auth/magic-link/consume", "/v1/auth/magic-link/resend", // not .../session: it sets the hosted-login cookie
		"/v1/passkeys/login/begin", "/v1/passkeys/login/finish", // not .../session: it sets the hosted-login cookie
		"/v1/social/exchange",           // one-time code exchange, no cookie session
		"/v1/social/*/callback",         // Apple response_mode=form_post lands cross-site
		"/v1/invites/accept",            // invitation token in the body, no cookie session
		"/v1/invites/accept/passkey/",   // the same, accepting with a passkey
		"/v1/invites/lookup",            // read-only preview by invitation token
		"/v1/billing/webhooks/",         // provider-signed (Stripe/Razorpay), no cookie session
		"/v1/webhooks/ses",              // SNS-signed SES events, no cookie session
		"/v1/billing/sandbox/",          // dev-only mock hosted-checkout page + pay (no cookie session)
		"/v1/agents/token",              // agent-credential auth (no cookie session)
		"/v1/credentials/verify",        // public JWT-VC verification (no cookie session)
		"/v1/mfa/push/challenges/",      // a linked phone answers with its device credential (no cookie session)
		"/v1/mfa/push/devices/*/unlink", // a linked phone removes itself with its device credential (no cookie session)
		"/v1/mfa/push/pairing/claim",    // a phone links with a one-time pairing code (no cookie session)
	}
}
