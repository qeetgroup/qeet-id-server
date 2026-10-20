package bootstrap

import (
	"net/http"
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
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/health"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/metrics"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/tracing"
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
	EmailTemplate *email.Handler
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
	Outbox        *outbox.Handler
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
}

func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(httpx.ClientIPContext) // the client address, for audit records written below a handler
	// NOTE: chimw.RealIP is deliberately NOT used. It rewrites r.RemoteAddr from
	// X-Forwarded-For / X-Real-IP unconditionally, with no notion of a trusted
	// proxy — which would re-introduce the spoofing that httpx.ClientIP now
	// defends against by making the transport peer (our safe fallback) equally
	// caller-controlled. Client IP resolution lives in httpx.ClientIP, governed
	// by TRUSTED_PROXY_HOPS.
	r.Use(chimw.Recoverer)
	r.Use(httpx.GeoCountryContext) // the trusted upstream country, for the sessions a request opens
	r.Use(d.InFlight.Middleware)
	r.Use(httpx.SecurityHeaders(d.ServiceEnv != config.EnvDev))
	// Tracing wraps metrics so the server span spans the whole request; both
	// derive low-cardinality names from the matched chi route pattern. When no
	// OTLP endpoint is configured the global tracer is a no-op, so this is a
	// cheap pass-through.
	//
	// It must also sit ABOVE AccessLog: chi middleware is outer-to-inner, and
	// AccessLog reads trace.SpanFromContext(r.Context()) when it writes its line.
	// With AccessLog outermost it only ever saw its own pre-span context, so the
	// trace_id/span_id attrs were silently never emitted and Grafana's
	// log-to-trace correlation had nothing to link on.
	r.Use(tracing.Middleware)
	r.Use(httpx.AccessLog)
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
			CookieSecure:   d.ServiceEnv != config.EnvDev,
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
			// Entries are exact paths unless they end in "/" (prefix) or contain
			// "*" (one path segment). Keep them narrow: a prefix over a whole
			// feature area also exempts every authenticated mutation later added
			// under it. Two such cases were found and closed here — "/v1/social/"
			// was exempting POST /v1/social/providers (a connection.write that
			// overwrites a tenant's social IdP), and "/v1/oauth/bc-authorize" as
			// a prefix was exempting the authenticated .../decision endpoint.
			ExemptPaths: csrfExemptPaths(),
		}))
	}

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

	// Root-mounted protocol routes (OIDC discovery/revoke/introspect, SCIM,
	// SAML, LDAP) sit OUTSIDE the /v1 group and therefore inherited no rate
	// limit at all — mountRootPublicRoutes used to run before any limiter even
	// existed. Two of those are unauthenticated or near-free to call:
	//
	//   POST /ldap/{id}/authenticate  verifies a username+password against the
	//     customer's own directory. Unthrottled, it is a password-spray gateway
	//     into a tenant's Active Directory that will also trip AD's lockout
	//     policy and take the customer's directory down.
	//   POST /oauth/introspect        needs only a public client_id (no secret),
	//     making it a token-liveness oracle.
	//
	// credentialLimiter matches the /v1 login throttle. protocolLimiter is
	// deliberately generous: SCIM sync and SAML SSO are legitimate machine
	// traffic and must not be throttled into failure — it exists to bound abuse,
	// not to shape normal load.
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
			r.Use(loginLimiter.Middleware)
			mountV1PublicRoutes(r, d)
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
			// Central cross-tenant guard: any route with a {tenantID} path param
			// must match the caller's own tenant (QID-18). Belt to the individual
			// handlers' suspenders. NOTE: this relies on the nested Route("/v1")
			// + Group structure — chi only exposes the {tenantID} param to a
			// group-level middleware when routes are matched by the nested
			// subrouter. Do NOT flatten these routes onto the top mux, or this
			// guard stops seeing the param and silently fails open. (rbac + users
			// also self-scope in-handler, so those two survive a refactor; the
			// other tenant-scoped resources rely on this middleware.)
			r.Use(httpx.EnforceTenantScope)
			r.Use(tenantLimiter.MiddlewareBy("tenant", ratelimit.PerTenant))
			r.Use(userLimiter.MiddlewareBy("user", ratelimit.PerUser))
			r.Use(apiKeyLimiter.MiddlewareBy("apikey", ratelimit.PerAPIKey))
			// RBAC permission enforcement for end-user principals. Gates the
			// routes listed in permissionMap(); API-key/service actors and
			// unmapped (self-service / public) routes pass through.
			r.Use(rbac.Enforce(d.RBACChecker, routePolicyMap()))
			// Sensitive actions also need a step-up of the calling session
			// (stepUpRoutes); asked only of a caller already authorized.
			r.Use(d.MFA.Service.StepUpGate(stepUpRoutes()))

			mountAuthenticatedRoutes(r, d)
		})
	})

	return r
}

// mountRootPublicRoutes is the single production registration point for
// protocol and operational routes mounted outside /v1.
//
// The chi.Group wrappers attach rate limiting without altering any route
// pattern — Group only composes middleware onto the same mux, so path matching,
// path parameters and the OpenAPI route set are unchanged. Probes are left
// unlimited on purpose: throttling /healthz or /readyz would make an
// orchestrator kill a pod that is merely busy.
func mountRootPublicRoutes(r chi.Router, d Deps, credentialLimiter, protocolLimiter *ratelimit.Limiter) {
	r.Get("/healthz", d.Health.Liveness)
	r.Get("/readyz", d.Health.Readiness)
	r.Get("/metrics", metrics.Handler().ServeHTTP)

	// Directory credential verification — same throttle as /v1 login.
	r.Group(func(r chi.Router) {
		r.Use(credentialLimiter.Middleware)
		d.LDAP.MountPublic(r)
	})

	// Protocol surfaces: machine traffic, generously bounded.
	r.Group(func(r chi.Router) {
		r.Use(protocolLimiter.Middleware)
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
	d.Principal.MountPublic(r)
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
	d.Outbox.Mount(r)
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
// issued to an application (one carrying client_id). Every other authenticated
// route refuses it (httpx.RefuseApplicationTokens): an application's token
// lets it read who the user is, not manage their account or organisation.
// Keep it to endpoints meant for applications (TestApplicationTokenRoutesStayNarrow).
func ApplicationTokenRoutes() []string {
	return []string{
		"GET /v1/oauth/userinfo",
		"POST /v1/oauth/userinfo",
	}
}

// LoginSessionRoutes lists the authenticated routes that also accept the hosted
// login's session cookie (qe_ls) in place of a bearer token, because the hosted
// login's own signed-in pages call them and it never holds a token. Every other
// authenticated route stays token-only.
//
// Keep it short: each entry lets a browser that is signed in to the hosted
// login act through that route. All must be user-only self-service routes and
// none may be CSRF-exempt (TestLoginSessionRoutesStayNarrow). Removing a
// passkey is deliberately not here: it stays token-only until removal checks
// that the user keeps a way to sign in.
func LoginSessionRoutes() []string {
	return []string{
		"GET /v1/passkeys",
		"PATCH /v1/passkeys/{id}",
		"POST /v1/passkeys/register/begin",
		"POST /v1/passkeys/register/finish",
	}
}

// csrfExemptPaths lists the paths that skip the double-submit/origin check.
// Extracted so TestNoAuthenticatedRouteIsCSRFExempt can assert the list never
// covers a route in the authenticated tree.
func csrfExemptPaths() []string {
	return []string{
		"/saml/acs/", "/saml/idp/sso", "/oauth/revoke", "/oauth/introspect",
		"/v1/oauth/token-code", "/v1/oauth/device_authorization",
		"/v1/oauth/bc-authorize", // exact: .../decision below it is authenticated
		"/v1/auth/signup", "/v1/auth/login", "/v1/auth/refresh",
		"/v1/auth/mfa",  // completes a token-flow sign-in: the mfa_token, not a cookie, is the credential
		"/v1/auth/mfa/", // its helpers (send a code, begin a passkey, send a push) — likewise
		"/v1/auth/forgot-password", "/v1/auth/reset-password", "/v1/auth/magic-link/",
		"/v1/passkeys/login/",
		"/v1/social/exchange",           // one-time code exchange, no cookie session
		"/v1/social/*/callback",         // Apple response_mode=form_post lands cross-site
		"/v1/invites/accept",            // invitation token in the body, no cookie session
		"/v1/invites/accept/passkey/",   // the same, accepting with a passkey
		"/v1/invites/lookup",            // read-only preview by invitation token
		"/v1/billing/webhooks/",         // provider-signed (Stripe/Razorpay), no cookie session
		"/v1/billing/sandbox/",          // dev-only mock hosted-checkout page + pay (no cookie session)
		"/v1/agents/token",              // agent-credential auth (no cookie session)
		"/v1/credentials/verify",        // public JWT-VC verification (no cookie session)
		"/v1/mfa/push/challenges/",      // a linked phone answers with its device credential (no cookie session)
		"/v1/mfa/push/devices/*/unlink", // a linked phone removes itself with its device credential (no cookie session)
		"/v1/mfa/push/pairing/claim",    // a phone links with a one-time pairing code (no cookie session)
	}
}
