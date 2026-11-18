package bootstrap

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/accessrequest"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authzen"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decisionlog"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/access/passkey"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/bot"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk"
	"github.com/qeetgroup/qeet-id-server/internal/developer/agent"
	"github.com/qeetgroup/qeet-id-server/internal/developer/apikey"
	"github.com/qeetgroup/qeet-id-server/internal/developer/authhook"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secret"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/vc"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal"
	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook"
	"github.com/qeetgroup/qeet-id-server/internal/federation/adminportal"
	"github.com/qeetgroup/qeet-id-server/internal/federation/directory"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcsso"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/group"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/identity/organization"
	"github.com/qeetgroup/qeet-id-server/internal/identity/organization/branding"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/identity/verification"
	"github.com/qeetgroup/qeet-id-server/internal/operations/activity"
	"github.com/qeetgroup/qeet-id-server/internal/operations/analytics"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/anomaly"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/critical"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
	"github.com/qeetgroup/qeet-id-server/internal/operations/compliance"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
	"github.com/qeetgroup/qeet-id-server/internal/operations/qeetai"
	"github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention"
	"github.com/qeetgroup/qeet-id-server/internal/operations/sales"
	"github.com/qeetgroup/qeet-id-server/internal/operations/search"
	"github.com/qeetgroup/qeet-id-server/internal/operations/servicehealth"
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
	Organization *organization.Handler
	User         *user.Handler
	Auth         *authentication.Handler
	AuthPolicy   *authpolicy.Handler
	RBAC         *rbac.Handler
	// AccessRequest serves people asking for a role and administrators answering.
	AccessRequest *accessrequest.Handler
	// CriticalEvents is the short list of what an on-call administrator triages.
	CriticalEvents *critical.Handler
	// RBACChecker enforces per-route permissions for end-user principals
	// (the authz policy table is RoutePolicies()). Satisfied by the
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
	Policy        *authpolicy.SecurityPolicyHandler
	GDPR          *gdpr.Handler
	Compliance    *compliance.Handler
	Audit         *audit.Handler
	AuditAnomaly  *anomaly.Handler
	Billing       *billing.Handler
	Entitlement   *entitlements.Handler
	Sales         *sales.Handler
	Analytics     *analytics.Handler
	ServiceHealth *servicehealth.Handler
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
	SSOGroups     *ssosync.Handler
	OIDCSSO       *oidcsso.Handler
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
	DecisionLog   *decisionlog.Handler
	Agent         *agent.Handler
	VC            *vc.Handler
	Search        *search.Handler
	Activity      *activity.Handler
	Health        *health.Handler
	MetricsToken  string // the bearer token /metrics needs ("": see MetricsOpen)
	MetricsOpen   bool   // with no token, /metrics is open (development only)
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
	// OrganizationLim, UserLim and APIKeyLim limit the authenticated routes per
	// organization, user and API key, at the organization's own limits where it
	// has set them.
	OrganizationLim, UserLim, APIKeyLim *ratelimit.OrganizationLimiter
	// Idempotency stores the answers to IdempotentRoutes requests sent with
	// an Idempotency-Key.
	Idempotency *idempotency.Store

	endStreams    []func() // run as shutdown begins, so open event streams end
	shutdownHooks []func() // run once the HTTP server has drained
}

// NewRouter builds the HTTP API: the middleware chain, the public routes, and
// the authenticated routes behind it.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(httpx.RequestIDHeader)              // every response names its request, for support and tracing
	r.Use(httpx.ClientIPContext)              // the client address, for audit records written below a handler
	r.Use(authentication.SignInClientContext) // the application a hosted sign-in is for, for its audit record
	// No encoded slash or backslash in a path, so the router and every check
	// that matches a path see the same segments.
	r.Use(httpx.RefuseEncodedSeparators)
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
	var appOrigin func(ctx context.Context, origin string) bool
	if d.OIDC != nil && d.OIDC.Service != nil {
		appOrigin = d.OIDC.Service.AllowsWebOrigin
	}
	r.Use(httpx.CORS(httpx.CORSConfig{
		Operator: d.AllowedOrigins, Headers: []string{idempotency.Header}, Exposed: []string{"Idempotent-Replayed"},
		PublicPaths: publicMetadataPaths, AppPaths: browserAppPaths, AppOrigin: appOrigin,
	}))
	// CSRF applies to cookie-bearing browser requests; bearer tokens and API keys
	// bypass it. CSRFDisabled is for dev only, and startup refuses it elsewhere.
	if !d.CSRFDisabled {
		r.Use(CSRF(d.AllowedOrigins, d.ServiceEnv != config.EnvDev, d.CSRFCookieDomain))
	}

	// newLimiter builds an in-process limiter, or a Redis-backed one when a
	// shared store is configured (so limits hold across replicas). A shared
	// store keys buckets by scope, so each limiter names its own.
	newLimiter := func(l ratelimits.BuiltInLimit) *ratelimit.Limiter {
		if d.RateLimitStore != nil {
			return ratelimit.NewWithStore(d.RateLimitStore, l.Rate, l.Capacity)
		}
		return ratelimit.New(l.Rate, l.Capacity)
	}
	// Per-IP throttle on auth-burning endpoints.
	loginLimiter := newLimiter(loginLimit)
	// The token endpoint serves an application's code exchanges and refreshes
	// for all its users from one address, and every credential it takes is
	// long and random, so it gets a machine-traffic bucket.
	tokenLimiter := newLimiter(tokenLimit)

	// Rate limits for root-mounted protocol routes. credentialLimiter matches the /v1
	// login throttle (LDAP authenticate is a password-spray target, introspect a token
	// oracle); protocolLimiter is generous, since SCIM and SAML are legitimate machine
	// traffic.
	credentialLimiter := newLimiter(credentialLimit)
	protocolLimiter := newLimiter(protocolLimit)

	mountRootPublicRoutes(r, d, credentialLimiter, protocolLimiter)

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
			// and organization management, which only the user's own tokens may do.
			r.Use(httpx.RefuseApplicationTokens(ApplicationTokenRoutes()))
			// Cross-organization guard: a {organizationID} path parameter must match the caller's
			// organization. It needs the nested Route("/v1") + Group structure to see the
			// parameter; flattening these routes onto the top mux makes it fail open.
			r.Use(httpx.EnforceOrganizationScope)
			// Row-level security: on organization-administration routes the
			// database shows the request only its organization's rows.
			r.Use(scopeOrganizationRoutes(RoutePolicies()))
			// Generous per-organization, per-user and per-key buckets: one
			// organization can't exhaust shared resources, nor one compromised
			// principal its organization's.
			r.Use(d.OrganizationLim.MiddlewareBy("organization", ratelimit.PerOrganization))
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
	r.Get("/metrics", httpx.MetricsGuard(d.MetricsToken, d.MetricsOpen, metrics.Handler()))

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
	d.VC.MountPublic(r)
	d.Audit.MountPublic(r)
	d.Passkey.MountPublic(r)
	d.AdminPortal.MountPublic(r)
	d.Branding.MountPublic(r)
	d.OIDC.MountBrowser(r)
	d.TokenVault.MountPublic(r)
	d.OIDCSSO.MountPublic(r)
	d.DomainVerify.MountPublic(r)
	d.MFA.MountPublic(r)
	d.SESWebhook.Mount(r)
}

// mountV1TokenRoutes registers the OAuth token endpoint, which applications
// call for many people from one address, and machine identities for their own
// tokens.
func mountV1TokenRoutes(r chi.Router, d Deps) {
	d.OIDC.MountToken(r)
}

// mountAuthenticatedRoutes is the single production registration point for
// routes protected by RequireAuth and the route policy catalogue. Keeping the
// mounts in one helper lets the coverage test walk the exact production route
// set without duplicating it or changing the load-bearing middleware nesting.
func mountAuthenticatedRoutes(r chi.Router, d Deps) {
	d.Auth.MountAuthed(r)
	d.Organization.Mount(r)
	d.User.Mount(r)
	d.RBAC.Mount(r)
	d.AccessRequest.Mount(r)
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
	d.Compliance.Mount(r)
	d.Retention.Mount(r)
	d.Audit.Mount(r)
	d.AuditAnomaly.Mount(r)
	d.CriticalEvents.Mount(r)
	d.Billing.Mount(r)
	d.Entitlement.Mount(r)
	d.Sales.Mount(r)
	d.Analytics.Mount(r)
	d.ServiceHealth.Mount(r)
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
	d.SSOGroups.Mount(r)
	d.OIDCSSO.Mount(r)
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
	d.DecisionLog.Mount(r)
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
		"DELETE /v1/passkeys/{id}",
		"POST /v1/passkeys/register/begin",
		"POST /v1/passkeys/register/finish",
	}
}

// scopeOrganizationRoutes applies row-level security (httpx.ScopeDatabase) to
// the organization-administration routes: those whose policy needs a user
// permission or a machine scope. A person's own routes (user-only policies)
// act on their data across organizations and run unscoped.
func scopeOrganizationRoutes(policies map[string]rbac.RoutePolicy) func(http.Handler) http.Handler {
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
		"POST /v1/organizations/{organizationID}/agents",
		"POST /v1/organizations/{organizationID}/billing/checkout",
		"POST /v1/organizations/{organizationID}/billing/invoices/{invoiceID}/pay",
		"POST /v1/users",
		"POST /v1/webhooks",
	}
}

// NoStoreRoutes lists the routes whose responses carry a token, a secret shown
// once, or a sign-in session cookie. NewRouter marks them Cache-Control:
// no-store and Pragma: no-cache (RFC 6749 §5.1).
func NoStoreRoutes() []string {
	return []string{
		// The token endpoint, the device and backchannel requests whose codes a
		// client polls it with, the consent answer carrying an authorization
		// code, and the IdP page carrying a signed SAML assertion.
		"POST /v1/oauth/token",
		"POST /v1/oauth/device_authorization",
		"POST /v1/oauth/bc-authorize",
		"POST /v1/oauth/authorize/decision",
		"POST /ldap/{id}/authenticate",
		"POST /ldap/{id}/session",
		"POST /saml/session",
		"POST /v1/oidc-connections/session",
		"GET /saml/idp/{organizationID}/sso",
		"POST /saml/idp/{organizationID}/sso",

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
		"POST /v1/auth/switch-organization",
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
		"POST /v1/oidc-connections/exchange",
		"POST /v1/organizations",

		// A secret, key, code or credential returned to its holder.
		"POST /v1/api-keys",
		"POST /v1/organizations/{organizationID}/api-keys/{id}/rotate",
		"POST /v1/oidc/clients",
		"POST /v1/organizations/{organizationID}/oidc/clients",
		"POST /v1/organizations/{organizationID}/oidc/clients/{id}/rotate-secret",
		"POST /v1/service-principals",
		"POST /v1/organizations/{organizationID}/service-principals/{id}/rotate-secret",
		"POST /v1/organizations/{organizationID}/agents",
		"POST /v1/organizations/{organizationID}/agents/{id}/rotate-secret",
		"POST /v1/webhooks",
		"POST /v1/organizations/{organizationID}/webhooks/{id}/rotate-secret",
		"POST /v1/mfa/totp/enroll/start",
		"POST /v1/mfa/totp/enroll/confirm",
		"POST /v1/mfa/recovery-codes/regenerate",
		"POST /v1/mfa/push/devices",
		"POST /v1/mfa/push/pairing",
		"POST /v1/mfa/push/pairing/claim",
		"POST /v1/organizations/{organizationID}/scim/token",
		"POST /v1/organizations/{organizationID}/scim/tokens",
		"POST /v1/organizations/{organizationID}/scim/tokens/{id}/rotate",
		"POST /v1/organizations/{organizationID}/admin-portal/links",
		"POST /v1/organizations/{organizationID}/secrets/{id}/reveal",
		"POST /v1/organizations/{organizationID}/credentials",
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
		"/v1/oauth/token", "/v1/oauth/device_authorization", // the client's credentials, code or token, never a cookie session
		"/ldap/*/authenticate",   // directory credentials in the body, answered with a token pair; no cookie session
		"/v1/oauth/bc-authorize", // exact: .../decision below it is authenticated
		"/v1/oauth/authorize",    // exact: an application's form POST, which only goes on by GET; .../decision is not exempt
		"/v1/auth/signup", "/v1/auth/login", "/v1/auth/refresh",
		"/v1/auth/mfa",  // completes a token-flow sign-in: the mfa_token, not a cookie, is the credential
		"/v1/auth/mfa/", // its helpers (send a code, begin a passkey, send a push) — likewise
		"/v1/auth/forgot-password", "/v1/auth/reset-password",
		"/v1/auth/magic-link/start", "/v1/auth/magic-link/consume", "/v1/auth/magic-link/resend", // not .../session: it sets the hosted-login cookie
		"/v1/passkeys/login/begin", "/v1/passkeys/login/finish", // not .../session: it sets the hosted-login cookie
		"/v1/social/exchange",               // one-time code exchange, no cookie session
		"/v1/social/*/callback",             // Apple response_mode=form_post lands cross-site
		"/v1/invites/accept",                // invitation token in the body, no cookie session
		"/v1/invites/accept/passkey/",       // the same, accepting with a passkey
		"/v1/invites/lookup",                // read-only preview by invitation token
		"/v1/billing/webhooks/",             // provider-signed (Stripe/Razorpay), no cookie session
		"/v1/webhooks/ses",                  // SNS-signed SES events, no cookie session
		"/v1/billing/sandbox/",              // dev-only mock hosted-checkout page + pay (no cookie session)
		"/v1/credentials/verify",            // public JWT-VC verification (no cookie session)
		"/v1/sso/discovery",                 // read-only lookup by an address's domain (no cookie session)
		"/v1/mfa/push/challenges/",          // a linked phone answers with its device credential (no cookie session)
		"/v1/mfa/push/devices/*/unlink",     // a linked phone removes itself with its device credential (no cookie session)
		"/v1/mfa/push/devices/*/push-token", // a linked phone replaces its rotated push token with its device credential (no cookie session)
		"/v1/mfa/push/devices/*/pending",    // a linked phone lists requests waiting on it with its device credential (no cookie session)
		"/v1/mfa/push/pairing/claim",        // a phone links with a one-time pairing code (no cookie session)
	}
}

// publicMetadataPaths answer any origin: the OpenID Connect and OAuth metadata
// and the signing keys, which hold nothing to protect.
var publicMetadataPaths = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/.well-known/oauth-protected-resource",
	"/.well-known/jwks.json",
}

// browserAppPaths are the OAuth endpoints a single-page application calls
// from the browser with its own code or token, never a cookie.
var browserAppPaths = []string{
	"/v1/oauth/token",
	"/v1/oauth/userinfo",
	"/oauth/revoke",
	"/oauth/introspect",
}
