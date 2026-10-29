package bootstrap

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authzen"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
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
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcsso"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync"
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
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/idempotency"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/health"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

type namedWorker struct {
	name   string
	run    worker.Func
	always bool
}

// Services wires every service as the API does, for a tool that drives them
// directly, such as the development seed. No worker runs, nothing listens, and
// committed events wait in the outbox for the API's dispatcher.
func Services(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool) Deps {
	depsCfg := *cfg
	depsCfg.NATSURL = ""
	deps, _ := buildDeps(ctx, &depsCfg, pool, outbox.LogPublisher{})
	return deps
}

// buildDeps constructs every repository, service, and handler and returns the
// HTTP dependency set plus the background workers to supervise. Keeping all
// wiring here lets main() focus on process lifecycle.
func buildDeps(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool, outboxPub outbox.Publisher) (Deps, []namedWorker) {
	outboundPolicy := newOutboundPolicy(cfg)
	keys := loadKeys(rootCtx, cfg, pool)
	sharedCipher, signingKeyRegistry, issuer := keys.cipher, keys.signingKeys, keys.issuer
	verifier := &httpx.AuthVerifier{
		Tokens:          issuer,
		DevTrustHeaders: cfg.AuthDevTrustHeaders,
	}

	tenantRepo := tenant.NewRepository(pool)
	tenantRepo.SetHostingRegion(cmp.Or(cfg.HostingRegion, cfg.AWSRegion)) // where every organisation is created
	userRepo := user.NewRepository(pool)
	rbacRepo := rbac.NewRepository(pool)
	rbacService := rbac.NewService(rbacRepo)
	if err := rbacRepo.SeedBuiltins(rootCtx); err != nil {
		slog.Warn("rbac seed", "err", err)
	}
	billingService := billing.NewService(pool)
	payments := billing.NewPayments(
		cfg.StripeSecretKey, cfg.StripeWebhookSecret,
		cfg.RazorpayKeyID, cfg.RazorpayKeySecret, cfg.RazorpayWebhookSecret,
	).WithRouting(cfg.PaymentDefaultProvider, billing.ParseCountryRoutes(cfg.PaymentCountryRoutes)) // card payments (Stripe/Razorpay), routed by billing country; no-op until keys are configured
	if cfg.PaymentSandbox {
		payments = payments.WithSandbox(cfg.PaymentSandboxBaseURL, "sandbox-dev-secret") // dev-only fake provider; config.Validate refuses it outside dev
	}
	billingService.SetPayments(payments)
	billingService.SetAllowUnpaidActivation(cfg.BillingAllowUnpaidActivation)    // else a paid plan with no provider is refused, not granted free
	billingService.SetOrgProvisioner(billingOrgProvisioner{tenants: tenantRepo}) // creates the org when a signup checkout is paid
	billingService.SetTaxConfig(billing.TaxConfig{                               // invoice GST/VAT (off unless configured)
		Enabled:       cfg.BillingTaxEnabled,
		SellerCountry: cfg.BillingSellerCountry,
		SellerState:   cfg.BillingSellerState,
		GSTRateBps:    cfg.BillingGSTRateBps,
	})
	if err := billingService.SeedBuiltins(rootCtx); err != nil {
		slog.Warn("billing seed", "err", err)
	}
	// entitlementSvc turns a tenant's plan into a capability set (feature flags +
	// numeric limits). It's the single source of truth read by the entitlements
	// endpoint and injected into every plan-enforcement point below.
	entitlementSvc := entitlements.NewService(entitlementPlanResolver{billing: billingService, tenants: tenantRepo})
	brandingRepo := branding.NewRepository(pool)
	emailTemplateService := email.NewService(pool)
	policyRepo := policy.NewRepository(pool)
	policyRepo.SetSessionDefaults(cfg.SessionMaxAge, cfg.SessionIdleTimeout)
	mail := newMailer(cfg, pool, brandingRepo, emailTemplateService)
	sender := mail.sender
	verifyService := verification.NewService(pool, sender, 10*time.Minute)
	recoveryService := recovery.NewService(pool, sender, time.Hour, cfg.AppBaseURL)
	recoveryService.SetHostedLogin(cfg.LoginBaseURL) // resets requested there link back to it
	retentionService := retention.NewService(pool)
	salesService := sales.NewService(pool, sender, cfg.SalesEmail)
	inviteService := invite.NewService(pool, sender, 14*24*time.Hour, cfg.AppBaseURL)
	authService := auth.NewService(pool, userRepo, issuer)
	authPolicyService := authpolicy.NewService(pool)

	// One password check for every path that sets a password:
	// authPolicyService.ValidateForTenant (organisation rules or platform baseline,
	// strength baseline, breach check).
	recoveryService.SetPasswordRules(authPolicyService)   // password reset
	recoveryService.SetMagicLinkPolicy(authPolicyService) // magic links only where the tenant allows them, with its lifetime
	inviteService.SetPasswordRules(authPolicyService)     // invite accept
	inviteService.SetAcceptMethods(authPolicyService)     // which ways of accepting the acceptance screen offers

	// Breached-password check (Have I Been Pwned k-anonymity), on unless
	// BREACHED_PASSWORD_CHECK turns it off. It fails open on a HIBP outage,
	// counted in breached_password_check_allowed_on_error_total, and only the
	// 5-character SHA-1 prefix leaves the process.
	if cfg.BreachedPasswordCheck {
		breachChecker := hibp.New(&http.Client{Timeout: 3 * time.Second}, cfg.BreachedPasswordAPIURL, cfg.BreachedPasswordMinCount)
		authPolicyService.SetBreachChecker(breachChecker)
		slog.Info("breached-password check enabled (HIBP k-anonymity; fail-open)", "min_count", cfg.BreachedPasswordMinCount)
	} else if !cfg.IsDev() {
		slog.Warn("breached-password check is off (BREACHED_PASSWORD_CHECK=false): new passwords are not checked against known breaches")
	}
	apikeyService := apikey.NewService(pool)
	principalService := principal.NewService(pool, issuer)
	mfaService := mfa.NewService(pool, cfg.JWTIssuer, sender, cfg.ExpoPushURL)
	mfaService.SetCipher(sharedCipher)
	mfaService.SetExpoAccessToken(cfg.ExpoAccessToken)
	authService.SetMFA(mfaService)                       // gate password login on a second factor when enrolled
	authService.SetRegistrationPolicy(authPolicyService) // gate hosted signup + the password check (signup, register, change)
	authService.SetMethodPolicy(authPolicyService)       // password sign-in only where the tenant allows it
	authService.SetDevicePolicy(authPolicyService)       // gate adaptive MFA (trusted-device skip)

	// Sign-in lockout: platform defaults and the bounds a tenant may choose come
	// from LOGIN_LOCKOUT_* and LOGIN_SPRAY_*; a tenant's own settings live in its
	// authentication policy.
	lockoutDefaults := authpolicy.Lockout{Threshold: cfg.LoginLockoutThreshold, Window: cfg.LoginLockoutWindow, Duration: cfg.LoginLockoutDuration}
	authPolicyService.SetLockoutLimits(authpolicy.LockoutLimits{
		Defaults: lockoutDefaults,
		Min:      authpolicy.Lockout{Threshold: cfg.LoginLockoutThresholdMin, Window: cfg.LoginLockoutWindowMin, Duration: cfg.LoginLockoutDurationMin},
		Max:      authpolicy.Lockout{Threshold: cfg.LoginLockoutThresholdMax, Window: cfg.LoginLockoutWindowMax, Duration: cfg.LoginLockoutDurationMax},
	})
	authService.SetLockoutConfig(auth.LockoutConfig{
		Defaults:          auth.Lockout(lockoutDefaults),
		AccountMultiplier: cfg.LoginLockoutAccountMultiplier,
		SourceAccounts:    cfg.LoginSprayAccounts,
		SourceWindow:      cfg.LoginSprayWindow,
		SourceBlock:       cfg.LoginSprayBlock,
	})
	authService.SetLockoutSource(func(ctx context.Context, tenantID uuid.UUID) (auth.Lockout, error) {
		l, err := authPolicyService.SignInLockout(ctx, tenantID)
		return auth.Lockout(l), err
	})
	authHookService := authhook.NewService(pool, outboundPolicy)
	authHookService.SetCipher(sharedCipher)
	authService.SetLoginHook(authHookService) // synchronous Actions/Hooks gate (no-op until configured)
	threatService := threat.NewService(pool)
	authService.SetAnomalyRecorder(threatService) // record sign-in lock and spraying-source anomalies
	notificationService := notification.NewService(pool)
	threatService.SetNotifier(notificationService) // alert the affected user in-app on lockout
	riskService := risk.NewService(pool)
	authService.SetRiskAssessor(riskService) // assess every sign-in; a risky one skips no factor
	authService.SetSender(sender)            // email the code that confirms a risky sign-in with no factor
	// A rotated refresh token sent again within the grace gets its rotation's
	// pair, for a client that renewed twice at once or lost the answer.
	authService.SetRefreshReuseGrace(cfg.RefreshTokenReuseGrace, sharedCipher)
	botService := bot.NewService(pool)
	siemService := siem.NewService(pool, outboundPolicy) // forwards audit events to configured log sinks
	siemService.SetCipher(sharedCipher)
	rebacService := rebac.NewService(pool) // fine-grained (relationship) authorization
	abacService := abac.NewService(pool)   // attribute-based access control (policy store + PDP)
	// One decision across the three engines (an ABAC deny refuses, then any
	// allow): the route guard, /v1/check, the relationship check and AuthZEN.
	decider := decide.New(rbacRepo, rebacService, abacService)
	authzenService := authzen.NewService(rbacRepo, rebacService, decider) // OpenID AuthZEN PDP facade
	agentService := agent.NewService(pool, issuer)                        // AI-agent identities (ephemeral scoped tokens)
	vcService := vc.NewService(pool, issuer)                              // W3C verifiable credentials (JWT-VC)

	// Qeet AI assistant: the conversation store is created here; the per-tenant
	// BYOK provider-config service + orchestrator + handler are wired below,
	// after the secrets key provider exists (they reuse the same AES data key to
	// encrypt tenant provider keys at rest).
	qeetaiService := qeetai.NewService(pool)
	// Live Activity hub: subscribes to NATS outbox events (when NATS_URL is set)
	// and fans them out to authenticated SSE connections filtered by tenant.
	// When NATS_URL is empty the hub acts as a no-op broker — the SSE stream
	// still connects and serves history/replay, but no live events are pushed.
	activityNATSConn := connectActivityNATS(cfg)
	activityHub := activity.NewHub(activityNATSConn)

	// Universal search: read-only fan-out across resource types. Reuses the
	// rbacRepo for per-type permission checks; no new DB objects required.
	searchService := search.NewService(pool, rbacRepo)
	webhookService := webhook.NewService(pool, outboundPolicy)
	webhookService.SetCipher(sharedCipher)
	webhookService.SetNotifier(notificationService) // alert webhook managers when a failing endpoint is turned off
	// Let the auth middleware deny suspended/decommissioned agents' tokens per
	// request.
	verifier.AgentStatus = agentService.AgentStatus
	// Session and role-change signals over the webhook dispatcher, so subscribers
	// can react before access tokens expire.
	sessionSignals := sessionsignal.New(webhookService.EnqueueTx)
	authService.SetSessionSignals(sessionSignals)
	authService.SetSessionLifetime(cfg.SessionMaxAge, cfg.SessionIdleTimeout) // session bounds where the organisation sets none
	verifier.SessionUsed = authService.SessionUsed                            // a session's last use, for its idle timeout and the session list
	verifier.SessionLive = authService.SessionLive                            // an ended session's access tokens are refused at once
	verifier.PrincipalLive = principalService.PrincipalLive                   // a disabled service principal's tokens are refused at once
	recoveryService.SetSessionSignals(sessionSignals)
	rbacService.SetEmitter(webhookService.Enqueue)
	gdprService := gdpr.NewService(pool, 30*24*time.Hour)
	gdprService.SetSessionSignals(sessionSignals)
	auditReader := audit.NewReader(pool)
	auditVerifier := audit.NewVerifier(pool)
	evidenceService := gdpr.NewEvidenceService(pool, auditVerifier, cfg.BreachedPasswordCheck)
	auditAnomalyService := anomaly.NewService(pool)
	analyticsReader := analytics.NewReader(pool)

	startedAt := time.Now()
	healthHandler := health.New(cfg.ServiceName, cfg.ServiceEnv, startedAt)
	healthHandler.ServiceProfile = cfg.ServiceProfile
	healthHandler.AddReadiness("db", health.PingDB(pool))
	healthHandler.AddReadiness("jwt-keyring", signingKeyRegistry.Ready) // not ready after repeated keyring refresh failures
	inFlight := httpx.NewInFlight()
	oidcService := oidc.NewService(pool, issuer)
	oidcService.SetAgentStatus(agentService.AgentStatus)            // a suspended agent's tokens introspect inactive
	oidcService.SetSessionLive(authService.SessionLive)             // an ended session's tokens introspect inactive and can't be exchanged
	oidcService.SetPrincipalLive(principalService.PrincipalLive)    // a disabled service principal's tokens introspect inactive
	oidcService.SetGrantMaxAge(cfg.SessionMaxAge)                   // grant bound where the organisation sets none
	oidcService.SetTokenExchangeMaxDepth(cfg.TokenExchangeMaxDepth) // bound a chain of exchanges
	oidcService.SetClientLockout(oidc.ClientLockout{                // wrong application secrets
		Threshold: cfg.ClientAuthLockoutThreshold, Window: cfg.ClientAuthLockoutWindow, Duration: cfg.ClientAuthLockoutDuration,
	})
	oidcService.SetNotifier(notificationService) // CIBA async consent prompts
	rpID, rpDisplayName, rpOrigins := cfg.WebAuthnRP()
	// UserVerification must be Required: go-webauthn checks the UV flag only on
	// strict equality, and without it a passkey proves possession alone. Passkey-only
	// accounts have no password, so this is the whole credential. The registration
	// ceremonies set it themselves.
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     rpOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		slog.Error("webauthn init", "err", err)
		os.Exit(1)
	}
	passkeyService := passkey.NewService(pool, wa, authService)
	passkeyService.SetMethodPolicy(authPolicyService) // offer and accept new passkeys only where the tenant allows them
	passkeyService.SetInvitations(inviteService)      // accept an invitation with a passkey
	passkeyService.SetSender(sender)                  // tell the account holder a passkey was added or removed
	mfaService.SetWebAuthn(passkeyService)            // a passkey can meet a sign-in's second-factor challenge
	mfaService.SetPlan(entitlementSvc)                // SMS codes only on plans that include them
	if mail.routed {
		mfaService.SetDeliveryCheck(mail.transport.Configured) // refuse codes no provider can deliver
	}
	socialService := social.NewService(pool, authService, cfg.AppBaseURL, outboundPolicy)
	socialService.SetCipher(sharedCipher)
	// Allowlist for the hosted flow's return_to. The callback sets the SSO
	// cookie before redirecting, so an unvalidated value would be an open
	// redirect on the auth domain. AllowedOrigins is already the vetted browser
	// origin set (Validate() refuses a wildcard outside dev).
	socialService.SetAllowedReturnOrigins(
		append([]string{cfg.AppBaseURL, cfg.LoginBaseURL}, cfg.AllowedOrigins()...)...)
	setPlatformSocialProviders(socialService, cfg)
	groupService := group.NewService(pool)
	scimService := scim.NewService(pool, userRepo)
	scimService.SetSessionSignals(sessionSignals)
	secretService := secret.NewService(pool, sharedCipher)
	// Token Vault seals with the same cipher as the secrets vault above —
	// one KMS/static-key setup backs both encrypted stores.
	tokenVaultService := tokenvault.NewService(pool, sharedCipher, outboundPolicy)

	// Qeet AI provider config: per-tenant keys, encrypted with the vault data key,
	// with QEETAI_* as the platform fallback. The orchestrator is always built,
	// since a tenant can bring its own key.
	qeetaiProviderCfg := qeetai.NewProviderConfig(pool, sharedCipher, qeetai.PlatformProvider{
		Provider:  cfg.QeetaiProvider,
		APIKey:    cfg.QeetaiAPIKey,
		Model:     cfg.QeetaiModel,
		BaseURL:   cfg.QeetaiBaseURL,
		MaxTokens: cfg.QeetaiMaxTokens,
	}, outboundPolicy)
	if qeetaiProviderCfg.PlatformConfigured() {
		slog.Info("Qeet AI: platform provider configured", "provider", cfg.QeetaiProvider, "model", cfg.QeetaiModel)
	} else {
		slog.Info("Qeet AI: no platform provider set — tenants must bring their own key (BYOK)")
	}
	qeetaiLimits := qeetai.Limits{
		HistoryMessages: cfg.QeetaiHistoryMessages, HistoryBytes: cfg.QeetaiHistoryBytes, OutputBytes: cfg.QeetaiMaxOutputBytes,
	}
	qeetaiHandler := &qeetai.Handler{
		Service:      qeetaiService,
		Orchestrator: qeetai.NewOrchestrator(qeetaiProviderCfg, qeetaiService, qeetaiLimits),
		Resolver:     qeetaiProviderCfg,
		Config:       qeetaiProviderCfg,
		Plan:         entitlementSvc, // platform fallback is a Pro+ feature; BYOK bypasses the gate
	}

	samlService := saml.NewService(pool, authService, cfg.AppBaseURL)
	oidcSSOService := oidcsso.NewService(pool, authService, cfg.AppBaseURL, outboundPolicy)
	oidcSSOService.SetCipher(sharedCipher)
	samlService.SetEgressPolicy(outboundPolicy) // IdP metadata URLs
	samlService.SetCipher(sharedCipher)         // the connections' SP encryption keys

	samlIdPKeyPEM, samlIdPCertPEM := samlIdPIdentity(cfg)
	samlIdP, err := saml.NewIdP(pool, samlIdPKeyPEM, samlIdPCertPEM, cfg.LoginBaseURL, authService)
	if err != nil {
		slog.Error("init saml idp", "err", err)
		os.Exit(1)
	}

	samlHandler := &saml.Handler{Service: samlService, IdP: samlIdP, PublicBaseURL: cfg.PublicBaseURL, CookieSecure: !cfg.IsDev()}
	adminPortalService := adminportal.NewService(pool, brandingRepo, cfg.LoginBaseURL)

	ldapService := ldap.NewService(pool, authService, outboundPolicy)
	ldapService.SetCipher(sharedCipher)
	ldapService.SetAllowSkipTLSVerify(cfg.IsDev()) // skip_tls_verify is a dev-only escape hatch
	directoryService := directory.NewService(scimService, ldapService)
	directoryService.SetEventStore(pool)
	scimService.SetOperationObserver(directoryService)
	ldapService.SetOperationObserver(directoryService)
	scimService.SetProfileMapper(directoryService)
	ldapService.SetProfileMapper(directoryService)
	ipAllowService := ipallow.NewService(pool)
	authService.SetAddressPolicy(ipAllowService) // address rules: every sign-in to an organisation, and every renewal
	authService.SetSignOutNotifier(oidcService)  // tell applications when someone signs out of the hosted login
	oidcService.SetLogoutHTTPClient(outboundPolicy)
	oidcService.SetAddressPolicy(ipAllowService) // address rules: application authorize, device approval and collection

	// Plan enforcement: inject the entitlement checker into every gated create
	// path. Numeric limits (seats/apps/api keys/custom roles) use SetPlanLimiter;
	// boolean features (webhooks/SSO/SCIM/LDAP) use SetPlanGate. Free-tier caps
	// bite here; paid tiers resolve to unlimited/enabled, so it's a no-op for them.
	inviteService.SetPlanLimiter(entitlementSvc) // seats
	rbacService.SetSeatGuard(inviteService)      // seats: a person's first role, directly
	groupService.SetSeatGuard(inviteService)     // seats: a person's first role, through a group
	scimService.SetSeatGuard(inviteService)      // seats: the same, through a directory-managed group
	oidcService.SetPlanLimiter(entitlementSvc)   // apps (relying parties)
	apikeyService.SetPlanLimiter(entitlementSvc) // api_keys
	rbacService.SetPlanLimiter(entitlementSvc)   // custom_roles
	webhookService.SetPlanGate(entitlementSvc)   // webhooks (feature)
	samlIdP.SetPlanGate(entitlementSvc)          // SSO (SAML), as identity provider
	samlService.SetPlanGate(entitlementSvc)      // SSO (SAML), through a tenant's identity provider
	oidcSSOService.SetPlanGate(entitlementSvc)   // SSO (OpenID Connect connections)
	scimService.SetPlanGate(entitlementSvc)      // SCIM
	ldapService.SetPlanGate(entitlementSvc)      // LDAP
	brandingRepo.SetPlanGate(entitlementSvc)     // custom branding
	brandingRepo.SetPublicBaseURL(cfg.PublicBaseURL)
	abacService.SetPlanGate(entitlementSvc) // ABAC
	// Current-usage provider for the billing usage-vs-limits display.
	entitlementSvc.SetUsageResolver(entitlementUsageResolver{
		invites: inviteService, oidc: oidcService, apikeys: apikeyService, rbacRepo: rbacRepo,
	})
	// custom domain — extracted from its inline handler so the gate can be wired.
	domainVerifyService := domainverify.NewService(pool, outboundPolicy)
	domainVerifyService.SetPlanGate(entitlementSvc)
	domainVerifyService.SetOwners(rbacRepo) // only owners name break-glass members
	// Domain capture: an address on a verified domain with SSO on, in an
	// organisation with an active SAML or LDAP connection, signs in only there,
	// except break-glass members and the administrators SSO never adopts.
	domainVerifyService.SetAdminPermissions(identitylink.AdminPermissions())
	authService.SetDomainCapture(domainVerifyService)     // password sign-in, sign-up, hosted registration
	recoveryService.SetDomainCapture(domainVerifyService) // password reset, magic links
	passkeyService.SetDomainCapture(domainVerifyService)  // passkey sign-in and sign-up

	limits := newRateLimits(rootCtx, cfg, pool)
	recoveryService.SetMagicLinkLimits(limits.magicAddress, limits.magicCaller)
	recoveryService.SetResetLimit(limits.resetAddress)
	rlStore, tenantTenantLim, tenantUserLim, tenantAPIKeyLim := limits.store, limits.tenant, limits.user, limits.apiKey
	rateLimitsHandler := &ratelimits.Handler{
		Pool:      pool,
		TenantLim: tenantTenantLim,
		UserLim:   tenantUserLim,
		APIKeyLim: tenantAPIKeyLim,
		Defaults: ratelimits.Defaults{TenantRate: tenantLimitDefault.Rate, TenantCapacity: tenantLimitDefault.Capacity,
			UserRate: userLimitDefault.Rate, UserCapacity: userLimitDefault.Capacity,
			APIKeyRate: apiKeyLimitDefault.Rate, APIKeyCapacity: apiKeyLimitDefault.Capacity},
		BuiltIn: builtInLimits,
	}

	// An open activity stream is checked again as its request was admitted.
	activityHandler := activity.NewHandler(pool, activityHub)
	activityHandler.Access = streamAccess{verifier: verifier, checker: decider, apiKeys: apikeyService,
		policy: RoutePolicies()["GET /v1/activity/stream"]}.Allowed
	v := newValidator()
	deps := Deps{
		Tenant: &tenant.Handler{Repo: tenantRepo, Validate: v, AuthService: authService, Signals: sessionSignals, OwnerCheck: rbacRepo.IsOwner},
		User: &user.Handler{Repo: userRepo, Validate: v, PasswordPolicy: authPolicyService.ValidateForTenant, MFA: mfaService, SignIns: authService, Signals: sessionSignals, Mailer: sender, ActOnCheck: rbacRepo.CheckActOn,
			Roles: importRoles{repo: rbacRepo, seats: inviteService}},
		AuthPolicy:    &authpolicy.Handler{Service: authPolicyService},
		Auth:          &auth.Handler{Service: authService, Validate: v, CookieSecure: !cfg.IsDev(), Bot: botService, GeoCountryHeader: cfg.GeoCountryHeader},
		RBAC:          &rbac.Handler{Repo: rbacRepo, Service: rbacService, Validate: v, Decider: decider},
		RBACChecker:   decider,
		Verification:  &verification.Handler{Service: verifyService},
		Recovery:      &recovery.Handler{Service: recoveryService, AuthService: authService, DevMode: cfg.IsDev(), CookieSecure: !cfg.IsDev(), PublicBaseURL: cfg.PublicBaseURL},
		Retention:     &retention.Handler{Service: retentionService},
		Invite:        &invite.Handler{Service: inviteService, AuthService: authService, Validate: v, GrantCheck: rbacRepo.CheckGrantRole},
		Branding:      &branding.Handler{Repo: brandingRepo},
		EmailTemplate: &email.Handler{Service: emailTemplateService, Sender: sender, Appearance: brandingRepo, TestEmailEnabled: mail.testEnabled},
		EmailDelivery: &email.DeliveryHandler{Store: mail.deliveries},
		SESWebhook:    &delivery.Webhook{Store: mail.deliveries, TopicARNs: cfg.SESEventsTopicARNs},
		APIKey:        &apikey.Handler{Service: apikeyService, GrantCheck: rbacRepo.CheckGrantScopes},
		APIKeyService: apikeyService,
		Principal:     &principal.Handler{Service: principalService, GrantCheck: rbacRepo.CheckGrantScopes},
		MFA:           &mfa.Handler{Service: mfaService, WebAuthn: passkeyService},
		Webhook:       &webhook.Handler{Service: webhookService},
		Policy:        &policy.Handler{Repo: policyRepo},
		GDPR:          &gdpr.Handler{Service: gdprService, Evidence: evidenceService, Reauth: authService},
		Audit:         &audit.Handler{Reader: auditReader, Verifier: auditVerifier},
		AuditAnomaly:  &anomaly.Handler{Service: auditAnomalyService},
		Billing:       &billing.Handler{Service: billingService},
		Entitlement:   &entitlements.Handler{Service: entitlementSvc},
		Sales:         &sales.Handler{Service: salesService},
		Analytics:     &analytics.Handler{Reader: analyticsReader},
		OIDC:          &oidc.Handler{Service: oidcService, Sessions: authService, Providers: socialService, Registration: authPolicyService, DeviceTrust: authPolicyService, Methods: authPolicyService, Branding: brandingRepo, LoginBaseURL: cfg.LoginBaseURL, CookieSecure: !cfg.IsDev(), PublicBaseURL: cfg.PublicBaseURL},
		Passkey:       &passkey.Handler{Service: passkeyService, CookieSecure: !cfg.IsDev()},
		Social:        &social.Handler{Service: socialService, CookieSecure: !cfg.IsDev(), LoginBaseURL: cfg.LoginBaseURL, PublicBaseURL: cfg.PublicBaseURL},
		Group: &group.Handler{Service: groupService, GrantCheck: rbacRepo.CheckGrantGroup, ReadsRoles: func(r *http.Request) bool {
			ok, err := rbac.Holds(r.Context(), rbacRepo, httpx.PrincipalFromCtx(r.Context()), "role.read")
			return err == nil && ok
		}},
		SCIM:         &scim.Handler{Service: scimService, PublicBaseURL: cfg.PublicBaseURL},
		Secret:       &secret.Handler{Service: secretService},
		TokenVault:   &tokenvault.Handler{Service: tokenVaultService, PublicBaseURL: cfg.PublicBaseURL, CookieSecure: !cfg.IsDev()},
		SAML:         samlHandler,
		AdminPortal:  &adminportal.Handler{Service: adminPortalService, SAML: samlService, SAMLSignIn: samlHandler, SCIM: scimService, Domains: domainVerifyService, PublicBaseURL: cfg.PublicBaseURL, CookieSecure: !cfg.IsDev()},
		LDAP:         &ldap.Handler{Service: ldapService},
		SSOGroups:    &ssosync.Handler{Service: ssosync.NewService(pool), GrantCheck: rbacRepo.CheckGrantGroup},
		OIDCSSO:      &oidcsso.Handler{Service: oidcSSOService, PublicBaseURL: cfg.PublicBaseURL, CookieSecure: !cfg.IsDev()},
		Directory:    &directory.Handler{Service: directoryService},
		IPAllow:      &ipallow.Handler{Service: ipAllowService},
		Threat:       &threat.Handler{Service: threatService},
		Bot:          &bot.Handler{Service: botService},
		Risk:         &risk.Handler{Service: riskService},
		RateLimits:   rateLimitsHandler,
		Notification: &notification.Handler{Service: notificationService},
		DomainVerify: &domainverify.Handler{Service: domainVerifyService},
		SIEM:         &siem.Handler{Service: siemService},
		AuthHook:     &authhook.Handler{Service: authHookService},
		ABAC:         &abac.Handler{Service: abacService},
		ReBAC:        &rebac.Handler{Service: rebacService, Decider: decider},
		AuthZEN:      &authzen.Handler{Service: authzenService},
		Agent:        &agent.Handler{Service: agentService, GrantCheck: rbacRepo.CheckGrantScopes},
		VC:           &vc.Handler{Service: vcService},
		Qeetai:       qeetaiHandler,
		Search:       &search.Handler{Service: searchService},
		Activity:     activityHandler,
		Health:       healthHandler,
		MetricsToken: cfg.MetricsToken,
		MetricsOpen:  cfg.IsDev(),
		InFlight:     inFlight,

		AuthVerifier:     verifier,
		AllowedOrigins:   cfg.AllowedOrigins(),
		ServiceName:      cfg.ServiceName,
		ServiceEnv:       cfg.ServiceEnv,
		StartedAt:        startedAt,
		CSRFDisabled:     cfg.CSRFDisabled,
		CSRFCookieDomain: cfg.CSRFCookieDomain,
		RateLimitStore:   rlStore,
		TenantLim:        tenantTenantLim,
		UserLim:          tenantUserLim,
		APIKeyLim:        tenantAPIKeyLim,
		Idempotency:      idempotency.NewStore(pool, sharedCipher),
	}
	deps.endStreams = append(deps.endStreams, activityHub.Shutdown)
	if activityNATSConn != nil {
		deps.shutdownHooks = append(deps.shutdownHooks, func() { _ = activityNATSConn.Drain() })
	}

	// Committed events reach the organisation's webhook subscriptions as well
	// as the event stream.
	outboxDispatcher := outbox.NewDispatcher(pool, webhookService.Relay(outboxPub), 2*time.Second, 50)
	workers := []namedWorker{
		{name: "jwt-keyring", run: func(ctx context.Context) { signingKeyRegistry.Run(ctx, issuer, cfg.JWTSigningKeyRefreshInterval) }, always: true},
		// Each instance enforces the overrides from its own cache.
		{name: "rate-limit-overrides", run: func(ctx context.Context) {
			ratelimit.ReloadEvery(ctx, time.Minute, tenantTenantLim, tenantUserLim, tenantAPIKeyLim)
		}, always: true},
		{name: "outbox", run: outboxDispatcher.Run},
		{name: "oidc-logout", run: oidcService.RunLogoutDeliveries},
		{name: "webhook", run: webhookService.RunDispatcher},
		{name: "gdpr", run: gdprService.Run},
		{name: "retention", run: retentionService.Run},
		{name: "siem", run: siemService.Run},
		{name: "audit-anomaly", run: auditAnomalyService.Run},
		// Audit-chain verification and the cleanups, once per interval across
		// instances.
		{name: "scheduler", run: func(ctx context.Context) {
			worker.RunScheduled(ctx, pool, MaintenanceJobs(pool, sessionSignals, sharedCipher, outboundPolicy), worker.SchedulerTick)
		}},
	}
	RegisterMaintenanceMetrics(pool, sharedCipher)
	return deps, workers
}
