package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"

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
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	worker "github.com/qeetgroup/qeet-id-server/internal/platform/jobs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/health"
)

type namedWorker struct {
	name   string
	run    worker.Func
	always bool
}

// buildDeps constructs every repository, service, and handler and returns the
// HTTP dependency set plus the background workers to supervise. Keeping all
// wiring here lets main() focus on process lifecycle.
func buildDeps(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool, outboxPub outbox.Publisher) (Deps, []namedWorker) {
	var egressProxy *url.URL
	if raw := strings.TrimSpace(cfg.EgressProxyURL); raw != "" {
		parsed, err := url.Parse(raw)
		if err != nil {
			slog.Error("parse EGRESS_PROXY_URL", "err", err)
			os.Exit(1)
		}
		egressProxy = parsed
		slog.Info("outbound integrations routed through egress proxy", "host", egressProxy.Host)
	}
	outboundPolicy := egress.NewPolicy(egress.Options{ProxyURL: egressProxy})
	if cfg.IsDev() {
		outboundPolicy = egress.DevelopmentPolicy()
	}
	keyProvider, err := SecretsKeyProvider(rootCtx, cfg)
	if err != nil {
		slog.Error("init secrets key provider", "err", err)
		os.Exit(1)
	}
	dataKey, err := keyProvider.DataKey(rootCtx)
	if err != nil {
		slog.Error("unwrap secrets data key", "err", err)
		os.Exit(1)
	}
	sharedCipher, err := envelope.New(dataKey)
	if err != nil {
		slog.Error("init domain encryption", "err", err)
		os.Exit(1)
	}
	// Pin the unwrapped DEK for the process lifetime. Both vaults and every
	// envelope-encrypted column derive from this one key, so re-unwrapping per
	// call would buy nothing — the plaintext key is already resident. The
	// consequence is that rotating a KMS-backed DEK needs a restart, not just a
	// KMS-side rotation; see docs/JWT-KEY-ROTATION.md for the same two-phase
	// shape applied to signing keys.
	keyProvider = secret.StaticKeyProvider{Key: dataKey}
	signingKeyPEM := cfg.JWTSigningKey
	ephemeralSigningKey := signingKeyPEM == ""
	if signingKeyPEM == "" {
		if !cfg.IsDev() {
			slog.Error("JWT_SIGNING_KEY is required outside dev (PEM-encoded EC P-256 private key)")
			os.Exit(1)
		}
		k, err := tokens.GenerateES256KeyPEM()
		if err != nil {
			slog.Error("generate ephemeral signing key", "err", err)
			os.Exit(1)
		}
		signingKeyPEM = k
		slog.Warn("JWT_SIGNING_KEY unset — generated and activated a new development ES256 key")
	}
	signingKeyRegistry, err := tokens.NewSigningKeyRegistry(pool, sharedCipher)
	if err != nil {
		slog.Error("init signing key registry", "err", err)
		os.Exit(1)
	}
	ephemeralEnvelopeKey := cfg.IsDev() && (cfg.SecretsProvider == "" || cfg.SecretsProvider == "static") && cfg.SecretsKey == ""
	activateSigningKey := cfg.JWTActivateSigningKey || ephemeralSigningKey || ephemeralEnvelopeKey
	if err := signingKeyRegistry.Reconcile(rootCtx, signingKeyPEM, cfg.JWTRetiredKeys, activateSigningKey, cfg.JWTSigningKeyRetireGrace); err != nil {
		slog.Error("reconcile JWT signing key registry", "err", err)
		os.Exit(1)
	}
	issuer, err := signingKeyRegistry.NewIssuer(rootCtx, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err != nil {
		slog.Error("init token issuer from registry", "err", err)
		os.Exit(1)
	}
	slog.Info("JWT signing key registry ready", "active_kid", issuer.KID())
	verifier := &httpx.AuthVerifier{
		Tokens:          issuer,
		DevTrustHeaders: cfg.AuthDevTrustHeaders,
	}

	tenantRepo := tenant.NewRepository(pool)
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

	sender := notifier.New(notifier.Config{
		EmailProvider:    cfg.EmailProvider,
		AWSRegion:        cfg.AWSRegion,
		SMTPHost:         cfg.SMTPHost,
		SMTPPort:         cfg.SMTPPort,
		SMTPUsername:     cfg.SMTPUsername,
		SMTPPassword:     cfg.SMTPPassword,
		SMTPFrom:         cfg.SMTPFrom,
		TwilioAccountSID: cfg.TwilioAccountSID,
		TwilioAuthToken:  cfg.TwilioAuthToken,
		TwilioFrom:       cfg.TwilioFrom,
		Dev:              cfg.IsDev(),
	})
	emailTransport, emailRouter := sender.(notifier.Router)
	emailTestEnabled := emailRouter && emailTransport.Email != nil
	sender = branding.Sender{Source: brandingRepo, Next: sender}
	sender = email.TemplateSender{Templates: emailTemplateService, Appearance: brandingRepo, Next: sender}
	// PNG fallback for the email logo (served at the app root): shown in clients
	// that strip the inline SVG mark (Gmail/Outlook/Yahoo).
	emailtmpl.SetLogoPNGURL(strings.TrimRight(cfg.AppBaseURL, "/") + "/logo192.png")
	verifyService := verification.NewService(pool, sender, 10*time.Minute)
	recoveryService := recovery.NewService(pool, sender, time.Hour, cfg.AppBaseURL)
	recoveryService.SetHostedLogin(cfg.LoginBaseURL) // resets requested there link back to it
	retentionService := retention.NewService(pool)
	salesService := sales.NewService(pool, sender, cfg.SalesEmail)
	inviteService := invite.NewService(pool, sender, 14*24*time.Hour, cfg.AppBaseURL)
	authService := auth.NewService(pool, userRepo, issuer)
	authPolicyService := authpolicy.NewService(pool)

	// One password check for every path that sets or replaces a password:
	// authPolicyService.ValidateForTenant (the organisation's rules, or the
	// platform baseline for a tenant-less account; the offline strength
	// baseline; the breach check). Sign-up, hosted registration and
	// self-service change reach it through SetRegistrationPolicy below; admin
	// create / set-password / bulk import through user.Handler.PasswordPolicy.
	recoveryService.SetPasswordRules(authPolicyService)   // password reset
	recoveryService.SetMagicLinkPolicy(authPolicyService) // magic links only where the tenant allows them, with its lifetime
	inviteService.SetPasswordRules(authPolicyService)     // invite accept
	inviteService.SetAcceptMethods(authPolicyService)     // which ways of accepting the acceptance screen offers

	// Breached-password detection (Have I Been Pwned k-anonymity). OFF by
	// default (BREACHED_PASSWORD_CHECK unset) so dev/CI/offline deploys are
	// unaffected; when enabled the password check above runs it on every
	// password-setting path, and it is fail-open at runtime (a HIBP outage
	// allows the password and is counted in
	// breached_password_check_allowed_on_error_total). Only the 5-char SHA-1
	// prefix ever leaves the process — never the plaintext.
	if cfg.BreachedPasswordCheck {
		breachChecker := hibp.New(&http.Client{Timeout: 3 * time.Second}, cfg.BreachedPasswordAPIURL, cfg.BreachedPasswordMinCount)
		authPolicyService.SetBreachChecker(breachChecker)
		slog.Info("breached-password check enabled (HIBP k-anonymity; fail-open)", "min_count", cfg.BreachedPasswordMinCount)
	}
	apikeyService := apikey.NewService(pool)
	principalService := principal.NewService(pool, issuer)
	mfaService := mfa.NewService(pool, cfg.JWTIssuer, sender, cfg.ExpoPushURL)
	mfaService.SetCipher(sharedCipher)
	authService.SetMFA(mfaService)                       // gate password login on a second factor when enrolled
	authService.SetRegistrationPolicy(authPolicyService) // gate hosted signup + the password check (signup, register, change)
	authService.SetMethodPolicy(authPolicyService)       // password sign-in only where the tenant allows it
	authService.SetDevicePolicy(authPolicyService)       // gate adaptive MFA (trusted-device skip)

	// Sign-in lockout (authentication/lockout.go): failures counted per account
	// + source network (the tenant-configurable lock), per account at a looser
	// cap, and per source across accounts (spraying). The platform defaults and
	// the bounds a tenant may choose within come from LOGIN_LOCKOUT_* /
	// LOGIN_SPRAY_* (validated by config.Load); a tenant's own settings live in
	// its authentication policy and apply on the next attempt.
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
	botService := bot.NewService(pool)
	siemService := siem.NewService(pool, outboundPolicy) // forwards audit events to configured log sinks
	siemService.SetCipher(sharedCipher)
	rebacService := rebac.NewService(pool)                       // fine-grained (relationship) authorization
	abacService := abac.NewService(pool)                         // attribute-based access control (policy store + PDP)
	authzenService := authzen.NewService(rbacRepo, rebacService) // OpenID AuthZEN PDP facade over RBAC/ReBAC
	agentService := agent.NewService(pool, issuer)               // AI-agent identities (ephemeral scoped tokens)
	vcService := vc.NewService(pool, issuer)                     // W3C verifiable credentials (JWT-VC)

	// Qeet AI assistant: the conversation store is created here; the per-tenant
	// BYOK provider-config service + orchestrator + handler are wired below,
	// after the secrets key provider exists (they reuse the same AES data key to
	// encrypt tenant provider keys at rest).
	qeetaiService := qeetai.NewService(pool)
	// Live Activity hub: subscribes to NATS outbox events (when NATS_URL is set)
	// and fans them out to authenticated SSE connections filtered by tenant.
	// When NATS_URL is empty the hub acts as a no-op broker — the SSE stream
	// still connects and serves history/replay, but no live events are pushed.
	var activityNATSConn *nats.Conn
	if cfg.NATSURL != "" {
		nc, err := nats.Connect(cfg.NATSURL,
			nats.Name("qeet-id-activity-sub"),
			nats.MaxReconnects(-1),
			nats.ReconnectWait(2*time.Second),
		)
		if err != nil {
			slog.Error("activity: connect nats subscriber", "err", err)
			os.Exit(1)
		}
		activityNATSConn = nc
		slog.Info("activity hub: connected to NATS", "url", cfg.NATSURL)
	}
	if activityNATSConn != nil {
		defer func() { _ = activityNATSConn.Drain() }()
	}
	activityHub := activity.NewHub(activityNATSConn)

	// Universal search: read-only fan-out across resource types. Reuses the
	// rbacRepo for per-type permission checks; no new DB objects required.
	searchService := search.NewService(pool, rbacRepo)
	webhookService := webhook.NewService(pool, outboundPolicy)
	webhookService.SetCipher(sharedCipher)
	// Agent lifecycle: emit webhook events on transitions, and let the auth
	// middleware deny suspended/decommissioned agents' tokens per request.
	agentService.SetEmitter(webhookService.Enqueue)
	verifier.AgentStatus = agentService.AgentStatus
	// CAEP/SSF-shaped signals over the existing webhook dispatcher: a tenant
	// that subscribes to these can react to a revoked session or a changed
	// role grant immediately, instead of waiting out the access-token TTL.
	// Every path that ends a session announces it (session.revoked) in the
	// transaction that ends it; see sessionsignal for reasons and destinations.
	sessionSignals := sessionsignal.New(webhookService.EnqueueTx)
	authService.SetSessionSignals(sessionSignals)
	authService.SetSessionLifetime(cfg.SessionMaxAge, cfg.SessionIdleTimeout) // session bounds where the organisation sets none
	verifier.SessionUsed = authService.SessionUsed                            // a session's last use, for its idle timeout and the session list
	recoveryService.SetSessionSignals(sessionSignals)
	rbacService.SetEmitter(webhookService.Enqueue)
	gdprService := gdpr.NewService(pool, 30*24*time.Hour)
	gdprService.SetSessionSignals(sessionSignals)
	auditReader := audit.NewReader(pool)
	auditVerifier := audit.NewVerifier(pool)
	evidenceService := gdpr.NewEvidenceService(pool, auditVerifier, cfg.BreachedPasswordCheck)
	auditAnomalyService := anomaly.NewService(pool)
	analyticsReader := analytics.NewReader(pool)
	outboxReader := outbox.NewReader(pool)

	startedAt := time.Now()
	healthHandler := health.New(cfg.ServiceName, cfg.ServiceEnv, startedAt)
	healthHandler.ServiceProfile = cfg.ServiceProfile
	healthHandler.AddReadiness("db", health.PingDB(pool))
	inFlight := httpx.NewInFlight()
	oidcService := oidc.NewService(pool, issuer)
	oidcService.SetGrantMaxAge(cfg.SessionMaxAge) // grant bound where the organisation sets none
	oidcService.SetNotifier(notificationService)  // CIBA async consent prompts
	rpID, rpDisplayName, rpOrigins := cfg.WebAuthnRP()
	// UserVerification: Required is load-bearing, not a preference.
	//
	// go-webauthn copies Config.AuthenticatorSelection.UserVerification into the
	// assertion and then gates on `session.UserVerification == Required` — a
	// strict equality. Left unset (or at "preferred") the UV flag in
	// authenticatorData is never checked, so a passkey proves only POSSESSION of
	// the authenticator. Accounts created through passkey signup have no
	// password at all, which made the passkey the entire credential and reduced
	// a "phishing-resistant MFA" product to a single touch on a borrowed device.
	//
	// Setting it here covers both login ceremonies (BeginLogin and
	// BeginDiscoverableLogin read it from the config); the two registration
	// ceremonies override AuthenticatorSelection explicitly and set it there.
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
	mfaService.SetWebAuthn(passkeyService)            // a passkey can meet a sign-in's second-factor challenge
	mfaService.SetPlan(entitlementSvc)                // SMS codes only on plans that include them
	if emailRouter {
		mfaService.SetDeliveryCheck(emailTransport.Configured) // refuse codes no provider can deliver
	}
	socialService := social.NewService(pool, authService, cfg.AppBaseURL, outboundPolicy)
	socialService.SetCipher(sharedCipher)
	// Allowlist for the hosted flow's return_to. The callback sets the SSO
	// cookie before redirecting, so an unvalidated value would be an open
	// redirect on the auth domain. AllowedOrigins is already the vetted browser
	// origin set (Validate() refuses a wildcard outside dev).
	socialService.SetAllowedReturnOrigins(
		append([]string{cfg.AppBaseURL, cfg.LoginBaseURL}, cfg.AllowedOrigins()...)...)
	// Platform-level (tenant-less) social login for the console's own accounts.
	// Off until credentials are set; Google only for now.
	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		socialService.SetPlatformProvider("google", cfg.GoogleClientID, cfg.GoogleClientSecret,
			"https://accounts.google.com/.well-known/openid-configuration")
	}
	if cfg.MicrosoftClientID != "" && cfg.MicrosoftClientSecret != "" {
		// /common allows both work/school and personal Microsoft accounts.
		socialService.SetPlatformProvider("microsoft", cfg.MicrosoftClientID, cfg.MicrosoftClientSecret,
			"https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration")
	}
	if cfg.GithubClientID != "" && cfg.GithubClientSecret != "" {
		socialService.SetPlatformGitHub(cfg.GithubClientID, cfg.GithubClientSecret) // GitHub isn't OIDC — dedicated adapter
	}
	if cfg.AppleClientID != "" && cfg.AppleTeamID != "" && cfg.AppleKeyID != "" && cfg.ApplePrivateKey != "" {
		socialService.SetPlatformApple(cfg.AppleClientID, cfg.AppleTeamID, cfg.AppleKeyID, cfg.ApplePrivateKey)
	}
	groupService := group.NewService(pool)
	scimService := scim.NewService(pool, userRepo)
	scimService.SetSessionSignals(sessionSignals)
	secretService, err := secret.NewService(rootCtx, pool, keyProvider)
	if err != nil {
		slog.Error("init secrets vault", "err", err)
		os.Exit(1)
	}
	// Token Vault reuses the same key provider as the secrets vault above —
	// one KMS/static-key setup backs both encrypted stores.
	tokenVaultService, err := tokenvault.NewService(rootCtx, pool, keyProvider, outboundPolicy)
	if err != nil {
		slog.Error("init token vault", "err", err)
		os.Exit(1)
	}

	// Qeet AI provider config: per-tenant BYOK keys encrypted with the same data
	// key as the secrets vault. When a tenant hasn't set its own key, the
	// deployment-level QEETAI_* env acts as the platform fallback. Because a
	// tenant can bring its own key even when no platform key is set, the
	// orchestrator is always constructed (configured state is resolved per-tenant).
	qeetaiProviderCfg, err := qeetai.NewProviderConfig(rootCtx, pool, keyProvider, qeetai.PlatformProvider{
		Provider:  cfg.QeetaiProvider,
		APIKey:    cfg.QeetaiAPIKey,
		Model:     cfg.QeetaiModel,
		BaseURL:   cfg.QeetaiBaseURL,
		MaxTokens: cfg.QeetaiMaxTokens,
	}, outboundPolicy)
	if err != nil {
		slog.Error("init Qeet AI provider config", "err", err)
		os.Exit(1)
	}
	if qeetaiProviderCfg.PlatformConfigured() {
		slog.Info("Qeet AI: platform provider configured", "provider", cfg.QeetaiProvider, "model", cfg.QeetaiModel)
	} else {
		slog.Info("Qeet AI: no platform provider set — tenants must bring their own key (BYOK)")
	}
	qeetaiHandler := &qeetai.Handler{
		Service:      qeetaiService,
		Orchestrator: qeetai.NewOrchestrator(qeetaiProviderCfg, qeetaiService),
		Resolver:     qeetaiProviderCfg,
		Config:       qeetaiProviderCfg,
		Plan:         entitlementSvc, // platform fallback is a Pro+ feature; BYOK bypasses the gate
	}

	samlService := saml.NewService(pool, authService, cfg.AppBaseURL)

	// SAML IdP signing identity: configured RSA key+cert in prod, or an
	// ephemeral self-signed cert in dev when unset.
	samlIdPKeyPEM, samlIdPCertPEM := cfg.SAMLIdPKey, cfg.SAMLIdPCert
	if samlIdPKeyPEM == "" || samlIdPCertPEM == "" {
		if !cfg.IsDev() {
			slog.Error("SAML_IDP_KEY and SAML_IDP_CERT are required outside dev (RSA private key + X.509 cert, PEM)")
			os.Exit(1)
		}
		k, c, gerr := saml.GenerateIdPKeyPEM("Qeet ID SAML IdP")
		if gerr != nil {
			slog.Error("generate ephemeral SAML IdP signing cert", "err", gerr)
			os.Exit(1)
		}
		samlIdPKeyPEM, samlIdPCertPEM = k, c
		slog.Warn("SAML_IDP_KEY/SAML_IDP_CERT unset — generated an ephemeral SAML IdP signing cert; SPs must re-import IdP metadata after a restart (dev only)")
	}
	samlIdP, err := saml.NewIdP(pool, samlIdPKeyPEM, samlIdPCertPEM, cfg.LoginBaseURL, authService)
	if err != nil {
		slog.Error("init saml idp", "err", err)
		os.Exit(1)
	}

	adminPortalService := adminportal.NewService(pool, brandingRepo, cfg.LoginBaseURL)

	ldapService := ldap.NewService(pool, authService, outboundPolicy)
	ldapService.SetCipher(sharedCipher)
	directoryService := directory.NewService(scimService, ldapService)
	directoryService.SetEventStore(pool)
	scimService.SetOperationObserver(directoryService)
	ldapService.SetOperationObserver(directoryService)
	scimService.SetProfileMapper(directoryService)
	ldapService.SetProfileMapper(directoryService)
	ipAllowService := ipallow.NewService(pool)

	// Plan enforcement: inject the entitlement checker into every gated create
	// path. Numeric limits (seats/apps/api keys/custom roles) use SetPlanLimiter;
	// boolean features (webhooks/SSO/SCIM/LDAP) use SetPlanGate. Free-tier caps
	// bite here; paid tiers resolve to unlimited/enabled, so it's a no-op for them.
	inviteService.SetPlanLimiter(entitlementSvc) // seats
	oidcService.SetPlanLimiter(entitlementSvc)   // apps (relying parties)
	apikeyService.SetPlanLimiter(entitlementSvc) // api_keys
	rbacService.SetPlanLimiter(entitlementSvc)   // custom_roles
	webhookService.SetPlanGate(entitlementSvc)   // webhooks (feature)
	samlIdP.SetPlanGate(entitlementSvc)          // SSO (SAML)
	scimService.SetPlanGate(entitlementSvc)      // SCIM
	ldapService.SetPlanGate(entitlementSvc)      // LDAP
	brandingRepo.SetPlanGate(entitlementSvc)     // custom branding
	abacService.SetPlanGate(entitlementSvc)      // ABAC
	// Current-usage provider for the billing usage-vs-limits display.
	entitlementSvc.SetUsageResolver(entitlementUsageResolver{
		invites: inviteService, oidc: oidcService, apikeys: apikeyService, rbacRepo: rbacRepo,
	})
	// custom domain — extracted from its inline handler so the gate can be wired.
	domainVerifyService := domainverify.NewService(pool)
	domainVerifyService.SetPlanGate(entitlementSvc)

	// Rate-limit store: Redis (shared across replicas) when REDIS_URL is set,
	// otherwise in-process. Required for correct limits when scaling out.
	var rlStore ratelimit.Store
	if cfg.RedisURL != "" {
		opt, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			slog.Error("parse REDIS_URL", "err", err)
			os.Exit(1)
		}
		rdb := redis.NewClient(opt)
		if err := rdb.Ping(rootCtx).Err(); err != nil {
			slog.Error("redis ping", "err", err)
			os.Exit(1)
		}
		rlStore = ratelimit.NewRedisStore(rdb)
		slog.Info("rate limiting via Redis (shared across replicas)")
	}

	// Build tenant-aware limiters that allow per-tenant rate overrides stored in DB.
	newTenantLim := func(defRate float64, defCap int, key string) *ratelimit.TenantLimiter {
		var store ratelimit.Store
		if rlStore != nil {
			store = rlStore
		} else {
			store = ratelimit.NewMemStore()
		}
		lim := ratelimit.NewTenantLimiter(store, defRate, defCap, pool, key)
		lim.LoadOverrides(rootCtx)
		return lim
	}
	// Magic-link requests are bounded more tightly than sign-in: three per
	// address, then one every five minutes; ten per caller, then one a minute.
	magicStore := rlStore
	if magicStore == nil {
		magicStore = ratelimit.NewMemStore()
	}
	recoveryService.SetMagicLinkLimits(
		ratelimit.NewWithStore(magicStore, 1.0/300, 3),
		ratelimit.NewWithStore(magicStore, 1.0/60, 10),
	)
	tenantTenantLim := newTenantLim(100, 500, "tenant")
	tenantUserLim := newTenantLim(30, 100, "user")
	tenantAPIKeyLim := newTenantLim(50, 200, "api_key")
	rateLimitsHandler := &ratelimits.Handler{
		Pool:      pool,
		TenantLim: tenantTenantLim,
		UserLim:   tenantUserLim,
		APIKeyLim: tenantAPIKeyLim,
		Defaults:  ratelimits.Defaults{TenantRate: 100, TenantCapacity: 500, UserRate: 30, UserCapacity: 100, APIKeyRate: 50, APIKeyCapacity: 200},
	}

	v := validator.New(validator.WithRequiredStructEnabled())
	// Use JSON field names in validation errors so the per-field messages the
	// API returns match the request body the client sent (e.g. "display_name",
	// not "DisplayName").
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
	deps := Deps{
		Tenant:        &tenant.Handler{Repo: tenantRepo, Validate: v, AuthService: authService},
		User:          &user.Handler{Repo: userRepo, Validate: v, PasswordPolicy: authPolicyService.ValidateForTenant, MFA: mfaService, SignIns: authService, Signals: sessionSignals},
		AuthPolicy:    &authpolicy.Handler{Service: authPolicyService},
		Auth:          &auth.Handler{Service: authService, Validate: v, CookieSecure: !cfg.IsDev(), Bot: botService, GeoCountryHeader: cfg.GeoCountryHeader},
		RBAC:          &rbac.Handler{Repo: rbacRepo, Service: rbacService, Validate: v},
		RBACChecker:   rbacRepo,
		Verification:  &verification.Handler{Service: verifyService},
		Recovery:      &recovery.Handler{Service: recoveryService, AuthService: authService, DevMode: cfg.IsDev(), CookieSecure: !cfg.IsDev()},
		Retention:     &retention.Handler{Service: retentionService},
		Invite:        &invite.Handler{Service: inviteService, AuthService: authService, Validate: v},
		Branding:      &branding.Handler{Repo: brandingRepo},
		EmailTemplate: &email.Handler{Service: emailTemplateService, Sender: sender, Appearance: brandingRepo, TestEmailEnabled: emailTestEnabled},
		APIKey:        &apikey.Handler{Service: apikeyService},
		APIKeyService: apikeyService,
		Principal:     &principal.Handler{Service: principalService},
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
		Outbox:        &outbox.Handler{Reader: outboxReader},
		OIDC:          &oidc.Handler{Service: oidcService, Sessions: authService, Providers: socialService, Registration: authPolicyService, DeviceTrust: authPolicyService, Methods: authPolicyService, Branding: brandingRepo, LoginBaseURL: cfg.LoginBaseURL, CookieSecure: !cfg.IsDev()},
		Passkey:       &passkey.Handler{Service: passkeyService, CookieSecure: !cfg.IsDev()},
		Social:        &social.Handler{Service: socialService, CookieSecure: !cfg.IsDev(), LoginBaseURL: cfg.LoginBaseURL},
		Group:         &group.Handler{Service: groupService},
		SCIM:          &scim.Handler{Service: scimService},
		Secret:        &secret.Handler{Service: secretService},
		TokenVault:    &tokenvault.Handler{Service: tokenVaultService},
		SAML:          &saml.Handler{Service: samlService, IdP: samlIdP, CookieSecure: !cfg.IsDev()},
		AdminPortal:   &adminportal.Handler{Service: adminPortalService, SAML: samlService, SCIM: scimService, CookieSecure: !cfg.IsDev()},
		LDAP:          &ldap.Handler{Service: ldapService},
		Directory:     &directory.Handler{Service: directoryService},
		IPAllow:       &ipallow.Handler{Service: ipAllowService},
		Threat:        &threat.Handler{Service: threatService},
		Bot:           &bot.Handler{Service: botService},
		Risk:          &risk.Handler{Service: riskService},
		RateLimits:    rateLimitsHandler,
		Notification:  &notification.Handler{Service: notificationService},
		DomainVerify:  &domainverify.Handler{Service: domainVerifyService},
		SIEM:          &siem.Handler{Service: siemService},
		AuthHook:      &authhook.Handler{Service: authHookService},
		ABAC:          &abac.Handler{Service: abacService},
		ReBAC:         &rebac.Handler{Service: rebacService},
		AuthZEN:       &authzen.Handler{Service: authzenService},
		Agent:         &agent.Handler{Service: agentService},
		VC:            &vc.Handler{Service: vcService},
		Qeetai:        qeetaiHandler,
		Search:        &search.Handler{Service: searchService},
		Activity:      activity.NewHandler(pool, activityHub),
		Health:        healthHandler,
		InFlight:      inFlight,

		AuthVerifier:     verifier,
		AllowedOrigins:   cfg.AllowedOrigins(),
		ServiceName:      cfg.ServiceName,
		ServiceEnv:       cfg.ServiceEnv,
		StartedAt:        startedAt,
		CSRFDisabled:     cfg.CSRFDisabled,
		CSRFCookieDomain: cfg.CSRFCookieDomain,
		RateLimitStore:   rlStore,
	}

	outboxDispatcher := outbox.NewDispatcher(pool, outboxPub, 2*time.Second, 50)
	workers := []namedWorker{
		{name: "jwt-keyring", run: func(ctx context.Context) { signingKeyRegistry.Run(ctx, issuer, cfg.JWTSigningKeyRefreshInterval) }, always: true},
		{name: "outbox", run: outboxDispatcher.Run},
		{name: "webhook", run: webhookService.RunDispatcher},
		{name: "gdpr", run: gdprService.Run},
		{name: "retention", run: retentionService.Run},
		{name: "siem", run: siemService.Run},
		{name: "audit-anomaly", run: auditAnomalyService.Run},
	}
	return deps, workers
}

// secretsKeyProvider builds the vault data-key provider selected by
// SECRETS_PROVIDER. "static" decodes SECRETS_KEY (or generates an ephemeral key
// in dev when unset); "aws-kms" unwraps the DEK from AWS KMS at boot.
// billingOrgProvisioner adapts the tenant repository to billing.OrgProvisioner,
// so billing can create an organization once a signup checkout is paid without
// importing the identity/tenant package (keeping the dependency direction clean).
type billingOrgProvisioner struct{ tenants *tenant.Repository }

func (p billingOrgProvisioner) ProvisionOrg(ctx context.Context, ownerID uuid.UUID, name, slug, region, plan string) (uuid.UUID, error) {
	t, err := p.tenants.CreateWithOwner(ctx, tenant.CreateInput{Slug: slug, Name: name, Plan: plan, Region: region}, ownerID)
	if err != nil {
		return uuid.Nil, err
	}
	return t.ID, nil
}

// entitlementPlanResolver resolves a tenant's effective plan code for the
// entitlements service. It prefers the billing subscription (the paid source of
// truth), falls back to the tenant's plan label, and defaults to free — so an
// in-app upgrade takes effect immediately (subscription) even before/without the
// label sync, and a plain free org (no subscription row) reads as free.
// Implemented here because only the composition root may touch both contexts.
type entitlementPlanResolver struct {
	billing *billing.Service
	tenants *tenant.Repository
}

func (r entitlementPlanResolver) EffectivePlan(ctx context.Context, tenantID uuid.UUID) (string, error) {
	if r.billing != nil {
		if sub, err := r.billing.GetSubscription(ctx, tenantID); err == nil && sub != nil && sub.PlanCode != "" {
			switch sub.Status {
			case "active", "past_due":
				return sub.PlanCode, nil
			case "trialing":
				// Trial grants the tier only until it expires; afterwards the
				// tenant reverts to free (evaluated lazily here — no scheduler).
				if sub.TrialEnd != nil && sub.TrialEnd.After(time.Now()) {
					return sub.PlanCode, nil
				}
				return "free", nil
			default:
				// canceled / unknown: a subscription row exists but isn't granting,
				// so this is a paid org that lapsed — free, not the stale label.
				return "free", nil
			}
		}
	}
	if r.tenants != nil {
		if t, err := r.tenants.Get(ctx, tenantID); err == nil && t != nil {
			return t.Plan, nil
		}
	}
	return "free", nil
}

// entitlementUsageResolver reports a tenant's current consumption for the
// billing usage-vs-limits display. It reuses the same count queries the plan
// gates check against. Best-effort per resource: a failed count is omitted
// rather than failing the whole response.
type entitlementUsageResolver struct {
	invites  *invite.Service
	oidc     *oidc.Service
	apikeys  *apikey.Service
	rbacRepo *rbac.Repository
}

func (u entitlementUsageResolver) Usage(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	out := map[string]int{}
	if u.invites != nil {
		if n, err := u.invites.CountSeats(ctx, tenantID); err == nil {
			out["seats"] = n
		}
	}
	if u.oidc != nil {
		if n, err := u.oidc.CountClients(ctx, tenantID); err == nil {
			out["apps"] = n
		}
	}
	if u.apikeys != nil {
		if n, err := u.apikeys.CountActive(ctx, tenantID); err == nil {
			out["api_keys"] = n
		}
	}
	if u.rbacRepo != nil {
		if n, err := u.rbacRepo.CountCustomRoles(ctx, tenantID); err == nil {
			out["custom_roles"] = int(n)
		}
	}
	return out, nil
}

func SecretsKeyProvider(ctx context.Context, cfg *config.Config) (secret.KeyProvider, error) {
	switch cfg.SecretsProvider {
	case "aws-kms":
		blob, err := base64.StdEncoding.DecodeString(cfg.SecretsWrappedDEK)
		if err != nil {
			return nil, fmt.Errorf("SECRETS_WRAPPED_DEK must be base64: %w", err)
		}
		slog.Info("secrets vault key via AWS KMS", "key_id", cfg.KMSKeyID)
		return secret.NewAWSKMSProvider(ctx, cfg.KMSKeyID, blob)
	case "", "static":
		if cfg.SecretsKey != "" {
			key, err := base64.StdEncoding.DecodeString(cfg.SecretsKey)
			if err != nil {
				return nil, fmt.Errorf("SECRETS_KEY must be base64: %w", err)
			}
			return secret.StaticKeyProvider{Key: key}, nil
		}
		// Reached only in dev — Validate() requires SECRETS_KEY otherwise.
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate ephemeral secrets key: %w", err)
		}
		slog.Warn("SECRETS_KEY unset — generated an ephemeral vault key; stored secrets will not survive a restart (dev only)")
		return secret.StaticKeyProvider{Key: key}, nil
	default:
		return nil, fmt.Errorf("unknown SECRETS_PROVIDER %q (want \"static\" or \"aws-kms\")", cfg.SecretsProvider)
	}
}
