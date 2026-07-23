package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/go-webauthn/webauthn/webauthn"
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
	"github.com/qeetgroup/qeet-id-server/internal/operations/copilot"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	notification "github.com/qeetgroup/qeet-id-server/internal/operations/notifications"
	"github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention"
	"github.com/qeetgroup/qeet-id-server/internal/operations/search"
	"github.com/qeetgroup/qeet-id-server/internal/operations/siem"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai/anthropic"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai/openai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	worker "github.com/qeetgroup/qeet-id-server/internal/platform/jobs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/health"
)

type namedWorker struct {
	name string
	run  worker.Func
}

// buildDeps constructs every repository, service, and handler and returns the
// HTTP dependency set plus the background workers to supervise. Keeping all
// wiring here lets main() focus on process lifecycle.
func buildDeps(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool, outboxPub outbox.Publisher) (Deps, []namedWorker) {
	signingKeyPEM := cfg.JWTSigningKey
	if signingKeyPEM == "" {
		if cfg.ServiceEnv != "dev" {
			slog.Error("JWT_SIGNING_KEY is required outside dev (PEM-encoded EC P-256 private key)")
			os.Exit(1)
		}
		k, err := tokens.GenerateES256KeyPEM()
		if err != nil {
			slog.Error("generate ephemeral signing key", "err", err)
			os.Exit(1)
		}
		signingKeyPEM = k
		slog.Warn("JWT_SIGNING_KEY unset — generated an ephemeral ES256 key; issued tokens will not survive a restart (dev only)")
	}
	issuer, err := tokens.NewIssuer(signingKeyPEM, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err != nil {
		slog.Error("init token issuer", "err", err)
		os.Exit(1)
	}
	if n := issuer.AddRetiredKeysPEM(cfg.JWTRetiredKeys); n > 0 {
		slog.Info("registered retired signing keys for rotation grace", "count", n)
	}
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
	billingService.SetPayments(billing.NewPayments(
		cfg.StripeSecretKey, cfg.StripeWebhookSecret,
		cfg.RazorpayKeyID, cfg.RazorpayKeySecret, cfg.RazorpayWebhookSecret,
	)) // card payments (Stripe/Razorpay); no-op until keys are configured
	if err := billingService.SeedBuiltins(rootCtx); err != nil {
		slog.Warn("billing seed", "err", err)
	}
	brandingRepo := branding.NewRepository(pool)
	emailTemplateService := email.NewService(pool)
	policyRepo := policy.NewRepository(pool)

	sender := notifier.New(notifier.Config{
		SMTPHost:         cfg.SMTPHost,
		SMTPPort:         cfg.SMTPPort,
		SMTPUsername:     cfg.SMTPUsername,
		SMTPPassword:     cfg.SMTPPassword,
		SMTPFrom:         cfg.SMTPFrom,
		TwilioAccountSID: cfg.TwilioAccountSID,
		TwilioAuthToken:  cfg.TwilioAuthToken,
		TwilioFrom:       cfg.TwilioFrom,
	})
	verifyService := verification.NewService(pool, sender, 10*time.Minute)
	recoveryService := recovery.NewService(pool, sender, time.Hour, cfg.AppBaseURL, cfg.LoginBaseURL)
	retentionService := retention.NewService(pool)
	inviteService := invite.NewService(pool, sender, 14*24*time.Hour, cfg.AppBaseURL)
	authService := auth.NewService(pool, userRepo, issuer)
	authPolicyService := authpolicy.NewService(pool)

	// Breached-password detection (Have I Been Pwned k-anonymity). OFF by
	// default (BREACHED_PASSWORD_CHECK unset) so dev/CI/offline deploys are
	// unaffected; when enabled it is injected into every password-setting flow
	// and is fail-open at runtime (a HIBP outage allows the password). Only the
	// 5-char SHA-1 prefix ever leaves the process — never the plaintext.
	if cfg.BreachedPasswordCheck {
		breachChecker := hibp.New(&http.Client{Timeout: 3 * time.Second}, cfg.BreachedPasswordAPIURL, cfg.BreachedPasswordMinCount)
		authPolicyService.SetBreachChecker(breachChecker) // user set-password (via ValidateForTenant)
		authService.SetBreachChecker(breachChecker)       // signup
		recoveryService.SetBreachChecker(breachChecker)   // password reset
		inviteService.SetBreachChecker(breachChecker)     // invite accept
		slog.Info("breached-password check enabled (HIBP k-anonymity; fail-open)", "min_count", cfg.BreachedPasswordMinCount)
	}
	apikeyService := apikey.NewService(pool)
	principalService := principal.NewService(pool, issuer)
	mfaService := mfa.NewService(pool, cfg.JWTIssuer, sender)
	authService.SetMFA(mfaService)                       // gate password login on a second factor when enrolled
	authService.SetRegistrationPolicy(authPolicyService) // gate hosted signup + validate new passwords per tenant
	authService.SetDevicePolicy(authPolicyService)       // gate adaptive MFA (trusted-device skip)
	authHookService := authhook.NewService(pool)
	authService.SetLoginHook(authHookService) // synchronous Actions/Hooks gate (no-op until configured)
	threatService := threat.NewService(pool)
	authService.SetAnomalyRecorder(threatService) // record credential-stuffing anomalies on lockout
	notificationService := notification.NewService(pool)
	threatService.SetNotifier(notificationService) // alert the affected user in-app on lockout
	riskService := risk.NewService(pool)
	authService.SetRiskAssessor(riskService) // override trusted-device skip when risk is too high
	botService := bot.NewService(pool)
	siemService := siem.NewService(pool)                         // forwards audit events to configured log sinks
	rebacService := rebac.NewService(pool)                       // fine-grained (relationship) authorization
	abacService := abac.NewService(pool)                         // attribute-based access control (policy store + PDP)
	authzenService := authzen.NewService(rbacRepo, rebacService) // OpenID AuthZEN PDP facade over RBAC/ReBAC
	agentService := agent.NewService(pool, issuer)               // AI-agent identities (ephemeral scoped tokens)
	vcService := vc.NewService(pool, issuer)                     // W3C verifiable credentials (JWT-VC)

	// AI Copilot: provider unset ⇒ feature disabled (handler still mounts; /status
	// reports configured=false; .../messages returns 409 copilot_unconfigured).
	// COPILOT_PROVIDER selects the backend: "openai" (or any OpenAI-compatible
	// endpoint via COPILOT_BASE_URL), else "anthropic".
	copilotService := copilot.NewService(pool)
	copilotConfigured := cfg.CopilotProvider != "" && cfg.CopilotAPIKey != ""
	var copilotOrchestrator *copilot.Orchestrator
	if copilotConfigured {
		var provider ai.Provider
		switch strings.ToLower(cfg.CopilotProvider) {
		case "openai":
			c := openai.New(cfg.CopilotAPIKey, cfg.CopilotBaseURL, cfg.CopilotModel, cfg.CopilotMaxTokens, nil)
			provider = c
		default: // "anthropic" and any unrecognised value fall back to Anthropic
			c := anthropic.New(cfg.CopilotAPIKey, cfg.CopilotBaseURL, cfg.CopilotModel, cfg.CopilotMaxTokens, nil)
			provider = anthropic.NewProvider(c)
		}
		copilotOrchestrator = copilot.NewOrchestrator(provider, copilotService)
		slog.Info("AI copilot enabled", "provider", cfg.CopilotProvider, "model", cfg.CopilotModel)
	} else {
		slog.Info("AI copilot disabled (COPILOT_PROVIDER/COPILOT_API_KEY not set)")
	}
	copilotHandler := &copilot.Handler{
		Service:      copilotService,
		Orchestrator: copilotOrchestrator,
		Configured:   copilotConfigured,
		Provider:     cfg.CopilotProvider,
		Model:        cfg.CopilotModel,
	}
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
	webhookService := webhook.NewService(pool)
	// Agent lifecycle: emit webhook events on transitions, and let the auth
	// middleware deny suspended/decommissioned agents' tokens per request.
	agentService.SetEmitter(webhookService.Enqueue)
	verifier.AgentStatus = agentService.AgentStatus
	// CAEP/SSF-shaped signals over the existing webhook dispatcher: a tenant
	// that subscribes to these can react to a revoked session or a changed
	// role grant immediately, instead of waiting out the access-token TTL.
	authService.SetEmitter(webhookService.Enqueue)
	rbacService.SetEmitter(webhookService.Enqueue)
	gdprService := gdpr.NewService(pool, 30*24*time.Hour)
	auditReader := audit.NewReader(pool)
	auditVerifier := audit.NewVerifier(pool)
	evidenceService := gdpr.NewEvidenceService(pool, auditVerifier, cfg.BreachedPasswordCheck)
	auditAnomalyService := anomaly.NewService(pool)
	analyticsReader := analytics.NewReader(pool)
	outboxReader := outbox.NewReader(pool)

	startedAt := time.Now()
	healthHandler := health.New(cfg.ServiceName, cfg.ServiceEnv, startedAt)
	healthHandler.AddReadiness("db", health.PingDB(pool))
	inFlight := httpx.NewInFlight()
	oidcService := oidc.NewService(pool, issuer)
	oidcService.SetNotifier(notificationService) // CIBA async consent prompts
	rpID, rpDisplayName, rpOrigins := cfg.WebAuthnRP()
	wa, err := webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: rpDisplayName, RPOrigins: rpOrigins})
	if err != nil {
		slog.Error("webauthn init", "err", err)
		os.Exit(1)
	}
	passkeyService := passkey.NewService(pool, wa, authService)
	socialService := social.NewService(pool, authService, cfg.AppBaseURL)
	groupService := group.NewService(pool)
	scimService := scim.NewService(pool, userRepo)
	// Secrets-vault data key: sourced per SECRETS_PROVIDER (static SECRETS_KEY,
	// AWS KMS, or an ephemeral dev key). Validate() guarantees the required
	// inputs are present outside dev.
	keyProvider, err := secretsKeyProvider(rootCtx, cfg)
	if err != nil {
		slog.Error("init secrets key provider", "err", err)
		os.Exit(1)
	}
	secretService, err := secret.NewService(rootCtx, pool, keyProvider)
	if err != nil {
		slog.Error("init secrets vault", "err", err)
		os.Exit(1)
	}
	// Token Vault reuses the same key provider as the secrets vault above —
	// one KMS/static-key setup backs both encrypted stores.
	tokenVaultService, err := tokenvault.NewService(rootCtx, pool, keyProvider)
	if err != nil {
		slog.Error("init token vault", "err", err)
		os.Exit(1)
	}
	samlService := saml.NewService(pool, authService, cfg.AppBaseURL)

	// SAML IdP signing identity: configured RSA key+cert in prod, or an
	// ephemeral self-signed cert in dev when unset.
	samlIdPKeyPEM, samlIdPCertPEM := cfg.SAMLIdPKey, cfg.SAMLIdPCert
	if samlIdPKeyPEM == "" || samlIdPCertPEM == "" {
		if cfg.ServiceEnv != "dev" {
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

	ldapService := ldap.NewService(pool, authService)
	ipAllowService := ipallow.NewService(pool)

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
		User:          &user.Handler{Repo: userRepo, Validate: v, PasswordPolicy: authPolicyService.ValidateForTenant, MFA: mfaService},
		AuthPolicy:    &authpolicy.Handler{Service: authPolicyService},
		Auth:          &auth.Handler{Service: authService, Validate: v, CookieSecure: cfg.ServiceEnv != "dev", Bot: botService, GeoCountryHeader: cfg.GeoCountryHeader},
		RBAC:          &rbac.Handler{Repo: rbacRepo, Service: rbacService, Validate: v},
		RBACChecker:   rbacRepo,
		Verification:  &verification.Handler{Service: verifyService},
		Recovery:      &recovery.Handler{Service: recoveryService, AuthService: authService},
		Retention:     &retention.Handler{Service: retentionService},
		Invite:        &invite.Handler{Service: inviteService, AuthService: authService, Validate: v},
		Branding:      &branding.Handler{Repo: brandingRepo},
		EmailTemplate: &email.Handler{Service: emailTemplateService},
		APIKey:        &apikey.Handler{Service: apikeyService},
		APIKeyService: apikeyService,
		Principal:     &principal.Handler{Service: principalService},
		MFA:           &mfa.Handler{Service: mfaService, WebAuthn: passkeyService},
		Webhook:       &webhook.Handler{Service: webhookService},
		Policy:        &policy.Handler{Repo: policyRepo},
		GDPR:          &gdpr.Handler{Service: gdprService, Evidence: evidenceService},
		Audit:         &audit.Handler{Reader: auditReader, Verifier: auditVerifier},
		AuditAnomaly:  &anomaly.Handler{Service: auditAnomalyService},
		Billing:       &billing.Handler{Service: billingService},
		Analytics:     &analytics.Handler{Reader: analyticsReader},
		Outbox:        &outbox.Handler{Reader: outboxReader},
		OIDC:          &oidc.Handler{Service: oidcService, Sessions: authService, Providers: socialService, Registration: authPolicyService, DeviceTrust: authPolicyService, Branding: brandingRepo, LoginBaseURL: cfg.LoginBaseURL, CookieSecure: cfg.ServiceEnv != "dev"},
		Passkey:       &passkey.Handler{Service: passkeyService, CookieSecure: cfg.ServiceEnv != "dev"},
		Social:        &social.Handler{Service: socialService, CookieSecure: cfg.ServiceEnv != "dev", LoginBaseURL: cfg.LoginBaseURL},
		Group:         &group.Handler{Service: groupService},
		SCIM:          &scim.Handler{Service: scimService},
		Secret:        &secret.Handler{Service: secretService},
		TokenVault:    &tokenvault.Handler{Service: tokenVaultService},
		SAML:          &saml.Handler{Service: samlService, IdP: samlIdP, CookieSecure: cfg.ServiceEnv != "dev"},
		AdminPortal:   &adminportal.Handler{Service: adminPortalService, SAML: samlService, SCIM: scimService},
		LDAP:          &ldap.Handler{Service: ldapService},
		IPAllow:       &ipallow.Handler{Service: ipAllowService},
		Threat:        &threat.Handler{Service: threatService},
		Bot:           &bot.Handler{Service: botService},
		Risk:          &risk.Handler{Service: riskService},
		RateLimits:    rateLimitsHandler,
		Notification:  &notification.Handler{Service: notificationService},
		DomainVerify:  &domainverify.Handler{Service: domainverify.NewService(pool)},
		SIEM:          &siem.Handler{Service: siemService},
		AuthHook:      &authhook.Handler{Service: authHookService},
		ABAC:          &abac.Handler{Service: abacService},
		ReBAC:         &rebac.Handler{Service: rebacService},
		AuthZEN:       &authzen.Handler{Service: authzenService},
		Agent:         &agent.Handler{Service: agentService},
		VC:            &vc.Handler{Service: vcService},
		Copilot:       copilotHandler,
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
func secretsKeyProvider(ctx context.Context, cfg *config.Config) (secret.KeyProvider, error) {
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
