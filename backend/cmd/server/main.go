package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	stdhttp "net/http"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mattn/go-isatty"
	"github.com/redis/go-redis/v9"

	"github.com/qeetgroup/qeet-id/internal/analytics"
	"github.com/qeetgroup/qeet-id/internal/apikey"
	"github.com/qeetgroup/qeet-id/internal/audit"
	"github.com/qeetgroup/qeet-id/internal/auth"
	"github.com/qeetgroup/qeet-id/internal/authpolicy"
	"github.com/qeetgroup/qeet-id/internal/billing"
	"github.com/qeetgroup/qeet-id/internal/branding"
	"github.com/qeetgroup/qeet-id/internal/config"
	"github.com/qeetgroup/qeet-id/internal/emailtemplate"
	"github.com/qeetgroup/qeet-id/internal/gdpr"
	"github.com/qeetgroup/qeet-id/internal/group"
	httpapi "github.com/qeetgroup/qeet-id/internal/http"
	"github.com/qeetgroup/qeet-id/internal/invite"
	"github.com/qeetgroup/qeet-id/internal/ipallow"
	"github.com/qeetgroup/qeet-id/internal/ldap"
	"github.com/qeetgroup/qeet-id/internal/mfa"
	"github.com/qeetgroup/qeet-id/internal/oidc"
	"github.com/qeetgroup/qeet-id/internal/passkey"
	"github.com/qeetgroup/qeet-id/internal/platform/buildinfo"
	"github.com/qeetgroup/qeet-id/internal/platform/db"
	"github.com/qeetgroup/qeet-id/internal/platform/health"
	"github.com/qeetgroup/qeet-id/internal/platform/hibp"
	"github.com/qeetgroup/qeet-id/internal/platform/httpx"
	"github.com/qeetgroup/qeet-id/internal/platform/logger"
	"github.com/qeetgroup/qeet-id/internal/platform/metrics"
	"github.com/qeetgroup/qeet-id/internal/platform/notifier"
	"github.com/qeetgroup/qeet-id/internal/platform/outbox"
	"github.com/qeetgroup/qeet-id/internal/platform/ratelimit"
	"github.com/qeetgroup/qeet-id/internal/platform/tokens"
	"github.com/qeetgroup/qeet-id/internal/platform/tracing"
	"github.com/qeetgroup/qeet-id/internal/platform/worker"
	"github.com/qeetgroup/qeet-id/internal/policy"
	"github.com/qeetgroup/qeet-id/internal/principal"
	"github.com/qeetgroup/qeet-id/internal/rbac"
	"github.com/qeetgroup/qeet-id/internal/recovery"
	"github.com/qeetgroup/qeet-id/internal/retention"
	"github.com/qeetgroup/qeet-id/internal/saml"
	"github.com/qeetgroup/qeet-id/internal/scim"
	"github.com/qeetgroup/qeet-id/internal/secret"
	"github.com/qeetgroup/qeet-id/internal/social"
	"github.com/qeetgroup/qeet-id/internal/tenant"
	"github.com/qeetgroup/qeet-id/internal/user"
	"github.com/qeetgroup/qeet-id/internal/verification"
	"github.com/qeetgroup/qeet-id/internal/webhook"
)

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	// Production-safety gate: refuse to start with dev-only escape hatches or
	// insecure defaults (CSRF off, dev-trust headers, placeholder JWT_SECRET,
	// missing signing key, wildcard origins, localhost base URL) when not in
	// dev. Cheaper than discovering it after a bad deploy.
	if err := cfg.Validate(); err != nil {
		slog.Error("refusing to start: "+err.Error(), "service_env", cfg.ServiceEnv)
		os.Exit(1)
	}

	level := parseLogLevel(cfg.LogLevel)
	var handler slog.Handler
	if cfg.ServiceEnv != "prod" && isatty.IsTerminal(os.Stdout.Fd()) {
		handler = logger.NewJSONColorHandler(os.Stdout, &logger.Options{Level: level, TimeFormat: "15:04:05"})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	slog.SetDefault(slog.New(logger.NewRedactingHandler(handler)))

	bi := buildinfo.Get()
	slog.Info("starting", "service", cfg.ServiceName, "version", bi.Version, "commit", bi.Commit, "built", bi.Date, "go", bi.GoVersion)
	metrics.SetBuildInfo(bi.Version, bi.Commit, bi.GoVersion)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Distributed tracing. No-op (no exporter, no network) when
	// OTEL_EXPORTER_OTLP_ENDPOINT is unset — the common case in dev/CI.
	tracerShutdown, err := tracing.Init(rootCtx, cfg.TracingConfig())
	if err != nil {
		slog.Error("init tracing", "err", err)
		os.Exit(1)
	}
	if cfg.OTelEndpoint != "" {
		slog.Info("tracing enabled", "endpoint", cfg.OTelEndpoint, "sample_ratio", cfg.OTelSampleRatio)
	} else {
		slog.Info("tracing disabled (no-op): set OTEL_EXPORTER_OTLP_ENDPOINT to enable")
	}

	pool, err := db.NewPool(rootCtx, cfg.DBURL, cfg.DBMinConns, cfg.DBMaxConns)
	if err != nil {
		slog.Error("connect db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	deps, workers := buildDeps(rootCtx, cfg, pool)

	if cfg.CSRFDisabled {
		slog.Warn("CSRF protection is DISABLED (dev only) — set CSRF_DISABLED=false to re-enable")
	}

	router := httpapi.NewRouter(deps)

	sup := worker.New()
	for _, w := range workers {
		sup.Register(w.name, w.run)
	}
	waitWorkers := sup.Start(rootCtx)

	srv := &stdhttp.Server{
		Addr:         ":" + cfg.HTTPPort,
		Handler:      router,
		ReadTimeout:  cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout,
	}
	go func() {
		slog.Info("listening", "addr", srv.Addr, "service", cfg.ServiceName, "env", cfg.ServiceEnv)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, stdhttp.ErrServerClosed) {
			slog.Error("server error", "err", err)
			stop()
		}
	}()

	<-rootCtx.Done()
	shutdownStart := time.Now()
	inFlightAtSignal := deps.InFlight.Count()
	slog.Info("shutdown initiated", "in_flight", inFlightAtSignal)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("http shutdown", "err", err)
	}

	workerDone := make(chan struct{})
	go func() {
		waitWorkers()
		close(workerDone)
	}()
	select {
	case <-workerDone:
	case <-shutdownCtx.Done():
		slog.Warn("worker drain timed out", "in_flight", deps.InFlight.Count())
	}

	// Flush any buffered spans before exit. No-op when tracing is disabled.
	if err := tracerShutdown(shutdownCtx); err != nil {
		slog.Warn("tracing shutdown", "err", err)
	}

	dropped := deps.InFlight.Count()
	duration := time.Since(shutdownStart)
	slog.Info("shutdown complete",
		"duration_ms", duration.Milliseconds(),
		"in_flight_at_signal", inFlightAtSignal,
		"dropped_requests", dropped,
	)

	// Best-effort audit row summarising the shutdown. If the DB is already
	// unhealthy we log and exit cleanly anyway.
	auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer auditCancel()
	if tx, err := pool.Begin(auditCtx); err == nil {
		err := audit.Record(auditCtx, tx, audit.Event{
			ActorType:    "system",
			Action:       "system.shutdown",
			ResourceType: "system",
			Metadata: map[string]any{
				"service":             cfg.ServiceName,
				"env":                 cfg.ServiceEnv,
				"duration_ms":         duration.Milliseconds(),
				"in_flight_at_signal": inFlightAtSignal,
				"dropped_requests":    dropped,
			},
		})
		if err != nil {
			slog.Warn("audit shutdown", "err", err)
			_ = tx.Rollback(auditCtx)
		} else if err := tx.Commit(auditCtx); err != nil {
			slog.Warn("audit shutdown commit", "err", err)
		}
	} else {
		slog.Warn("audit shutdown begin tx", "err", err)
	}
}

type namedWorker struct {
	name string
	run  worker.Func
}

// buildDeps constructs every repository, service, and handler and returns the
// HTTP dependency set plus the background workers to supervise. Keeping all
// wiring here lets main() focus on process lifecycle.
func buildDeps(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool) (httpapi.Deps, []namedWorker) {
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
	if err := rbacRepo.SeedBuiltins(rootCtx); err != nil {
		slog.Warn("rbac seed", "err", err)
	}
	billingService := billing.NewService(pool)
	if err := billingService.SeedBuiltins(rootCtx); err != nil {
		slog.Warn("billing seed", "err", err)
	}
	brandingRepo := branding.NewRepository(pool)
	emailTemplateService := emailtemplate.NewService(pool)
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
	recoveryService := recovery.NewService(pool, sender, time.Hour, cfg.AppBaseURL)
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
		breachChecker := hibp.New(&stdhttp.Client{Timeout: 3 * time.Second}, cfg.BreachedPasswordAPIURL, cfg.BreachedPasswordMinCount)
		authPolicyService.SetBreachChecker(breachChecker) // user set-password (via ValidateForTenant)
		authService.SetBreachChecker(breachChecker)       // signup
		recoveryService.SetBreachChecker(breachChecker)   // password reset
		inviteService.SetBreachChecker(breachChecker)     // invite accept
		slog.Info("breached-password check enabled (HIBP k-anonymity; fail-open)", "min_count", cfg.BreachedPasswordMinCount)
	}
	apikeyService := apikey.NewService(pool)
	principalService := principal.NewService(pool, issuer)
	mfaService := mfa.NewService(pool, cfg.JWTIssuer, sender)
	webhookService := webhook.NewService(pool)
	gdprService := gdpr.NewService(pool, 30*24*time.Hour)
	auditReader := audit.NewReader(pool)
	auditVerifier := audit.NewVerifier(pool)
	analyticsReader := analytics.NewReader(pool)
	outboxReader := outbox.NewReader(pool)

	startedAt := time.Now()
	healthHandler := health.New(cfg.ServiceName, cfg.ServiceEnv, startedAt)
	healthHandler.AddReadiness("db", health.PingDB(pool))
	inFlight := httpx.NewInFlight()
	oidcService := oidc.NewService(pool, issuer)
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
	deps := httpapi.Deps{
		Tenant:        &tenant.Handler{Repo: tenantRepo, Validate: v, AuthService: authService},
		User:          &user.Handler{Repo: userRepo, Validate: v, PasswordPolicy: authPolicyService.ValidateForTenant},
		AuthPolicy:    &authpolicy.Handler{Service: authPolicyService},
		Auth:          &auth.Handler{Service: authService, Validate: v, CookieSecure: cfg.ServiceEnv != "dev"},
		RBAC:          &rbac.Handler{Repo: rbacRepo, Service: rbac.NewService(rbacRepo), Validate: v},
		Verification:  &verification.Handler{Service: verifyService},
		Recovery:      &recovery.Handler{Service: recoveryService, AuthService: authService},
		Retention:     &retention.Handler{Service: retentionService},
		Invite:        &invite.Handler{Service: inviteService, AuthService: authService, Validate: v},
		Branding:      &branding.Handler{Repo: brandingRepo},
		EmailTemplate: &emailtemplate.Handler{Service: emailTemplateService},
		APIKey:        &apikey.Handler{Service: apikeyService},
		APIKeyService: apikeyService,
		Principal:     &principal.Handler{Service: principalService},
		MFA:           &mfa.Handler{Service: mfaService, WebAuthn: passkeyService},
		Webhook:       &webhook.Handler{Service: webhookService},
		Policy:        &policy.Handler{Repo: policyRepo},
		GDPR:          &gdpr.Handler{Service: gdprService},
		Audit:         &audit.Handler{Reader: auditReader, Verifier: auditVerifier},
		Billing:       &billing.Handler{Service: billingService},
		Analytics:     &analytics.Handler{Reader: analyticsReader},
		Outbox:        &outbox.Handler{Reader: outboxReader},
		OIDC:          &oidc.Handler{Service: oidcService, Sessions: authService, Providers: socialService, LoginBaseURL: cfg.LoginBaseURL, CookieSecure: cfg.ServiceEnv != "dev"},
		Passkey:       &passkey.Handler{Service: passkeyService, CookieSecure: cfg.ServiceEnv != "dev"},
		Social:        &social.Handler{Service: socialService, CookieSecure: cfg.ServiceEnv != "dev"},
		Group:         &group.Handler{Service: groupService},
		SCIM:          &scim.Handler{Service: scimService},
		Secret:        &secret.Handler{Service: secretService},
		SAML:          &saml.Handler{Service: samlService, IdP: samlIdP, CookieSecure: cfg.ServiceEnv != "dev"},
		LDAP:          &ldap.Handler{Service: ldapService},
		IPAllow:       &ipallow.Handler{Service: ipAllowService},
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

	outboxDispatcher := outbox.NewDispatcher(pool, outbox.LogPublisher{}, 2*time.Second, 50)
	workers := []namedWorker{
		{name: "outbox", run: outboxDispatcher.Run},
		{name: "webhook", run: webhookService.RunDispatcher},
		{name: "gdpr", run: gdprService.Run},
		{name: "retention", run: retentionService.Run},
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
