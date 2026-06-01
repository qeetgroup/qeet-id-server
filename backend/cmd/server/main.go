package main

import (
	"context"
	"errors"
	"log/slog"
	stdhttp "net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mattn/go-isatty"

	"github.com/qeetgroup/qeet-identity/internal/analytics"
	"github.com/qeetgroup/qeet-identity/internal/apikey"
	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/auth"
	"github.com/qeetgroup/qeet-identity/internal/authpolicy"
	"github.com/qeetgroup/qeet-identity/internal/billing"
	"github.com/qeetgroup/qeet-identity/internal/branding"
	"github.com/qeetgroup/qeet-identity/internal/config"
	"github.com/qeetgroup/qeet-identity/internal/emailtemplate"
	"github.com/qeetgroup/qeet-identity/internal/gdpr"
	"github.com/qeetgroup/qeet-identity/internal/group"
	httpapi "github.com/qeetgroup/qeet-identity/internal/http"
	"github.com/qeetgroup/qeet-identity/internal/invite"
	"github.com/qeetgroup/qeet-identity/internal/ipallow"
	"github.com/qeetgroup/qeet-identity/internal/ldap"
	"github.com/qeetgroup/qeet-identity/internal/mfa"
	"github.com/qeetgroup/qeet-identity/internal/oidc"
	"github.com/qeetgroup/qeet-identity/internal/passkey"
	"github.com/qeetgroup/qeet-identity/internal/platform/db"
	"github.com/qeetgroup/qeet-identity/internal/platform/health"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
	"github.com/qeetgroup/qeet-identity/internal/platform/logger"
	"github.com/qeetgroup/qeet-identity/internal/platform/notifier"
	"github.com/qeetgroup/qeet-identity/internal/platform/outbox"
	"github.com/qeetgroup/qeet-identity/internal/platform/tokens"
	"github.com/qeetgroup/qeet-identity/internal/platform/worker"
	"github.com/qeetgroup/qeet-identity/internal/policy"
	"github.com/qeetgroup/qeet-identity/internal/principal"
	"github.com/qeetgroup/qeet-identity/internal/rbac"
	"github.com/qeetgroup/qeet-identity/internal/recovery"
	"github.com/qeetgroup/qeet-identity/internal/retention"
	"github.com/qeetgroup/qeet-identity/internal/saml"
	"github.com/qeetgroup/qeet-identity/internal/scim"
	"github.com/qeetgroup/qeet-identity/internal/social"
	"github.com/qeetgroup/qeet-identity/internal/tenant"
	"github.com/qeetgroup/qeet-identity/internal/user"
	"github.com/qeetgroup/qeet-identity/internal/verification"
	"github.com/qeetgroup/qeet-identity/internal/webhook"
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

	// Safety guard: CSRF_DISABLED is a dev convenience for Postman/curl
	// testing — it must never be honoured outside SERVICE_ENV=dev. Failing
	// loudly here is cheaper than discovering a production deploy has CSRF
	// off because someone copied a .env file.
	if cfg.CSRFDisabled && cfg.ServiceEnv != "dev" {
		slog.Error("CSRF_DISABLED is only permitted when SERVICE_ENV=dev — refusing to start",
			"service_env", cfg.ServiceEnv)
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

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
	issuer := tokens.NewIssuer(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
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

	sender := notifier.LogSender{}
	verifyService := verification.NewService(pool, sender, 10*time.Minute)
	recoveryService := recovery.NewService(pool, sender, time.Hour, cfg.AppBaseURL)
	retentionService := retention.NewService(pool)
	inviteService := invite.NewService(pool, sender, 14*24*time.Hour, cfg.AppBaseURL)
	authService := auth.NewService(pool, userRepo, issuer)
	authPolicyService := authpolicy.NewService(pool)
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
	samlService := saml.NewService(pool, authService, cfg.AppBaseURL)
	ldapService := ldap.NewService(pool, authService)
	ipAllowService := ipallow.NewService(pool)

	v := validator.New(validator.WithRequiredStructEnabled())
	deps := httpapi.Deps{
		Tenant:        &tenant.Handler{Repo: tenantRepo, Validate: v, AuthService: authService},
		User:          &user.Handler{Repo: userRepo, Validate: v, PasswordPolicy: authPolicyService.ValidateForTenant},
		AuthPolicy:    &authpolicy.Handler{Service: authPolicyService},
		Auth:          &auth.Handler{Service: authService, Validate: v},
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
		MFA:           &mfa.Handler{Service: mfaService},
		Webhook:       &webhook.Handler{Service: webhookService},
		Policy:        &policy.Handler{Repo: policyRepo},
		GDPR:          &gdpr.Handler{Service: gdprService},
		Audit:         &audit.Handler{Reader: auditReader, Verifier: auditVerifier},
		Billing:       &billing.Handler{Service: billingService},
		Analytics:     &analytics.Handler{Reader: analyticsReader},
		Outbox:        &outbox.Handler{Reader: outboxReader},
		OIDC:          &oidc.Handler{Service: oidcService},
		Passkey:       &passkey.Handler{Service: passkeyService},
		Social:        &social.Handler{Service: socialService},
		Group:         &group.Handler{Service: groupService},
		SCIM:          &scim.Handler{Service: scimService},
		SAML:          &saml.Handler{Service: samlService},
		LDAP:          &ldap.Handler{Service: ldapService},
		IPAllow:       &ipallow.Handler{Service: ipAllowService},
		Health:        healthHandler,
		InFlight:      inFlight,

		AuthVerifier:   verifier,
		AllowedOrigins: cfg.AllowedOrigins(),
		ServiceName:    cfg.ServiceName,
		ServiceEnv:     cfg.ServiceEnv,
		StartedAt:      startedAt,
		CSRFDisabled:   cfg.CSRFDisabled,
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
