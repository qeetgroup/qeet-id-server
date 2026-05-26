package main

import (
	"context"
	"errors"
	"log/slog"
	stdhttp "net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/mattn/go-isatty"

	"github.com/qeetgroup/qeet-identity/internal/apikey"
	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/auth"
	"github.com/qeetgroup/qeet-identity/internal/branding"
	"github.com/qeetgroup/qeet-identity/internal/config"
	"github.com/qeetgroup/qeet-identity/internal/gdpr"
	"github.com/qeetgroup/qeet-identity/internal/group"
	httpapi "github.com/qeetgroup/qeet-identity/internal/http"
	"github.com/qeetgroup/qeet-identity/internal/invite"
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
	"github.com/qeetgroup/qeet-identity/internal/policy"
	"github.com/qeetgroup/qeet-identity/internal/principal"
	"github.com/qeetgroup/qeet-identity/internal/rbac"
	"github.com/qeetgroup/qeet-identity/internal/recovery"
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
	brandingRepo := branding.NewRepository(pool)
	policyRepo := policy.NewRepository(pool)

	sender := notifier.LogSender{}
	verifyService := verification.NewService(pool, sender, 10*time.Minute)
	recoveryService := recovery.NewService(pool, sender, time.Hour, "http://localhost:3000")
	inviteService := invite.NewService(pool, sender, 14*24*time.Hour, "http://localhost:3000")
	authService := auth.NewService(pool, userRepo, issuer)
	apikeyService := apikey.NewService(pool)
	principalService := principal.NewService(pool, issuer)
	mfaService := mfa.NewService(pool, cfg.JWTIssuer)
	webhookService := webhook.NewService(pool)
	gdprService := gdpr.NewService(pool, 30*24*time.Hour)
	auditReader := audit.NewReader(pool)
	auditVerifier := audit.NewVerifier(pool)

	startedAt := time.Now()
	healthHandler := health.New(cfg.ServiceName, cfg.ServiceEnv, startedAt)
	healthHandler.AddReadiness("db", health.PingDB(pool))
	inFlight := httpx.NewInFlight()
	oidcService := oidc.NewService(pool, issuer)
	passkeyService := passkey.NewService(pool)
	socialService := social.NewService(pool)
	groupService := group.NewService(pool)

	v := validator.New(validator.WithRequiredStructEnabled())
	deps := httpapi.Deps{
		Tenant:        &tenant.Handler{Repo: tenantRepo, Validate: v},
		User:          &user.Handler{Repo: userRepo, Validate: v},
		Auth:          &auth.Handler{Service: authService, Validate: v},
		RBAC:          &rbac.Handler{Repo: rbacRepo, Validate: v},
		Verification:  &verification.Handler{Service: verifyService},
		Recovery:      &recovery.Handler{Service: recoveryService, AuthService: authService},
		Invite:        &invite.Handler{Service: inviteService, AuthService: authService, Validate: v},
		Branding:      &branding.Handler{Repo: brandingRepo},
		APIKey:        &apikey.Handler{Service: apikeyService},
		APIKeyService: apikeyService,
		Principal:     &principal.Handler{Service: principalService},
		MFA:           &mfa.Handler{Service: mfaService},
		Webhook:       &webhook.Handler{Service: webhookService},
		Policy:        &policy.Handler{Repo: policyRepo},
		GDPR:          &gdpr.Handler{Service: gdprService},
		Audit:         &audit.Handler{Reader: auditReader, Verifier: auditVerifier},
		OIDC:          &oidc.Handler{Service: oidcService},
		Passkey:       &passkey.Handler{Service: passkeyService},
		Social:        &social.Handler{Service: socialService},
		Group:         &group.Handler{Service: groupService},
		Health:        healthHandler,
		InFlight:      inFlight,

		AuthVerifier:   verifier,
		AllowedOrigins: cfg.AllowedOrigins(),
		ServiceName:    cfg.ServiceName,
		ServiceEnv:     cfg.ServiceEnv,
		StartedAt:      startedAt,
	}

	router := httpapi.NewRouter(deps)

	outboxDispatcher := outbox.NewDispatcher(pool, outbox.LogPublisher{}, 2*time.Second, 50)

	var workerWG sync.WaitGroup
	startWorker := func(name string, run func(context.Context)) {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			run(rootCtx)
			slog.Info("worker stopped", "name", name)
		}()
	}
	startWorker("outbox", outboxDispatcher.Run)
	startWorker("webhook", webhookService.RunDispatcher)
	startWorker("gdpr", gdprService.Run)

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
	inFlightAtSignal := inFlight.Count()
	slog.Info("shutdown initiated", "in_flight", inFlightAtSignal)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("http shutdown", "err", err)
	}

	workerDone := make(chan struct{})
	go func() {
		workerWG.Wait()
		close(workerDone)
	}()
	select {
	case <-workerDone:
	case <-shutdownCtx.Done():
		slog.Warn("worker drain timed out", "in_flight", inFlight.Count())
	}

	dropped := inFlight.Count()
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
