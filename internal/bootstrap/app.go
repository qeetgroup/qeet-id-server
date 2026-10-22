// Package bootstrap is the composition root: it loads configuration, wires every
// service, builds the HTTP router and runs the server and its background workers.
package bootstrap

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mattn/go-isatty"

	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
	db "github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	worker "github.com/qeetgroup/qeet-id-server/internal/platform/jobs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo"
	logger "github.com/qeetgroup/qeet-id-server/internal/platform/observability/logging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/metrics"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/tracing"
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

// Run loads and validates the configuration, then runs the API server and its
// workers until shutdown. It exits the process if startup fails.
func Run() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	// Production-safety gate: refuse to start when not in dev with dev-only escape
	// hatches or insecure defaults (CSRF off, dev-trust headers, placeholder
	// JWT_SECRET, missing signing key, wildcard origins, localhost base URL).
	if err := cfg.Validate(); err != nil {
		slog.Error("refusing to start: "+err.Error(), "service_env", cfg.ServiceEnv)
		os.Exit(1)
	}

	level := parseLogLevel(cfg.LogLevel)
	var handler slog.Handler
	useText := cfg.ServiceEnv != config.EnvProd && isatty.IsTerminal(os.Stdout.Fd())
	switch strings.ToLower(cfg.LogFormat) {
	case "json":
		useText = false
	case "text":
		useText = true
	}
	if useText {
		handler = logger.NewJSONColorHandler(os.Stdout, &logger.Options{Level: level, TimeFormat: "15:04:05"})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	slog.SetDefault(slog.New(logger.NewRedactingHandler(handler)))

	// Client IP resolution must be configured before the listener starts: it
	// keys the login rate limiter and every audit record.
	httpx.SetTrustedProxyHops(cfg.TrustedProxyHops)
	httpx.SetRelayKeys(cfg.RelayKeys()) // first-party relays may name the person's address
	httpx.SetGeoCountryHeader(cfg.GeoCountryHeader)
	if !cfg.IsDev() && cfg.TrustedProxyHops == 0 {
		slog.Warn("TRUSTED_PROXY_HOPS is 0: X-Forwarded-For is ignored and every " +
			"client IP will be the transport peer. Set it to the number of reverse " +
			"proxies in front of this server (1 for a single Caddy/nginx/ALB).")
	}

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

	// Run migrations before opening the runtime pool. A database a later
	// release migrated past this build is refused, unchanged, with the
	// recovery step (migrations.SchemaError).
	slog.Info("running database migrations")
	if err := migrations.Run(cfg.DBURL); err != nil {
		slog.Error("migrations failed", "err", err)
		os.Exit(1)
	}
	schema, err := migrations.Read(cfg.DBURL)
	if err != nil {
		slog.Error("read schema version", "err", err)
		os.Exit(1)
	}
	slog.Info("database schema", "migration", schema.Database, "latest", schema.Latest)

	pool, err := db.NewPool(rootCtx, cfg.DBURL, cfg.DBMinConns, cfg.DBMaxConns)
	if err != nil {
		slog.Error("connect db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Outbox event publisher: NATS when NATS_URL is set, else log-only.
	outboxPub, closeOutboxPub, err := outbox.NewPublisher(cfg.NATSURL)
	if err != nil {
		slog.Error("outbox publisher", "err", err)
		os.Exit(1)
	}
	defer func() { _ = closeOutboxPub() }()
	if cfg.NATSURL != "" {
		slog.Info("outbox publishing to NATS", "url", cfg.NATSURL)
	}

	deps, workers := buildDeps(rootCtx, cfg, pool, outboxPub)
	deps.Health.Schema = &schema

	if cfg.CSRFDisabled {
		slog.Warn("CSRF protection is DISABLED (dev only) — set CSRF_DISABLED=false to re-enable")
	}

	router := NewRouter(deps)

	sup := worker.New()
	for _, w := range workers {
		if cfg.EmbeddedWorkers || w.always {
			sup.Register(w.name, w.run)
		}
	}
	if !cfg.EmbeddedWorkers {
		slog.Info("embedded workers disabled; expecting standalone worker deployment")
	}
	waitWorkers := sup.Start(rootCtx)

	srv := startHTTPServer(cfg, router, stop)

	<-rootCtx.Done()
	gracefulShutdown(srv, deps, waitWorkers, tracerShutdown, pool, cfg)
}
