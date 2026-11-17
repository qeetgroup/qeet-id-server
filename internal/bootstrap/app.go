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
	"time"

	"github.com/mattn/go-isatty"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/logging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/metrics"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/tracing"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
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

// LoadConfig loads and validates the configuration and installs the logger
// it asks for (LOG_LEVEL, LOG_FORMAT), as every command does. It exits the
// process if either fails.
func LoadConfig() *config.Config {
	// JSON until the configuration chooses, so even a refusal to start is a
	// structured line.
	slog.SetDefault(slog.New(logging.NewRedactingHandler(slog.NewJSONHandler(os.Stdout, nil))))
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
		handler = logging.NewJSONColorHandler(os.Stdout, &logging.Options{Level: level, TimeFormat: "15:04:05"})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	slog.SetDefault(slog.New(logging.NewRedactingHandler(handler)))
	return cfg
}

// Run loads and validates the configuration, then runs the API server and its
// workers until shutdown. It exits the process if startup fails.
func Run() {
	cfg := LoadConfig()

	// Client IP resolution must be configured before the listener starts: it
	// keys the login rate limiter and every audit record.
	httpx.SetTrustedProxyHops(cfg.TrustedProxyHops)
	httpx.SetRelayKeys(cfg.RelayKeys()) // first-party relays may name the person's address
	httpx.SetGeoCountryHeader(cfg.GeoCountryHeader)
	httpx.SetGeoCityHeader(cfg.GeoCityHeader)
	password.Configure(password.Limits{
		Concurrency: cfg.PasswordHashConcurrency, Queue: cfg.PasswordHashQueue, MaxWait: cfg.PasswordHashMaxWait,
	})
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

	pool, err := postgres.NewPool(rootCtx, cfg.DBURL, cfg.DBMinConns, cfg.DBMaxConns)
	if err != nil {
		slog.Error("connect db", "err", err)
		os.Exit(1)
	}
	// Every platform audit chain gets a first row, so verification can tell a
	// chain whose rows were removed from one never written to. A failure here
	// is reported by the next verification, and retried at the next start.
	if err := audit.OpenPlatformChains(rootCtx, pool); err != nil {
		slog.Error("open the platform audit chains", "err", err)
	}

	// Outbox event publisher: NATS when NATS_URL is set, else log-only.
	outboxPub, closeOutboxPub, err := outbox.NewPublisher(cfg.NATSURL)
	if err != nil {
		slog.Error("outbox publisher", "err", err)
		os.Exit(1)
	}
	if cfg.NATSURL != "" {
		slog.Info("outbox publishing to NATS", "url", logging.StripURLCredentials(cfg.NATSURL))
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
	stop() // a second signal ends the process at once
	gracefulShutdown(srv, deps, waitWorkers, closeOutboxPub, tracerShutdown, pool, cfg)
}

// RunWorkers runs the background workers the API embeds, without the API, for
// a deployment that runs the API with EMBEDDED_WORKERS=false. The API runs the
// migrations; this refuses a schema it can't run on. It exits the process if
// startup fails.
func RunWorkers() {
	cfg := LoadConfig()
	bi := buildinfo.Get()
	slog.Info("worker starting", "service", cfg.ServiceName+"-worker", "version", bi.Version, "commit", bi.Commit, "go", bi.GoVersion)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if _, err := migrations.CheckCompatible(cfg.DBURL); err != nil {
		slog.Error("refusing to start: " + err.Error())
		os.Exit(1)
	}
	pool, err := postgres.NewPool(rootCtx, cfg.DBURL, cfg.DBMinConns, cfg.DBMaxConns)
	if err != nil {
		slog.Error("connect db", "err", err)
		os.Exit(1)
	}
	outboxPub, closeOutboxPub, err := outbox.NewPublisher(cfg.NATSURL)
	if err != nil {
		slog.Error("outbox publisher", "err", err)
		os.Exit(1)
	}

	// Only the API serves the live activity feed, so the workers' wiring leaves
	// out its NATS subscription; the outbox above still publishes to NATS.
	depsCfg := *cfg
	depsCfg.NATSURL = ""
	deps, workers := buildDeps(rootCtx, &depsCfg, pool, outboxPub)
	sup := worker.New()
	for _, w := range workers {
		sup.Register(w.name, w.run)
	}
	waitWorkers := sup.Start(rootCtx)

	<-rootCtx.Done()
	stop() // a second signal ends the process at once
	slog.Info("worker shutdown initiated")
	// The workers may take all of SHUTDOWN_TIMEOUT but the share kept for
	// closing the pool.
	end := time.Now().Add(cfg.ShutdownTimeout)
	if within(end.Add(-newShutdownBudget(cfg.ShutdownTimeout, 0).close), waitWorkers) {
		slog.Info("worker shutdown complete")
	} else {
		slog.Warn("worker drain timed out; leased jobs are picked up again")
	}
	for _, hook := range deps.shutdownHooks {
		hook()
	}
	_ = closeOutboxPub()
	if !within(end, pool.Close) {
		slog.Warn("database pool close timed out")
	}
}
