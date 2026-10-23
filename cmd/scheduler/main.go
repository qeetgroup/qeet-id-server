// Command scheduler runs the Qeet ID scheduled maintenance jobs (audit-chain
// verification and the cleanups) standalone. The API normally runs them as
// its embedded "scheduler" worker; either way each job runs once per interval
// across every instance, so running this beside the API is safe.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	webhook "github.com/qeetgroup/qeet-id-server/internal/developer/webhooks"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/logging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("refusing to start: "+err.Error(), "service_env", cfg.ServiceEnv)
		os.Exit(1)
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(logging.NewRedactingHandler(handler)))

	bi := buildinfo.Get()
	slog.Info("scheduler starting",
		"service", cfg.ServiceName+"-scheduler",
		"version", bi.Version,
		"commit", bi.Commit,
		"go", bi.GoVersion,
	)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The API migrates; this only refuses a database a later release has
	// migrated past this build, or a half-applied migration.
	if _, err := migrations.CheckCompatible(cfg.DBURL); err != nil {
		slog.Error("refusing to start: " + err.Error())
		os.Exit(1)
	}
	pool, err := postgres.NewPool(rootCtx, cfg.DBURL, cfg.DBMinConns, cfg.DBMaxConns)
	if err != nil {
		slog.Error("connect db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	// Sessions the cleanup removes that were never ended are announced
	// (session.revoked, reason expired) to the organisations' subscribers.
	sessionSignals := sessionsignal.New(webhook.NewService(pool).EnqueueTx)

	jobs := bootstrap.MaintenanceJobs(pool, sessionSignals)
	for _, j := range jobs {
		slog.Info("job registered", "name", j.Name, "interval", j.Interval)
	}
	worker.RunScheduled(rootCtx, pool, jobs, worker.SchedulerTick)
	slog.Info("scheduler shutdown complete")
}
