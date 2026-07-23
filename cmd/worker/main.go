// Command worker runs the Qeet ID background workers standalone. They normally
// run embedded in cmd/server; run this binary to scale workers independently
// (N worker replicas + M API replicas sharing one Postgres database).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/developer/webhooks"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/anomaly"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention"
	"github.com/qeetgroup/qeet-id-server/internal/operations/siem"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/jobs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/logging"
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
	slog.SetDefault(slog.New(logger.NewRedactingHandler(handler)))

	bi := buildinfo.Get()
	slog.Info("worker starting",
		"service", cfg.ServiceName+"-worker",
		"version", bi.Version,
		"commit", bi.Commit,
		"go", bi.GoVersion,
	)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	// Mirror the workers registered in cmd/server/main.go buildDeps().
	outboxDispatcher := outbox.NewDispatcher(pool, outboxPub, 2*time.Second, 50)
	webhookService := webhook.NewService(pool)
	gdprService := gdpr.NewService(pool, 30*24*time.Hour)
	retentionService := retention.NewService(pool)
	siemService := siem.NewService(pool)
	auditAnomalyService := anomaly.NewService(pool)

	sup := worker.New()
	sup.Register("outbox", outboxDispatcher.Run)
	sup.Register("webhook", webhookService.RunDispatcher)
	sup.Register("gdpr", gdprService.Run)
	sup.Register("retention", retentionService.Run)
	sup.Register("siem", siemService.Run)
	sup.Register("audit-anomaly", auditAnomalyService.Run)

	wait := sup.Start(rootCtx)

	<-rootCtx.Done()
	slog.Info("worker shutdown initiated")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() { wait(); close(done) }()

	select {
	case <-done:
		slog.Info("worker shutdown complete")
	case <-shutdownCtx.Done():
		slog.Warn("worker shutdown timed out — some jobs may be redelivered")
	}
}
