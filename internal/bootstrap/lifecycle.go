package bootstrap

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
)

// Shutdown phase budgets. These are spent sequentially, so the worst-case
// shutdown is their sum — keep that under the orchestrator's termination grace
// period (Kubernetes terminationGracePeriodSeconds, ECS stopTimeout).
const (
	httpDrainTimeout   = 15 * time.Second
	workerDrainTimeout = 15 * time.Second
	traceFlushTimeout  = 5 * time.Second
)

// gracefulShutdown drains in-flight HTTP requests and background workers within
// a bounded window, flushes tracing, and writes a best-effort shutdown audit
// row. It runs once rootCtx is cancelled (SIGINT/SIGTERM, or a fatal serve
// error via startHTTPServer's stop()).
func gracefulShutdown(
	srv *http.Server,
	deps Deps,
	waitWorkers func(),
	tracerShutdown func(context.Context) error,
	pool *pgxpool.Pool,
	cfg *config.Config,
) {
	shutdownStart := time.Now()
	inFlightAtSignal := deps.InFlight.Count()
	slog.Info("shutdown initiated", "in_flight", inFlightAtSignal)

	// Each phase gets its own timeout, so a slow HTTP drain can't use up the time
	// for the worker drain and the tracer flush.
	httpCtx, cancelHTTP := context.WithTimeout(context.Background(), httpDrainTimeout)
	defer cancelHTTP()
	if err := srv.Shutdown(httpCtx); err != nil {
		slog.Error("http shutdown", "err", err)
	}
	for _, hook := range deps.shutdownHooks {
		hook()
	}

	workerCtx, cancelWorkers := context.WithTimeout(context.Background(), workerDrainTimeout)
	defer cancelWorkers()
	workerDone := make(chan struct{})
	go func() {
		waitWorkers()
		// Links already answered as sent finish storing and sending.
		if deps.Recovery != nil {
			deps.Recovery.Service.Wait()
		}
		close(workerDone)
	}()
	select {
	case <-workerDone:
	case <-workerCtx.Done():
		slog.Warn("worker drain timed out", "in_flight", deps.InFlight.Count())
	}

	// Flush any buffered spans before exit. No-op when tracing is disabled.
	traceCtx, cancelTrace := context.WithTimeout(context.Background(), traceFlushTimeout)
	defer cancelTrace()
	if err := tracerShutdown(traceCtx); err != nil {
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
