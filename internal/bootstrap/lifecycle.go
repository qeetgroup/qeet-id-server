package bootstrap

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
)

// shutdownBudget is how a stop spends SHUTDOWN_TIMEOUT, phase by phase. Each
// phase ends at its deadline whatever is still running, so the whole stop fits
// the budget and the container's stop timeout need only exceed it.
type shutdownBudget struct {
	drainDelay time.Duration // readiness answers 503 while requests still arrive
	httpDrain  time.Duration // in-flight requests finish; any left are cut
	stop       time.Duration // workers, event connections and tracing stop together
	close      time.Duration // the shutdown audit row, then the database pool
}

// newShutdownBudget gives the drain delay first, a fifth of total to stopping,
// a tenth to closing and the rest to the HTTP drain: 5s, 9s, 4s and 2s at the
// defaults. config.Validate keeps the drain delay to at most half of total.
func newShutdownBudget(total, drainDelay time.Duration) shutdownBudget {
	b := shutdownBudget{drainDelay: drainDelay, stop: total / 5, close: total / 10}
	b.httpDrain = max(total-drainDelay-b.stop-b.close, 0)
	return b
}

func (b shutdownBudget) total() time.Duration {
	return b.drainDelay + b.httpDrain + b.stop + b.close
}

// shutdown is what a stopping server stops, in the order run stops it.
type shutdown struct {
	budget     shutdownBudget                        // how long each phase may take
	server     *http.Server                          // drained, then closed
	notReady   func()                                // readiness answers 503
	endStreams []func()                              // open event streams end
	stop       []func()                              // run together; each returns once its part has stopped
	flush      func(context.Context) error           // buffered trace spans are sent
	record     func(context.Context, shutdownReport) // the shutdown audit row
	closePool  func()                                // the database pool closes
	inFlight   func() int64                          // requests being served
}

// shutdownReport summarises a stop for its log line and audit row.
type shutdownReport struct {
	duration         time.Duration
	inFlightAtSignal int64
	dropped          int64 // requests still running when the HTTP drain ended
}

// run stops the server within its budget and reports how the stop went.
func (s shutdown) run() shutdownReport {
	start := time.Now()
	report := shutdownReport{inFlightAtSignal: s.inFlight()}
	slog.Info("shutdown initiated", "in_flight", report.inFlightAtSignal, "budget", s.budget.total().String())

	// Answer not ready first, so the load balancer stops sending requests before
	// the listener closes. An event stream never ends by itself, so it is told to
	// now rather than hold up the drain.
	s.notReady()
	for _, end := range s.endStreams {
		end()
	}
	if s.budget.drainDelay > 0 {
		slog.Info("draining: readiness answers 503", "for", s.budget.drainDelay)
		time.Sleep(s.budget.drainDelay)
	}

	deadline := start.Add(s.budget.drainDelay + s.budget.httpDrain)
	httpCtx, cancelHTTP := context.WithDeadline(context.Background(), deadline)
	err := s.server.Shutdown(httpCtx)
	cancelHTTP()
	if err != nil {
		// Cut what is left, so its handlers end and give back their connections.
		report.dropped = s.inFlight()
		slog.Warn("http drain timed out; closing the remaining connections", "in_flight", report.dropped)
		_ = s.server.Close()
	}

	deadline = deadline.Add(s.budget.stop)
	stopCtx, cancelStop := context.WithDeadline(context.Background(), deadline)
	defer cancelStop()
	var wg sync.WaitGroup
	for _, stop := range s.stop {
		wg.Go(stop)
	}
	wg.Go(func() {
		if err := s.flush(stopCtx); err != nil {
			slog.Warn("tracing shutdown", "err", err)
		}
	})
	if !within(deadline, wg.Wait) {
		slog.Warn("workers did not stop in time; leased jobs are picked up again")
	}

	report.duration = time.Since(start)
	recordCtx, cancelRecord := context.WithDeadline(context.Background(), deadline.Add(s.budget.close/2))
	s.record(recordCtx, report)
	cancelRecord()
	if !within(deadline.Add(s.budget.close), s.closePool) {
		slog.Warn("database pool close timed out")
	}
	slog.Info("shutdown complete",
		"duration_ms", time.Since(start).Milliseconds(),
		"in_flight_at_signal", report.inFlightAtSignal,
		"dropped_requests", report.dropped,
	)
	return report
}

// within runs fn and reports whether it returned by deadline. Past it, fn is
// left running and the process exits without waiting for it.
func within(deadline time.Time, fn func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

// gracefulShutdown stops the API within SHUTDOWN_TIMEOUT once rootCtx is
// cancelled (SIGINT/SIGTERM, or a fatal serve error via startHTTPServer's
// stop()). The workers began stopping with rootCtx; it waits for them after
// the HTTP drain.
func gracefulShutdown(
	srv *http.Server,
	deps Deps,
	waitWorkers func(),
	closeOutbox func() error,
	tracerShutdown func(context.Context) error,
	pool *pgxpool.Pool,
	cfg *config.Config,
) {
	shutdown{
		budget:     newShutdownBudget(cfg.ShutdownTimeout, cfg.ShutdownDrainDelay),
		server:     srv,
		notReady:   deps.Health.Drain,
		endStreams: deps.endStreams,
		stop: append([]func(){func() {
			waitWorkers()
			// Links already answered as sent finish storing and sending.
			if deps.Recovery != nil {
				deps.Recovery.Service.Wait()
			}
			_ = closeOutbox() // once the outbox worker, which publishes on it, has stopped
		}}, deps.shutdownHooks...),
		flush:     tracerShutdown,
		record:    func(ctx context.Context, r shutdownReport) { recordShutdown(ctx, pool, cfg, r) },
		closePool: pool.Close,
		inFlight:  deps.InFlight.Count,
	}.run()
}

// recordShutdown writes a best-effort audit row summarising the stop. If the
// database is already unhealthy it logs and the process exits cleanly anyway.
func recordShutdown(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, r shutdownReport) {
	if err := audit.RecordAlone(ctx, pool, audit.Actor{Type: "system"}.EventIn(nil, "system.shutdown", "system", uuid.Nil, map[string]any{
		"service":             cfg.ServiceName,
		"env":                 cfg.ServiceEnv,
		"duration_ms":         r.duration.Milliseconds(),
		"in_flight_at_signal": r.inFlightAtSignal,
		"dropped_requests":    r.dropped,
	})); err != nil {
		slog.Warn("audit shutdown", "err", err)
	}
}
