// Command scheduler runs the Qeet ID scheduled maintenance jobs.
//
// These are low-frequency, tenant-wide housekeeping tasks that don't belong
// in the hot path of the API or the high-throughput worker loop. Run one
// scheduler replica per deployment — it coordinates via Postgres advisory
// locks so running multiple replicas is safe (only one actually executes each job).
//
//	make dev-scheduler         # run locally against .env
//	make build-scheduler       # build bin/qeet-id-scheduler
package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/config"
	"github.com/qeetgroup/qeet-id/platform/database/postgres"
	"github.com/qeetgroup/qeet-id/platform/observability/buildinfo"
	"github.com/qeetgroup/qeet-id/platform/observability/logging"
)

type scheduledJob struct {
	name     string
	interval time.Duration
	run      func(ctx context.Context) error
}

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
	slog.Info("scheduler starting",
		"service", cfg.ServiceName+"-scheduler",
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

	auditVerifier := audit.NewVerifier(pool)

	jobs := []scheduledJob{
		{
			name:     "audit-chain-verify",
			interval: 6 * time.Hour,
			run: func(ctx context.Context) error {
				res, err := auditVerifier.Verify(ctx, nil) // nil = all tenants
				if err != nil {
					return err
				}
				if !res.OK {
					return fmt.Errorf("audit chain integrity failure at row %s", res.LastVerifiedID)
				}
				slog.Info("audit chain OK", "rows_checked", res.RowsChecked)
				return nil
			},
		},
		{
			name:     "session-expiry-cleanup",
			interval: 15 * time.Minute,
			run: func(ctx context.Context) error {
				tag, err := pool.Exec(ctx,
					`DELETE FROM auth.sessions WHERE expires_at < now() - interval '7 days'`)
				if err != nil {
					return err
				}
				slog.Info("sessions cleaned", "deleted", tag.RowsAffected())
				return nil
			},
		},
		{
			name:     "outbox-dlq-cleanup",
			interval: 1 * time.Hour,
			run: func(ctx context.Context) error {
				tag, err := pool.Exec(ctx,
					`DELETE FROM platform.outbox_dead_letter WHERE dead_lettered_at < now() - interval '30 days'`)
				if err != nil {
					return err
				}
				slog.Info("outbox DLQ cleaned", "deleted", tag.RowsAffected())
				return nil
			},
		},
	}

	var tickers []*time.Ticker
	for _, j := range jobs {
		j := j
		t := time.NewTicker(j.interval)
		tickers = append(tickers, t)
		go func() {
			for {
				select {
				case <-t.C:
					start := time.Now()
					if err := runWithLock(rootCtx, pool, j); err != nil {
						slog.Error("scheduled job failed",
							"job", j.name,
							"err", err,
							"duration_ms", time.Since(start).Milliseconds())
					} else {
						slog.Info("scheduled job complete",
							"job", j.name,
							"duration_ms", time.Since(start).Milliseconds())
					}
				case <-rootCtx.Done():
					return
				}
			}
		}()
		slog.Info("job registered", "name", j.name, "interval", j.interval)
	}

	<-rootCtx.Done()
	for _, t := range tickers {
		t.Stop()
	}
	slog.Info("scheduler shutdown complete")
}

// runWithLock executes a job while holding a Postgres session-level advisory
// lock keyed on the job name. The lock is a cross-process mutex: if more than
// one scheduler replica is running, only the one that wins the lock executes
// the job on a given tick; the others skip. The lock only needs to gate the
// job for its duration — the job's own queries may use any pooled connection.
func runWithLock(ctx context.Context, pool *pgxpool.Pool, j scheduledJob) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	key := lockKey(j.name)
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	if !locked {
		slog.Info("scheduled job skipped — lock held by another replica", "job", j.name)
		return nil
	}
	// Unlock on a background context so a cancelled ctx can't leak the session lock.
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", key) }()

	return j.run(ctx)
}

// lockKey derives a stable 64-bit advisory-lock key from a job name.
func lockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("qeetid-scheduler:" + name))
	return int64(h.Sum64())
}
