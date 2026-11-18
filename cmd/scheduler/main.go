// Command scheduler runs the scheduled maintenance jobs standalone; the API normally runs them as its
// "scheduler" worker, and each job runs once per interval across all instances, so both are safe.
// Subcommands: replay-dead-letters [-type T] [-since RFC3339], mark-invoice-paid -invoice ID -reference
// REF, open-incident -component C -impact I -title T [-detail D], resolve-incident -incident ID.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
	"github.com/qeetgroup/qeet-id-server/internal/operations/servicehealth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

func main() {
	cfg := setUp()

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
	// migrated past this build, a half-applied migration, or a database built
	// from other migration files.
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
	if len(os.Args) > 1 && os.Args[1] == replayCommand {
		code := replayDeadLetters(rootCtx, pool, os.Args[2:])
		pool.Close()
		os.Exit(code)
	}
	if len(os.Args) > 1 && (os.Args[1] == openIncidentCommand || os.Args[1] == resolveIncidentCommand) {
		run := openIncident
		if os.Args[1] == resolveIncidentCommand {
			run = resolveIncident
		}
		code := run(rootCtx, servicehealth.NewIncidents(pool), os.Args[2:])
		pool.Close()
		os.Exit(code)
	}
	scheduler, err := bootstrap.NewScheduler(cfg, pool)
	if err != nil {
		slog.Error("start-up refused", "err", err)
		os.Exit(1)
	}
	if len(os.Args) > 1 && os.Args[1] == markPaidCommand {
		code := markInvoicePaid(rootCtx, scheduler.Billing, os.Args[2:])
		pool.Close()
		os.Exit(code)
	}
	jobs, err := scheduledJobs(rootCtx, cfg, pool, scheduler)
	if err != nil {
		slog.Error("start-up refused", "err", err)
		os.Exit(1)
	}
	for _, j := range jobs {
		slog.Info("job registered", "name", j.Name, "interval", j.Interval)
	}
	worker.RunScheduled(rootCtx, pool, jobs, worker.SchedulerTick)
	slog.Info("scheduler shutdown complete")
}

// scheduledJobs returns every job the scheduler runs, or the dependency a
// constructor refused. The webhook queue carries what the jobs announce: the
// sessions the cleanup removes (session.revoked, reason expired) and the roles
// the access-request sweep takes back.
func scheduledJobs(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool, s bootstrap.Scheduler) ([]worker.Scheduled, error) {
	queue := webhook.NewQueue(pool)
	signals := sessionsignal.New(queue.EnqueueTx)
	// The re-encryption job needs the same data keys as the API.
	box, err := bootstrap.SecretsCipher(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("init domain encryption: %w", err)
	}
	jobs, err := bootstrap.MaintenanceJobs(pool, signals, box, bootstrap.OutboundPolicy(cfg))
	if err != nil {
		return nil, err
	}
	accessRequests, err := bootstrap.SchedulerAccessRequests(pool, signals, s.Billing, queue.Enqueue, notification.NewService(pool))
	if err != nil {
		return nil, err
	}
	jobs = append(jobs, bootstrap.BillingJobs(s.Billing, s.Invoices)...)
	jobs = append(jobs, bootstrap.AccessRequestJobs(accessRequests)...)
	return append(jobs, bootstrap.AuditRetentionJobs(pool, s.Plans, box)...), nil
}

// setUp loads the configuration and installs the logger as the API does,
// exiting if either fails.
func setUp() *config.Config { return bootstrap.LoadConfig() }
