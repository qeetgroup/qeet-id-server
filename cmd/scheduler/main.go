// Command scheduler runs the Qeet ID scheduled maintenance jobs (audit-chain
// verification and the cleanups) standalone. The API normally runs them as
// its embedded "scheduler" worker; either way each job runs once per interval
// across every instance, so running this beside the API is safe.
//
// "scheduler replay-dead-letters [-type event.type] [-since RFC3339]" instead
// moves dead-lettered outbox events back to the outbox, to be published again,
// and exits. "scheduler mark-invoice-paid -invoice ID -reference REF" records
// an invoice paid outside a checkout, such as by bank transfer, and exits.
// "scheduler open-incident -component C -impact I -title T [-detail D]" and
// "scheduler resolve-incident -incident ID" post and end a service incident.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook"
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
		code := run(rootCtx, servicehealth.NewService(pool), os.Args[2:])
		pool.Close()
		os.Exit(code)
	}
	billingService := bootstrap.SchedulerBilling(cfg, pool)
	if len(os.Args) > 1 && os.Args[1] == markPaidCommand {
		code := markInvoicePaid(rootCtx, billingService, os.Args[2:])
		pool.Close()
		os.Exit(code)
	}
	// Sessions the cleanup removes that were never ended are announced
	// (session.revoked, reason expired) to the organizations' subscribers.
	sessionSignals := sessionsignal.New(webhook.NewService(pool).EnqueueTx)

	// The re-encryption job needs the same data keys as the API.
	box, err := bootstrap.SecretsCipher(rootCtx, cfg)
	if err != nil {
		slog.Error("init domain encryption", "err", err)
		os.Exit(1)
	}

	jobs := append(bootstrap.MaintenanceJobs(pool, sessionSignals, box, bootstrap.OutboundPolicy(cfg)), bootstrap.BillingJobs(billingService)...)
	jobs = append(jobs, bootstrap.AccessRequestJobs(bootstrap.SchedulerAccessRequests(pool))...)
	jobs = append(jobs, bootstrap.AuditRetentionJobs(pool, billingService, box)...)
	for _, j := range jobs {
		slog.Info("job registered", "name", j.Name, "interval", j.Interval)
	}
	worker.RunScheduled(rootCtx, pool, jobs, worker.SchedulerTick)
	slog.Info("scheduler shutdown complete")
}

// setUp loads the configuration and installs the logger as the API does,
// exiting if either fails.
func setUp() *config.Config { return bootstrap.LoadConfig() }
