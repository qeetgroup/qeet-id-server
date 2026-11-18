package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope/reseal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/idempotency"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// AuditVerifyInterval is how often every audit chain is verified.
const AuditVerifyInterval = 6 * time.Hour

// MaintenanceJobs returns the scheduled housekeeping jobs, each run once per interval across all
// instances. Cleanups announce what they end through signals; stored values are re-sealed with box's
// current key, which also signs audit checkpoints; outbound (public addresses only by default) bounds
// the jobs that fetch from the web.
func MaintenanceJobs(pool *pgxpool.Pool, signals *sessionsignal.Signaller, box *envelope.Cipher, outbound ...*egress.Policy) ([]worker.Scheduled, error) {
	purges, err := gdpr.NewService(pool, 0, signals)
	if err != nil {
		return nil, fmt.Errorf("organization purges: %w", err)
	}
	return []worker.Scheduled{
		samlMetadataRefreshJob(pool, outbound),
		auditChainVerifyJob(audit.NewVerifier(pool, box)),
		sessionExpiryCleanupJob(pool, signals),
		organizationDeletionsJob(pool, signals),
		refreshRetryCleanupJob(pool),
		mfaCleanupJob(pool),
		samlTestSignInCleanupJob(pool),
		signInHistoryCleanupJob(pool),
		outboxCleanupJob(pool),
		idempotencyCleanupJob(pool),
		outboxDLQCleanupJob(pool),
		signInStateCleanupJob(pool),
		recordCleanupJob(pool),
		organizationPurgesJob(purges),
		qeetaiConversationRetentionJob(pool),
		gdprExportExpiryJob(pool),
		emailDeliveryCleanupJob(pool),
		secretsReencryptJob(pool, box),
	}, nil
}

// outboxCleanupJob removes published outbox events past their retention.
func outboxCleanupJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "outbox-cleanup",
		Interval: time.Hour,
		Run: func(ctx context.Context) error {
			n, err := outbox.PurgePublished(ctx, pool, outbox.PublishedRetention)
			if err != nil {
				return err
			}
			slog.Info("published outbox events cleaned", "deleted", n)
			return nil
		},
	}
}

// idempotencyCleanupJob removes expired idempotency keys and their answers.
func idempotencyCleanupJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "idempotency-cleanup",
		Interval: time.Hour,
		Run: func(ctx context.Context) error {
			n, err := idempotency.Purge(ctx, pool)
			if err != nil {
				return err
			}
			slog.Info("idempotency keys cleaned", "deleted", n)
			return nil
		},
	}
}

// outboxDLQCleanupJob removes dead-lettered outbox events past their
// retention.
func outboxDLQCleanupJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "outbox-dlq-cleanup",
		Interval: time.Hour,
		Run: func(ctx context.Context) error {
			n, err := outbox.PurgeDeadLetters(ctx, pool, outbox.DeadLetterRetention)
			if err != nil {
				return err
			}
			slog.Info("outbox DLQ cleaned", "deleted", n)
			return nil
		},
	}
}

// secretsReencryptJob seals again with box's current key the values sealed
// with a previous data key, or before values named their key.
func secretsReencryptJob(pool *pgxpool.Pool, box *envelope.Cipher) worker.Scheduled {
	return worker.Scheduled{
		Name:     "secrets-reencrypt",
		Interval: 15 * time.Minute,
		Run: func(ctx context.Context) error {
			run, err := reseal.Run(ctx, pool, box, EncryptedColumns(), ReencryptBatch, ReencryptBudget)
			if err != nil {
				return err
			}
			if run.Resealed > 0 || run.Unreadable > 0 || !run.Finished {
				slog.Info("stored values re-encrypted", "resealed", run.Resealed, "unreadable", run.Unreadable,
					"finished", run.Finished)
			}
			return nil
		},
	}
}

// AuditRetentionInterval is how often audit events past their organization's
// plan's retention are deleted.
const AuditRetentionInterval = 24 * time.Hour

// AuditRetentionJobs returns the job that deletes each organization's audit
// events older than plans lets it keep them (audit_retention_days). box signs
// the chains' purge checkpoints.
func AuditRetentionJobs(pool *pgxpool.Pool, plans entitlements.PlanLimiter, box *envelope.Cipher) []worker.Scheduled {
	return []worker.Scheduled{{
		Name:     "audit-retention",
		Interval: AuditRetentionInterval,
		Run: func(ctx context.Context) error {
			n, err := audit.PurgeExpired(ctx, pool, box, func(ctx context.Context, organizationID uuid.UUID) (int, error) {
				return plans.Limit(ctx, organizationID, entitlements.LimitAuditRetentionDays)
			})
			if n > 0 {
				slog.Info("audit events past their plan's retention deleted", "deleted", n)
			}
			return err
		},
	}}
}

// runSweeps runs the retention sweeps across every organization and logs what
// each deleted as msg.
func runSweeps(ctx context.Context, pool *pgxpool.Pool, msg string, sweeps []retention.Sweep) error {
	deleted, err := retention.RunSweeps(postgres.AcrossOrganizations(ctx), pool, sweeps)
	attrs := make([]any, 0, 2*len(deleted))
	for _, s := range sweeps {
		attrs = append(attrs, s.Name, deleted[s.Name])
	}
	slog.Info(msg, attrs...)
	return err
}

// RegisterMaintenanceMetrics exposes each job's and the audit verification's last success (read from
// the database at scrape time, so any instance's run counts), the outbox backlog, the values not yet
// on box's current key and this instance's pool. Registering twice is a no-op.
func RegisterMaintenanceMetrics(pool *pgxpool.Pool, box *envelope.Cipher) {
	for _, c := range []prometheus.Collector{
		worker.LastSuccessCollector(pool), audit.VerificationMetrics(pool),
		outbox.LagCollector(pool), postgres.PoolCollector(pool), webhook.BacklogCollector(pool),
		reseal.Collector(pool, box, EncryptedColumns()),
	} {
		var dup prometheus.AlreadyRegisteredError
		if err := prometheus.Register(c); err != nil && !errors.As(err, &dup) {
			slog.Warn("register maintenance metrics", "err", err)
		}
	}
}
