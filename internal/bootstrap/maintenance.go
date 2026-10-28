package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope/reseal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/idempotency"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// AuditVerifyInterval is how often every audit chain is verified.
const AuditVerifyInterval = 6 * time.Hour

// MaintenanceJobs returns the scheduled housekeeping jobs. Each runs once per
// interval across all instances. Expired sessions the cleanup removes are
// announced through signals as session.revoked (reason expired); stored values
// are re-sealed with box's current key. outbound, public addresses only if not
// given, bounds the jobs that fetch from the web.
func MaintenanceJobs(pool *pgxpool.Pool, signals *sessionsignal.Signaller, box *envelope.Cipher, outbound ...*egress.Policy) []worker.Scheduled {
	verifier := audit.NewVerifier(pool)
	return []worker.Scheduled{
		{
			// A connection backed by its IdP's metadata URL picks up the IdP's
			// new signing certificates.
			Name:     "saml-metadata-refresh",
			Interval: saml.MetadataRefreshInterval,
			Run: func(ctx context.Context) error {
				run, err := saml.RefreshMetadata(ctx, pool, egress.PublicPolicy(outbound...))
				if run.Refreshed+run.Failed > 0 {
					slog.Info("saml metadata refreshed", "refreshed", run.Refreshed, "failed", run.Failed)
				}
				return err
			},
		},
		{
			Name:     "audit-chain-verify",
			Interval: AuditVerifyInterval,
			Run: func(ctx context.Context) error {
				run, err := verifier.VerifyAll(ctx)
				if err == nil {
					slog.Info("audit chains intact", "scope", run.Scope, "tenants", run.TenantsWalked, "rows_checked", run.RowsChecked)
				}
				return err
			},
		},
		{
			Name:     "session-expiry-cleanup",
			Interval: 15 * time.Minute,
			Run: func(ctx context.Context) error {
				purged, err := auth.PurgeEndedSessions(ctx, pool, auth.SessionRetention, signals)
				if err != nil {
					return err
				}
				slog.Info("sessions cleaned", "sessions", purged.Sessions, "login_sessions", purged.LoginSessions,
					"ceremonies", purged.Ceremonies, "trusted_devices", purged.TrustedDevices)
				return nil
			},
		},
		{
			// An organisation whose scheduled deletion is due is deleted.
			Name:     "tenant-deletions",
			Interval: 15 * time.Minute,
			Run: func(ctx context.Context) error {
				n, err := tenant.DeleteDue(postgres.AcrossTenants(ctx), tenant.NewRepository(pool), signals)
				if n > 0 {
					slog.Info("organisations deleted as scheduled", "deleted", n)
				}
				return err
			},
		},
		{
			// A rotation's kept pair is needed only for the refresh reuse grace.
			Name:     "refresh-retry-cleanup",
			Interval: 5 * time.Minute,
			Run: func(ctx context.Context) error {
				n, err := auth.ClearRefreshRetries(ctx, pool)
				if err != nil {
					return err
				}
				slog.Info("kept refresh rotations cleared", "cleared", n)
				return nil
			},
		},
		{
			Name:     "mfa-cleanup",
			Interval: time.Hour,
			Run: func(ctx context.Context) error {
				codes, err := mfa.PurgeExpiredOTPCodes(ctx, pool, mfa.OTPCodeRetention)
				if err != nil {
					return err
				}
				push, err := mfa.PurgeExpiredPushChallenges(ctx, pool, mfa.OTPCodeRetention)
				if err != nil {
					return err
				}
				pairings, err := mfa.PurgeExpiredPushPairings(ctx, pool, mfa.OTPCodeRetention)
				if err != nil {
					return err
				}
				slog.Info("expired MFA codes and push requests cleaned", "codes", codes, "push_requests", push,
					"pairing_codes", pairings)
				return nil
			},
		},
		{
			// A SAML test sign-in holds what the IdP asserted about a person.
			Name:     "saml-test-sign-in-cleanup",
			Interval: 15 * time.Minute,
			Run: func(ctx context.Context) error {
				n, err := saml.PurgeTestSignIns(ctx, pool, saml.TestSignInRetention)
				if err != nil {
					return err
				}
				slog.Info("SAML test sign-ins cleaned", "deleted", n)
				return nil
			},
		},
		{
			Name:     "sign-in-history-cleanup",
			Interval: 24 * time.Hour,
			Run: func(ctx context.Context) error {
				n, err := risk.PurgeSignInHistory(ctx, pool, risk.SignInHistoryRetention)
				if err != nil {
					return err
				}
				slog.Info("sign-in history cleaned", "deleted", n)
				return nil
			},
		},
		{
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
		},
		{
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
		},
		{
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
		},
		{
			// Spent sign-in links, codes and requests, and stale failure counters
			// (retention.SignInSweeps).
			Name:     "sign-in-state-cleanup",
			Interval: time.Hour,
			Run: func(ctx context.Context) error {
				return runSweeps(ctx, pool, "sign-in state cleaned", retention.SignInSweeps)
			},
		},
		{
			// Deliveries, detections, events, notifications, invitations and
			// application grants past their use (retention.RecordSweeps).
			Name:     "record-cleanup",
			Interval: 24 * time.Hour,
			Run: func(ctx context.Context) error {
				return runSweeps(ctx, pool, "records cleaned", retention.RecordSweeps)
			},
		},
		{
			// A built data export is downloadable for a week; then its payload,
			// a full copy of the person's data, is deleted.
			Name:     "gdpr-export-expiry",
			Interval: time.Hour,
			Run: func(ctx context.Context) error {
				n, err := gdpr.ExpireExports(ctx, pool, gdpr.ExportRetention)
				if err != nil {
					return err
				}
				slog.Info("data export payloads deleted", "expired", n)
				return nil
			},
		},
		{
			// Delivery records answer "did that invitation arrive?"; after 90
			// days they answer nothing. Suppressions are kept.
			Name:     "email-delivery-cleanup",
			Interval: 24 * time.Hour,
			Run: func(ctx context.Context) error {
				n, err := delivery.NewStore(pool).DeleteBefore(ctx, time.Now().Add(-delivery.Retention))
				if err != nil {
					return err
				}
				slog.Info("email delivery records cleaned", "deleted", n)
				return nil
			},
		},
		{
			// Values sealed with a previous data key, or before values named
			// their key, are sealed again with the current one.
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
		},
	}
}

// runSweeps runs the retention sweeps across every organisation and logs what
// each deleted as msg.
func runSweeps(ctx context.Context, pool *pgxpool.Pool, msg string, sweeps []retention.Sweep) error {
	deleted, err := retention.RunSweeps(postgres.AcrossTenants(ctx), pool, sweeps)
	attrs := make([]any, 0, 2*len(deleted))
	for _, s := range sweeps {
		attrs = append(attrs, s.Name, deleted[s.Name])
	}
	slog.Info(msg, attrs...)
	return err
}

// RegisterMaintenanceMetrics exposes when each scheduled job, and the audit
// verification, last succeeded (read from the database at scrape time, so it
// holds whichever instance ran them), the outbox backlog, the stored values
// not yet on box's current key and this instance's connection pool.
// Registering twice is a no-op.
func RegisterMaintenanceMetrics(pool *pgxpool.Pool, box *envelope.Cipher) {
	for _, c := range []prometheus.Collector{
		worker.LastSuccessCollector(pool), audit.VerificationMetrics(pool),
		outbox.LagCollector(pool), postgres.PoolCollector(pool),
		reseal.Collector(pool, box, EncryptedColumns()),
	} {
		var dup prometheus.AlreadyRegisteredError
		if err := prometheus.Register(c); err != nil && !errors.As(err, &dup) {
			slog.Warn("register maintenance metrics", "err", err)
		}
	}
}
