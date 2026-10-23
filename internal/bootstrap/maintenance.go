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
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/idempotency"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// AuditVerifyInterval is how often every audit chain is verified.
const AuditVerifyInterval = 6 * time.Hour

// MaintenanceJobs returns the scheduled housekeeping jobs. Each runs once per
// interval across all instances. Expired sessions the cleanup removes are
// announced through signals as session.revoked (reason expired).
func MaintenanceJobs(pool *pgxpool.Pool, signals *sessionsignal.Signaller) []worker.Scheduled {
	verifier := audit.NewVerifier(pool)
	return []worker.Scheduled{
		{
			Name:     "audit-chain-verify",
			Interval: AuditVerifyInterval,
			Run: func(ctx context.Context) error {
				run, err := verifier.VerifyAll(ctx)
				if err == nil {
					slog.Info("audit chains intact", "tenants", run.TenantsWalked, "rows_checked", run.RowsChecked)
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
				tag, err := pool.Exec(ctx,
					`DELETE FROM platform.outbox_dead_letter WHERE dead_lettered_at < now() - interval '30 days'`)
				if err != nil {
					return err
				}
				slog.Info("outbox DLQ cleaned", "deleted", tag.RowsAffected())
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
	}
}

// RegisterMaintenanceMetrics exposes when each scheduled job, and the audit
// verification, last succeeded (read from the database at scrape time, so it
// holds whichever instance ran them). Registering twice is a no-op.
func RegisterMaintenanceMetrics(pool *pgxpool.Pool) {
	for _, c := range []prometheus.Collector{worker.LastSuccessCollector(pool), audit.VerificationMetrics(pool)} {
		var dup prometheus.AlreadyRegisteredError
		if err := prometheus.Register(c); err != nil && !errors.As(err, &dup) {
			slog.Warn("register maintenance metrics", "err", err)
		}
	}
}
