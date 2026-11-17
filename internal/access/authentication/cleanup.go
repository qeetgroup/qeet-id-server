package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

// SessionRetention is how long ended sessions are kept before the cleanup job
// deletes them: API and console sessions revoked (or whose refresh tokens all
// expired) longer ago than this, and hosted-login sessions expired longer ago.
const SessionRetention = 7 * 24 * time.Hour

// SessionsPurged counts what one cleanup run deleted.
type SessionsPurged struct {
	Sessions      int64
	LoginSessions int64
	// Ceremonies are passkey ceremonies that expired unfinished.
	Ceremonies int64
	// TrustedDevices are remembered devices that expired.
	TrustedDevices int64
}

// PurgeEndedSessions deletes sessions past retention, keeping live sessions and
// those ended inside the window, in batches (postgres.DeleteInBatches).
// Sessions that simply expired are announced to subscribers as expired in the
// transaction of their batch; signals may be nil.
func PurgeEndedSessions(ctx context.Context, pool *pgxpool.Pool, retention time.Duration, signals *sessionsignal.Signaller) (SessionsPurged, error) {
	q := dbgen.New(pool)
	cutoff := time.Now().UTC().Add(-retention)
	var out SessionsPurged
	var err error
	if out.Sessions, err = postgres.DeleteInBatches(ctx, func(ctx context.Context, limit int32) (int64, error) {
		return purgeSessionBatch(ctx, pool, cutoff, limit, signals)
	}); err != nil {
		return out, err
	}
	if out.LoginSessions, err = postgres.DeleteInBatches(ctx, func(ctx context.Context, limit int32) (int64, error) {
		return q.PurgeExpiredLoginSessions(ctx, dbgen.PurgeExpiredLoginSessionsParams{Cutoff: cutoff, MaxRows: limit})
	}); err != nil {
		return out, err
	}
	if out.TrustedDevices, err = postgres.DeleteInBatches(ctx, func(ctx context.Context, limit int32) (int64, error) {
		return q.PurgeExpiredTrustedDevices(ctx, dbgen.PurgeExpiredTrustedDevicesParams{Cutoff: cutoff, MaxRows: limit})
	}); err != nil {
		return out, err
	}
	out.Ceremonies, err = postgres.DeleteInBatches(ctx, q.PurgeExpiredCeremonies)
	return out, err
}

// purgeSessionBatch deletes at most limit sessions past the cutoff and
// announces those that expired, in one transaction, and returns how many it
// deleted.
func purgeSessionBatch(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time, limit int32, signals *sessionsignal.Signaller) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := dbgen.New(tx).PurgeEndedSessions(ctx, dbgen.PurgeEndedSessionsParams{Cutoff: cutoff, MaxRows: limit})
	if err != nil {
		return 0, err
	}
	var expired []sessionsignal.Session
	for _, r := range rows {
		if !r.Expired {
			continue
		}
		sess := sessionsignal.Session{ID: r.ID, UserID: r.UserID}
		if r.OrganizationID.Valid {
			sess.OrganizationID = uuid.UUID(r.OrganizationID.Bytes)
		}
		expired = append(expired, sess)
	}
	signals.Revoked(ctx, tx, sessionsignal.ReasonExpired, expired...)
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int64(len(rows)), nil
}
