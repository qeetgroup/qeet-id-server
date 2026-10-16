package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
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
}

// PurgeEndedSessions deletes the sessions that are past retention (see
// SessionRetention) as of now. Live sessions — not revoked, with a refresh
// token still usable inside the window — and sessions ended inside the window
// are kept. A run with nothing to delete succeeds with zero counts. Sessions
// that were never ended (every refresh token expired) are announced to
// subscribers as expired, in the same transaction (signals may be nil).
func PurgeEndedSessions(ctx context.Context, pool *pgxpool.Pool, retention time.Duration, signals *sessionsignal.Signaller) (SessionsPurged, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return SessionsPurged{}, err
	}
	defer tx.Rollback(ctx)
	q := dbgen.New(tx)
	cutoff := time.Now().UTC().Add(-retention)
	rows, err := q.PurgeEndedSessions(ctx, cutoff)
	if err != nil {
		return SessionsPurged{}, err
	}
	var expired []sessionsignal.Session
	for _, r := range rows {
		if !r.Expired {
			continue
		}
		sess := sessionsignal.Session{ID: r.ID, UserID: r.UserID}
		if r.TenantID.Valid {
			sess.TenantID = uuid.UUID(r.TenantID.Bytes)
		}
		expired = append(expired, sess)
	}
	signals.Revoked(ctx, tx, sessionsignal.ReasonExpired, expired...)
	out := SessionsPurged{Sessions: int64(len(rows))}
	if out.LoginSessions, err = q.PurgeExpiredLoginSessions(ctx, cutoff); err != nil {
		return SessionsPurged{}, err
	}
	if out.Ceremonies, err = q.PurgeExpiredCeremonies(ctx); err != nil {
		return SessionsPurged{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SessionsPurged{}, err
	}
	return out, nil
}
