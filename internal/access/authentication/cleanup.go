package auth

import (
	"context"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
)

// SessionRetention is how long ended sessions are kept before the cleanup job
// deletes them: API and console sessions revoked (or whose refresh tokens all
// expired) longer ago than this, and hosted-login sessions expired longer ago.
const SessionRetention = 7 * 24 * time.Hour

// SessionsPurged counts what one cleanup run deleted.
type SessionsPurged struct {
	Sessions      int64
	LoginSessions int64
}

// PurgeEndedSessions deletes the sessions that are past retention (see
// SessionRetention) as of now. Live sessions — not revoked, with a refresh
// token still usable inside the window — and sessions ended inside the window
// are kept. A run with nothing to delete succeeds with zero counts.
func PurgeEndedSessions(ctx context.Context, db dbgen.DBTX, retention time.Duration) (SessionsPurged, error) {
	q := dbgen.New(db)
	cutoff := time.Now().UTC().Add(-retention)
	var out SessionsPurged
	var err error
	if out.Sessions, err = q.PurgeEndedSessions(ctx, cutoff); err != nil {
		return SessionsPurged{}, err
	}
	if out.LoginSessions, err = q.PurgeExpiredLoginSessions(ctx, cutoff); err != nil {
		return SessionsPurged{}, err
	}
	return out, nil
}
