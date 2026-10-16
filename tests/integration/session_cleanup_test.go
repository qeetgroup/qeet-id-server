//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

// The scheduled session cleanup deletes the sessions that are past retention
// — ended longer ago than the window, or whose refresh tokens all expired
// longer ago — and the hosted-login sessions that expired longer ago, and
// keeps everything else. It runs against the fully migrated schema these
// tests use.

// sessionAt opens an API session for userID and backdates it: opened at
// opened, ended at revoked (nil: never), and every refresh token expiring at
// expires. Its maximum age and idle timeout are set far enough out not to
// matter (see boundedSession for sessions that reach them).
func sessionAt(t *testing.T, ctx context.Context, svc *auth.Service, userID uuid.UUID, opened time.Time, revoked *time.Time, expires time.Time) uuid.UUID {
	t.Helper()
	pair, err := svc.IssuePair(ctx, userID, uuid.Nil, "198.51.100.7", "cleanup", "password")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE auth.sessions SET created_at = $2, last_seen_at = $2, revoked_at = $3,
		expires_at = NOW() + INTERVAL '365 days', idle_timeout = INTERVAL '365 days' WHERE id = $1`,
		pair.SessionID, opened, revoked); err != nil {
		t.Fatalf("backdate session: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE auth.refresh_tokens SET issued_at = $2, expires_at = $3 WHERE session_id = $1`,
		pair.SessionID, opened, expires); err != nil {
		t.Fatalf("backdate refresh token: %v", err)
	}
	return pair.SessionID
}

// boundedSession opens an API session for userID that was opened 40 days ago,
// last renewed at lastSeen with a one-day idle timeout, and ends however
// active at maxAge; its refresh token stays usable for 20 more days, so only
// the session's own bounds can have ended it.
func boundedSession(t *testing.T, ctx context.Context, svc *auth.Service, userID uuid.UUID, lastSeen, maxAge time.Time) uuid.UUID {
	t.Helper()
	opened := time.Now().UTC().Add(-40 * 24 * time.Hour)
	id := sessionAt(t, ctx, svc, userID, opened, nil, time.Now().UTC().Add(20*24*time.Hour))
	if _, err := testPool.Exec(ctx, `UPDATE auth.sessions SET last_seen_at = $2, expires_at = $3, idle_timeout = INTERVAL '1 day' WHERE id = $1`,
		id, lastSeen, maxAge); err != nil {
		t.Fatalf("bound session: %v", err)
	}
	return id
}

// loginSessionExpiring opens a hosted-login session for userID expiring at exp.
func loginSessionExpiring(t *testing.T, ctx context.Context, svc *auth.Service, userID uuid.UUID, exp time.Time) string {
	t.Helper()
	raw, err := svc.CreateLoginSession(ctx, userID, "198.51.100.7", "cleanup")
	if err != nil {
		t.Fatalf("open hosted-login session: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE auth.login_sessions SET created_at = $2, expires_at = $2 WHERE token_hash = $1`, tokens.HashRefresh(raw), exp); err != nil {
		t.Fatalf("backdate hosted-login session: %v", err)
	}
	return raw
}

func sessionExists(t *testing.T, ctx context.Context, id uuid.UUID) bool {
	t.Helper()
	var ok bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.sessions WHERE id = $1)`, id).Scan(&ok); err != nil {
		t.Fatalf("look up session: %v", err)
	}
	return ok
}

func loginSessionsOf(t *testing.T, ctx context.Context, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.login_sessions WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("count hosted-login sessions: %v", err)
	}
	return n
}

// TestSessionCleanupDeletesOnlyWhatIsPastRetention covers: the run completes on
// the migrated schema; sessions ended, or with every refresh token expired,
// before the window are deleted with their refresh tokens and counted, and so
// are sessions that reached their idle timeout or maximum age before it; a
// session ended inside the window, a live session, a session whose refresh
// token expired inside the window, sessions that reached their idle timeout or
// maximum age inside it, and one opened inside the window are kept;
// hosted-login sessions expired before the window are deleted and the rest
// kept; and the next run, with nothing left to delete, succeeds with zero.
func TestSessionCleanupDeletesOnlyWhatIsPastRetention(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := auth.NewService(testPool, user.NewRepository(testPool), mustIssuer())
	tenantID := createTenant(t, ctx, uniqueSlug("cleanup"))
	me := createUserInTenant(t, ctx, tenantID)

	now := time.Now().UTC()
	day := 24 * time.Hour
	past := func(d time.Duration) *time.Time { at := now.Add(-d); return &at }

	endedLongAgo := sessionAt(t, ctx, svc, me, now.Add(-40*day), past(8*day), now.Add(-10*day))
	expiredLongAgo := sessionAt(t, ctx, svc, me, now.Add(-40*day), nil, now.Add(-8*day))
	endedRecently := sessionAt(t, ctx, svc, me, now.Add(-40*day), past(1*day), now.Add(20*day))
	live := sessionAt(t, ctx, svc, me, now.Add(-40*day), nil, now.Add(20*day))
	expiredRecently := sessionAt(t, ctx, svc, me, now.Add(-40*day), nil, now.Add(-1*day))
	openedRecently := sessionAt(t, ctx, svc, me, now.Add(-1*day), nil, now.Add(-1*time.Hour))
	idleLongAgo := boundedSession(t, ctx, svc, me, now.Add(-9*day), now.Add(20*day))
	maxAgeLongAgo := boundedSession(t, ctx, svc, me, now.Add(-1*time.Hour), now.Add(-8*day))
	idleRecently := boundedSession(t, ctx, svc, me, now.Add(-2*day), now.Add(20*day))
	maxAgeRecently := boundedSession(t, ctx, svc, me, now.Add(-1*time.Hour), now.Add(-1*day))

	// Passkey ceremonies: one expired unfinished, one still open.
	var expiredCeremony, openCeremony uuid.UUID
	for _, c := range []struct {
		id  *uuid.UUID
		exp time.Time
	}{{&expiredCeremony, now.Add(-time.Minute)}, {&openCeremony, now.Add(4 * time.Minute)}} {
		if err := testPool.QueryRow(ctx, `
			INSERT INTO auth.webauthn_sessions (kind, data, expires_at) VALUES ('login_discoverable', '{}', $1) RETURNING id`,
			c.exp).Scan(c.id); err != nil {
			t.Fatalf("seed ceremony: %v", err)
		}
	}
	loginSessionExpiring(t, ctx, svc, me, now.Add(-8*day))
	loginSessionExpiring(t, ctx, svc, me, now.Add(-1*day))
	if _, err := svc.CreateLoginSession(ctx, me, "198.51.100.7", "cleanup"); err != nil {
		t.Fatalf("open live hosted-login session: %v", err)
	}

	purged, err := auth.PurgeEndedSessions(ctx, testPool, auth.SessionRetention, nil)
	if err != nil {
		t.Fatalf("cleanup run failed: %v", err)
	}
	if purged.Sessions < 4 || purged.LoginSessions < 1 {
		t.Fatalf("cleanup counted %+v, want at least the 4 sessions and 1 hosted-login session past retention", purged)
	}
	for name, id := range map[string]uuid.UUID{
		"ended before the window":                      endedLongAgo,
		"all refresh tokens expired before the window": expiredLongAgo,
		"idle timeout reached before the window":       idleLongAgo,
		"maximum age reached before the window":        maxAgeLongAgo,
	} {
		if sessionExists(t, ctx, id) {
			t.Errorf("session %s was kept", name)
		}
	}
	var orphanTokens int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.refresh_tokens WHERE session_id = ANY($1)`, []uuid.UUID{endedLongAgo, expiredLongAgo}).Scan(&orphanTokens); err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	if orphanTokens != 0 {
		t.Errorf("%d refresh tokens of deleted sessions remain", orphanTokens)
	}
	for name, id := range map[string]uuid.UUID{
		"ended inside the window": endedRecently,
		"live":                    live,
		"refresh token expired inside the window": expiredRecently,
		"opened inside the window":                openedRecently,
		"idle timeout reached inside the window":  idleRecently,
		"maximum age reached inside the window":   maxAgeRecently,
	} {
		if !sessionExists(t, ctx, id) {
			t.Errorf("session %s was deleted", name)
		}
	}
	var ceremonies int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.webauthn_sessions WHERE id = ANY($1)`,
		[]uuid.UUID{expiredCeremony, openCeremony}).Scan(&ceremonies); err != nil || ceremonies != 1 || purged.Ceremonies < 1 {
		t.Errorf("ceremonies left = %d (purged %d, %v), want only the open one", ceremonies, purged.Ceremonies, err)
	}
	if n := loginSessionsOf(t, ctx, me); n != 2 {
		t.Errorf("hosted-login sessions left = %d, want the 2 not expired before the window", n)
	}

	again, err := auth.PurgeEndedSessions(ctx, testPool, auth.SessionRetention, nil)
	if err != nil {
		t.Fatalf("second cleanup run failed: %v", err)
	}
	if again != (auth.SessionsPurged{}) {
		t.Fatalf("second run deleted %+v, want nothing", again)
	}
}

// TestSessionCleanupKeepsALiveSessionUsable: a live session survives the
// cleanup and its refresh token still renews.
func TestSessionCleanupKeepsALiveSessionUsable(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := auth.NewService(testPool, user.NewRepository(testPool), mustIssuer())
	me := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("cleanup-live")))
	pair, err := svc.IssuePair(ctx, me, uuid.Nil, "198.51.100.7", "cleanup", "password")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if _, err := auth.PurgeEndedSessions(ctx, testPool, auth.SessionRetention, nil); err != nil {
		t.Fatalf("cleanup run failed: %v", err)
	}
	if _, err := svc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken}); err != nil {
		t.Fatalf("a live session stopped renewing after the cleanup: %v", err)
	}
}
