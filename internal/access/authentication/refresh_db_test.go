//go:build integration

package authentication

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRefreshCharacterized pins what a refresh-token renewal does in each
// state of its token, session, account and organization: the answer, what it
// rotates or ends, and the audit rows it writes.
func TestRefreshCharacterized(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	count := func(action string, resource uuid.UUID) int {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = $1 AND resource_id = $2`, action, resource)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	revoked := func(session uuid.UUID) bool {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NOT NULL`, session) == 1
	}

	t.Run("rotation", func(t *testing.T) {
		svc := newService(t)
		a, organization := member(t)
		first := signIn(t, svc, a)
		exec(`UPDATE auth.sessions SET last_seen_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, first.SessionID)
		second, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken})
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if second.RefreshToken == first.RefreshToken || second.AccessToken == "" || second.TokenType != "Bearer" ||
			second.SessionID != first.SessionID || second.UserID != a.ID || second.OrganizationID == nil ||
			*second.OrganizationID != organization || !second.SessionExpiresAt.Equal(first.SessionExpiresAt) ||
			!second.IdleExpiresAt.After(time.Now()) {
			t.Fatalf("refresh returned %+v; want a new token pair for the same session", second)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.refresh_tokens WHERE session_id = $1 AND used_at IS NOT NULL
			AND replaced_by IS NOT NULL`, first.SessionID); n != 1 {
			t.Errorf("%d used tokens naming their replacement, want 1", n)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND last_seen_at > NOW() - INTERVAL '10 seconds'`,
			first.SessionID); n != 1 {
			t.Error("the renewal did not count as the session's use")
		}
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: second.RefreshToken}); err != nil {
			t.Errorf("refresh with the replacement: %v", err)
		}
	})

	t.Run("unknown or expired token", func(t *testing.T) {
		svc := newService(t)
		a, _ := member(t)
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: "not-a-token"}); !errors.Is(err, ErrRefreshTokenInvalid) {
			t.Errorf("unknown token: %v, want %v", err, ErrRefreshTokenInvalid)
		}
		pair := signIn(t, svc, a)
		exec(`UPDATE auth.refresh_tokens SET expires_at = NOW() - INTERVAL '1 second' WHERE session_id = $1`, pair.SessionID)
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, ErrRefreshTokenInvalid) {
			t.Errorf("expired token: %v, want %v", err, ErrRefreshTokenInvalid)
		}
		if revoked(pair.SessionID) {
			t.Error("an expired refresh token ended its session")
		}
	})

	t.Run("reuse is theft", func(t *testing.T) {
		svc := newService(t)
		a, _ := member(t)
		first := signIn(t, svc, a)
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}); err != nil {
			t.Fatal(err)
		}
		in := RefreshInput{RefreshToken: first.RefreshToken}
		in.IP, in.UserAgent, in.RequestID = "192.0.2.9", "thief", "req-reuse"
		if _, err := svc.Refresh(ctx, in); !errors.Is(err, errs.ErrAuthSessionRevoked) {
			t.Fatalf("reuse: %v, want %v", err, errs.ErrAuthSessionRevoked)
		}
		if !revoked(first.SessionID) || count("auth.token_reuse_detected", first.SessionID) != 1 {
			t.Error("the reuse did not end and record the session")
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.token_reuse_detected' AND resource_id = $1
			AND actor_type = 'system' AND actor_user_id = $2 AND host(ip) = '192.0.2.9' AND request_id = 'req-reuse'`,
			first.SessionID, a.ID); n != 1 {
			t.Error("the reuse was not recorded with the request it came from")
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE event_type = 'auth.session.revoked_for_reuse'
			AND aggregate_id = $1`, first.SessionID); n != 1 {
			t.Errorf("%d theft events queued, want 1", n)
		}
		if _, err := svc.Refresh(ctx, in); !errors.Is(err, errs.ErrAuthSessionRevoked) || count("auth.token_reuse_detected", first.SessionID) != 1 {
			t.Errorf("reuse of an ended session: %v; want %v, recorded once", err, errs.ErrAuthSessionRevoked)
		}
	})

	t.Run("ended session, account or organization", func(t *testing.T) {
		svc := newService(t)
		for _, tc := range []struct {
			name  string
			setup func(a dbtest.Account, organization, session uuid.UUID)
			want  error
		}{
			{"revoked session", func(_ dbtest.Account, _, session uuid.UUID) {
				exec(`UPDATE auth.sessions SET revoked_at = NOW() WHERE id = $1`, session)
			}, errs.ErrAuthSessionRevoked},
			{"suspended account", func(a dbtest.Account, _, _ uuid.UUID) {
				exec(`UPDATE account.users SET status = 'suspended' WHERE id = $1`, a.ID)
			}, errs.ErrAuthAccountSuspended},
			{"deleted account", func(a dbtest.Account, _, _ uuid.UUID) {
				exec(`UPDATE account.users SET deleted_at = NOW() WHERE id = $1`, a.ID)
			}, errs.ErrAuthAccountSuspended},
			{"suspended organization", func(_ dbtest.Account, organization, _ uuid.UUID) {
				exec(`UPDATE organization.organizations SET status = 'suspended' WHERE id = $1`, organization)
			}, ErrOrganizationInactive},
		} {
			a, organization := member(t)
			pair := signIn(t, svc, a)
			tc.setup(a, organization, pair.SessionID)
			if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, tc.want) {
				t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
			}
			if n := dbtest.Count(t, `SELECT count(*) FROM auth.refresh_tokens WHERE session_id = $1 AND used_at IS NULL`, pair.SessionID); n != 1 {
				t.Errorf("%s: the token was spent", tc.name)
			}
		}
	})

	t.Run("timed out", func(t *testing.T) {
		svc := newService(t)
		for _, tc := range []struct{ reason, sql string }{
			{timedOutMaxAge, `UPDATE auth.sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`},
			{timedOutIdle, `UPDATE auth.sessions SET last_seen_at = NOW() - idle_timeout - INTERVAL '1 second' WHERE id = $1`},
		} {
			a, _ := member(t)
			pair := signIn(t, svc, a)
			exec(tc.sql, pair.SessionID)
			for range 2 {
				if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, ErrSessionTimedOut) {
					t.Errorf("%s: %v, want %v", tc.reason, err, ErrSessionTimedOut)
				}
			}
			if !revoked(pair.SessionID) {
				t.Errorf("%s: the session was not ended", tc.reason)
			}
			if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.session_expired' AND resource_id = $1
				AND metadata->>'reason' = $2 AND actor_type = 'system'`, pair.SessionID, tc.reason); n != 1 {
				t.Errorf("%s: the ending was recorded %d times, want once", tc.reason, n)
			}
		}
	})

	t.Run("refused address", func(t *testing.T) {
		svc := newService(t)
		a, _ := member(t)
		pair := signIn(t, svc, a)
		svc.addresses = addressFunc(func(_ context.Context, _, _ uuid.UUID, ip, _ string) error {
			if ip == "198.51.100.7" {
				return errs.ErrAuthAddressNotAllowed
			}
			return nil
		})
		in := RefreshInput{RefreshToken: pair.RefreshToken}
		in.IP = "198.51.100.7"
		if _, err := svc.Refresh(ctx, in); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
			t.Fatalf("refused address: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
		}
		if revoked(pair.SessionID) {
			t.Error("a refused address ended the session")
		}
		in.IP = "192.0.2.10"
		if _, err := svc.Refresh(ctx, in); err != nil {
			t.Errorf("the same token from an allowed address: %v", err)
		}
	})
}

// TestRefreshRotation checks that a refresh token renews its session once, and
// that presenting a spent one ends the session, so its replacement stops
// working too.
func TestRefreshRotation(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, _ := member(t)
	first := signIn(t, svc, a)

	second, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken || second.SessionID != first.SessionID {
		t.Fatalf("refresh returned %+v; want a new token for session %s", second, first.SessionID)
	}

	// The spent token first: presenting it is what ends the session.
	for _, tc := range []struct{ name, token string }{{"spent", first.RefreshToken}, {"replacement", second.RefreshToken}} {
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: tc.token}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
			t.Errorf("refresh with the %s token: %v, want %v", tc.name, err, errs.ErrAuthSessionRevoked)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NOT NULL`, first.SessionID); n != 1 {
		t.Error("reusing a spent refresh token left the session live")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.token_reuse_detected' AND resource_id = $1`, first.SessionID); n != 1 {
		t.Error("the reuse was not audited")
	}
}

// TestRenewalFromARefusedAddress checks that a renewal from an address the
// organization's rules refuse is refused and recorded, and that the refresh
// token still renews from an allowed address.
func TestRenewalFromARefusedAddress(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.addresses = ipallow.NewService(pool)
	a, organization := member(t)
	enforceAddressRules(t, organization)
	pair, err := svc.IssuePair(ctx, a.ID, organization, "192.0.2.10", "test", "password")
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}

	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken, IP: "198.51.100.7"}); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Fatalf("renewal from a refused address: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.address_refused' AND organization_id = $1
		AND metadata->>'path' = 'refresh' AND metadata->>'address' = '198.51.100.7'`, organization); n != 1 {
		t.Errorf("the refused renewal was recorded %d times, want 1", n)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken, IP: "192.0.2.10"}); err != nil {
		t.Errorf("renewal from an allowed address after a refused one: %v", err)
	}
}

// TestTokenReuseOnAOrganizationlessSession checks that the theft of an organization-less
// session's refresh token is recorded as an event of no organization, like
// the session's other records, rather than of an organization that doesn't
// exist.
func TestTokenReuseOnAOrganizationlessSession(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a := dbtest.User(t, uuid.Nil)
	pair, err := svc.IssuePair(ctx, a.ID, uuid.Nil, "", "test", "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
		t.Fatalf("reuse the spent token: %v, want %v", err, errs.ErrAuthSessionRevoked)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.token_reuse_detected' AND resource_id = $1
		AND organization_id IS NULL`, pair.SessionID); n != 1 {
		t.Errorf("the reuse was recorded with no organization %d times, want once", n)
	}
}
