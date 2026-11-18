//go:build integration

package auth

import (
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// withReuseGrace returns the service with a refresh reuse grace and a cipher
// to keep rotations under.
func withReuseGrace(t *testing.T, grace time.Duration) *Service {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(key)
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(t)
	svc.SetRefreshReuseGrace(grace, cipher)
	return svc
}

// TestRefreshRetryWithinTheGrace checks that a rotated refresh token sent again
// within the grace gets the pair its rotation issued, audited, with the
// session kept; and that the pair renews as usual afterwards.
func TestRefreshRetryWithinTheGrace(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := withReuseGrace(t, 30*time.Second)
	a, _ := member(t)
	first := signIn(t, svc, a)

	rotated, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	for i := range 2 {
		again, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken})
		if err != nil {
			t.Fatalf("retry %d: %v, want the rotation's pair", i, err)
		}
		if again.RefreshToken != rotated.RefreshToken || again.AccessToken != rotated.AccessToken ||
			again.SessionID != rotated.SessionID || !again.ExpiresAt.Equal(rotated.ExpiresAt) {
			t.Fatalf("retry %d returned another pair: %+v, want %+v", i, again, rotated)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NULL`, first.SessionID); n != 1 {
		t.Fatal("a retry within the grace ended the session")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.refresh_token_retried' AND resource_id = $1`, first.SessionID); n != 2 {
		t.Errorf("%d retries audited, want 2", n)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: rotated.RefreshToken}); err != nil {
		t.Errorf("renewing with the retried pair: %v", err)
	}
}

// TestRefreshRetryOutsideTheGrace checks that a rotated token sent again after
// the grace, or after its replacement has been used, still ends the session as
// theft.
func TestRefreshRetryOutsideTheGrace(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := withReuseGrace(t, 30*time.Second)

	t.Run("after the grace", func(t *testing.T) {
		a, _ := member(t)
		first := signIn(t, svc, a)
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}); err != nil {
			t.Fatal(err)
		}
		if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.refresh_tokens SET used_at = NOW() - interval '31 seconds' WHERE session_id = $1 AND used_at IS NOT NULL`, first.SessionID); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
			t.Fatalf("reuse after the grace: %v, want %v", err, errs.ErrAuthSessionRevoked)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.token_reuse_detected' AND resource_id = $1`, first.SessionID); n != 1 {
			t.Error("the reuse was not audited as theft")
		}
	})

	t.Run("after the replacement was used", func(t *testing.T) {
		a, _ := member(t)
		first := signIn(t, svc, a)
		second, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: second.RefreshToken}); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
			t.Fatalf("reuse once the chain moved on: %v, want %v", err, errs.ErrAuthSessionRevoked)
		}
	})

	t.Run("with no grace", func(t *testing.T) {
		svc := newService(t)
		a, _ := member(t)
		first := signIn(t, svc, a)
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
			t.Fatalf("immediate reuse without a grace: %v, want %v", err, errs.ErrAuthSessionRevoked)
		}
	})

	t.Run("on an ended session", func(t *testing.T) {
		a, _ := member(t)
		first := signIn(t, svc, a)
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}); err != nil {
			t.Fatal(err)
		}
		if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.sessions SET revoked_at = NOW() WHERE id = $1`, first.SessionID); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
			t.Fatalf("retry on an ended session: %v, want %v", err, errs.ErrAuthSessionRevoked)
		}
	})
}

// TestConcurrentRefreshesGetOnePair checks that renewals racing with one token
// all get the same pair, as two instances of a client renewing at once do.
func TestConcurrentRefreshesGetOnePair(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := withReuseGrace(t, 30*time.Second)
	a, _ := member(t)
	first := signIn(t, svc, a)

	const n = 3
	pairs := make([]*TokenPair, n)
	failures := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { pairs[i], failures[i] = svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}) })
	}
	wg.Wait()
	for i := range n {
		if failures[i] != nil {
			t.Fatalf("renewal %d: %v", i, failures[i])
		}
		if pairs[i].RefreshToken != pairs[0].RefreshToken {
			t.Errorf("renewal %d got another refresh token", i)
		}
	}
}

// TestClearRefreshRetries checks that the cleanup drops kept rotations past
// any grace and keeps recent ones.
func TestClearRefreshRetries(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := withReuseGrace(t, 30*time.Second)
	kept := func(sessionID any) int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.refresh_tokens WHERE session_id = $1 AND replacement_enc IS NOT NULL`, sessionID)
	}
	a, _ := member(t)
	old, recent := signIn(t, svc, a), signIn(t, svc, a)
	for _, p := range []*TokenPair{old, recent} {
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: p.RefreshToken}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.refresh_tokens SET used_at = NOW() - interval '3 minutes' WHERE session_id = $1`, old.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := ClearRefreshRetries(ctx, dbtest.Pool(t)); err != nil {
		t.Fatal(err)
	}
	if kept(old.SessionID) != 0 || kept(recent.SessionID) != 1 {
		t.Errorf("kept rotations after cleanup: old %d, recent %d; want 0 and 1", kept(old.SessionID), kept(recent.SessionID))
	}
}
