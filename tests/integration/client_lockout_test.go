//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestWrongApplicationSecretsLockTheApplicationOut pins the application
// secret lockout: wrong secrets count against the application on every
// endpoint that takes one; past the threshold even the right secret is
// refused until the lockout ends, with the same answer as a wrong secret or an
// unknown application; each failure is recorded with the address and no
// secret; the lockout is recorded and announced once; a right secret before
// the threshold resets the count.
func TestWrongApplicationSecretsLockTheApplicationOut(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("lockout"))
	svc := oidc.NewService(testPool, mustIssuer())
	svc.SetClientLockout(oidc.ClientLockout{Threshold: 3, Window: time.Hour, Duration: time.Hour})
	redirect := "https://app.example/cb"
	const wrong = "not-the-secret-0123456789"

	r := chi.NewRouter()
	r.Use(httpx.ClientIPContext)
	(&oidc.Handler{Service: svc}).MountPublic(r)
	introspect := func(clientID, secret string) int {
		form := url.Values{"client_id": {clientID}, "client_secret": {secret}, "token": {"opaque"}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.5:7000"
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr.Code
	}
	authFailed := func(t *testing.T, what string, err error) {
		t.Helper()
		if !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Fatalf("%s: err = %v, want %v", what, err, errs.ErrOIDCClientAuthFailed)
		}
	}
	refresh := func(clientID, secret string) error {
		_, err := svc.RefreshToken(ctx, clientID, secret, "no-such-refresh-token", "")
		return err
	}

	t.Run("wrong secrets across endpoints lock the application out, even for the right secret", func(t *testing.T) {
		client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirect)
		authFailed(t, "refresh with a wrong secret", refresh(client.ClientID, wrong))
		if code := introspect(client.ClientID, wrong); code != http.StatusUnauthorized {
			t.Fatalf("introspect with a wrong secret: %d, want 401", code)
		}
		authFailed(t, "refresh with a wrong secret", refresh(client.ClientID, wrong))

		// Locked: the right secret gets the very answer a wrong one does.
		authFailed(t, "the right secret while locked out", refresh(client.ClientID, secret))
		authFailed(t, "an unknown application", refresh("qci_no-such-app", secret))

		var locks, events int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE action = 'oidc.client_locked_out' AND resource_id = $1`, client.ID).Scan(&locks); err != nil {
			t.Fatal(err)
		}
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM platform.outbox WHERE event_type = 'oidc.client.locked_out' AND aggregate_id = $1`, client.ID).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if locks != 1 || events != 1 {
			t.Fatalf("lockout recorded %d time(s) and announced %d time(s), want once each", locks, events)
		}

		var failedFromAddress, leaked int
		if err := testPool.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE host(ip) = '203.0.113.5'), count(*) FILTER (WHERE metadata::text LIKE '%' || $2 || '%')
			FROM audit.events WHERE action = 'oidc.client_auth_failed' AND resource_id = $1`, client.ID, wrong).Scan(&failedFromAddress, &leaked); err != nil {
			t.Fatal(err)
		}
		if failedFromAddress != 1 || leaked != 0 {
			t.Fatalf("failures recorded with the address: %d (want 1); holding the secret: %d (want 0)", failedFromAddress, leaked)
		}

		state, err := svc.RecentClientAuthFailures(ctx, tenantID, client.ID)
		if err != nil {
			t.Fatalf("recent failures: %v", err)
		}
		if state.LockedUntil == nil || len(state.Items) != 3 {
			t.Fatalf("admin view: locked_until %v, %d failure(s); want a lockout and 3", state.LockedUntil, len(state.Items))
		}

		// Once the lockout ends, the right secret works and the slate is clean.
		if _, err := testPool.Exec(ctx, `UPDATE auth.oidc_client_auth_lockouts SET locked_until = NOW() - INTERVAL '1 second' WHERE client_row_id = $1`, client.ID); err != nil {
			t.Fatal(err)
		}
		if err := refresh(client.ClientID, secret); errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Fatalf("the right secret after the lockout ended: %v", err)
		}
	})

	t.Run("the right secret before the threshold resets the count", func(t *testing.T) {
		client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirect)
		for range 2 {
			authFailed(t, "wrong secret", refresh(client.ClientID, wrong))
		}
		if err := refresh(client.ClientID, secret); errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Fatalf("the right secret: %v", err)
		}
		for range 2 {
			authFailed(t, "wrong secret", refresh(client.ClientID, wrong))
		}
		if err := refresh(client.ClientID, secret); errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Fatalf("locked out after a reset: %v", err)
		}
	})
}
