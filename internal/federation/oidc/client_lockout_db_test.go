//go:build integration

package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestWrongSecretsFromAnotherAddressDontLockTheApplicationOut checks that
// wrong secrets lock an application out only for the network they came from:
// the right secret from that network is refused, from any other it works,
// and a lockout of one network doesn't end with another's success.
func TestWrongSecretsFromAnotherAddressDontLockTheApplicationOut(t *testing.T) {
	svc := newTestService(t, dbtest.Pool(t), dbtest.Issuer(t), func(d *Deps) {
		d.Lockout = ClientLockout{Threshold: 3, Window: time.Minute, Duration: time.Minute}
	})
	client, secret := registerClient(t, svc, dbtest.Organization(t))
	router := chi.NewRouter()
	router.Use(httpx.ClientIPContext)
	(&Handler{Service: svc}).MountToken(router)
	// With the client authenticated, an unknown refresh token is invalid_grant;
	// a refused client is invalid_client.
	unknownGrant := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"not-a-token"}}.Encode()
	answer := func(from, pass string) string {
		t.Helper()
		req := httptest.NewRequestWithContext(dbtest.Context(t), http.MethodPost, "/oauth/token", strings.NewReader(unknownGrant))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(client.ClientID, pass)
		req.RemoteAddr = from
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		got, _ := decodeTokenError(t, rec)
		return got
	}

	for _, attacker := range []struct{ from, sameNetwork, elsewhere string }{
		{"198.51.100.7:4000", "198.51.100.7:4001", "203.0.113.9:4000"},
		{"[2001:db8:1:2::1]:4000", "[2001:db8:1:2::ffff]:4000", "[2001:db8:1:3::1]:4000"},
	} {
		for range 3 {
			if got := answer(attacker.from, "wrong-secret"); got != "invalid_client" {
				t.Fatalf("a wrong secret from %s: %s, want invalid_client", attacker.from, got)
			}
		}
		if got := answer(attacker.sameNetwork, secret); got != "invalid_client" {
			t.Errorf("the right secret from the locked-out network (%s): %s, want invalid_client", attacker.sameNetwork, got)
		}
		if got := answer(attacker.elsewhere, secret); got != "invalid_grant" {
			t.Errorf("the right secret from another network (%s) while %s is locked out: %s, want the client authenticated", attacker.elsewhere, attacker.from, got)
		}
		if got := answer(attacker.from, secret); got != "invalid_client" {
			t.Errorf("the right secret from %s after another network's success: %s, want it still locked out", attacker.from, got)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'oidc.client_locked_out' AND resource_id = $1`, client.ID); n != 2 {
		t.Errorf("%d lockouts recorded, want one per network", n)
	}
}
