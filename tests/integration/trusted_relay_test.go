//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestARelayedSignInIsJudgedByThePersonsAddress pins the trusted relay: a
// sign-in the console's server relays with a valid relay key is judged, and
// recorded, by the person's own address, not the relay's; a request claiming
// an address without the key is judged by its real one.
func TestARelayedSignInIsJudgedByThePersonsAddress(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	const relayKey = "console-relay-key-0123456789abcdefghij"
	httpx.SetRelayKeys([]string{relayKey})
	t.Cleanup(func() { httpx.SetRelayKeys(nil) })

	google := createTenant(t, ctx, uniqueSlug("relay"))
	addressRules(t, ctx, google, true, [2]string{"192.0.2.0/24", "deny"})
	email := uniqueSlug("relayed") + "@example.com"
	uma := createTenantUser(t, ctx, google, email)
	addTenantMembership(t, ctx, uma, google)
	hash, err := password.Hash(factorPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, $2)`, uma, hash); err != nil {
		t.Fatal(err)
	}
	authSvc, _ := newAuth()
	r := chi.NewRouter()
	(&auth.Handler{Service: authSvc, Validate: validator.New()}).Mount(r)
	signIn := func(from, key, claimed string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"email": email, "password": factorPassword})
		req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = from + ":4000"
		if key != "" {
			req.Header.Set(httpx.RelayKeyHeader, key)
		}
		if claimed != "" {
			req.Header.Set(httpx.RelayClientIPHeader, claimed)
		}
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}
	const relay = "10.0.0.5" // the console server: allowed

	t.Run("a refused person behind the relay is refused", func(t *testing.T) {
		rr := signIn(relay, relayKey, "192.0.2.10")
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), errs.CodeAuthAddressNotAllowed) {
			t.Fatalf("relayed sign-in from a denied address: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("an allowed person behind the relay signs in, recorded at their own address", func(t *testing.T) {
		rr := signIn(relay, relayKey, "198.51.100.7")
		if rr.Code != http.StatusOK {
			t.Fatalf("relayed sign-in: %d %s", rr.Code, rr.Body.String())
		}
		var out struct {
			SessionID string `json:"session_id"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		var ip string
		if err := testPool.QueryRow(ctx, `SELECT host(ip) FROM auth.sessions WHERE id = $1`, out.SessionID).Scan(&ip); err != nil || ip != "198.51.100.7" {
			t.Fatalf("session address = %q (%v), want the person's 198.51.100.7", ip, err)
		}
	})

	t.Run("a claimed address without the relay key is ignored", func(t *testing.T) {
		// From a denied address, claiming an allowed one.
		rr := signIn("192.0.2.20", "not-the-relay-key-0123456789abcdefgh", "198.51.100.7")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("forged relay claim: %d %s; want the real address refused", rr.Code, rr.Body.String())
		}
	})
}
