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
)

// postToken posts form to the token endpoint, with Basic credentials when
// user is not empty.
func postToken(t *testing.T, h http.Handler, form url.Values, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(dbtest.Context(t), http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestTokenEndpointAnswersGrantErrorsInOAuthShape checks the token endpoint's
// answers to refused client authentication and grants.
func TestTokenEndpointAnswersGrantErrorsInOAuthShape(t *testing.T) {
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	issued := redeemCode(t, svc, client, secret, user.ID, "")
	router := chi.NewRouter()
	(&Handler{Service: svc}).MountToken(router)

	form := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	code := form("grant_type", "authorization_code", "code", "not-a-code", "redirect_uri", testRedirect)
	for _, tc := range []struct {
		name             string
		form             url.Values
		user, pass       string
		status           int
		error, challenge string
	}{
		{"a wrong Basic secret", code, client.ClientID, "wrong-secret", http.StatusUnauthorized, "invalid_client", `Basic realm="qeet"`},
		{"a wrong form secret", form("grant_type", "refresh_token", "client_id", client.ClientID, "client_secret", "wrong-secret", "refresh_token", issued.RefreshToken), "", "", http.StatusUnauthorized, "invalid_client", ""},
		{"an unknown client", code, "qci_unknown", secret, http.StatusUnauthorized, "invalid_client", `Basic realm="qeet"`},
		{"an unknown code", code, client.ClientID, secret, http.StatusBadRequest, "invalid_grant", ""},
		{"an unknown refresh token", form("grant_type", "refresh_token", "refresh_token", "not-a-token"), client.ClientID, secret, http.StatusBadRequest, "invalid_grant", ""},
		{"no refresh token", form("grant_type", "refresh_token"), client.ClientID, secret, http.StatusBadRequest, "invalid_request", ""},
		{"a resource other than the one the grant is bound to", form("grant_type", "refresh_token", "refresh_token", issued.RefreshToken, "resource", resourceB), client.ClientID, secret, http.StatusBadRequest, "invalid_target", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postToken(t, router, tc.form, tc.user, tc.pass)
			if rec.Code != tc.status {
				t.Errorf("status %d, want %d", rec.Code, tc.status)
			}
			if got, _ := decodeTokenError(t, rec); got != tc.error {
				t.Errorf("error %q, want %q", got, tc.error)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tc.challenge {
				t.Errorf("WWW-Authenticate %q, want %q", got, tc.challenge)
			}
		})
	}

	// A locked-out application is answered as a wrong secret, its right one too.
	svc.SetClientLockout(ClientLockout{Threshold: 1, Window: time.Minute, Duration: time.Minute})
	refresh := form("grant_type", "refresh_token", "refresh_token", issued.RefreshToken)
	postToken(t, router, refresh, client.ClientID, "wrong-secret")
	rec := postToken(t, router, refresh, client.ClientID, secret)
	if got, _ := decodeTokenError(t, rec); rec.Code != http.StatusUnauthorized || got != "invalid_client" {
		t.Errorf("locked-out application = %d %q, want 401 invalid_client", rec.Code, got)
	}
}
