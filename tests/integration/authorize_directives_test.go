//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

// TestAuthorizeHonoursTheRequestsDirectives pins the browser authorize
// endpoint to the OIDC directives it advertises: response_type is required
// and only code is served; prompt=none never shows a page (login_required,
// consent_required); prompt=login and max_age force a fresh sign-in, after
// which the request completes and the ID token's auth_time shows it; request
// objects and other response modes are refused, not ignored; discovery lists
// what is honoured.
func TestAuthorizeHonoursTheRequestsDirectives(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	issuer := mustIssuer()
	authSvc := auth.NewService(testPool, user.NewRepository(testPool), issuer)
	svc := oidc.NewService(testPool, issuer)
	tenantID := createTenant(t, ctx, uniqueSlug("directives"))
	redirect := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirect)
	h := &oidc.Handler{Service: svc, Sessions: authSvc, LoginBaseURL: "http://login.test"}
	router := chi.NewRouter()
	router.Route("/v1", h.MountBrowser)
	h.MountPublic(router)

	person := func(t *testing.T, consented bool) uuid.UUID {
		t.Helper()
		id := createUserInTenant(t, ctx, tenantID)
		addTenantMembership(t, ctx, id, tenantID)
		if consented {
			if err := svc.GrantConsent(ctx, id, client.ClientID, []string{"openid"}); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	// signIn opens a hosted-login session that began ago.
	signIn := func(t *testing.T, id uuid.UUID, ago time.Duration) string {
		t.Helper()
		raw, err := authSvc.CreateLoginSession(ctx, id, "198.51.100.7", "browser")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx, `UPDATE auth.login_sessions SET created_at = NOW() - make_interval(secs => $2)
			WHERE token_hash = $1`, tokens.HashRefresh(raw), ago.Seconds()); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	authorize := func(cookie string, extra url.Values) *url.URL {
		q := url.Values{"client_id": {client.ClientID}, "redirect_uri": {redirect}, "scope": {"openid"},
			"state": {"s1"}, "response_type": {"code"}, "nonce": {testNonce},
			"code_challenge": {testChallenge}, "code_challenge_method": {"S256"}}
		for k, v := range extra {
			if v == nil {
				q.Del(k)
				continue
			}
			q[k] = v
		}
		return get(router, "/v1/oauth/authorize?"+q.Encode(), cookie)
	}
	errorAtApp := func(t *testing.T, loc *url.URL, want string) {
		t.Helper()
		if loc == nil || loc.Host != "app.example" || loc.Query().Get("error") != want {
			t.Fatalf("redirect = %v, want the application with error=%s", loc, want)
		}
	}

	t.Run("response_type is required, and only code is served", func(t *testing.T) {
		cookie := signIn(t, person(t, true), time.Minute)
		errorAtApp(t, authorize(cookie, url.Values{"response_type": nil}), "invalid_request")
		errorAtApp(t, authorize(cookie, url.Values{"response_type": {"token"}}), "unsupported_response_type")
	})

	t.Run("request objects and other response modes are refused, not ignored", func(t *testing.T) {
		cookie := signIn(t, person(t, true), time.Minute)
		errorAtApp(t, authorize(cookie, url.Values{"request_uri": {"urn:x"}}), "request_uri_not_supported")
		errorAtApp(t, authorize(cookie, url.Values{"response_mode": {"fragment"}}), "invalid_request")
	})

	t.Run("prompt=none never shows a page", func(t *testing.T) {
		errorAtApp(t, authorize("", url.Values{"prompt": {"none"}}), "login_required")
		cookie := signIn(t, person(t, false), time.Minute)
		errorAtApp(t, authorize(cookie, url.Values{"prompt": {"none"}}), "consent_required")
	})

	t.Run("prompt=login asks for a fresh sign-in, then the request completes", func(t *testing.T) {
		id := person(t, true)
		loc := authorize(signIn(t, id, time.Hour), url.Values{"prompt": {"login"}})
		if loc == nil || loc.Host != "login.test" || loc.Query().Get("prompt") != "login" {
			t.Fatalf("prompt=login with a session: redirect %v, want the hosted login", loc)
		}
		back, _ := url.Parse(loc.Query().Get("return_to"))
		fresh := signIn(t, id, 0)
		done := get(router, back.RequestURI(), fresh)
		if done == nil || done.Host != "app.example" || done.Query().Get("code") == "" {
			t.Fatalf("after signing in again: redirect %v, want a code", done)
		}
	})

	t.Run("max_age forces a fresh sign-in, and auth_time reports it", func(t *testing.T) {
		id := person(t, true)
		loc := authorize(signIn(t, id, 2*time.Hour), url.Values{"max_age": {"60"}})
		if loc == nil || loc.Host != "login.test" {
			t.Fatalf("max_age=60 with a two-hour-old sign-in: redirect %v, want the hosted login", loc)
		}
		back, _ := url.Parse(loc.Query().Get("return_to"))
		done := get(router, back.RequestURI(), signIn(t, id, 0))
		if done == nil || done.Query().Get("code") == "" {
			t.Fatalf("after signing in again: redirect %v, want a code", done)
		}
		issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, done.Query().Get("code"), redirect, testVerifier, "")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		at, err := strconv.ParseInt(idTokenNumber(t, issued.IDToken, "auth_time"), 10, 64)
		if err != nil || time.Since(time.Unix(at, 0)) > time.Minute {
			t.Fatalf("auth_time = %d (%v), want the fresh sign-in", at, err)
		}
		if idTokenClaim(t, issued.IDToken, "sid") == "" {
			t.Fatal("the ID token names no session")
		}
	})

	t.Run("discovery lists only what is honoured", func(t *testing.T) {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
		var doc struct {
			Prompts       []string `json:"prompt_values_supported"`
			ResponseModes []string `json:"response_modes_supported"`
			ResponseTypes []string `json:"response_types_supported"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &doc)
		if !slices.Equal(doc.Prompts, []string{"none", "login", "consent"}) || !slices.Equal(doc.ResponseModes, []string{"query"}) ||
			!slices.Equal(doc.ResponseTypes, []string{"code"}) {
			t.Fatalf("discovery = %+v", doc)
		}
	})
}

// get sends a browser GET with an optional hosted-login cookie and returns
// where it redirects (nil when it doesn't).
func get(router http.Handler, path, cookie string) *url.URL {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		return nil
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		return nil
	}
	return loc
}

// idTokenNumber reads a numeric claim from an ID token as its decimal string.
func idTokenNumber(t *testing.T, idToken, claim string) string {
	t.Helper()
	parts := strings.Split(idToken, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var all map[string]any
	if err := dec.Decode(&all); err != nil {
		t.Fatal(err)
	}
	n, _ := all[claim].(json.Number)
	return n.String()
}
