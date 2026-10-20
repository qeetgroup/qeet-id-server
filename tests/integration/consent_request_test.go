//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
)

// TestConsentDecisionsComeFromTheStoredRequest pins the hosted consent step to
// the request the server checked. An authorize request whose redirect_uri isn't
// registered never reaches consent; consent gets an opaque request id, not the
// protocol values; and Allow or Deny sends only that id, so neither can be
// pointed at an address the application never registered.
func TestConsentDecisionsComeFromTheStoredRequest(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	issuer := mustIssuer()
	authSvc := auth.NewService(testPool, user.NewRepository(testPool), issuer)
	svc := oidc.NewService(testPool, issuer)
	tenantID := createTenant(t, ctx, uniqueSlug("consent"))
	redirect := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirect)

	authH := &auth.Handler{Service: authSvc, Validate: validator.New()}
	oidcH := &oidc.Handler{Service: svc, Sessions: authSvc, LoginBaseURL: "http://login.test"}
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		authH.Mount(r)
		oidcH.MountBrowser(r)
	})

	signIn := func(t *testing.T) string {
		t.Helper()
		id := createUserInTenant(t, ctx, tenantID)
		addTenantMembership(t, ctx, id, tenantID)
		raw, err := authSvc.CreateLoginSession(ctx, id, "198.51.100.7", "browser")
		if err != nil {
			t.Fatalf("open hosted-login session: %v", err)
		}
		return raw
	}
	do := func(t *testing.T, method, path, cookie string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}
	authorizeURL := func(redirectURI, scope, state string) string {
		q := url.Values{"client_id": {client.ClientID}, "redirect_uri": {redirectURI}, "scope": {scope},
			"state": {state}, "response_type": {"code"}, "code_challenge": {testChallenge}, "code_challenge_method": {"S256"}, "nonce": {testNonce}}
		return "/v1/oauth/authorize?" + q.Encode()
	}
	// startConsent runs authorize for a user who hasn't consented and returns the
	// request id the hosted consent page is given.
	startConsent := func(t *testing.T, cookie, scope, state string) string {
		t.Helper()
		rr := do(t, http.MethodGet, authorizeURL(redirect, scope, state), cookie, nil)
		loc, err := url.Parse(rr.Header().Get("Location"))
		if rr.Code != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), "http://login.test/consent") {
			t.Fatalf("authorize: status %d, location %q; want the hosted consent page", rr.Code, rr.Header().Get("Location"))
		}
		id := loc.Query().Get("request_id")
		if _, err := uuid.Parse(id); err != nil {
			t.Fatalf("consent location %q carries no request id", loc)
		}
		for _, leaked := range []string{"redirect_uri", "state", "scope", "client_id", "code_challenge"} {
			if loc.Query().Has(leaked) {
				t.Fatalf("consent location %q still carries %s", loc, leaked)
			}
		}
		return id
	}
	redirectOf := func(t *testing.T, rr *httptest.ResponseRecorder) string {
		t.Helper()
		var out struct {
			Redirect string `json:"redirect"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out.Redirect
	}

	t.Run("an authorize request with an unregistered redirect_uri never reaches consent", func(t *testing.T) {
		cookie := signIn(t)
		for _, bad := range []string{"https://evil.example/phish", "javascript:alert(document.domain)//"} {
			rr := do(t, http.MethodGet, authorizeURL(bad, "openid", "s0"), cookie, nil)
			if loc := rr.Header().Get("Location"); loc != "" {
				t.Fatalf("redirect_uri %q: redirected to %q; want the error shown here", bad, loc)
			}
			if rr.Code < 400 {
				t.Fatalf("redirect_uri %q: status %d; want an error", bad, rr.Code)
			}
		}
	})

	t.Run("an old-style decision carrying its own redirect_uri is refused and redirects nowhere", func(t *testing.T) {
		cookie := signIn(t)
		rr := do(t, http.MethodPost, "/v1/oauth/authorize/decision", cookie, map[string]any{
			"approve": false, "client_id": client.ClientID, "redirect_uri": "javascript:alert(document.domain)//",
			"scope": "openid", "state": "s1",
		})
		if rr.Code < 400 || strings.Contains(rr.Body.String(), "javascript:") {
			t.Fatalf("status %d, body %s; want a refusal with no redirect", rr.Code, rr.Body.String())
		}
	})

	t.Run("the consent page reads its stored request, and only from the browser that started it", func(t *testing.T) {
		cookie := signIn(t)
		id := startConsent(t, cookie, "openid profile", "s2")
		rr := do(t, http.MethodGet, "/v1/oauth/authorize/request?request_id="+id, cookie, nil)
		var got struct {
			ClientID string `json:"client_id"`
			Scope    string `json:"scope"`
		}
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil ||
			got.ClientID != client.ClientID || got.Scope != "openid profile" {
			t.Fatalf("read request: status %d, body %s", rr.Code, rr.Body.String())
		}
		if rr := do(t, http.MethodGet, "/v1/oauth/authorize/request?request_id="+id, signIn(t), nil); rr.Code == http.StatusOK {
			t.Fatal("another browser read the stored request")
		}
		if rr := do(t, http.MethodPost, "/v1/oauth/authorize/decision", signIn(t), map[string]any{"request_id": id, "approve": false}); rr.Code < 400 {
			t.Fatalf("another browser decided the request: status %d", rr.Code)
		}
	})

	t.Run("deny sends access_denied with the original state to the registered address, once", func(t *testing.T) {
		cookie := signIn(t)
		id := startConsent(t, cookie, "openid", "s3")
		rr := do(t, http.MethodPost, "/v1/oauth/authorize/decision", cookie, map[string]any{"request_id": id, "approve": false})
		loc, err := url.Parse(redirectOf(t, rr))
		if rr.Code != http.StatusOK || err != nil || !strings.HasPrefix(loc.String(), redirect+"?") ||
			loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "s3" {
			t.Fatalf("deny: status %d, body %s", rr.Code, rr.Body.String())
		}
		if rr := do(t, http.MethodPost, "/v1/oauth/authorize/decision", cookie, map[string]any{"request_id": id, "approve": false}); rr.Code < 400 {
			t.Fatal("a decided request was decided again")
		}
	})

	t.Run("a decision matching no stored request is refused", func(t *testing.T) {
		rr := do(t, http.MethodPost, "/v1/oauth/authorize/decision", signIn(t), map[string]any{"request_id": uuid.NewString(), "approve": true})
		if rr.Code < 400 || redirectOf(t, rr) != "" {
			t.Fatalf("status %d, body %s; want a refusal", rr.Code, rr.Body.String())
		}
	})

	t.Run("a decision that changes the stored request is refused", func(t *testing.T) {
		cookie := signIn(t)
		id := startConsent(t, cookie, "openid", "s4")
		rr := do(t, http.MethodPost, "/v1/oauth/authorize/decision", cookie, map[string]any{
			"request_id": id, "approve": true, "scope": "openid profile email",
		})
		if rr.Code < 400 || redirectOf(t, rr) != "" {
			t.Fatalf("status %d, body %s; want a refusal", rr.Code, rr.Body.String())
		}
	})

	t.Run("approve delivers a working code to the registered address", func(t *testing.T) {
		cookie := signIn(t)
		id := startConsent(t, cookie, "openid", "s5")
		rr := do(t, http.MethodPost, "/v1/oauth/authorize/decision", cookie, map[string]any{"request_id": id, "approve": true})
		loc, err := url.Parse(redirectOf(t, rr))
		if rr.Code != http.StatusOK || err != nil || !strings.HasPrefix(loc.String(), redirect+"?") || loc.Query().Get("state") != "s5" {
			t.Fatalf("approve: status %d, body %s", rr.Code, rr.Body.String())
		}
		if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, loc.Query().Get("code"), redirect, testVerifier, ""); err != nil {
			t.Fatalf("the delivered code doesn't redeem: %v", err)
		}
	})
}
