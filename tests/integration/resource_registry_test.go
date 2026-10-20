//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
)

// TestTokensForAResourceAreForThatResourceAlone pins RFC 8707 resource
// indicators to the organisation's registry: an unregistered resource is
// invalid_target; a token issued for a resource names it alone, so the
// platform API refuses it and the service accepts it; the authorize request
// carries a resource into the code; a token without one is the platform's;
// the device and backchannel flows refuse a resource instead of dropping it.
func TestTokensForAResourceAreForThatResourceAlone(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("resources"))
	userID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, userID, tenantID)
	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)
	redirect := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirect)
	const reports = "https://reports.example.com"
	registerResource(t, ctx, svc, tenantID, reports, "")

	code := func(t *testing.T, resource string) (string, error) {
		t.Helper()
		c, _, err := svc.AuthorizeInLoginSession(ctx, uuid.Nil, userID, client.ClientID, redirect, []string{"openid"},
			testNonce, testChallenge, "S256", "", resource)
		return c, err
	}
	invalidTarget := func(t *testing.T, what string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "invalid_target") {
			t.Fatalf("%s: err = %v, want invalid_target", what, err)
		}
	}

	t.Run("an unregistered resource is refused, at authorize and at the token endpoint", func(t *testing.T) {
		_, err := code(t, "https://evil.example.com")
		invalidTarget(t, "authorize", err)
		c, err := code(t, "")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		_, err = svc.ExchangeCode(ctx, client.ClientID, secret, c, redirect, testVerifier, "https://evil.example.com")
		invalidTarget(t, "token request", err)
	})

	t.Run("a resource named at authorize is the token's only audience; the platform refuses it", func(t *testing.T) {
		c, err := code(t, reports)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, c, redirect, testVerifier, "")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if _, err := issuer.VerifyAccess(issued.AccessToken); err == nil {
			t.Fatal("the platform API accepted a token issued for another service")
		}
		claims, err := issuer.VerifyAccessFor(issued.AccessToken, reports)
		if err != nil {
			t.Fatalf("the service named refused its own token: %v", err)
		}
		if auds := []string(claims.Audience); len(auds) != 1 || auds[0] != reports {
			t.Fatalf("aud = %v, want only %q", auds, reports)
		}
	})

	t.Run("a token request can't name another resource than the authorization did", func(t *testing.T) {
		const other = "https://billing.example.com"
		registerResource(t, ctx, svc, tenantID, other, "")
		c, err := code(t, reports)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		_, err = svc.ExchangeCode(ctx, client.ClientID, secret, c, redirect, testVerifier, other)
		invalidTarget(t, "token request naming another resource", err)
	})

	t.Run("a token with no resource is the platform's, and a service checking its own name refuses it", func(t *testing.T) {
		c, err := code(t, "")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, c, redirect, testVerifier, "")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if _, err := issuer.VerifyAccess(issued.AccessToken); err != nil {
			t.Fatalf("the platform refused its own token: %v", err)
		}
		if _, err := issuer.VerifyAccessFor(issued.AccessToken, reports); err == nil {
			t.Fatal("a downstream service accepted a token that doesn't name it")
		}
	})

	t.Run("the device and backchannel flows refuse a resource instead of dropping it", func(t *testing.T) {
		r := chi.NewRouter()
		h := &oidc.Handler{Service: svc}
		h.MountBrowser(r)
		h.MountPublic(r)
		post := func(path string, form url.Values) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			return rr
		}
		for name, rr := range map[string]*httptest.ResponseRecorder{
			"device poll": post("/oauth/token-code", url.Values{
				"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {client.ClientID},
				"device_code": {"x"}, "resource": {reports},
			}),
			"device authorization": post("/oauth/device_authorization", url.Values{
				"client_id": {client.ClientID}, "client_secret": {secret}, "resource": {reports},
			}),
		} {
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_target") {
				t.Fatalf("%s with a resource: %d %s; want 400 invalid_target", name, rr.Code, rr.Body.String())
			}
		}
	})
}
