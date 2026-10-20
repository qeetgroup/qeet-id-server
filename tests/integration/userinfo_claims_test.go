//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestUserinfoReturnsTheClaimsTheScopesGrant pins userinfo and the ID token to
// the OpenID Connect standard claims: email gives email and email_verified,
// profile gives name and picture, neither is returned without its scope; a
// token without openid is refused with the bearer challenge; POST answers like
// GET; an invalid token gets the invalid_token challenge; discovery lists the
// claims.
func TestUserinfoReturnsTheClaimsTheScopesGrant(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("userinfo"))
	userID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, userID, tenantID)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users
		SET display_name = 'Ada Lovelace', avatar_url = 'https://cdn.example/ada.png', email_verified_at = NOW()
		WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	var email string
	if err := testPool.QueryRow(ctx, `SELECT email FROM "user".users WHERE id = $1`, userID).Scan(&email); err != nil {
		t.Fatal(err)
	}
	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)
	redirect := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirect)

	signIn := func(t *testing.T, scopes ...string) *oidc.TokenResponse {
		t.Helper()
		code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirect, scopes, testNonce, testChallenge, "S256")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		out, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirect, testVerifier, "")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		return out
	}
	r := chi.NewRouter()
	r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: issuer}))
	(&oidc.Handler{Service: svc}).Mount(r)
	ask := func(method, token string) (*httptest.ResponseRecorder, map[string]any) {
		req := httptest.NewRequest(method, "/oauth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr, out
	}

	t.Run("email and profile give their claims, by GET and POST alike", func(t *testing.T) {
		tok := signIn(t, "openid", "email", "profile").AccessToken
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rr, out := ask(method, tok)
			if rr.Code != http.StatusOK || out["email"] != email || out["email_verified"] != true ||
				out["name"] != "Ada Lovelace" || out["picture"] != "https://cdn.example/ada.png" || out["sub"] != userID.String() {
				t.Fatalf("%s userinfo: %d %+v", method, rr.Code, out)
			}
			if _, ok := out["updated_at"]; !ok {
				t.Fatalf("%s userinfo: no updated_at with profile", method)
			}
		}
	})

	t.Run("without the email scope there is no email", func(t *testing.T) {
		rr, out := ask(http.MethodGet, signIn(t, "openid").AccessToken)
		if rr.Code != http.StatusOK {
			t.Fatalf("userinfo: %d", rr.Code)
		}
		for _, claim := range []string{"email", "email_verified", "name", "picture"} {
			if _, ok := out[claim]; ok {
				t.Fatalf("openid-only userinfo carries %s: %+v", claim, out)
			}
		}
	})

	t.Run("a token without openid is refused with the bearer challenge", func(t *testing.T) {
		tok, _, err := issuer.IssueAccess(userID, tenantID, uuid.New(), "email")
		if err != nil {
			t.Fatal(err)
		}
		rr, _ := ask(http.MethodGet, tok)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
			t.Fatalf("no openid: %d, challenge %q", rr.Code, rr.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("an invalid token gets the invalid_token challenge", func(t *testing.T) {
		rr, _ := ask(http.MethodGet, "not-a-token")
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("invalid token: %d, challenge %q", rr.Code, rr.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("the ID token carries the same claims", func(t *testing.T) {
		id := signIn(t, "openid", "email").IDToken
		if got := idTokenClaim(t, id, "email"); got != email {
			t.Fatalf("ID token email = %q, want %q", got, email)
		}
	})

	t.Run("discovery lists the claims it returns", func(t *testing.T) {
		pub := chi.NewRouter()
		(&oidc.Handler{Service: svc}).MountPublic(pub)
		rr := httptest.NewRecorder()
		pub.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
		var doc struct {
			Claims []string `json:"claims_supported"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &doc)
		for _, c := range []string{"email", "email_verified", "name", "picture", "updated_at"} {
			if !slices.Contains(doc.Claims, c) {
				t.Fatalf("claims_supported %v lacks %s", doc.Claims, c)
			}
		}
	})
}
