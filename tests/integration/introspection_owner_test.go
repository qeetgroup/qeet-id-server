//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
)

// TestIntrospectionAnswersOnlyForTheTokensOwner pins introspection (RFC 7662)
// to the token's owner: the application it was issued to, or the service that
// serves a registered resource it was issued for. Another application of the
// same tenant gets active false, and the attempt is audited. The answer names
// the token's real audience and its resource.
func TestIntrospectionAnswersOnlyForTheTokensOwner(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("introspect"))
	userID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, userID, tenantID)
	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)
	redirect := "https://app.example/cb"
	a, aSecret := registerOIDCClient(t, ctx, svc, tenantID, redirect)
	b, bSecret := registerOIDCClient(t, ctx, svc, tenantID, redirect)
	server, serverSecret := registerOIDCClient(t, ctx, svc, tenantID, redirect)
	const reports = "https://reports.example.com"
	registerResource(t, ctx, svc, tenantID, reports, server.ClientID)

	signIn := func(t *testing.T, clientID, secret, resource string) *oidc.TokenResponse {
		t.Helper()
		code, _, err := svc.AuthorizeInLoginSession(ctx, uuid.Nil, userID, clientID, redirect, []string{"openid"},
			testNonce, testChallenge, "S256", "", resource)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		out, err := svc.ExchangeCode(ctx, clientID, secret, code, redirect, testVerifier, "")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		return out
	}
	introspect := func(t *testing.T, clientID, secret, token string) map[string]any {
		t.Helper()
		out, err := svc.Introspect(ctx, clientID, secret, token, "")
		if err != nil {
			t.Fatalf("introspect: %v", err)
		}
		return out
	}
	bTokens := signIn(t, b.ClientID, bSecret, "")

	t.Run("another application of the tenant learns nothing, and is recorded", func(t *testing.T) {
		if out := introspect(t, a.ClientID, aSecret, bTokens.AccessToken); out["active"] != false || len(out) != 1 {
			t.Fatalf("A introspecting B's access token: %+v, want only active false", out)
		}
		if out := introspect(t, a.ClientID, aSecret, bTokens.RefreshToken); out["active"] != false {
			t.Fatalf("A introspecting B's refresh token: %+v, want active false", out)
		}
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events
			WHERE tenant_id = $1 AND action = 'oidc.introspection_refused'
			  AND metadata->>'client_id' = $2 AND metadata->>'token_client_id' = $3`, tenantID, a.ClientID, b.ClientID).Scan(&n); err != nil || n != 1 {
			t.Fatalf("refused introspection audit rows = %d (%v), want 1", n, err)
		}
	})

	t.Run("the owner sees its token, with the real audience", func(t *testing.T) {
		out := introspect(t, b.ClientID, bSecret, bTokens.AccessToken)
		if out["active"] != true || out["client_id"] != b.ClientID || out["aud"] != issuer.JWTAudience() {
			t.Fatalf("B introspecting its own token: %+v", out)
		}
	})

	t.Run("a token for a resource names it, and the service serving it may introspect it", func(t *testing.T) {
		tok := signIn(t, a.ClientID, aSecret, reports).AccessToken
		for name, c := range map[string][2]string{"the issuing application": {a.ClientID, aSecret}, "the resource's server": {server.ClientID, serverSecret}} {
			out := introspect(t, c[0], c[1], tok)
			if out["active"] != true || out["aud"] != reports || out["resource"] != reports {
				t.Fatalf("%s introspecting a resource token: %+v, want active with aud and resource %q", name, out, reports)
			}
		}
		if out := introspect(t, b.ClientID, bSecret, tok); out["active"] != false {
			t.Fatalf("an unrelated application introspecting a resource token: %+v, want active false", out)
		}
	})

	t.Run("a token from another tenant stays inactive", func(t *testing.T) {
		other := createTenant(t, ctx, uniqueSlug("introspect-other"))
		otherSvc := oidc.NewService(testPool, issuer)
		oc, oSecret := registerOIDCClient(t, ctx, otherSvc, other, redirect)
		if out := introspect(t, oc.ClientID, oSecret, bTokens.AccessToken); out["active"] != false {
			t.Fatalf("another tenant's application: %+v, want active false", out)
		}
	})
}
