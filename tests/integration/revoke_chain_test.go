//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRevokingARefreshTokenEndsItsWholeGrant pins public revocation (RFC 7009)
// to the grant: any link of a rotated chain ends every link, introspection
// agrees, the admin grant list drops it, and it is audited. An access token is
// refused as unsupported_token_type instead of a success that revokes nothing;
// an unknown token, or another application's, is a no-op.
func TestRevokingARefreshTokenEndsItsWholeGrant(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("revoke"))
	userID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, userID, tenantID)
	svc := oidc.NewService(testPool, mustIssuer())
	redirect := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirect)
	other, otherSecret := registerOIDCClient(t, ctx, svc, tenantID, redirect)

	signIn := func(t *testing.T, clientID, clientSecret string) *oidc.TokenResponse {
		t.Helper()
		code, _, err := svc.Authorize(ctx, userID, clientID, redirect, []string{"openid"}, testNonce, testChallenge, "S256")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		out, err := svc.ExchangeCode(ctx, clientID, clientSecret, code, redirect, testVerifier, "")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		return out
	}
	rotate := func(t *testing.T, refresh string) string {
		t.Helper()
		out, err := svc.RefreshToken(ctx, client.ClientID, secret, refresh, "")
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		return out.RefreshToken
	}
	active := func(t *testing.T, token string) bool {
		t.Helper()
		resp, err := svc.Introspect(ctx, client.ClientID, secret, token, "")
		if err != nil {
			t.Fatalf("introspect: %v", err)
		}
		on, _ := resp["active"].(bool)
		return on
	}
	grantListed := func(t *testing.T) int {
		t.Helper()
		grants, err := svc.ListGrants(ctx, tenantID)
		if err != nil {
			t.Fatalf("list grants: %v", err)
		}
		n := 0
		for _, g := range grants {
			if g.ClientID == client.ClientID {
				n++
			}
		}
		return n
	}

	t.Run("revoking the newest link ends every earlier one, and the grant leaves the list", func(t *testing.T) {
		first := signIn(t, client.ClientID, secret).RefreshToken
		second := rotate(t, first)
		third := rotate(t, second)
		before := grantListed(t)
		if err := svc.RevokeToken(ctx, client.ClientID, secret, third, "refresh_token"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		for name, tok := range map[string]string{"first": first, "second": second, "third": third} {
			if active(t, tok) {
				t.Fatalf("the %s link of the revoked chain still introspects as active", name)
			}
		}
		if _, err := svc.RefreshToken(ctx, client.ClientID, secret, third, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
			t.Fatalf("renewing with the revoked token: err = %v, want %v", err, errs.ErrOIDCRefreshTokenRevoked)
		}
		if after := grantListed(t); after != before-1 {
			t.Fatalf("admin grant list: %d grant(s) before, %d after; want one fewer", before, after)
		}
		var audited int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events
			WHERE tenant_id = $1 AND action = 'oidc.grant_revoked' AND metadata->>'tokens_revoked' = '3'`, tenantID).Scan(&audited); err != nil || audited != 1 {
			t.Fatalf("revocation audit rows = %d (%v), want 1 naming 3 tokens", audited, err)
		}
	})

	t.Run("revoking an earlier link ends the live one too", func(t *testing.T) {
		first := signIn(t, client.ClientID, secret).RefreshToken
		live := rotate(t, first)
		if err := svc.RevokeToken(ctx, client.ClientID, secret, first, ""); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if active(t, live) {
			t.Fatal("the live link survived the revocation of an earlier one")
		}
	})

	t.Run("an access token is refused, not silently accepted", func(t *testing.T) {
		access := signIn(t, client.ClientID, secret).AccessToken
		err := svc.RevokeToken(ctx, client.ClientID, secret, access, "access_token")
		if err == nil || !strings.Contains(err.Error(), "unsupported_token_type") {
			t.Fatalf("revoking an access token: err = %v, want unsupported_token_type", err)
		}
	})

	t.Run("an unknown token, or another application's, is a no-op", func(t *testing.T) {
		if err := svc.RevokeToken(ctx, client.ClientID, secret, "no-such-token", ""); err != nil {
			t.Fatalf("unknown token: %v", err)
		}
		theirs := signIn(t, other.ClientID, otherSecret).RefreshToken
		if err := svc.RevokeToken(ctx, client.ClientID, secret, theirs, ""); err != nil {
			t.Fatalf("another application's token: %v", err)
		}
		if _, err := svc.RefreshToken(ctx, other.ClientID, otherSecret, theirs, ""); err != nil {
			t.Fatalf("the other application's grant was touched: %v", err)
		}
	})
}
