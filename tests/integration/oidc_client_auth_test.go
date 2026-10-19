//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestPublicClientsCantStandInForConfidentialOnes pins what a client_id alone
// can do. A public application's id is in every sign-in link, so with no secret
// it may run its own sign-in (code + PKCE, refresh, device) and revoke its own
// tokens, but it is refused at introspection, token exchange and backchannel
// sign-in, and can't be registered or edited to hold those flows. A
// confidential application's wrong secret is refused and audited.
func TestPublicClientsCantStandInForConfidentialOnes(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("oidc-auth"))
	userID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, userID, tenantID)
	svc := oidc.NewService(testPool, mustIssuer())
	redirect := "https://app.example/cb"

	conf, secret := registerOIDCClient(t, ctx, svc, tenantID, redirect)
	register := func(t *testing.T, in oidc.CreateClientInput) (*oidc.Client, error) {
		t.Helper()
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		c, _, err := svc.RegisterClient(ctx, tx, in)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		return c, nil
	}
	spa, err := register(t, oidc.CreateClientInput{TenantID: tenantID, Name: "SPA", Type: "public", RedirectURIs: []string{redirect}})
	if err != nil {
		t.Fatalf("register public client: %v", err)
	}

	// A signed-in user's tokens, from the confidential client.
	code, _, err := svc.Authorize(ctx, userID, conf.ClientID, redirect, []string{"openid", "profile"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	userTokens, err := svc.ExchangeCode(ctx, conf.ClientID, secret, code, redirect, "", "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	authFailures := func(t *testing.T, clientID, reason string) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'oidc.client_auth_failed'
			    AND metadata->>'client_id' = $2 AND metadata->>'reason' = $3`,
			tenantID, clientID, reason).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		return n
	}

	t.Run("a public client can't introspect a token", func(t *testing.T) {
		before := authFailures(t, spa.ClientID, "public_client")
		out, err := svc.Introspect(ctx, spa.ClientID, "", userTokens.AccessToken, "")
		if !errors.Is(err, errs.ErrOIDCClientAuthFailed) || out != nil {
			t.Fatalf("introspect as a public client: out %v, err %v; want refused with nothing returned", out, err)
		}
		if authFailures(t, spa.ClientID, "public_client") != before+1 {
			t.Fatal("the refusal was not audited")
		}
	})

	t.Run("a confidential client still introspects with its secret", func(t *testing.T) {
		out, err := svc.Introspect(ctx, conf.ClientID, secret, userTokens.AccessToken, "")
		if err != nil || out["active"] != true {
			t.Fatalf("introspect: %v, %v", out, err)
		}
	})

	t.Run("a confidential client's wrong secret is refused and audited everywhere", func(t *testing.T) {
		before := authFailures(t, conf.ClientID, "invalid_secret")
		if _, err := svc.Introspect(ctx, conf.ClientID, "wrong", userTokens.AccessToken, ""); !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Fatalf("introspect: %v", err)
		}
		if err := svc.RevokeToken(ctx, conf.ClientID, "wrong", userTokens.RefreshToken, ""); !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Fatalf("revoke: %v", err)
		}
		if _, err := svc.RefreshToken(ctx, conf.ClientID, "wrong", userTokens.RefreshToken, ""); !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Fatalf("refresh: %v", err)
		}
		if got := authFailures(t, conf.ClientID, "invalid_secret"); got != before+3 {
			t.Fatalf("audited wrong-secret attempts = %d, want %d", got-before, 3)
		}
	})

	var spaRefresh string
	t.Run("the public browser sign-in with PKCE still works", func(t *testing.T) {
		verifier, challenge := newPKCE(t)
		c, _, err := svc.Authorize(ctx, userID, spa.ClientID, redirect, []string{"openid"}, "", challenge, "S256")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		out, err := svc.ExchangeCode(ctx, spa.ClientID, "", c, redirect, verifier, "")
		if err != nil || out.AccessToken == "" {
			t.Fatalf("exchange: %v", err)
		}
		spaRefresh = out.RefreshToken
	})

	t.Run("a public client can revoke its own refresh token", func(t *testing.T) {
		if spaRefresh == "" {
			t.Skip("no refresh token")
		}
		if err := svc.RevokeToken(ctx, spa.ClientID, "", spaRefresh, "refresh_token"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if _, err := svc.RefreshToken(ctx, spa.ClientID, "", spaRefresh, ""); err == nil {
			t.Fatal("the revoked refresh token still works")
		}
	})

	for _, grant := range []string{"urn:ietf:params:oauth:grant-type:token-exchange", "token_exchange", "urn:openid:params:grant-type:ciba"} {
		t.Run("a public client can't be registered with "+grant, func(t *testing.T) {
			_, err := register(t, oidc.CreateClientInput{
				TenantID: tenantID, Name: uniqueSlug("pub"), Type: "public",
				RedirectURIs: []string{redirect}, GrantTypes: []string{"authorization_code", grant},
			})
			if !errors.Is(err, errs.ErrOIDCUnsupportedFlow) {
				t.Fatalf("err = %v, want %v", err, errs.ErrOIDCUnsupportedFlow)
			}
		})
	}

	t.Run("a confidential client can still be registered with token exchange", func(t *testing.T) {
		if _, err := register(t, oidc.CreateClientInput{
			TenantID: tenantID, Name: uniqueSlug("svc"), Type: "confidential",
			GrantTypes: []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		}); err != nil {
			t.Fatalf("register: %v", err)
		}
	})

	update := func(t *testing.T, id uuid.UUID, in oidc.UpdateClientInput) error {
		t.Helper()
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		if _, err := svc.UpdateClient(ctx, tx, tenantID, id, in); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	t.Run("editing a public client to add token exchange is refused", func(t *testing.T) {
		grants := []string{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"}
		if err := update(t, spa.ID, oidc.UpdateClientInput{GrantTypes: &grants}); !errors.Is(err, errs.ErrOIDCUnsupportedFlow) {
			t.Fatalf("err = %v, want %v", err, errs.ErrOIDCUnsupportedFlow)
		}
	})

	t.Run("editing a client is held to the registration rules", func(t *testing.T) {
		for _, uris := range [][]string{{"https://app.example/cb#frag"}, {"http://app.example/cb"}, {}} {
			u := uris
			if err := update(t, conf.ID, oidc.UpdateClientInput{RedirectURIs: &u}); !errors.Is(err, errs.ErrOIDCRedirectURIInvalid) {
				t.Fatalf("redirect URIs %v: err = %v, want %v", u, err, errs.ErrOIDCRedirectURIInvalid)
			}
		}
		unknown := []string{"password"}
		if err := update(t, conf.ID, oidc.UpdateClientInput{GrantTypes: &unknown}); !errors.Is(err, errs.ErrOIDCGrantTypeUnsupported) {
			t.Fatalf("unknown grant: err = %v", err)
		}
		name := "Renamed RP"
		if err := update(t, conf.ID, oidc.UpdateClientInput{Name: &name}); err != nil {
			t.Fatalf("a valid edit was refused: %v", err)
		}
	})

	// A public client given these flows before registration checked them.
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.oidc_clients SET grant_types = $2 WHERE id = $1`, spa.ID,
		[]string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:openid:params:grant-type:ciba"}); err != nil {
		t.Fatalf("grant flows directly: %v", err)
	}

	t.Run("a public client holding token exchange is refused at request time", func(t *testing.T) {
		_, err := svc.TokenExchange(ctx, spa.ClientID, "", userTokens.AccessToken,
			"urn:ietf:params:oauth:token-type:access_token", "", "openid", "", "", "")
		if !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Fatalf("err = %v, want %v", err, errs.ErrOIDCClientAuthFailed)
		}
	})

	t.Run("a public client holding backchannel sign-in is refused at request time", func(t *testing.T) {
		var email string
		if err := testPool.QueryRow(ctx, `SELECT email FROM "user".users WHERE id = $1`, userID).Scan(&email); err != nil {
			t.Fatalf("read email: %v", err)
		}
		_, err := svc.BackchannelAuthorize(ctx, spa.ClientID, "", email, "openid", "")
		if !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Fatalf("err = %v, want %v", err, errs.ErrOIDCClientAuthFailed)
		}
	})
}
