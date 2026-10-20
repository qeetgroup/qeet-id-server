//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestEveryApplicationProvesItsSignIns pins the authorization-code rules for
// every application, confidential ones included: a PKCE code_challenge (S256)
// and, with openid, a nonce that comes back in the ID token. A confidential
// application can be exempted until a date within 90 days, which its details
// show; outside it, it is held to the rules. A code presented twice revokes
// what its first redemption issued.
func TestEveryApplicationProvesItsSignIns(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("pkce-all"))
	userID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, userID, tenantID)
	svc := oidc.NewService(testPool, mustIssuer())
	redirect := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirect)
	openid := []string{"openid"}

	exempt := func(t *testing.T, c *oidc.Client, until *time.Time) (*oidc.Client, error) {
		t.Helper()
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		updated, err := svc.UpdateClient(ctx, tx, tenantID, c.ID, oidc.UpdateClientInput{
			PKCEExemptUntil: oidc.OptionalTime{Set: true, At: until},
		})
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		return updated, nil
	}
	at := func(d time.Duration) *time.Time { v := time.Now().Add(d).UTC().Truncate(time.Second); return &v }

	t.Run("a confidential application that sends no proof key is refused", func(t *testing.T) {
		if _, _, err := svc.Authorize(ctx, userID, client.ClientID, redirect, openid, testNonce, "", ""); !errors.Is(err, errs.ErrOIDCCodeChallengeRequired) {
			t.Fatalf("no challenge: err = %v, want %v", err, errs.ErrOIDCCodeChallengeRequired)
		}
	})

	t.Run("openid without a nonce is refused", func(t *testing.T) {
		if _, _, err := svc.Authorize(ctx, userID, client.ClientID, redirect, openid, "", testChallenge, "S256"); !errors.Is(err, errs.ErrOIDCNonceRequired) {
			t.Fatalf("no nonce: err = %v, want %v", err, errs.ErrOIDCNonceRequired)
		}
	})

	t.Run("the plain method is refused, as before", func(t *testing.T) {
		if _, _, err := svc.Authorize(ctx, userID, client.ClientID, redirect, openid, testNonce, testVerifier, "plain"); !errors.Is(err, errs.ErrOIDCCodeChallengeMethodUnsupported) {
			t.Fatalf("plain: err = %v, want %v", err, errs.ErrOIDCCodeChallengeMethodUnsupported)
		}
	})

	t.Run("the hosted consent screen isn't asked for a request that would be refused", func(t *testing.T) {
		_, err := svc.StartConsentRequest(ctx, uuid.New(), userID, oidc.ConsentRequest{
			ClientID: client.ClientID, RedirectURI: redirect, Scopes: openid, Nonce: testNonce,
		})
		if !errors.Is(err, errs.ErrOIDCCodeChallengeRequired) {
			t.Fatalf("consent request without a challenge: err = %v, want %v", err, errs.ErrOIDCCodeChallengeRequired)
		}
	})

	t.Run("the ID token carries the nonce that was sent", func(t *testing.T) {
		code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirect, openid, testNonce, testChallenge, "S256")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirect, testVerifier, "")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if got := idTokenClaim(t, issued.IDToken, "nonce"); got != testNonce {
			t.Fatalf("ID token nonce = %q, want %q", got, testNonce)
		}
	})

	t.Run("an exemption keeps an application working until it ends, and the application shows when", func(t *testing.T) {
		until := at(7 * 24 * time.Hour)
		updated, err := exempt(t, client, until)
		if err != nil {
			t.Fatalf("exempt: %v", err)
		}
		got, err := svc.GetClient(ctx, tenantID, client.ID)
		if err != nil {
			t.Fatalf("get client: %v", err)
		}
		if updated.PKCEExemptUntil == nil || got.PKCEExemptUntil == nil || !got.PKCEExemptUntil.Equal(*until) {
			t.Fatalf("pkce_exempt_until = %v (update) / %v (get), want %v", updated.PKCEExemptUntil, got.PKCEExemptUntil, until)
		}
		code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirect, openid, "", "", "")
		if err != nil {
			t.Fatalf("authorize while exempt: %v", err)
		}
		if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirect, "", ""); err != nil {
			t.Fatalf("exchange while exempt: %v", err)
		}

		// A code issued while exempt doesn't redeem once the exemption has ended.
		pending, _, err := svc.Authorize(ctx, userID, client.ClientID, redirect, openid, "", "", "")
		if err != nil {
			t.Fatalf("authorize while exempt: %v", err)
		}
		if _, err := testPool.Exec(ctx, `UPDATE auth.oidc_clients SET pkce_exempt_until = NOW() - INTERVAL '1 minute' WHERE id = $1`, client.ID); err != nil {
			t.Fatalf("end the exemption: %v", err)
		}
		if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, pending, redirect, "", ""); !errors.Is(err, errs.ErrOIDCCodeChallengeRequired) {
			t.Fatalf("exchange after the exemption ended: err = %v, want %v", err, errs.ErrOIDCCodeChallengeRequired)
		}
		if _, _, err := svc.Authorize(ctx, userID, client.ClientID, redirect, openid, "", "", ""); !errors.Is(err, errs.ErrOIDCCodeChallengeRequired) {
			t.Fatalf("authorize after the exemption ended: err = %v, want %v", err, errs.ErrOIDCCodeChallengeRequired)
		}
		if cleared, err := exempt(t, client, nil); err != nil || cleared.PKCEExemptUntil != nil {
			t.Fatalf("clear the exemption: %v, %v", cleared, err)
		}
	})

	t.Run("an exemption is for a confidential application and ends in the future, within 90 days", func(t *testing.T) {
		public := registerOIDCPublicClient(t, ctx, svc, tenantID, "https://spa.example/cb")
		for name, c := range map[string]struct {
			client *oidc.Client
			until  *time.Time
		}{
			"a public application": {public, at(24 * time.Hour)},
			"already over":         {client, at(-time.Minute)},
			"beyond 90 days":       {client, at(91 * 24 * time.Hour)},
		} {
			if _, err := exempt(t, c.client, c.until); !errors.Is(err, errs.ErrOIDCPKCEExemptionInvalid) {
				t.Fatalf("%s: err = %v, want %v", name, err, errs.ErrOIDCPKCEExemptionInvalid)
			}
		}
	})

	t.Run("a code presented twice revokes what its first redemption issued, and only that", func(t *testing.T) {
		signIn := func(t *testing.T) (string, *oidc.TokenResponse) {
			t.Helper()
			code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirect, openid, testNonce, testChallenge, "S256")
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirect, testVerifier, "")
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			return code, issued
		}
		code, first := signIn(t)
		_, other := signIn(t)
		renewed, err := svc.RefreshToken(ctx, client.ClientID, secret, first.RefreshToken, "")
		if err != nil {
			t.Fatalf("renew: %v", err)
		}
		if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirect, testVerifier, ""); !errors.Is(err, errs.ErrOIDCAuthCodeUsed) {
			t.Fatalf("second redemption: err = %v, want %v", err, errs.ErrOIDCAuthCodeUsed)
		}
		if _, err := svc.RefreshToken(ctx, client.ClientID, secret, renewed.RefreshToken, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
			t.Fatalf("renewing the grant from the reused code: err = %v, want %v", err, errs.ErrOIDCRefreshTokenRevoked)
		}
		if _, err := svc.RefreshToken(ctx, client.ClientID, secret, other.RefreshToken, ""); err != nil {
			t.Fatalf("a grant from another code was revoked too: %v", err)
		}
		var audited int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events
			WHERE tenant_id = $1 AND action = 'oidc.authorization_code_reused' AND metadata->>'client_id' = $2`,
			tenantID, client.ClientID).Scan(&audited); err != nil || audited != 1 {
			t.Fatalf("reuse audit rows = %d (%v), want 1", audited, err)
		}
	})
}

// idTokenClaim reads one claim from an ID token's payload (already verified
// by the issuer that minted it).
func idTokenClaim(t *testing.T, idToken, claim string) string {
	t.Helper()
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", idToken)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode ID token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("parse ID token payload: %v", err)
	}
	v, _ := claims[claim].(string)
	return v
}
