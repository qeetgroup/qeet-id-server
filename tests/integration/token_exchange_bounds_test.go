//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestTokenExchangeNeverExtendsACredential pins RFC 8693 exchange's bounds: the
// result expires no later than the subject token; a suspended person's token
// is refused; only an application entitled to the subject (issued to it, or
// the person delegated to it) may exchange; a chain stops at the configured
// depth; every exchange is audited; a narrower single hop still works.
func TestTokenExchangeNeverExtendsACredential(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("exchange"))
	userID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, userID, tenantID)
	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)
	svc.SetTokenExchangeMaxDepth(2)
	register := func(t *testing.T) (*oidc.Client, string) {
		t.Helper()
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
			TenantID: tenantID, Name: "Exchanger", RedirectURIs: []string{"https://app.example/cb"},
			GrantTypes: []string{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return c, secret
	}
	client, secret := register(t)
	if err := svc.GrantConsent(ctx, userID, client.ClientID, []string{"doc.read", "doc.write"}); err != nil {
		t.Fatal(err)
	}
	subject := func(t *testing.T, life time.Duration) string {
		t.Helper()
		tok, _, err := issuer.IssueSessionAccess(userID, tenantID, uuid.New(), map[string]any{}, time.Now().Add(life))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	exchange := func(c *oidc.Client, secret, token, scope string) (*oidc.TokenResponse, error) {
		return svc.TokenExchange(ctx, c.ClientID, secret, token, "", "", scope, "", "", "")
	}

	t.Run("the result expires no later than the subject token", func(t *testing.T) {
		out, err := exchange(client, secret, subject(t, 2*time.Minute), "")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		claims, err := issuer.VerifyAccessAnyAudience(out.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		if claims.ExpiresAt.After(time.Now().Add(2*time.Minute + 2*time.Second)) {
			t.Fatalf("exchanged token expires %v, after the subject's two minutes", claims.ExpiresAt)
		}
	})

	t.Run("a narrower single hop succeeds with the narrower scopes", func(t *testing.T) {
		tok, _, err := issuer.IssueAccess(userID, tenantID, uuid.New(), "doc.read doc.write")
		if err != nil {
			t.Fatal(err)
		}
		out, err := exchange(client, secret, tok, "doc.read")
		if err != nil || out.Scope != "doc.read" {
			t.Fatalf("narrower exchange: %+v, %v", out, err)
		}
	})

	t.Run("an application the person didn't delegate to can't exchange their token", func(t *testing.T) {
		stranger, strangerSecret := register(t)
		if _, err := exchange(stranger, strangerSecret, subject(t, 5*time.Minute), ""); !errors.Is(err, errs.ErrOIDCSubjectTokenInvalid) {
			t.Fatalf("exchange by an unentitled application: err = %v, want %v", err, errs.ErrOIDCSubjectTokenInvalid)
		}
	})

	t.Run("a chain stops at the configured depth", func(t *testing.T) {
		first, err := exchange(client, secret, subject(t, 5*time.Minute), "")
		if err != nil {
			t.Fatalf("first exchange: %v", err)
		}
		second, err := exchange(client, secret, first.AccessToken, "")
		if err != nil {
			t.Fatalf("second exchange: %v", err)
		}
		if _, err := exchange(client, secret, second.AccessToken, ""); !errors.Is(err, errs.ErrOIDCExchangeDepthExceeded) {
			t.Fatalf("third exchange: err = %v, want %v", err, errs.ErrOIDCExchangeDepthExceeded)
		}
	})

	t.Run("every exchange is audited", func(t *testing.T) {
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events
			WHERE tenant_id = $1 AND action = 'oidc.token_exchanged' AND actor_user_id = $2
			  AND metadata->>'client_id' = $3 AND metadata ? 'scope' AND metadata ? 'resource' AND metadata ? 'actor'`,
			tenantID, userID, client.ClientID).Scan(&n); err != nil || n < 4 {
			t.Fatalf("exchange audit rows = %d (%v), want one per exchange (4)", n, err)
		}
	})

	t.Run("a suspended person's token is refused", func(t *testing.T) {
		tok := subject(t, 5*time.Minute)
		if _, err := testPool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, userID); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = testPool.Exec(ctx, `UPDATE "user".users SET status = 'active' WHERE id = $1`, userID) })
		if _, err := exchange(client, secret, tok, ""); !errors.Is(err, errs.ErrAuthAccountSuspended) {
			t.Fatalf("exchange for a suspended person: err = %v, want %v", err, errs.ErrAuthAccountSuspended)
		}
	})
}
