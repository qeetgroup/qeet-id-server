//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestApplicationGrantsStopWhenTheAccountDoes pins every application grant to
// the account's standing. Once a user is suspended or deleted, no application
// can renew, redeem or collect tokens for them, by refresh, authorization
// code, device or backchannel, and the refused refresh ends that application's
// grants for the user. An active account renews as before.
func TestApplicationGrantsStopWhenTheAccountDoes(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("standing"))
	svc := oidc.NewService(testPool, mustIssuer())
	redirect := "https://app.example/cb"
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "RP", Type: "confidential", RedirectURIs: []string{redirect},
		GrantTypes: []string{"authorization_code", "refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code", "urn:openid:params:grant-type:ciba"},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	member := func(t *testing.T) uuid.UUID {
		t.Helper()
		id := createUserInTenant(t, ctx, tenantID)
		addTenantMembership(t, ctx, id, tenantID)
		return id
	}
	code := func(t *testing.T, userID uuid.UUID) string {
		t.Helper()
		c, _, err := svc.Authorize(ctx, userID, client.ClientID, redirect, []string{"openid"}, testNonce, testChallenge, "S256")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		return c
	}
	signIn := func(t *testing.T, userID uuid.UUID) *oidc.TokenResponse {
		t.Helper()
		out, err := svc.ExchangeCode(ctx, client.ClientID, secret, code(t, userID), redirect, testVerifier, "")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		return out
	}
	suspend := func(t *testing.T, userID uuid.UUID) {
		t.Helper()
		if _, err := testPool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, userID); err != nil {
			t.Fatalf("suspend: %v", err)
		}
	}
	softDelete := func(t *testing.T, userID uuid.UUID) {
		t.Helper()
		if _, err := testPool.Exec(ctx, `UPDATE "user".users SET status = 'deleted', deleted_at = NOW() WHERE id = $1`, userID); err != nil {
			t.Fatalf("delete: %v", err)
		}
	}

	t.Run("an active account renews as before", func(t *testing.T) {
		tok := signIn(t, member(t))
		if _, err := svc.RefreshToken(ctx, client.ClientID, secret, tok.RefreshToken, ""); err != nil {
			t.Fatalf("refresh: %v", err)
		}
	})

	t.Run("a suspended account can't renew, and its other grants for the app end", func(t *testing.T) {
		uma := member(t)
		first, second := signIn(t, uma), signIn(t, uma)
		suspend(t, uma)
		if _, err := svc.RefreshToken(ctx, client.ClientID, secret, first.RefreshToken, ""); !errors.Is(err, errs.ErrAuthAccountSuspended) {
			t.Fatalf("refresh after suspend: err = %v, want %v", err, errs.ErrAuthAccountSuspended)
		}
		if _, err := testPool.Exec(ctx, `UPDATE "user".users SET status = 'active' WHERE id = $1`, uma); err != nil {
			t.Fatalf("reactivate: %v", err)
		}
		if _, err := svc.RefreshToken(ctx, client.ClientID, secret, second.RefreshToken, ""); err == nil {
			t.Fatal("a grant from before the suspension still renews after reactivation")
		}
	})

	t.Run("a deleted account can't renew", func(t *testing.T) {
		uma := member(t)
		tok := signIn(t, uma)
		softDelete(t, uma)
		if _, err := svc.RefreshToken(ctx, client.ClientID, secret, tok.RefreshToken, ""); !errors.Is(err, errs.ErrAuthAccountSuspended) {
			t.Fatalf("refresh after delete: err = %v, want %v", err, errs.ErrAuthAccountSuspended)
		}
	})

	t.Run("a code issued before the suspension can't be redeemed after it", func(t *testing.T) {
		uma := member(t)
		c := code(t, uma)
		suspend(t, uma)
		if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, c, redirect, testVerifier, ""); !errors.Is(err, errs.ErrAuthAccountSuspended) {
			t.Fatalf("exchange after suspend: err = %v, want %v", err, errs.ErrAuthAccountSuspended)
		}
	})

	t.Run("a device approved before the suspension gets no tokens after it", func(t *testing.T) {
		uma := member(t)
		device, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
		if err != nil {
			t.Fatalf("device authorize: %v", err)
		}
		if err := svc.DecideDevice(ctx, uma, userCode, true, ""); err != nil {
			t.Fatalf("approve device: %v", err)
		}
		suspend(t, uma)
		_, err = svc.DeviceToken(ctx, client.ClientID, device, "")
		if err == nil || !strings.Contains(err.Error(), "account_suspended") {
			t.Fatalf("device token after suspend: err = %v, want account_suspended", err)
		}
	})

	t.Run("a backchannel request approved before the suspension gets no tokens after it", func(t *testing.T) {
		uma := member(t)
		var email string
		if err := testPool.QueryRow(ctx, `SELECT email FROM "user".users WHERE id = $1`, uma).Scan(&email); err != nil {
			t.Fatalf("read email: %v", err)
		}
		req, err := svc.BackchannelAuthorize(ctx, client.ClientID, secret, email, "openid", "")
		if err != nil {
			t.Fatalf("backchannel authorize: %v", err)
		}
		pending, err := svc.ListPendingCIBA(ctx, uma)
		if err != nil || len(pending) != 1 {
			t.Fatalf("pending backchannel requests: %v, %v", pending, err)
		}
		if err := svc.DecideBackchannel(ctx, uma, pending[0].ID, true); err != nil {
			t.Fatalf("approve backchannel: %v", err)
		}
		suspend(t, uma)
		_, err = svc.BackchannelToken(ctx, client.ClientID, req.AuthReqID)
		if err == nil || !strings.Contains(err.Error(), "account_suspended") {
			t.Fatalf("backchannel token after suspend: err = %v, want account_suspended", err)
		}
	})
}
