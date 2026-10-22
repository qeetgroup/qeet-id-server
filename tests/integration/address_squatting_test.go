//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// TestAnAddressIsClaimedOnlyByProvingIt: whoever holds the account for an
// address gets that person's invitations and federated sign-ins, so the
// account must have proved the address. Accepting an invitation link the
// inviter was also shown verified the address; a social sign-in adopted an
// existing account that never proved its address, its squatter's password
// still working. A link shown to someone else no longer verifies, a social
// sign-in adopts only a verified account, and a password reset — its link
// reaches only the address — verifies it, ending the squatter's password and
// sessions. Each verification records its proof.
func TestAnAddressIsClaimedOnlyByProvingIt(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	verified := func(t *testing.T, id uuid.UUID) bool {
		t.Helper()
		var v bool
		if err := testPool.QueryRow(ctx, `SELECT email_verified_at IS NOT NULL FROM "user".users WHERE id = $1`, id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	squat := func(t *testing.T, tenantID *uuid.UUID, email string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := testPool.QueryRow(ctx, `INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id`, tenantID, email).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}

	t.Run("accepting an invitation link the inviter was shown leaves the address unverified", func(t *testing.T) {
		svc := invite.NewService(testPool, &mailbox{}, time.Hour, "http://console.test")
		svc.SetPasswordRules(authpolicy.NewService(testPool))
		tenantID := createTenant(t, ctx, uniqueSlug("copied-link"))
		email := uniqueSlug("ceo") + "@another-company.example"
		_, link, err := svc.Create(ctx, invite.CreateInput{TenantID: tenantID, Email: email}, nil)
		if err != nil || link == "" {
			t.Fatalf("create = %q, %v; want the link the console can copy", link, err)
		}
		res, err := svc.Accept(ctx, invite.AcceptInput{Token: link, Password: "A-long-and-secret-passphrase-1"})
		if err != nil {
			t.Fatalf("accept the copied link: %v", err)
		}
		if verified(t, res.UserID) {
			t.Fatal("the address was marked verified by a link the inviter holds too")
		}
		if _, err := svc.ListForUser(ctx, res.UserID); !errors.Is(err, errs.ErrInviteEmailNotVerified) {
			t.Fatalf("the new account's invitation inbox = %v, want invite.email_not_verified", err)
		}
	})

	// An organisation's social provider vouching for the address.
	tenantID := createTenant(t, ctx, uniqueSlug("squat-org"))
	setSelfRegistration(t, ctx, tenantID, true)
	authSvc, _ := newAuth()
	orgProvider := func(t *testing.T, email string) (*social.Service, string) {
		t.Helper()
		idp := fakeIdPWithUserinfo(t, fmt.Sprintf(`{"sub":%q,"email":%q,"email_verified":true}`, uniqueSlug("sub"), email))
		t.Cleanup(idp.Close)
		provider := uniqueSlug("idp")
		if _, err := testPool.Exec(ctx, `
			INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, discovery_url)
			VALUES ($1, $2, 'cid', 'csecret', $3)`, tenantID, provider, idp.URL+"/.well-known/openid-configuration"); err != nil {
			t.Fatal(err)
		}
		svc := social.NewService(testPool, authSvc, "http://app.local", egress.DevelopmentPolicy())
		svc.SetCipher(testEnvelope(t))
		return svc, provider
	}
	orgSignIn := func(svc *social.Service, provider string) (*social.CallbackResult, error) {
		authURL, err := svc.BeginLogin(ctx, provider, tenantID.String(), "http://api.local/v1/social/"+provider+"/callback", "")
		if err != nil {
			return nil, err
		}
		u, _ := url.Parse(authURL)
		return svc.CompleteCallback(ctx, provider, u.Query().Get("state"), "upstream-code", true)
	}

	t.Run("an organisation's social sign-in doesn't adopt an account that never proved its address", func(t *testing.T) {
		email := uniqueSlug("victim") + "@corp.example"
		squatter := squat(t, &tenantID, email) // registered through the open hosted sign-up
		svc, provider := orgProvider(t, email)
		if res, err := orgSignIn(svc, provider); !errors.Is(err, errs.ErrSocialAccountUnverified) || (res != nil && res.Code != "") {
			t.Fatalf("sign-in = %+v, %v; want social.account_unverified and no code", res, err)
		}

		// The owner resets the password from the link only their inbox gets.
		rec := &recordSender{}
		reset := recovery.NewService(testPool, rec, time.Hour, "https://app.example")
		reset.SetPasswordRules(authpolicy.NewService(testPool))
		if _, err := reset.StartPasswordReset(ctx, email); err != nil {
			t.Fatal(err)
		}
		if err := reset.ConfirmPasswordReset(ctx, extractToken(t, rec.last.Body), "The-owner's-own-passphrase-2", recovery.AuditCtx{IP: "198.51.100.4"}); err != nil {
			t.Fatalf("reset: %v", err)
		}
		if !verified(t, squatter) {
			t.Fatal("a completed reset didn't verify the address")
		}
		var proof string
		if err := testPool.QueryRow(ctx, `SELECT metadata->>'proof' FROM audit.events
			WHERE resource_id = $1 AND action = 'email.verified' ORDER BY created_at DESC LIMIT 1`, squatter).Scan(&proof); err != nil || proof != "password_reset" {
			t.Fatalf("email.verified proof = %q (%v), want password_reset", proof, err)
		}
		if res, err := orgSignIn(svc, provider); err != nil || res.Code == "" {
			t.Fatalf("after the owner verified it, sign-in = %+v, %v; want a code", res, err)
		}
	})

	t.Run("the console's social sign-in doesn't adopt one either", func(t *testing.T) {
		email := uniqueSlug("victim") + "@example.com"
		squat(t, nil, email)
		idp := fakeIdPWithUserinfo(t, fmt.Sprintf(`{"sub":%q,"email":%q,"email_verified":true}`, uniqueSlug("sub"), email))
		defer idp.Close()
		svc := social.NewService(testPool, authSvc, "http://app.local", egress.DevelopmentPolicy())
		provider := uniqueSlug("console-idp")
		svc.SetPlatformProvider(provider, "cid", "secret", idp.URL+"/.well-known/openid-configuration")
		loginURL, err := svc.BeginPlatformLogin(ctx, provider, "http://api.local/v1/social/"+provider+"/callback", false)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(loginURL)
		if res, err := svc.CompletePlatformCallback(ctx, provider, u.Query().Get("state"), "login-code", true); !errors.Is(err, errs.ErrSocialAccountUnverified) || (res != nil && res.LoginCode != "") {
			t.Fatalf("console sign-in = %+v, %v; want social.account_unverified and no code", res, err)
		}
	})
}
