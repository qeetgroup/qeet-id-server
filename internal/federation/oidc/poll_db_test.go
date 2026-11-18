//go:build integration

package oidc

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestPolledGrantsRedeemAlike checks that the device and backchannel grants
// collect an approval the same way: refused while the client is no longer
// registered for the grant, and collected once it is again; refused once the
// person left the application's organization, the request spent; and when the
// refresh token fails to be stored, nothing is spent, so the next poll gets
// the tokens.
func TestPolledGrantsRedeemAlike(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	organization, home := dbtest.Organization(t), dbtest.Organization(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	device, _ := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Type: "public", GrantTypes: []string{grantTypeDeviceCode, "refresh_token"}})
	ciba, cibaSecret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: []string{grantTypeCIBA, "refresh_token"}})

	for _, tc := range []struct {
		name, grant, requests string
		client                *Client
		// approved returns the code of a request a approved.
		approved func(a dbtest.Account) string
		collect  func(code string) (*TokenResponse, error)
	}{
		{
			name: "device", grant: grantTypeDeviceCode, requests: "auth.oidc_device_codes", client: device,
			approved: func(a dbtest.Account) string {
				t.Helper()
				raw, userCode, _, err := svc.DeviceAuthorize(ctx, device.ClientID, nil)
				if err != nil {
					t.Fatalf("device authorize: %v", err)
				}
				if err := svc.DecideDevice(ctx, a.ID, userCode, true, deviceIP); err != nil {
					t.Fatalf("approve: %v", err)
				}
				return raw
			},
			collect: func(code string) (*TokenResponse, error) {
				return svc.DeviceToken(ctx, device.ClientID, "", code, deviceIP)
			},
		},
		{
			name: "backchannel", grant: grantTypeCIBA, requests: "auth.oidc_ciba_requests", client: ciba,
			approved: func(a dbtest.Account) string {
				t.Helper()
				raw, id := pendingBackchannel(t, svc, ciba, cibaSecret, a)
				if err := svc.DecideBackchannel(ctx, a.ID, uuid.Nil, id, true, ""); err != nil {
					t.Fatalf("approve: %v", err)
				}
				return raw
			},
			collect: func(code string) (*TokenResponse, error) {
				return svc.BackchannelToken(ctx, ciba.ClientID, cibaSecret, code)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A poll at once after another is slow_down; the test polls as if later.
			repoll := func() {
				exec(`UPDATE `+tc.requests+` SET last_polled_at = NULL WHERE organization_id = $1 AND client_id = $2`, organization, tc.client.ClientID)
			}
			spent := func(code string) bool {
				hashColumn := "device_code_hash"
				if tc.grant == grantTypeCIBA {
					hashColumn = "auth_req_id_hash"
				}
				return dbtest.Count(t, `SELECT count(*) FROM `+tc.requests+` WHERE organization_id = $1 AND `+hashColumn+` = $2 AND consumed_at IS NOT NULL`,
					organization, codes.Hash(code)) == 1
			}
			person := dbtest.User(t, organization, organization)

			code := tc.approved(person)
			exec(`UPDATE auth.oidc_clients SET grant_types = ARRAY['refresh_token'] WHERE client_id = $1`, tc.client.ClientID)
			if _, err := tc.collect(code); !errors.Is(err, ErrGrantTypeNotAllowed) {
				t.Errorf("collect once the client lost the grant: %v, want %v", err, ErrGrantTypeNotAllowed)
			}
			exec(`UPDATE auth.oidc_clients SET grant_types = ARRAY[$2, 'refresh_token'] WHERE client_id = $1`, tc.client.ClientID, tc.grant)
			repoll()
			if issued, err := tc.collect(code); err != nil || issued.AccessToken == "" || issued.RefreshToken == "" {
				t.Errorf("collect once the client has the grant again: %+v, %v; want the tokens", issued, err)
			}

			code = tc.approved(person)
			owner := dbtest.Owner(t)
			if _, err := owner.Exec(ctx, `
				CREATE FUNCTION pg_temp.refuse_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refresh store down'; END $$;
				CREATE TRIGGER refuse_refresh BEFORE INSERT ON auth.oidc_refresh_tokens FOR EACH ROW
				WHEN (NEW.client_id = '`+tc.client.ClientID+`') EXECUTE FUNCTION pg_temp.refuse_refresh()`); err != nil {
				t.Fatal(err)
			}
			repoll()
			if _, err := tc.collect(code); err == nil {
				t.Error("collect while the refresh token can't be stored: tokens issued")
			}
			if _, err := owner.Exec(ctx, `DROP TRIGGER refuse_refresh ON auth.oidc_refresh_tokens`); err != nil {
				t.Fatal(err)
			}
			if spent(code) {
				t.Error("a failed collection spent the request")
			}
			repoll()
			if issued, err := tc.collect(code); err != nil || issued.RefreshToken == "" {
				t.Errorf("collect after the failed store: %+v, %v; want the tokens", issued, err)
			}

			guest := dbtest.User(t, home, home, organization)
			code = tc.approved(guest)
			exec(`DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, guest.ID, organization)
			repoll()
			if issued, err := tc.collect(code); !errors.Is(err, ErrUserOrganizationMismatch) {
				t.Errorf("collect once the person left the organization: %+v, %v; want %v", issued, err, ErrUserOrganizationMismatch)
			}
			if !spent(code) {
				t.Error("the refused collection left the request unspent")
			}
		})
	}
}

// TestDevicePollingAuthenticatesConfidentialClients checks that collecting a
// device grant's tokens needs a confidential client's secret, and a public
// client's device_code alone.
func TestDevicePollingAuthenticatesConfidentialClients(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	grants := []string{"urn:ietf:params:oauth:grant-type:device_code"}

	approved := func(clientID string) string {
		t.Helper()
		raw, userCode, _, err := svc.DeviceAuthorize(ctx, clientID, nil)
		if err != nil {
			t.Fatalf("device authorize: %v", err)
		}
		if err := svc.DecideDevice(ctx, user.ID, userCode, true, deviceIP); err != nil {
			t.Fatalf("approve device: %v", err)
		}
		return raw
	}

	confidential, secret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: grants})
	deviceCode := approved(confidential.ClientID)
	for name, presented := range map[string]string{"no secret": "", "a wrong secret": "wrong-secret"} {
		if _, err := svc.DeviceToken(ctx, confidential.ClientID, presented, deviceCode, deviceIP); !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Errorf("confidential client polling with %s: %v, want %v", name, err, errs.ErrOIDCClientAuthFailed)
		}
	}
	if issued, err := svc.DeviceToken(ctx, confidential.ClientID, secret, deviceCode, deviceIP); err != nil || issued.AccessToken == "" {
		t.Fatalf("confidential client polling with its secret: %+v, %v", issued, err)
	}

	public, _ := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Type: "public", GrantTypes: grants})
	if issued, err := svc.DeviceToken(ctx, public.ClientID, "", approved(public.ClientID), deviceIP); err != nil || issued.AccessToken == "" {
		t.Fatalf("public client polling: %+v, %v", issued, err)
	}
}

// TestBackchannelPollingAuthenticatesTheClient checks that collecting a CIBA
// grant's tokens needs the client's secret.
func TestBackchannelPollingAuthenticatesTheClient(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	client, secret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: []string{grantTypeCIBA}})

	started, err := svc.BackchannelAuthorize(ctx, client.ClientID, secret, user.Email, "openid", "")
	if err != nil {
		t.Fatalf("backchannel authorize: %v", err)
	}
	pending, err := svc.ListPendingCIBA(ctx, user.ID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending requests: %+v, %v", pending, err)
	}
	if err := svc.DecideBackchannel(ctx, user.ID, uuid.Nil, pending[0].ID, true, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	for name, presented := range map[string]string{"no secret": "", "a wrong secret": "wrong-secret"} {
		if _, err := svc.BackchannelToken(ctx, client.ClientID, presented, started.AuthReqID); !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Errorf("polling with %s: %v, want %v", name, err, errs.ErrOIDCClientAuthFailed)
		}
	}
	if issued, err := svc.BackchannelToken(ctx, client.ClientID, secret, started.AuthReqID); err != nil || issued.AccessToken == "" {
		t.Fatalf("polling with the secret: %+v, %v", issued, err)
	}
}

// TestPollTokenAnswersInOrder pins what polling with a device code answers at
// each step, and what each answer leaves behind: the poll's time, the spent
// request, and the tokens of the one successful poll.
func TestPollTokenAnswersInOrder(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	device, _ := registerClientWith(t, svc, CreateClientInput{
		OrganizationID: organization, Type: "public", GrantTypes: []string{grantTypeDeviceCode, "refresh_token"},
		Scopes: []string{"openid", "profile"},
	})
	other, _ := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Type: "public", GrantTypes: []string{grantTypeDeviceCode}})
	person := dbtest.User(t, organization, organization)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	type stored struct {
		polled, spent bool
	}
	row := func(code string) stored {
		t.Helper()
		var s stored
		if err := pool.QueryRow(ctx, `SELECT last_polled_at IS NOT NULL, consumed_at IS NOT NULL FROM auth.oidc_device_codes WHERE device_code_hash = $1`,
			codes.Hash(code)).Scan(&s.polled, &s.spent); err != nil {
			t.Fatal(err)
		}
		return s
	}
	issue := func(approve bool) string {
		t.Helper()
		raw, userCode, _, err := svc.DeviceAuthorize(ctx, device.ClientID, []string{"openid", "profile"})
		if err != nil {
			t.Fatalf("device authorize: %v", err)
		}
		if approve {
			if err := svc.DecideDevice(ctx, person.ID, userCode, true, deviceIP); err != nil {
				t.Fatalf("approve: %v", err)
			}
		}
		return raw
	}
	poll := func(code string) (*TokenResponse, error) {
		exec(`UPDATE auth.oidc_device_codes SET last_polled_at = NULL WHERE device_code_hash = $1`, codes.Hash(code))
		return svc.DeviceToken(ctx, device.ClientID, "", code, deviceIP)
	}
	refusal := func(err error) string {
		var oe *oauthError
		if errors.As(err, &oe) {
			return oe.Code + ": " + oe.Description
		}
		if err == nil {
			return "<nil>"
		}
		return err.Error()
	}

	if _, err := svc.DeviceToken(ctx, device.ClientID, "", "", deviceIP); refusal(err) != "invalid_request: device_code required" {
		t.Errorf("no code: %s", refusal(err))
	}
	if _, err := svc.DeviceToken(ctx, device.ClientID, "", "not-a-code", deviceIP); refusal(err) != "invalid_grant: unknown device_code" {
		t.Errorf("unknown code: %s", refusal(err))
	}
	pending := issue(false)
	if _, err := svc.DeviceToken(ctx, other.ClientID, "", pending, deviceIP); refusal(err) != "invalid_grant: client mismatch" {
		t.Errorf("another client's code: %s", refusal(err))
	}
	if row(pending).polled {
		t.Error("a mismatched client's poll was timed")
	}
	if _, err := poll(pending); refusal(err) != "authorization_pending: the user has not yet completed authorization" {
		t.Errorf("pending: %s", refusal(err))
	}
	if s := row(pending); !s.polled || s.spent {
		t.Errorf("after a pending poll: %+v, want timed and not spent", s)
	}
	if _, err := svc.DeviceToken(ctx, device.ClientID, "", pending, deviceIP); refusal(err) != "slow_down: polling too frequently" {
		t.Errorf("polled again at once: %s", refusal(err))
	}
	exec(`UPDATE auth.oidc_device_codes SET expires_at = NOW() - INTERVAL '1 second' WHERE device_code_hash = $1`, codes.Hash(pending))
	if _, err := poll(pending); refusal(err) != "expired_token: device_code expired" {
		t.Errorf("expired: %s", refusal(err))
	}
	denied := issue(false)
	exec(`UPDATE auth.oidc_device_codes SET status = 'denied' WHERE device_code_hash = $1`, codes.Hash(denied))
	if _, err := poll(denied); refusal(err) != "access_denied: the user denied the authorization request" {
		t.Errorf("denied: %s", refusal(err))
	}

	approved := issue(true)
	got, err := poll(approved)
	if err != nil {
		t.Fatalf("approved: %v", err)
	}
	if got.AccessToken == "" || got.IDToken == "" || got.RefreshToken == "" || got.TokenType != "Bearer" ||
		got.Scope != "openid profile" || got.ExpiresIn != int(svc.issuer.AccessTTL().Seconds()) {
		t.Errorf("approved: %+v, want access, ID and refresh tokens for openid profile", got)
	}
	if !row(approved).spent {
		t.Error("the collected request is not spent")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE client_id = $1 AND user_id = $2 AND authorization_code_hash = $3`,
		device.ClientID, person.ID, codes.Hash(approved)); n != 1 {
		t.Errorf("%d refresh tokens bound to the device code, want 1", n)
	}
	if _, err := poll(approved); refusal(err) != "invalid_grant: device_code already used" {
		t.Errorf("collected again: %s", refusal(err))
	}

	suspended := issue(true)
	exec(`UPDATE account.users SET status = 'suspended' WHERE id = $1`, person.ID)
	if _, err := poll(suspended); refusal(err) != "invalid_grant: account_suspended" {
		t.Errorf("suspended since the approval: %s", refusal(err))
	}
	if !row(suspended).spent {
		t.Error("the refused collection left the request unspent")
	}
}
