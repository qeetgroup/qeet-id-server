//go:build integration

package oidc

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/access/risk/ipallow"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// pendingBackchannel starts a backchannel request of client for a and returns
// its auth_req_id and the id a's approval names.
func pendingBackchannel(t *testing.T, svc *Service, client *Client, secret string, a dbtest.Account) (string, uuid.UUID) {
	t.Helper()
	ctx := dbtest.Context(t)
	started, err := svc.BackchannelAuthorize(ctx, client.ClientID, secret, a.Email, "openid", "")
	if err != nil {
		t.Fatalf("backchannel authorize: %v", err)
	}
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `SELECT id FROM auth.oidc_ciba_requests WHERE auth_req_id_hash = $1`,
		codes.Hash(started.AuthReqID)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return started.AuthReqID, id
}

// TestBackchannelApprovalMeetsTheOrganisationsRules checks that approving a
// backchannel request needs what signing in to the application does: the
// person still a member of its organisation, an address its rules allow (a
// refusal recorded), and a session that met the second factor it requires.
func TestBackchannelApprovalMeetsTheOrganisationsRules(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	svc.SetAddressPolicy(ipallow.NewService(pool))
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(mfa.NewService(pool, "Qeet", notifier.LogSender{}, ""))
	svc.SetSessionFactors(authSvc.SessionFactorShortfall)
	tenant, home := dbtest.Tenant(t), dbtest.Tenant(t)
	client, secret := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, GrantTypes: []string{grantTypeCIBA}})
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`WITH rule AS (INSERT INTO tenant.ip_rules (tenant_id, cidr, label, action) VALUES ($1, '192.0.2.0/24', 'office', 'allow'))
		INSERT INTO tenant.ip_rules_config (tenant_id, enabled) VALUES ($1, TRUE)`, tenant)
	const office, elsewhere = "192.0.2.10", "198.51.100.7"
	a := dbtest.User(t, home, home, tenant)
	pair, err := authSvc.IssuePair(ctx, a.ID, home, office, "test", "password")
	if err != nil {
		t.Fatal(err)
	}
	session := pair.SessionID
	decide := func(id uuid.UUID, ip string) error {
		return svc.DecideBackchannel(ctx, a.ID, session, id, true, ip)
	}

	_, id := pendingBackchannel(t, svc, client, secret, a)
	if err := decide(id, elsewhere); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Errorf("approve from an address the rules refuse: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'auth.address_refused' AND metadata->>'path' = 'ciba_approval'`, tenant); n != 1 {
		t.Errorf("the refused approval was recorded %d times, want once", n)
	}
	if err := decide(id, office); err != nil {
		t.Fatalf("approve from the office: %v", err)
	}

	exec(`INSERT INTO tenant.security_policies (tenant_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since) VALUES ($1, 'required', 0, NOW())`, tenant)
	_, id = pendingBackchannel(t, svc, client, secret, a)
	if err := decide(id, office); !errors.Is(err, errs.ErrMFAEnrollmentRequired) {
		t.Errorf("approve through a session short of the factor the organisation requires: %v, want %v", err, errs.ErrMFAEnrollmentRequired)
	}
	exec(`UPDATE auth.sessions SET second_factor = 'mfa' WHERE id = $1`, session)
	if err := decide(id, office); err != nil {
		t.Fatalf("approve through a session that met the factor: %v", err)
	}

	_, id = pendingBackchannel(t, svc, client, secret, a)
	exec(`DELETE FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, a.ID, tenant)
	if err := decide(id, office); !errors.Is(err, errs.ErrOIDCUserTenantMismatch) {
		t.Errorf("approve once no longer a member of the organisation: %v, want %v", err, errs.ErrOIDCUserTenantMismatch)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_ciba_requests WHERE id = $1 AND status = 'pending'`, id); n != 1 {
		t.Error("a refused approval changed the request")
	}
}

// TestCIBAGrantRemovedAfterAuthorizeIsRefusedAtToken checks that collecting a
// backchannel grant's tokens needs a confidential client still holding the CIBA
// grant and a person still in its organisation, and that a token that fails to
// be stored leaves the request unspent, so a later poll gets it.
func TestCIBAGrantRemovedAfterAuthorizeIsRefusedAtToken(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	client, secret := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, GrantTypes: []string{grantTypeCIBA, "refresh_token"}})
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	approved := func(a dbtest.Account) string {
		t.Helper()
		raw, id := pendingBackchannel(t, svc, client, secret, a)
		if err := svc.DecideBackchannel(ctx, a.ID, uuid.Nil, id, true, ""); err != nil {
			t.Fatalf("approve: %v", err)
		}
		return raw
	}
	// A poll at once after another is slow_down; the tests poll as if later.
	repoll := func() {
		exec(`UPDATE auth.oidc_ciba_requests SET last_polled_at = NULL WHERE client_id = $1`, client.ClientID)
	}
	a := dbtest.User(t, tenant, tenant)

	authReqID := approved(a)
	exec(`UPDATE auth.oidc_clients SET grant_types = ARRAY['refresh_token'] WHERE client_id = $1`, client.ClientID)
	if _, err := svc.BackchannelToken(ctx, client.ClientID, secret, authReqID); !errors.Is(err, errs.ErrOIDCGrantTypeNotAllowed) {
		t.Errorf("collect once the client lost the CIBA grant: %v, want %v", err, errs.ErrOIDCGrantTypeNotAllowed)
	}
	exec(`UPDATE auth.oidc_clients SET grant_types = ARRAY[$2, 'refresh_token'] WHERE client_id = $1`, client.ClientID, grantTypeCIBA)
	repoll()
	exec(`UPDATE auth.oidc_clients SET type = 'public' WHERE client_id = $1`, client.ClientID)
	if _, err := svc.BackchannelToken(ctx, client.ClientID, secret, authReqID); err == nil {
		t.Error("collect once the client is no longer confidential: tokens issued")
	}
	exec(`UPDATE auth.oidc_clients SET type = 'confidential' WHERE client_id = $1`, client.ClientID)
	repoll()

	owner := dbtest.Owner(t)
	if _, err := owner.Exec(ctx, `
		CREATE FUNCTION pg_temp.refuse_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refresh store down'; END $$;
		CREATE TRIGGER refuse_refresh BEFORE INSERT ON auth.oidc_refresh_tokens FOR EACH ROW
		WHEN (NEW.client_id = '`+client.ClientID+`') EXECUTE FUNCTION pg_temp.refuse_refresh()`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.BackchannelToken(ctx, client.ClientID, secret, authReqID); err == nil {
		t.Fatal("collect while the refresh token can't be stored: tokens issued")
	}
	if _, err := owner.Exec(ctx, `DROP TRIGGER refuse_refresh ON auth.oidc_refresh_tokens`); err != nil {
		t.Fatal(err)
	}
	repoll()
	if issued, err := svc.BackchannelToken(ctx, client.ClientID, secret, authReqID); err != nil || issued.RefreshToken == "" {
		t.Errorf("collect after the failed store: %+v, %v; want the tokens", issued, err)
	}

	authReqID = approved(a)
	exec(`DELETE FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, a.ID, tenant)
	exec(`UPDATE "user".users SET tenant_id = $2 WHERE id = $1`, a.ID, dbtest.Tenant(t))
	repoll()
	if _, err := svc.BackchannelToken(ctx, client.ClientID, secret, authReqID); err == nil {
		t.Error("collect once the person left the organisation: tokens issued")
	}
}
