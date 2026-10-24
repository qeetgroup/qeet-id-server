//go:build integration

package user

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestCredentialChangesNeedAnAccountOfOneOrganisation checks that the home
// organisation may set the password or reset the second factors of an account
// only while no other live organisation shares it, that each change ends the
// person's sign-ins or factors, is audited and emailed, and that signing out
// everywhere needs no such exclusivity.
func TestCredentialChangesNeedAnAccountOfOneOrganisation(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	solo := dbtest.User(t, tenant, tenant)
	shared := dbtest.User(t, tenant, tenant, other)
	for _, u := range []uuid.UUID{solo.ID, shared.ID} {
		session(t, u, tenant, "")
		exec(t, `INSERT INTO auth.mfa_totp (user_id, secret, confirmed_at) VALUES ($1, 'secret', NOW())`, u)
	}
	session(t, shared.ID, other, "")
	mailbox := &dbtest.Mailbox{}
	h := testHandler(t, mailbox)
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	newPassword := map[string]any{"password": "Kx7mQ2vLp9Wz-set"}
	passwords := `SELECT count(*) FROM auth.password_credentials WHERE user_id = $1`
	factors := `SELECT count(*) FROM auth.mfa_totp WHERE user_id = $1`

	sharedPath := "/users/" + shared.ID.String()
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, sharedPath + "/password"},
		{http.MethodDelete, sharedPath + "/mfa"},
	} {
		rec := dbtest.Do(t, as, tc.method, tc.path, newPassword)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeUserCredentialsShared) {
			t.Errorf("%s %s of a shared account: %d %s, want 403 %s", tc.method, tc.path, rec.Code, rec.Body.String(), errs.CodeUserCredentialsShared)
		}
	}
	if dbtest.Count(t, passwords, shared.ID) != 0 || dbtest.Count(t, factors, shared.ID) != 1 || liveSessions(t, shared.ID) != 2 || mailbox.Len() != 0 {
		t.Error("a refused credential change still changed the shared account or told its owner")
	}

	soloPath := "/users/" + solo.ID.String()
	if rec := dbtest.Do(t, as, http.MethodPost, soloPath+"/password", newPassword); rec.Code != http.StatusNoContent {
		t.Fatalf("set the password: %d %s", rec.Code, rec.Body.String())
	}
	if dbtest.Count(t, passwords, solo.ID) != 1 || liveSessions(t, solo.ID) != 0 || audited(t, tenant, "user.password_set", solo.ID) != 1 {
		t.Error("setting the password didn't store it, end the sessions and audit it")
	}
	if m := mailbox.Last(t); m.To != solo.Email || !strings.Contains(m.Subject, "password") {
		t.Errorf("the password notice went to %s about %q, want %s", m.To, m.Subject, solo.Email)
	}
	rec := dbtest.Do(t, as, http.MethodDelete, soloPath+"/mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset the second factors: %d %s", rec.Code, rec.Body.String())
	}
	if dbtest.Count(t, factors, solo.ID) != 0 || audited(t, tenant, "mfa.admin_reset", solo.ID) != 1 {
		t.Error("resetting the second factors didn't remove them and audit it")
	}
	if m := mailbox.Last(t); m.To != solo.Email || !strings.Contains(m.Subject, "two-step") || mailbox.Len() != 2 {
		t.Errorf("the factor reset notice went to %s about %q (%d sent), want a second message to %s", m.To, m.Subject, mailbox.Len(), solo.Email)
	}

	rec = dbtest.Do(t, as, http.MethodPost, sharedPath+"/sessions/revoke-all", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"revoked":2`) {
		t.Errorf("sign a shared account out everywhere: %d %s, want both sessions ended", rec.Code, rec.Body.String())
	}
	if liveSessions(t, shared.ID) != 0 || audited(t, tenant, "session.admin_revoked_all", shared.ID) != 1 {
		t.Error("signing out everywhere left a session or wasn't audited")
	}

	exec(t, `UPDATE tenant.tenants SET deleted_at = NOW() WHERE id = $1`, other)
	if rec := dbtest.Do(t, as, http.MethodPost, sharedPath+"/password", newPassword); rec.Code != http.StatusNoContent {
		t.Errorf("set the password of an account shared only with a deleted organisation: %d %s, want 204", rec.Code, rec.Body.String())
	}

	h.SignIns, h.MFA, h.PasswordPolicy = nil, nil, nil
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, soloPath + "/password", newPassword},
		{http.MethodDelete, soloPath + "/mfa", nil},
		{http.MethodPost, soloPath + "/sessions/revoke-all", nil},
	} {
		if rec := dbtest.Do(t, as, tc.method, tc.path, tc.body); rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s with nothing to do it: %d, want 501", tc.method, tc.path, rec.Code)
		}
	}
}

// TestAdminPhoneChangeDropsItsVerification checks that an administrator giving
// a person a new phone number leaves it unverified, so applications aren't told
// the new number is verified.
func TestAdminPhoneChangeDropsItsVerification(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	target := dbtest.User(t, tenant, tenant)
	exec(t, `UPDATE "user".users SET phone = '+14155550100', phone_verified_at = NOW() WHERE id = $1`, target.ID)
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), testHandler(t, nil).Mount)
	rec := dbtest.Do(t, as, http.MethodPatch, "/users/"+target.ID.String(), map[string]any{"phone": "+14155550199"})
	if rec.Code != http.StatusOK {
		t.Fatalf("change the phone: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND phone = '+14155550199' AND phone_verified_at IS NULL`, target.ID); n != 1 {
		t.Errorf("the new number is stored as verified: %s", rec.Body.String())
	}
}

// TestAccountViewsDescribeTheCallersOrganisation checks that the MFA-required
// flag is set, audited and shown in the security summary, and that the access
// view lists only the caller's organisation, its roles and groups, and splits
// the permissions into direct and inherited ones.
func TestAccountViewsDescribeTheCallersOrganisation(t *testing.T) {
	home, tenant := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, home, home)
	member := dbtest.User(t, home, tenant)
	dbtest.Assign(t, member.ID, home, dbtest.Role(t, home, "users.read"))
	dbtest.SetPassword(t, member.ID, "Kx7mQ2vLp9Wz")
	exec(t, `INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, last_used_at) VALUES ($1, convert_to(gen_random_uuid()::text, 'UTF8'), '\x02', NOW())`, member.ID)
	exec(t, `
		WITH g AS (INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, 'Engineering') RETURNING id),
		     m AS (INSERT INTO tenant.group_members (group_id, user_id, tenant_id) SELECT id, $2, $1 FROM g)
		INSERT INTO rbac.group_roles (tenant_id, group_id, role_id) SELECT $1, id, $3 FROM g
	`, home, member.ID, dbtest.Role(t, home, "users.read", "users.write"))
	as := dbtest.Serve(dbtest.Principal(admin.ID, home), testHandler(t, nil).Mount)
	path := "/users/" + member.ID.String()

	if rec := dbtest.Do(t, as, http.MethodPut, path+"/mfa-required", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Errorf("set the MFA-required flag without a value: %d, want 400", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodPut, path+"/mfa-required", map[string]any{"required": true}); rec.Code != http.StatusOK {
		t.Fatalf("require MFA: %d %s", rec.Code, rec.Body.String())
	}
	if n := audited(t, home, "user.mfa_required_set", member.ID); n != 1 {
		t.Errorf("%d user.mfa_required_set audit events, want 1", n)
	}
	var sum SecuritySummary
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, path+"/security", nil), &sum)
	if !sum.MFARequired || sum.MFAEnabled || !sum.PasswordSet || sum.PasswordChangedAt == nil || sum.Passkeys != 1 || sum.PasskeyLastUsedAt == nil {
		t.Errorf("security summary %+v, want MFA required but not set up, a password and a used passkey", sum)
	}

	rec := dbtest.Do(t, as, http.MethodGet, path+"/access", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("read the member's access: %d %s", rec.Code, rec.Body.String())
	}
	var access AccessSummary
	dbtest.Decode(t, rec, &access)
	if access.Organization == nil || access.Organization.ID != home {
		t.Errorf("the access view describes organisation %+v, want the caller's", access.Organization)
	}
	if len(access.Roles) != 1 || len(access.Groups) != 1 || access.Groups[0].Name != "Engineering" {
		t.Errorf("the access view lists roles %+v and groups %+v, want the one role and group held here", access.Roles, access.Groups)
	}
	if access.PermissionsDirect != 1 || access.PermissionsInherited != 1 || access.PermissionsTotal != 2 {
		t.Errorf("permissions %d direct, %d inherited, %d in all; want 1, 1 and 2", access.PermissionsDirect, access.PermissionsInherited, access.PermissionsTotal)
	}
}

// TestSignInMethodsCountWhatTheOrganisationAllows checks that a password or
// passkey counts only while the account's organisation allows it, that a
// linked identity counts only while it can still sign in, and that a refused
// removal of the last method is audited.
func TestSignInMethodsCountWhatTheOrganisationAllows(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	u := dbtest.User(t, tenant, tenant)
	count := func() SignInMethods {
		t.Helper()
		m, err := CountSignInMethods(ctx, pool, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := count(); m.Total() != 0 {
		t.Errorf("a new account counts %+v, want no way in", m)
	}
	dbtest.SetPassword(t, u.ID, "Kx7mQ2vLp9Wz")
	exec(t, `INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key) VALUES ($1, convert_to(gen_random_uuid()::text, 'UTF8'), '\x02')`, u.ID)
	exec(t, `INSERT INTO "user".external_identities (user_id, tenant_id, provider, subject) VALUES ($1, $2, 'saml', 'saml-subject'), ($1, $2, 'google', 'google-subject')`, u.ID, tenant)
	exec(t, `INSERT INTO auth.platform_social_identities (user_id, provider, subject) VALUES ($1, 'github', $2)`, u.ID, dbtest.Unique("github"))
	if m := count(); m != (SignInMethods{Password: true, Passkeys: 1, LinkedIdentities: 2}) {
		t.Errorf("counted %+v, want the password, the passkey, SAML and the platform identity, not Google with no provider", m)
	}
	exec(t, `INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret) VALUES ($1, 'google', 'id', 'secret')`, tenant)
	exec(t, `INSERT INTO tenant.auth_policy (tenant_id, password_enabled, passkey_enabled) VALUES ($1, FALSE, FALSE)`, tenant)
	if m := count(); m != (SignInMethods{LinkedIdentities: 3}) || m.Total() != 3 {
		t.Errorf("counted %+v, want only the three linked identities once the organisation turns off passwords and passkeys", m)
	}

	tx, err := pool.Begin(postgres.AcrossTenants(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if m, err := LockSignInMethods(ctx, tx, u.ID); err != nil || m.Total() != 3 {
		t.Errorf("counted %+v under the account's lock (%v), want 3", m, err)
	}
	if _, err := LockSignInMethods(ctx, tx, uuid.New()); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("lock an account that doesn't exist: %v, want not found", err)
	}

	methodID := uuid.New()
	err = RefuseLastMethodRemoval(ctx, pool, u.ID, &tenant, "passkey", methodID, Remover{UserID: &u.ID})
	if !errors.Is(err, errs.ErrAuthLastSignInMethod) {
		t.Errorf("refuse removing the last method: %v, want %v", err, errs.ErrAuthLastSignInMethod)
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM audit.events
		WHERE tenant_id = $1 AND action = 'auth.sign_in_method_removal_refused' AND resource_id = $2 AND metadata->>'method_id' = $3
	`, tenant, u.ID, methodID.String()); n != 1 {
		t.Errorf("%d audit events record the refused removal, want 1", n)
	}
}
