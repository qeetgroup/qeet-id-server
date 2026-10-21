//go:build integration

package integration

import (
	"context"
	"testing"
)

// TestIntrospectionReportsRevocation (ADR-0017): introspection is the
// authoritative answer on revocation. A signature-valid access token is
// reported inactive once its account is suspended or deleted, or its
// membership of the organisation ends, and active again when the account is
// reinstated. Before the fix it said active for any token that verified.
func TestIntrospectionReportsRevocation(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newAppTokenFixture(t, ctx)
	user := createUserInTenant(t, ctx, f.tenantID)
	addTenantMembership(t, ctx, user, f.tenantID)
	tok := f.appToken(t, ctx, user, "openid", "email").AccessToken

	active := func(step string) bool {
		t.Helper()
		out, err := f.oidc.Introspect(ctx, f.clientID, f.secret, tok, "access_token")
		if err != nil {
			t.Fatalf("%s: introspect: %v", step, err)
		}
		return out["active"] == true
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := testPool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}

	if !active("issued") {
		t.Fatal("a fresh token is inactive")
	}
	exec(`UPDATE "user".users SET status = 'suspended' WHERE id = $1`, user)
	if active("suspended") {
		t.Fatal("the token of a suspended account is still active")
	}
	exec(`UPDATE "user".users SET status = 'active' WHERE id = $1`, user)
	if !active("reinstated") {
		t.Fatal("the token is inactive after the account was reinstated")
	}
	exec(`UPDATE "user".users SET deleted_at = now() WHERE id = $1`, user)
	if active("deleted") {
		t.Fatal("the token of a deleted account is still active")
	}
	exec(`UPDATE "user".users SET deleted_at = NULL WHERE id = $1`, user)
	exec(`DELETE FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, user, f.tenantID)
	if active("removed from the organisation") {
		t.Fatal("the token of a former member is still active")
	}
}
