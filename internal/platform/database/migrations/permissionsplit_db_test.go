//go:build integration

package migrations_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestPermissionSplitKeepsAccess checks migration 0207 on what was there
// before it: a role or API key holding user.write or tenant.write gains the
// permissions split from them, so it can still do what it did, an
// organisation gains its built-in admin, member and viewer roles, unless it
// already named a role so, and running it again changes nothing.
func TestPermissionSplitKeepsAccess(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	tenant, named := dbtest.Tenant(t), dbtest.Tenant(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// As before 0207: no built-in roles, and one organisation with a custom
	// role it called Admin.
	exec(`DELETE FROM rbac.roles WHERE tenant_id = ANY($1) AND is_system AND name <> 'owner'`, []uuid.UUID{tenant, named})
	exec(`INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, 'Admin')`, named)
	exec(`INSERT INTO rbac.permissions (key) SELECT unnest($1::text[]) ON CONFLICT (key) DO NOTHING`,
		[]string{"role.write", "audit.read", "secret.read", "user.read"})
	helpdesk := dbtest.Role(t, tenant, "user.read", "user.write", "tenant.write")
	var key uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO auth.api_keys (tenant_id, name, prefix, key_hash, scopes) VALUES ($1, 'sync', $2, 'x', $3) RETURNING id`,
		tenant, dbtest.Unique("k")[:8], []string{"user.read", "user.write"}).Scan(&key); err != nil {
		t.Fatal(err)
	}
	split, err := os.ReadFile("0207_finer_permissions.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	rolePermissions := func(roleID uuid.UUID) []string {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT p.key FROM rbac.role_permissions rp JOIN rbac.permissions p ON p.id = rp.permission_id WHERE rp.role_id = $1 ORDER BY 1`, roleID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var keys []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				t.Fatal(err)
			}
			keys = append(keys, k)
		}
		return keys
	}
	builtin := func(tenantID uuid.UUID, name string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT id FROM rbac.roles WHERE tenant_id = $1 AND is_system AND name = $2`, tenantID, name).Scan(&id); err != nil {
			t.Fatalf("built-in %s role: %v", name, err)
		}
		return id
	}

	for run := 1; run <= 2; run++ {
		exec(string(split))
		if got, want := rolePermissions(helpdesk), []string{"member.invite", "session.revoke", "tenant.delete", "tenant.write", "user.credentials", "user.delete", "user.read", "user.suspend", "user.write"}; !slices.Equal(got, want) {
			t.Errorf("run %d: a role with user.write and tenant.write holds %v, want %v", run, got, want)
		}
		var scopes []string
		if err := pool.QueryRow(ctx, `SELECT scopes FROM auth.api_keys WHERE id = $1`, key).Scan(&scopes); err != nil {
			t.Fatal(err)
		}
		if want := []string{"user.read", "user.write", "user.delete", "user.suspend", "user.credentials", "session.revoke", "member.invite"}; !slices.Equal(scopes, want) {
			t.Errorf("run %d: an API key with user.write has scopes %v, want %v", run, scopes, want)
		}
		admin := rolePermissions(builtin(tenant, "admin"))
		if slices.Contains(admin, "tenant.delete") || !slices.Contains(admin, "user.delete") || !slices.Contains(admin, "role.write") {
			t.Errorf("run %d: admin holds %v; want everything but tenant.delete", run, admin)
		}
		viewer := rolePermissions(builtin(tenant, "viewer"))
		if slices.Contains(viewer, "secret.read") || !slices.Contains(viewer, "audit.read") || slices.ContainsFunc(viewer, func(k string) bool { return !strings.HasSuffix(k, ".read") }) {
			t.Errorf("run %d: viewer holds %v; want every read but secret.read, and nothing else", run, viewer)
		}
		if member := rolePermissions(builtin(tenant, "member")); len(member) != 0 {
			t.Errorf("run %d: member holds %v, want nothing", run, member)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM rbac.roles WHERE tenant_id = $1 AND lower(name) = 'admin'`, named); n != 1 {
			t.Errorf("run %d: an organisation with its own Admin role has %d admin roles, want only its own", run, n)
		}
	}
}
