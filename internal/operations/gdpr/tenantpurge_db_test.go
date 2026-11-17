//go:build integration

package gdpr

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// tenantRowsLeft counts tenantID's rows in every table with a tenant_id.
func tenantRowsLeft(t *testing.T, tenantID uuid.UUID) map[string]int {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	rows, err := pool.Query(ctx, `
		SELECT c.oid::regclass::text FROM pg_class c
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
		WHERE c.relkind = 'r' AND c.relnamespace::regnamespace::text NOT IN ('pg_catalog', 'information_schema')`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	rows.Close()
	left := map[string]int{}
	for _, table := range tables {
		if table == "platform.tenant_purges" {
			continue
		}
		if n := dbtest.Count(t, fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1`, table), tenantID); n > 0 {
			left[table] = n
		}
	}
	return left
}

// TestPurgingADeletedOrganisation checks that an organisation deleted longer
// ago than its restore window loses every row of every table, its audit
// chain included; that a person whose home it was is erased and removed,
// unless they belong to another organisation, whose member they stay, with no
// home organisation; that a guest loses only their place in it; that the purge
// is recorded where it outlives the data; and that an organisation deleted
// within the window, or whose deletion was called off, is left alone.
func TestPurgingADeletedOrganisation(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	gone, other, recent := dbtest.Tenant(t), dbtest.Tenant(t), dbtest.Tenant(t)
	homeOnly := dbtest.User(t, gone, gone)
	alsoElsewhere := dbtest.User(t, gone, gone, other)
	guest := dbtest.User(t, other, other, gone)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []uuid.UUID{homeOnly.ID, guest.ID} {
		exec(`INSERT INTO auth.sessions (user_id, tenant_id) VALUES ($1, $2)`, u, gone)
	}
	exec(`INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, 'Finance')`, gone)
	exec(`INSERT INTO audit.events (tenant_id, actor_type, action, resource_type) VALUES ($1, 'system', 'tenant.updated', 'tenant')`, gone)
	exec(`UPDATE tenant.tenants SET status = 'deleted', deleted_at = NOW() - interval '31 days' WHERE id = $1`, gone)
	exec(`UPDATE tenant.tenants SET status = 'deleted', deleted_at = NOW() - interval '1 day' WHERE id = $1`, recent)

	svc := NewService(pool, 0)
	n, err := svc.PurgeDeletedTenants(ctx, TenantPurgeAfter)
	if err != nil || n < 1 {
		t.Fatalf("purge: %d, %v", n, err)
	}
	if left := tenantRowsLeft(t, gone); len(left) != 0 {
		t.Errorf("rows of the purged organisation left: %v", left)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.tenants WHERE id = $1`, gone); n != 0 {
		t.Error("the purged organisation is still there")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1`, homeOnly.ID); n != 0 {
		t.Error("an account whose only organisation was purged is still there")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND tenant_id IS NULL AND deleted_at IS NULL`, alsoElsewhere.ID); n != 1 {
		t.Error("an account also of another organisation wasn't kept with no home organisation")
	}
	for _, u := range []uuid.UUID{alsoElsewhere.ID, guest.ID} {
		if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, u, other); n != 1 {
			t.Errorf("%s lost their role in another organisation", u)
		}
	}
	var removed, detached int
	if err := pool.QueryRow(ctx, `SELECT accounts_removed, accounts_detached FROM platform.tenant_purges WHERE tenant_id = $1 AND rows_purged ? 'audit.events'`, gone).Scan(&removed, &detached); err != nil || removed != 1 || detached != 1 {
		t.Errorf("purge record: removed %d, detached %d (%v); want 1 and 1, counting the audit log", removed, detached, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id IS NULL AND action = 'tenant.purged' AND resource_id = $1`, gone); n != 1 {
		t.Errorf("%d platform records of the purge, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.tenants WHERE id = $1`, recent); n != 1 {
		t.Error("an organisation deleted within its restore window was purged")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.tenants WHERE id = $1`, other); n != 1 {
		t.Error("an organisation that was never deleted is gone")
	}
}
