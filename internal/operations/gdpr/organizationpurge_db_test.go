//go:build integration

package gdpr

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// organizationRowsLeft counts organizationID's rows in every table with an organization_id.
func organizationRowsLeft(t *testing.T, organizationID uuid.UUID) map[string]int {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	rows, err := pool.Query(ctx, `
		SELECT c.oid::regclass::text FROM pg_class c
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped
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
		if table == "platform.organization_purges" {
			continue
		}
		if n := dbtest.Count(t, fmt.Sprintf(`SELECT count(*) FROM %s WHERE organization_id = $1`, table), organizationID); n > 0 {
			left[table] = n
		}
	}
	return left
}

// TestPurgingADeletedOrganization checks that an organization deleted longer
// ago than its restore window loses every row of every table, its audit
// chain included; that a person whose home it was is erased and removed,
// unless they belong to another organization, whose member they stay, with no
// home organization; that a guest loses only their place in it; that the purge
// is recorded where it outlives the data; and that an organization deleted
// within the window, or whose deletion was called off, is left alone.
func TestPurgingADeletedOrganization(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	gone, other, recent := dbtest.Organization(t), dbtest.Organization(t), dbtest.Organization(t)
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
		exec(`INSERT INTO auth.sessions (user_id, organization_id) VALUES ($1, $2)`, u, gone)
	}
	exec(`INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Finance')`, gone)
	exec(`INSERT INTO audit.events (organization_id, actor_type, action, resource_type) VALUES ($1, 'system', 'organization.updated', 'organization')`, gone)
	exec(`UPDATE organization.organizations SET status = 'deleted', deleted_at = NOW() - interval '31 days' WHERE id = $1`, gone)
	exec(`UPDATE organization.organizations SET status = 'deleted', deleted_at = NOW() - interval '1 day' WHERE id = $1`, recent)

	svc := testService(t, pool, 0)
	n, err := svc.PurgeDeletedOrganizations(ctx, OrganizationPurgeAfter)
	if err != nil || n < 1 {
		t.Fatalf("purge: %d, %v", n, err)
	}
	if left := organizationRowsLeft(t, gone); len(left) != 0 {
		t.Errorf("rows of the purged organization left: %v", left)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.organizations WHERE id = $1`, gone); n != 0 {
		t.Error("the purged organization is still there")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1`, homeOnly.ID); n != 0 {
		t.Error("an account whose only organization was purged is still there")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND organization_id IS NULL AND deleted_at IS NULL`, alsoElsewhere.ID); n != 1 {
		t.Error("an account also of another organization wasn't kept with no home organization")
	}
	for _, u := range []uuid.UUID{alsoElsewhere.ID, guest.ID} {
		if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, u, other); n != 1 {
			t.Errorf("%s lost their role in another organization", u)
		}
	}
	var removed, detached int
	if err := pool.QueryRow(ctx, `SELECT accounts_removed, accounts_detached FROM platform.organization_purges WHERE organization_id = $1 AND rows_purged ? 'audit.events'`, gone).Scan(&removed, &detached); err != nil || removed != 1 || detached != 1 {
		t.Errorf("purge record: removed %d, detached %d (%v); want 1 and 1, counting the audit log", removed, detached, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id IS NULL AND action = 'organization.purged' AND resource_id = $1`, gone); n != 1 {
		t.Errorf("%d platform records of the purge, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.organizations WHERE id = $1`, recent); n != 1 {
		t.Error("an organization deleted within its restore window was purged")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.organizations WHERE id = $1`, other); n != 1 {
		t.Error("an organization that was never deleted is gone")
	}
}
