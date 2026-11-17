//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// accountLevelTables are the tables with an organization_id that have no row-level
// security policy: they hold a person's own data across organizations (read by
// "my sessions", "my invitations", sign-in), or are platform-wide.
var accountLevelTables = map[string]bool{
	"audit.events":                  true, // one hash chain per organization and one platform chain
	"platform.organization_purges":  true, // the record of a purged organization, kept after it is gone
	"auth.login_codes":              true, // sign-in, before an organization applies
	"auth.login_context_history":    true, // a person's sign-in history, across organizations
	"auth.magic_links":              true, // sign-in, before an organization applies
	"auth.mfa_login_challenges":     true, // sign-in, before an organization applies
	"auth.mfa_push_pairings":        true, // a person's devices
	"auth.notifications":            true, // a person's inbox, across organizations
	"auth.oauth_states":             true, // sign-in, before an organization applies
	"auth.oidc_authorization_codes": true, // the hosted login, across organizations
	"auth.oidc_ciba_requests":       true, // ended with every sign-in of the person
	"auth.oidc_device_codes":        true, // ended with every sign-in of the person
	"auth.oidc_logout_deliveries":   true, // background delivery
	"auth.oidc_refresh_tokens":      true, // a person's application grants, across organizations
	"auth.sessions":                 true, // a person's sessions, across organizations
	"auth.trusted_devices":          true, // a person's devices, across organizations
	"platform.email_messages":       true, // platform delivery records
	"platform.email_suppressions":   true, // platform suppression list
	"platform.rate_limit_overrides": true, // read by every instance's limiter
	"platform.sales_leads":          true, // the public contact form
	"rbac.user_roles":               true, // a person's memberships, across organizations
	"organization.signup_checkouts": true, // sign-up, before the organization exists
	"account.export_requests":       true, // a person's own data
	"account.external_identities":   true, // a person's linked accounts
	"account.purge_requests":        true, // a person's own data
	"account.users":                 true, // accounts are platform-wide
}

// TestOrganizationTablesHaveRowSecurity checks that every table with an organization_id has
// the organization_isolation policy, unless it is account-level, so a new
// organization-owned table can't be added without one.
func TestOrganizationTablesHaveRowSecurity(t *testing.T) {
	rows, err := dbtest.Pool(t).Query(dbtest.Context(t), `
		SELECT c.oid::regclass::text, c.relrowsecurity,
		       EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid AND p.polname = 'organization_isolation')
		FROM pg_class c
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped
		WHERE c.relkind = 'r' AND c.relnamespace::regnamespace::text NOT IN ('pg_catalog', 'information_schema')
		ORDER BY 1
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var table string
		var enabled, policy bool
		if err := rows.Scan(&table, &enabled, &policy); err != nil {
			t.Fatal(err)
		}
		table = unquote(table)
		seen[table] = true
		switch {
		case accountLevelTables[table] && (enabled || policy):
			t.Errorf("%s is listed as account-level but has row-level security", table)
		case !accountLevelTables[table] && (!enabled || !policy):
			t.Errorf("%s has an organization_id but no organization_isolation policy; add one in its migration, or list it in accountLevelTables with why", table)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for table := range accountLevelTables {
		if !seen[table] {
			t.Errorf("%s is listed in accountLevelTables but has no organization_id; delete it from the list", table)
		}
	}
}

// unquote drops the quotes regclass puts around a reserved name ("user").
func unquote(s string) string { return strings.ReplaceAll(s, `"`, "") }

// TestRowSecurityConfinesAScopedConnection checks that a connection scoped to
// one organization sees, writes and changes only that organization's rows,
// whatever its query asks, and that one acting across organizations sees all.
func TestRowSecurityConfinesAScopedConnection(t *testing.T) {
	pool := dbtest.Pool(t)
	mine, theirs := dbtest.Organization(t), dbtest.Organization(t)
	for _, organization := range []any{mine, theirs} {
		if _, err := pool.Exec(dbtest.Context(t), `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Engineering')`, organization); err != nil {
			t.Fatal(err)
		}
	}
	count := func(ctx context.Context) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization.groups WHERE organization_id = ANY($1)`, []any{mine, theirs}).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	scoped := postgres.WithOrganization(dbtest.Context(t), mine)
	if n := count(scoped); n != 1 {
		t.Errorf("scoped to one organisation, a query for both sees %d groups, want its own 1", n)
	}
	if n := count(postgres.AcrossOrganizations(scoped)); n != 2 {
		t.Errorf("across organisations, %d groups, want 2", n)
	}
	_, err := pool.Exec(scoped, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Planted')`, theirs)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("scoped, a row for another organisation was written: %v, want a row-level security refusal", err)
	}
	tag, err := pool.Exec(scoped, `UPDATE organization.groups SET name = 'Renamed' WHERE organization_id = $1`, theirs)
	if err != nil || tag.RowsAffected() != 0 {
		t.Errorf("scoped, another organisation's group was changed: %v rows, %v", tag.RowsAffected(), err)
	}
}

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestReferencesStayInTheirOrganization checks that every foreign key from one
// organization-owned table to another names the organization, so the database
// refuses a row that points at another organization's.
func TestReferencesStayInTheirOrganization(t *testing.T) {
	rows, err := dbtest.Pool(t).Query(dbtest.Context(t), `
		SELECT c.conrelid::regclass::text, c.conname
		FROM pg_constraint c
		JOIN pg_attribute child ON child.attrelid = c.conrelid AND child.attname = 'organization_id' AND child.attnotnull
		JOIN pg_attribute parent ON parent.attrelid = c.confrelid AND parent.attname = 'organization_id' AND parent.attnotnull
		WHERE c.contype = 'f' AND NOT child.attnum = ANY (c.conkey)
		ORDER BY 1, 2
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var table, constraint string
		if err := rows.Scan(&table, &constraint); err != nil {
			t.Fatal(err)
		}
		t.Errorf("%s.%s refers to another organization-owned row by id alone; refer to it by (organization_id, id)", table, constraint)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	mine, theirs := dbtest.Organization(t), dbtest.Organization(t)
	user := dbtest.User(t, mine)
	_, err = dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO rbac.user_roles (user_id, organization_id, role_id) VALUES ($1, $2, $3)
	`, user.ID, mine, dbtest.Role(t, theirs))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Errorf("a role from another organisation was granted: %v, want a foreign key violation", err)
	}
}
