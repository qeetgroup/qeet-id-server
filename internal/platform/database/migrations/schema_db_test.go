//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestReferencesStayInTheirOrganisation checks that every foreign key from one
// organisation-owned table to another names the organisation, so the database
// refuses a row that points at another organisation's.
func TestReferencesStayInTheirOrganisation(t *testing.T) {
	rows, err := dbtest.Pool(t).Query(dbtest.Context(t), `
		SELECT c.conrelid::regclass::text, c.conname
		FROM pg_constraint c
		JOIN pg_attribute child ON child.attrelid = c.conrelid AND child.attname = 'tenant_id' AND child.attnotnull
		JOIN pg_attribute parent ON parent.attrelid = c.confrelid AND parent.attname = 'tenant_id' AND parent.attnotnull
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
		t.Errorf("%s.%s refers to another organisation-owned row by id alone; refer to it by (tenant_id, id)", table, constraint)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	mine, theirs := dbtest.Tenant(t), dbtest.Tenant(t)
	user := dbtest.User(t, mine)
	_, err = dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO rbac.user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)
	`, user.ID, mine, dbtest.Role(t, theirs))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Errorf("a role from another organisation was granted: %v, want a foreign key violation", err)
	}
}
