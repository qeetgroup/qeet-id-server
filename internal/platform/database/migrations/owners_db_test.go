//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestOrganisationsKeepAnOwnerButOffboardTheirOwn checks that an organisation
// still can't suspend, delete or strip its own last active owner, but can
// suspend and delete its own account when that account is the last owner of an
// organisation it created elsewhere.
func TestOrganisationsKeepAnOwnerButOffboardTheirOwn(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Pool(t)
	lastOwner := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "QI409"
	}
	ownerRole := func(tenant uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, tenant).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	employer, side := dbtest.Tenant(t), dbtest.Tenant(t)
	boss := dbtest.User(t, employer)
	dbtest.Assign(t, boss.ID, employer, ownerRole(employer))
	employee := dbtest.User(t, employer, employer)
	sideOwner := ownerRole(side)
	dbtest.Assign(t, employee.ID, side, sideOwner)

	if _, err := pool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, boss.ID); !lastOwner(err) {
		t.Errorf("suspend the employer's last owner: %v, want QI409", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, employee.ID, side); !lastOwner(err) {
		t.Errorf("take the owner role from the side organisation's last owner: %v, want QI409", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, employee.ID); err != nil {
		t.Errorf("the employer suspends its employee who owns an organisation elsewhere: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET status = 'active' WHERE id = $1`, employee.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET deleted_at = NOW() WHERE id = $1`, employee.ID); err != nil {
		t.Errorf("the employer deletes that employee: %v", err)
	}
}
