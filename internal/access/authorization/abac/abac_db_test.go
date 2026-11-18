//go:build integration

package abac

import (
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// namedRole creates a role called name in organization and returns its id.
func namedRole(t *testing.T, organization uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `INSERT INTO rbac.roles (organization_id, name) VALUES ($1, $2) RETURNING id`, organization, name).Scan(&id); err != nil {
		t.Fatalf("create role %s: %v", name, err)
	}
	return id
}

// group creates a group called name in organization holding roles, with members.
func group(t *testing.T, organization uuid.UUID, name string, roles []uuid.UUID, members ...uuid.UUID) {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, $2) RETURNING id`, organization, name).Scan(&id); err != nil {
		t.Fatalf("create group %s: %v", name, err)
	}
	for _, m := range members {
		if _, err := pool.Exec(ctx, `INSERT INTO organization.group_members (group_id, user_id, organization_id) VALUES ($1, $2, $3)`, id, m, organization); err != nil {
			t.Fatalf("add a member to %s: %v", name, err)
		}
	}
	for _, r := range roles {
		if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organization, id, r); err != nil {
			t.Fatalf("give %s a role: %v", name, err)
		}
	}
}

// session opens a session for user in organization whose sign-in met factor ("" for
// none) and returns its id.
func session(t *testing.T, user, organization uuid.UUID, factor string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		INSERT INTO auth.sessions (user_id, organization_id, second_factor) VALUES ($1, $2, NULLIF($3, '')) RETURNING id
	`, user, organization, factor).Scan(&id); err != nil {
		t.Fatalf("open a session: %v", err)
	}
	return id
}
