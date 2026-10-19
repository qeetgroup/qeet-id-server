//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	group "github.com/qeetgroup/qeet-id-server/internal/identity/groups"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestGroupMembersStayInsideTheOrganization pins the tenant boundary on group
// membership: an organization's groups take only its own live members. A user
// from another organization, an id with no account and a deleted account are
// refused the same way and write nothing, and the member list never shows a
// person who isn't a member of the organization.
func TestGroupMembersStayInsideTheOrganization(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := group.NewService(testPool)
	actor := audit.Actor{Type: "system"}

	home := createTenant(t, ctx, uniqueSlug("groups-home"))
	other := createTenant(t, ctx, uniqueSlug("groups-other"))

	// adminCreated has this organization as its home but no membership row yet.
	adminCreated := createUserInTenant(t, ctx, home)
	// invited belongs to the other organization and joined this one by invitation.
	invited := createUserInTenant(t, ctx, other)
	addTenantMembership(t, ctx, invited, home)
	// outsider belongs only to the other organization.
	outsider := createUserInTenant(t, ctx, other)
	addTenantMembership(t, ctx, outsider, other)
	deleted := createUserInTenant(t, ctx, home)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET deleted_at = NOW() WHERE id = $1`, deleted); err != nil {
		t.Fatalf("soft-delete user: %v", err)
	}

	eng, err := svc.Create(ctx, group.CreateInput{TenantID: home, Name: uniqueSlug("eng")}, actor)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	otherGroup, err := svc.Create(ctx, group.CreateInput{TenantID: other, Name: uniqueSlug("other-eng")}, actor)
	if err != nil {
		t.Fatalf("create other group: %v", err)
	}

	rows := func(userID uuid.UUID) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM tenant.group_members WHERE group_id = $1 AND user_id = $2`, eng.ID, userID).Scan(&n); err != nil {
			t.Fatalf("count group_members: %v", err)
		}
		return n
	}
	listed := func(userID uuid.UUID) bool {
		t.Helper()
		members, err := svc.ListMembers(ctx, eng.ID, home)
		if err != nil {
			t.Fatalf("list members: %v", err)
		}
		for _, m := range members {
			if m.UserID == userID {
				return true
			}
		}
		return false
	}
	removals := func(userID uuid.UUID) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'group.member_removed'
			   AND resource_id = $2 AND metadata->>'user_id' = $3`,
			home, eng.ID, userID.String()).Scan(&n); err != nil {
			t.Fatalf("count audit events: %v", err)
		}
		return n
	}

	t.Run("members of the organization can be added", func(t *testing.T) {
		for _, uid := range []uuid.UUID{adminCreated, invited} {
			if err := svc.AddMember(ctx, eng.ID, uid, home, actor); err != nil {
				t.Fatalf("add member: %v", err)
			}
			if !listed(uid) {
				t.Fatal("an added member is missing from the member list")
			}
		}
	})

	t.Run("adding a member twice still succeeds", func(t *testing.T) {
		if err := svc.AddMember(ctx, eng.ID, invited, home, actor); err != nil {
			t.Fatalf("repeat add: %v", err)
		}
		if n := rows(invited); n != 1 {
			t.Fatalf("rows = %d, want 1", n)
		}
	})

	refusals := []struct {
		name   string
		userID uuid.UUID
	}{
		{"a user from another organization", outsider},
		{"a user id that does not exist", uuid.New()},
		{"a deleted user", deleted},
	}
	var bodies []string
	for _, c := range refusals {
		t.Run("refuses "+c.name, func(t *testing.T) {
			err := svc.AddMember(ctx, eng.ID, c.userID, home, actor)
			if !errors.Is(err, errs.ErrGroupUserNotFound) {
				t.Fatalf("err = %v, want %v", err, errs.ErrGroupUserNotFound)
			}
			if n := rows(c.userID); n != 0 {
				t.Fatalf("a refused add wrote %d row(s)", n)
			}
			rec := httptest.NewRecorder()
			httpx.WriteError(rec, httptest.NewRequest(http.MethodPost, "/", nil), err)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
			bodies = append(bodies, rec.Body.String())
		})
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("refusals are distinguishable:\n%s\n%s", bodies[0], bodies[i])
		}
	}

	t.Run("another organization's group is still not found", func(t *testing.T) {
		if err := svc.AddMember(ctx, otherGroup.ID, adminCreated, home, actor); !errors.Is(err, errs.ErrGroupNotFound) {
			t.Fatalf("err = %v, want %v", err, errs.ErrGroupNotFound)
		}
	})

	t.Run("the member list hides a non-member written before the fix", func(t *testing.T) {
		if _, err := testPool.Exec(ctx,
			`INSERT INTO tenant.group_members (group_id, user_id, tenant_id) VALUES ($1, $2, $3)`,
			eng.ID, outsider, home); err != nil {
			t.Fatalf("seed foreign member row: %v", err)
		}
		if listed(outsider) {
			t.Fatal("the member list shows a user from another organization")
		}
	})

	t.Run("a removal that matches no row writes no audit entry", func(t *testing.T) {
		stranger := uuid.New()
		if err := svc.RemoveMember(ctx, eng.ID, stranger, home, actor); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if n := removals(stranger); n != 0 {
			t.Fatalf("an empty removal wrote %d audit row(s)", n)
		}
	})

	t.Run("a real removal is audited once", func(t *testing.T) {
		if err := svc.RemoveMember(ctx, eng.ID, invited, home, actor); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if rows(invited) != 0 {
			t.Fatal("the member is still in the group")
		}
		if n := removals(invited); n != 1 {
			t.Fatalf("removal audit rows = %d, want 1", n)
		}
	})

	t.Run("the database refuses a member with no account", func(t *testing.T) {
		_, err := testPool.Exec(ctx,
			`INSERT INTO tenant.group_members (group_id, user_id, tenant_id) VALUES ($1, $2, $3)`,
			eng.ID, uuid.New(), home)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Fatalf("err = %v, want a foreign-key violation", err)
		}
	})

	t.Run("the migration removes rows with no account before adding the key", func(t *testing.T) {
		up, err := os.ReadFile(filepath.Join("..", "..", "internal", "platform", "database", "migrations",
			"0135_group_members_user_fk.up.sql"))
		if err != nil {
			t.Fatalf("read migration: %v", err)
		}
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `ALTER TABLE tenant.group_members DROP CONSTRAINT group_members_user_id_fkey`); err != nil {
			t.Fatalf("drop key: %v", err)
		}
		ghost := uuid.New()
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant.group_members (group_id, user_id, tenant_id) VALUES ($1, $2, $3)`,
			eng.ID, ghost, home); err != nil {
			t.Fatalf("seed ghost row: %v", err)
		}
		if _, err := tx.Exec(ctx, string(up)); err != nil {
			t.Fatalf("apply migration: %v", err)
		}
		var ghosts, keys int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM tenant.group_members WHERE user_id = $1`, ghost).Scan(&ghosts); err != nil {
			t.Fatalf("count ghost rows: %v", err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM pg_constraint WHERE conname = 'group_members_user_id_fkey'`).Scan(&keys); err != nil {
			t.Fatalf("count keys: %v", err)
		}
		if ghosts != 0 || keys != 1 {
			t.Fatalf("after the migration: ghost rows = %d (want 0), keys = %d (want 1)", ghosts, keys)
		}
	})
}
