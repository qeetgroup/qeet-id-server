//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	group "github.com/qeetgroup/qeet-id-server/internal/identity/groups"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestGroupNestingStaysInsideTheOrganization pins the group hierarchy to one
// organization and keeps it a tree: a parent must be one of the organization's
// own groups, a move can't put a group inside itself or its own subgroups, and
// an update changes only the fields it names.
func TestGroupNestingStaysInsideTheOrganization(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := group.NewService(testPool)
	actor := audit.Actor{Type: "system"}

	home := createTenant(t, ctx, uniqueSlug("nest-home"))
	other := createTenant(t, ctx, uniqueSlug("nest-other"))

	create := func(tenantID uuid.UUID, name string, parent *uuid.UUID) *group.Group {
		t.Helper()
		g, err := svc.Create(ctx, group.CreateInput{TenantID: tenantID, Name: name, Description: name + " team", ParentID: parent}, actor)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return g
	}
	// update sends a PATCH body exactly as the API receives it.
	update := func(id uuid.UUID, body string) (*group.Group, error) {
		t.Helper()
		var in group.UpdateInput
		if err := json.Unmarshal([]byte(body), &in); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
		return svc.Update(ctx, id, home, in, actor)
	}
	type state struct {
		name, description string
		parent            *uuid.UUID
	}
	read := func(id uuid.UUID) state {
		t.Helper()
		var s state
		if err := testPool.QueryRow(ctx,
			`SELECT name, description, parent_id FROM tenant.groups WHERE id = $1`, id).
			Scan(&s.name, &s.description, &s.parent); err != nil {
			t.Fatalf("read group: %v", err)
		}
		return s
	}
	parentIs := func(t *testing.T, id uuid.UUID, want *uuid.UUID) {
		t.Helper()
		got := read(id).parent
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Fatalf("parent = %v, want %v", got, want)
		}
	}

	root := create(home, uniqueSlug("eng"), nil)
	child := create(home, uniqueSlug("backend"), &root.ID)
	grandchild := create(home, uniqueSlug("api"), &child.ID)
	foreign := create(other, uniqueSlug("other-eng"), nil)

	var bodies []string
	notFound := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, errs.ErrGroupParentNotFound) {
			t.Fatalf("err = %v, want %v", err, errs.ErrGroupParentNotFound)
		}
		rec := httptest.NewRecorder()
		httpx.WriteError(rec, httptest.NewRequest(http.MethodPost, "/", nil), err)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		bodies = append(bodies, rec.Body.String())
	}
	cycle := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, errs.ErrGroupCycle) {
			t.Fatalf("err = %v, want %v", err, errs.ErrGroupCycle)
		}
		rec := httptest.NewRecorder()
		httpx.WriteError(rec, httptest.NewRequest(http.MethodPatch, "/", nil), err)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	}

	t.Run("create under another organization's group is refused", func(t *testing.T) {
		name := uniqueSlug("grafted")
		_, err := svc.Create(ctx, group.CreateInput{TenantID: home, Name: name, ParentID: &foreign.ID}, actor)
		notFound(t, err)
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM tenant.groups WHERE name = $1`, name).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 0 {
			t.Fatal("a group was created under another organization's group")
		}
	})

	t.Run("create under a parent that does not exist is refused the same way", func(t *testing.T) {
		missing := uuid.New()
		_, err := svc.Create(ctx, group.CreateInput{TenantID: home, Name: uniqueSlug("orphan"), ParentID: &missing}, actor)
		notFound(t, err)
		if len(bodies) == 2 && bodies[0] != bodies[1] {
			t.Fatalf("a missing and a foreign parent are distinguishable:\n%s\n%s", bodies[0], bodies[1])
		}
	})

	t.Run("moving under another organization's group is refused and keeps the parent", func(t *testing.T) {
		_, err := update(child.ID, `{"parent_id": "`+foreign.ID.String()+`"}`)
		notFound(t, err)
		parentIs(t, child.ID, &root.ID)
	})

	t.Run("a group can't be its own parent", func(t *testing.T) {
		_, err := update(child.ID, `{"parent_id": "`+child.ID.String()+`"}`)
		cycle(t, err)
		parentIs(t, child.ID, &root.ID)
	})

	t.Run("a group can't move under its own subgroup", func(t *testing.T) {
		_, err := update(root.ID, `{"parent_id": "`+grandchild.ID.String()+`"}`)
		cycle(t, err)
		parentIs(t, root.ID, nil)
	})

	t.Run("a valid move inside the organization works", func(t *testing.T) {
		if _, err := update(grandchild.ID, `{"parent_id": "`+root.ID.String()+`"}`); err != nil {
			t.Fatalf("move: %v", err)
		}
		parentIs(t, grandchild.ID, &root.ID)
	})

	t.Run("moving a group keeps its name and description", func(t *testing.T) {
		if _, err := update(grandchild.ID, `{"parent_id": "`+child.ID.String()+`"}`); err != nil {
			t.Fatalf("move: %v", err)
		}
		after := read(grandchild.ID)
		if after.name != grandchild.Name || after.description != grandchild.Description {
			t.Fatalf("moves changed name/description to %q/%q, want %q/%q",
				after.name, after.description, grandchild.Name, grandchild.Description)
		}
		parentIs(t, grandchild.ID, &child.ID)
	})

	t.Run("renaming a group keeps it where it is", func(t *testing.T) {
		name := uniqueSlug("api-renamed")
		if _, err := update(grandchild.ID, `{"name": "`+name+`"}`); err != nil {
			t.Fatalf("rename: %v", err)
		}
		after := read(grandchild.ID)
		if after.name != name {
			t.Fatalf("name = %q, want %q", after.name, name)
		}
		parentIs(t, grandchild.ID, &child.ID)
	})

	t.Run("a null parent makes the group top-level", func(t *testing.T) {
		if _, err := update(grandchild.ID, `{"parent_id": null}`); err != nil {
			t.Fatalf("detach: %v", err)
		}
		parentIs(t, grandchild.ID, nil)
	})

	t.Run("the database refuses a parent from another organization", func(t *testing.T) {
		_, err := testPool.Exec(ctx,
			`INSERT INTO tenant.groups (tenant_id, parent_id, name) VALUES ($1, $2, $3)`,
			home, foreign.ID, uniqueSlug("direct"))
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Fatalf("err = %v, want a foreign-key violation", err)
		}
	})

	t.Run("deleting a group still removes its subgroups", func(t *testing.T) {
		top := create(home, uniqueSlug("top"), nil)
		sub := create(home, uniqueSlug("sub"), &top.ID)
		if err := svc.Delete(ctx, top.ID, home, actor); err != nil {
			t.Fatalf("delete: %v", err)
		}
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM tenant.groups WHERE id = $1`, sub.ID).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 0 {
			t.Fatal("the subgroup outlived its parent")
		}
	})

	t.Run("the migration detaches a parent in another organization and adds the key", func(t *testing.T) {
		up := readRepoFile(t, "internal", "platform", "database", "migrations", "0136_group_parent_same_tenant.up.sql")
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		restoreOldKey(t, ctx, tx)
		grafted := uuid.New()
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant.groups (id, tenant_id, parent_id, name) VALUES ($1, $2, $3, $4)`,
			grafted, home, foreign.ID, uniqueSlug("grafted")); err != nil {
			t.Fatalf("seed grafted group: %v", err)
		}
		if _, err := tx.Exec(ctx, up); err != nil {
			t.Fatalf("apply migration: %v", err)
		}
		var parent *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT parent_id FROM tenant.groups WHERE id = $1`, grafted).Scan(&parent); err != nil {
			t.Fatalf("the grafted group is gone: %v", err)
		}
		if parent != nil {
			t.Fatalf("parent = %v, want detached", parent)
		}
		var keys int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM pg_constraint WHERE conname IN ('groups_tenant_parent_fkey', 'groups_tenant_id_id_key')`).Scan(&keys); err != nil {
			t.Fatalf("count keys: %v", err)
		}
		if keys != 2 {
			t.Fatalf("constraints after the migration = %d, want 2", keys)
		}
	})

	t.Run("the down migration restores the id-only key", func(t *testing.T) {
		down := readRepoFile(t, "internal", "platform", "database", "migrations", "0136_group_parent_same_tenant.down.sql")
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, down); err != nil {
			t.Fatalf("apply down migration: %v", err)
		}
		var oldKey, newKeys int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FILTER (WHERE conname = 'groups_parent_id_fkey'),
			        count(*) FILTER (WHERE conname IN ('groups_tenant_parent_fkey', 'groups_tenant_id_id_key'))
			   FROM pg_constraint`).Scan(&oldKey, &newKeys); err != nil {
			t.Fatalf("count keys: %v", err)
		}
		if oldKey != 1 || newKeys != 0 {
			t.Fatalf("after the down migration: old key = %d (want 1), new constraints = %d (want 0)", oldKey, newKeys)
		}
	})

	t.Run("the integrity check reports cross-organization parents and loops", func(t *testing.T) {
		check := readRepoFile(t, "tools", "scripts", "group-hierarchy-check.sql")
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		restoreOldKey(t, ctx, tx)
		grafted, self, loopA, loopB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO tenant.groups (id, tenant_id, parent_id, name) VALUES ($1, $2, $3, $4)`, []any{grafted, home, foreign.ID, uniqueSlug("g")}},
			{`INSERT INTO tenant.groups (id, tenant_id, name) VALUES ($1, $2, $3)`, []any{self, home, uniqueSlug("s")}},
			{`UPDATE tenant.groups SET parent_id = id WHERE id = $1`, []any{self}},
			{`INSERT INTO tenant.groups (id, tenant_id, name) VALUES ($1, $2, $3)`, []any{loopA, home, uniqueSlug("a")}},
			{`INSERT INTO tenant.groups (id, tenant_id, parent_id, name) VALUES ($1, $2, $3, $4)`, []any{loopB, home, loopA, uniqueSlug("b")}},
			{`UPDATE tenant.groups SET parent_id = $2 WHERE id = $1`, []any{loopA, loopB}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				t.Fatalf("seed bad hierarchy: %v", err)
			}
		}
		rows, err := tx.Query(ctx, check)
		if err != nil {
			t.Fatalf("run check: %v", err)
		}
		found := map[uuid.UUID]string{}
		for rows.Next() {
			var problem string
			var tenantID, id uuid.UUID
			var name string
			var parent *uuid.UUID
			if err := rows.Scan(&problem, &tenantID, &id, &name, &parent); err != nil {
				t.Fatalf("scan: %v", err)
			}
			found[id] = problem
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows: %v", err)
		}
		want := map[uuid.UUID]string{grafted: "foreign_parent", self: "loop", loopA: "loop", loopB: "loop"}
		for id, problem := range want {
			if found[id] != problem {
				t.Fatalf("group %s reported as %q, want %q (all: %v)", id, found[id], problem, found)
			}
		}
		for _, healthy := range []uuid.UUID{root.ID, child.ID, grandchild.ID} {
			if p, ok := found[healthy]; ok {
				t.Fatalf("a healthy group was reported as %q", p)
			}
		}
	})
}

// restoreOldKey puts back the id-only parent key the schema had before
// migration 0136, inside tx, so a test can seed the rows that key allowed.
func restoreOldKey(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	for _, stmt := range []string{
		`ALTER TABLE tenant.groups DROP CONSTRAINT groups_tenant_parent_fkey`,
		`ALTER TABLE tenant.groups DROP CONSTRAINT groups_tenant_id_id_key`,
		`ALTER TABLE tenant.groups ADD CONSTRAINT groups_parent_id_fkey
		     FOREIGN KEY (parent_id) REFERENCES tenant.groups (id) ON DELETE CASCADE`,
	} {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			t.Fatalf("restore the old key: %v", err)
		}
	}
}

func readRepoFile(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(b)
}
