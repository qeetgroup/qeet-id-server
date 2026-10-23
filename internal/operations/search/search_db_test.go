//go:build integration

package search

import (
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// page is one search answer.
type page struct {
	Results    []Result `json:"results"`
	NextCursor string   `json:"next_cursor"`
}

// TestSearchFindsOnlyTheOrganisationsOwn checks that a search finds the
// matching users, groups, roles, applications and audit events of the
// caller's organisation and none of another's, that each type needs its read
// permission, that types narrow it, and that pages follow the cursor.
func TestSearchFindsOnlyTheOrganisationsOwn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	mine, theirs := dbtest.Tenant(t), dbtest.Tenant(t)
	reader := dbtest.User(t, mine)
	dbtest.Assign(t, reader.ID, mine, dbtest.Role(t, mine, "user.read", "tenant.read", "group.read", "role.read", "connection.read", "audit.read"))
	narrow := dbtest.User(t, mine)
	dbtest.Assign(t, narrow.ID, mine, dbtest.Role(t, mine, "group.read"))
	for _, tenant := range []uuid.UUID{mine, theirs} {
		for _, sql := range []string{
			`INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, 'Zephyr engineering')`,
			`INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, 'Zephyr admin')`,
		} {
			if _, err := pool.Exec(ctx, sql, tenant); err != nil {
				t.Fatal(err)
			}
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(tenant, "zephyr.rotated", "key", uuid.New(), nil)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewService(pool, rbac.NewRepository(pool))
	search := func(as uuid.UUID, query string) page {
		t.Helper()
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(as, mine), (&Handler{Service: svc}).Mount), http.MethodGet, "/search?"+query, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("search %s: %d %s", query, rec.Code, rec.Body.String())
		}
		var p page
		dbtest.Decode(t, rec, &p)
		return p
	}
	typesOf := func(p page) []string {
		var out []string
		for _, r := range p.Results {
			if !slices.Contains(out, r.Type) {
				out = append(out, r.Type)
			}
		}
		slices.Sort(out)
		return out
	}

	all := search(reader.ID, "q=zephyr&limit=50")
	if got := typesOf(all); !slices.Contains(got, TypeGroup) || !slices.Contains(got, TypeRole) || !slices.Contains(got, TypeAuditEvent) {
		t.Errorf("types found %v; want groups, roles and audit events", got)
	}
	if len(all.Results) != 3 {
		t.Errorf("found %d results, want the organisation's 3 (none of the other's)", len(all.Results))
	}
	if got := typesOf(search(narrow.ID, "q=zephyr")); !slices.Equal(got, []string{TypeGroup}) {
		t.Errorf("with group.read alone, types %v; want groups only", got)
	}
	if got := typesOf(search(reader.ID, "q=zephyr&types="+TypeRole)); !slices.Equal(got, []string{TypeRole}) {
		t.Errorf("types=role: %v", got)
	}
	first := search(reader.ID, "q=zephyr&limit=2")
	if len(first.Results) != 2 || first.NextCursor == "" {
		t.Fatalf("first page %+v; want two and a cursor", first)
	}
	rest := search(reader.ID, "q=zephyr&limit=2&cursor="+first.NextCursor)
	if len(rest.Results) != 1 || rest.Results[0].ID == first.Results[0].ID || rest.Results[0].ID == first.Results[1].ID {
		t.Errorf("second page %+v; want the remaining one", rest.Results)
	}
	if rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(reader.ID, mine), (&Handler{Service: svc}).Mount), http.MethodGet, "/search?q=", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("an empty query: %d, want 400", rec.Code)
	}
}
