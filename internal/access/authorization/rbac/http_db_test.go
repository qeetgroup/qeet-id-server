//go:build integration

package rbac

import (
	"net/http"
	"slices"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestAPersonReadsTheirOwnPermissions checks that GET /me/permissions answers
// the caller's own effective permissions in the organization their token is
// for, with the grants behind them: empty lists for someone holding none, and
// never what they hold in another organization, though the route, a person's
// own, runs without the database's organization scope. A token for no
// organization is refused.
func TestAPersonReadsTheirOwnPermissions(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	h := &Handler{Repo: repo, Service: newRoleService(t, repo), Validate: validator.New(validator.WithRequiredStructEnabled())}
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	member := dbtest.User(t, organization)
	dbtest.Assign(t, member.ID, other, dbtest.Role(t, other, "user.read", "role.write"))

	// As in production: the principal, and no row-level security scope.
	as := func(p *httpx.Principal) http.Handler {
		r := chi.NewRouter()
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
			})
		})
		h.Mount(r)
		return r
	}
	type answer struct {
		Permissions []string    `json:"permissions"`
		Grants      []GrantStep `json:"grants"`
	}
	mine := func(p *httpx.Principal) answer {
		t.Helper()
		rec := dbtest.Do(t, as(p), http.MethodGet, "/me/permissions", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /me/permissions: %d %s", rec.Code, rec.Body.String())
		}
		var got answer
		dbtest.Decode(t, rec, &got)
		if got.Permissions == nil || got.Grants == nil {
			t.Errorf("GET /me/permissions: %s; want both lists, empty or not", rec.Body.String())
		}
		return got
	}

	if got := mine(dbtest.Principal(member.ID, organization)); len(got.Permissions) != 0 || len(got.Grants) != 0 {
		t.Errorf("a member holding nothing here, but roles in another organization: %+v, want nothing", got)
	}

	readers := dbtest.Role(t, organization, "audit.read")
	dbtest.Assign(t, member.ID, organization, readers)
	var group uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Support') RETURNING id`, organization).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organization, group, dbtest.Role(t, organization, "user.read")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.group_members (organization_id, group_id, user_id) VALUES ($1, $2, $3)`, organization, group, member.ID); err != nil {
		t.Fatal(err)
	}
	got := mine(dbtest.Principal(member.ID, organization))
	if !slices.Equal(got.Permissions, []string{"audit.read", "user.read"}) || len(got.Grants) != 2 {
		t.Errorf("a member with a role and a group's role: %+v, want audit.read and user.read, two grants", got)
	}
	for _, g := range got.Grants {
		if g.Permission == "role.write" || g.Via != "direct" && (g.GroupID == nil || *g.GroupID != group) {
			t.Errorf("a grant that isn't the member's here: %+v", g)
		}
	}

	if got := mine(dbtest.Principal(member.ID, other)); !slices.Equal(got.Permissions, []string{"role.write", "user.read"}) {
		t.Errorf("the same person signed in to the other organization: %v, want what they hold there", got.Permissions)
	}

	noOrganization := &httpx.Principal{UserID: &member.ID, ActorType: "user", Subject: member.ID.String()}
	if rec := dbtest.Do(t, as(noOrganization), http.MethodGet, "/me/permissions", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a token for no organization: %d, want 401", rec.Code)
	}
}
