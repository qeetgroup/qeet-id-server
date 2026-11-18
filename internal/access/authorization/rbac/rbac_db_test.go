//go:build integration

package rbac

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// newRoleService returns the role service over repo with no plan limit, no
// seat limit, no webhook events and no session announcements.
func newRoleService(t *testing.T, repo *Repository) *Service {
	t.Helper()
	svc, err := NewService(repo, ServiceDeps{
		Emitter: func(context.Context, uuid.UUID, string, any) error { return nil },
		Limits:  unlimited{}, Seats: unlimited{}, Signals: sessionsignal.New(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// unlimited is a plan with no limit on anything.
type unlimited struct{}

func (unlimited) Limit(context.Context, uuid.UUID, string) (int, error) { return -1, nil }
func (unlimited) SeatLimit(context.Context, uuid.UUID) (int, error)     { return -1, nil }
func (unlimited) WithinSeats(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ int, change func() error) error {
	return change()
}

// TestRolesStayInTheirOrganization checks that one organization can neither read nor change
// another organization's roles, nor assign them, nor assign its own roles to another
// organization's user.
func TestRolesStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	const perm = "reports:export"
	roleA := dbtest.Role(t, organizationA, perm)
	roleB := dbtest.Role(t, organizationB)
	userA := dbtest.User(t, organizationA)
	dbtest.Assign(t, userA.ID, organizationA, roleA)
	adminB := dbtest.User(t, organizationB, organizationB)
	memberB := dbtest.User(t, organizationB, organizationB)
	var permID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM rbac.permissions WHERE key = $1`, perm).Scan(&permID); err != nil {
		t.Fatalf("permission id: %v", err)
	}

	h := &Handler{Repo: repo, Service: newRoleService(t, repo), Validate: validator.New(validator.WithRequiredStructEnabled())}
	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), h.Mount)
	roleAPath := "/roles/" + roleA.String() + "/permissions"
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, roleAPath, http.StatusNotFound},
		{http.MethodPost, roleAPath + "/" + permID.String(), http.StatusNotFound},
		{http.MethodDelete, roleAPath + "/" + permID.String(), http.StatusNotFound},
		{http.MethodPost, "/users/" + memberB.ID.String() + "/organizations/" + organizationB.String() + "/roles/" + roleA.String(), http.StatusNotFound},
		{http.MethodPost, "/users/" + userA.ID.String() + "/organizations/" + organizationB.String() + "/roles/" + roleB.String(), http.StatusNotFound},
		{http.MethodDelete, "/users/" + userA.ID.String() + "/organizations/" + organizationA.String() + "/roles/" + roleA.String(), http.StatusForbidden},
		{http.MethodGet, "/users/" + userA.ID.String() + "/organizations/" + organizationA.String() + "/permissions", http.StatusForbidden},
		{http.MethodGet, "/organizations/" + organizationA.String() + "/roles", http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, nil); rec.Code != tc.want {
			t.Errorf("organization B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/organizations/"+organizationB.String()+"/roles", nil)); slices.Contains(ids, roleA) {
		t.Error("organization B's role list includes organization A's role")
	}

	if ok, err := repo.Check(ctx, userA.ID, organizationA, perm); err != nil || !ok {
		t.Errorf("organization A's user lost %s: %v, %v", perm, ok, err)
	}
	if ok, err := repo.Check(ctx, memberB.ID, organizationB, perm); err != nil || ok {
		t.Errorf("organization B's member holds organization A's %s: %v, %v", perm, ok, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, userA.ID, organizationB); n != 0 {
		t.Error("organization A's user was given a role in organization B")
	}
}

// limit is a PlanLimiter allowing n of every resource.
type limit int

func (n limit) Limit(context.Context, uuid.UUID, string) (int, error) { return int(n), nil }

// TestRoleLifecycle checks that a custom role is refused beyond the plan's
// limit; that a permission granted to a role reaches a person given the role
// directly or through a group, and so passes enforcement, until the role, the
// group's role or the permission is taken away; that each change is audited;
// and that a person's role changes are announced.
func TestRoleLifecycle(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	svc := newRoleService(t, repo)
	var announced []string
	svc.emitter = func(_ context.Context, _ uuid.UUID, eventType string, payload any) error {
		announced = append(announced, eventType+":"+payload.(map[string]any)["change"].(string))
		return nil
	}
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	direct, viaGroup := dbtest.User(t, organization), dbtest.User(t, organization)
	actor := audit.Actor{UserID: &admin.ID, Type: "user"}
	const perm = "reports:export"
	dbtest.Role(t, organization, perm) // makes sure the permission exists
	var permID, groupID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM rbac.permissions WHERE key = $1`, perm).Scan(&permID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, $2) RETURNING id`, organization, dbtest.Unique("group")).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.group_members (organization_id, group_id, user_id) VALUES ($1, $2, $3)`, organization, groupID, viaGroup.ID); err != nil {
		t.Fatal(err)
	}
	holds := func(u dbtest.Account) bool {
		t.Helper()
		ok, err := repo.Check(ctx, u.ID, organization, perm)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	enforced := func(u dbtest.Account) int {
		t.Helper()
		h := dbtest.Serve(dbtest.Principal(u.ID, organization), func(r chi.Router) {
			r.Use(Enforce(repo, map[string]RoutePolicy{"GET /reports": PermissionPolicy(perm)}))
			r.Get("/reports", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		})
		return dbtest.Do(t, h, http.MethodGet, "/reports", nil).Code
	}
	audited := func(action string) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = $1 AND organization_id = $2`, action, organization)
	}

	svc.limits = limit(0)
	if _, err := svc.CreateRole(ctx, organization, "Analyst", "", actor); !errors.Is(err, errs.ErrPlanLimit) {
		t.Errorf("a custom role over the plan's limit: %v, want %v", err, errs.ErrPlanLimit)
	}
	svc.limits = limit(5)
	role, err := svc.CreateRole(ctx, organization, "Analyst", "Reads reports", actor)
	if err != nil || audited("role.created") != 1 {
		t.Fatalf("create role: %+v, %v, audited %d times", role, err, audited("role.created"))
	}
	if err := svc.GrantPermission(ctx, organization, role.ID, permID, actor); err != nil {
		t.Fatalf("grant permission: %v", err)
	}
	// The organization's log names the role, the permission and who changed it.
	permissionChanged := func(action string) int {
		return dbtest.Count(t, `
			SELECT count(*) FROM audit.events
			WHERE organization_id = $1 AND action = $2 AND resource_type = 'role' AND resource_id = $3
			  AND actor_user_id = $4 AND metadata->>'permission' = $5 AND metadata->>'permission_id' = $6`,
			organization, action, role.ID, admin.ID, perm, permID.String())
	}
	if n := permissionChanged("role.permission_granted"); n != 1 {
		t.Errorf("%d role.permission_granted records in the organization, want 1", n)
	}
	if holds(direct) || enforced(direct) != http.StatusForbidden {
		t.Fatal("a person without the role holds its permission")
	}

	if err := svc.AssignRole(ctx, direct.ID, organization, role.ID, &admin.ID, actor); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := svc.AssignRoleToGroup(ctx, groupID, organization, role.ID, &admin.ID, actor); err != nil {
		t.Fatalf("assign role to group: %v", err)
	}
	for name, u := range map[string]dbtest.Account{"given the role": direct, "in the group": viaGroup} {
		if !holds(u) || enforced(u) != http.StatusOK {
			t.Errorf("a person %s doesn't hold the role's permission", name)
		}
	}
	if audited("role.assigned") != 1 || audited("role.group_assigned") != 1 {
		t.Error("the role assignments were not audited")
	}

	if err := svc.RemoveRoleFromGroup(ctx, groupID, organization, role.ID, actor); err != nil {
		t.Fatalf("remove role from group: %v", err)
	}
	if holds(viaGroup) {
		t.Error("a group member kept the permission after the group lost the role")
	}
	if err := svc.RevokePermission(ctx, organization, role.ID, permID, actor); err != nil {
		t.Fatalf("revoke permission: %v", err)
	}
	if n := permissionChanged("role.permission_revoked"); n != 1 {
		t.Errorf("%d role.permission_revoked records in the organization, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id IS NULL AND resource_id = $1`, role.ID); n != 0 {
		t.Errorf("%d of the role's changes are on the platform's record, want none", n)
	}
	if holds(direct) || enforced(direct) != http.StatusForbidden {
		t.Error("a person kept a permission revoked from their role")
	}
	if err := svc.UnassignRole(ctx, direct.ID, organization, role.ID, actor); err != nil || audited("role.unassigned") != 1 {
		t.Errorf("unassign role: %v, audited %d times", err, audited("role.unassigned"))
	}
	if want := []string{"token.claims_change:role_assigned", "token.claims_change:role_unassigned"}; !slices.Equal(announced, want) {
		t.Errorf("announced %v; want %v", announced, want)
	}
}

// TestRolesSayWhoHoldsThem checks that the roles list counts people holding a
// role directly, only through a group, and the groups; that the holders list
// says how each holds it and pages; and that another organization's role is
// not found.
func TestRolesSayWhoHoldsThem(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	direct, both, viaGroup, gone := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization), dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	var role, foreign, group uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name) VALUES ($1, 'Editor') RETURNING id`, organization).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name) VALUES ($1, 'Editor') RETURNING id`, other).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Writers') RETURNING id`, organization).Scan(&group); err != nil {
		t.Fatal(err)
	}
	for _, u := range []uuid.UUID{direct.ID, both.ID, gone.ID} {
		exec(`INSERT INTO rbac.user_roles (user_id, organization_id, role_id) VALUES ($1, $2, $3)`, u, organization, role)
	}
	exec(`INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organization, group, role)
	for _, u := range []uuid.UUID{both.ID, viaGroup.ID} {
		exec(`INSERT INTO organization.group_members (group_id, user_id, organization_id) VALUES ($1, $2, $3)`, group, u, organization)
	}
	exec(`UPDATE account.users SET deleted_at = NOW() WHERE id = $1`, gone.ID)

	repo := NewRepository(pool)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Repo: repo, Service: newRoleService(t, repo), Validate: validator.New()}).Mount)
	base := "/organizations/" + organization.String() + "/roles"
	var list struct {
		Items []Role `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base, nil), &list)
	var editor *Role
	for i := range list.Items {
		if list.Items[i].ID == role {
			editor = &list.Items[i]
		}
	}
	if editor == nil || editor.Holders == nil || *editor.Holders != (RoleHolderCounts{PeopleDirect: 2, PeopleThroughGroups: 1, Groups: 1}) {
		t.Fatalf("Editor %+v; want 2 people directly, 1 only through a group, 1 group", editor)
	}

	var page RoleHolders
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"/"+role.String()+"/holders", nil), &page)
	how := map[uuid.UUID]string{}
	for _, p := range page.People {
		groups := ""
		for _, g := range p.ViaGroups {
			groups += g.Name
		}
		how[p.UserID] = fmt.Sprintf("%v/%s", p.Direct, groups)
	}
	if len(page.People) != 3 || how[direct.ID] != "true/" || how[both.ID] != "true/Writers" || how[viaGroup.ID] != "false/Writers" || len(page.Groups) != 1 {
		t.Errorf("holders %v, groups %v; want three people held as granted and the one group", how, page.Groups)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"/"+role.String()+"/holders?limit=2", nil), &page)
	if len(page.People) != 2 || page.NextCursor != "2" {
		t.Errorf("first page of 2: %d people, cursor %q", len(page.People), page.NextCursor)
	}
	page = RoleHolders{}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"/"+role.String()+"/holders?limit=2&cursor=2", nil), &page)
	if len(page.People) != 1 || page.NextCursor != "" {
		t.Errorf("second page: %d people, cursor %q; want the last one", len(page.People), page.NextCursor)
	}
	if rec := dbtest.Do(t, h, http.MethodGet, base+"/"+foreign.String()+"/holders", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization's role: %d, want 404", rec.Code)
	}
}

// TestRemovingAGuestsLastRoleEndsTheirSessions checks that taking a guest's
// last role in an organization, which ends their membership, ends their
// sessions there as removing them does, and only there; a guest keeping a role,
// and someone whose home it is, keep theirs.
func TestRemovingAGuestsLastRoleEndsTheirSessions(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	home, organization := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "role.write", "role.read", "user.read"))
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Repo: repo, Service: newRoleService(t, repo), Validate: validator.New(validator.WithRequiredStructEnabled())}).Mount)
	session := func(userID, in uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO auth.sessions (user_id, organization_id) VALUES ($1, $2) RETURNING id`, userID, in).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	live := func(id uuid.UUID) bool {
		return dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NULL`, id) == 1
	}
	unassign := func(userID, role uuid.UUID) {
		t.Helper()
		if rec := dbtest.Do(t, h, http.MethodDelete, "/users/"+userID.String()+"/organizations/"+organization.String()+"/roles/"+role.String(), nil); rec.Code != http.StatusNoContent {
			t.Fatalf("remove the role: %d %s", rec.Code, rec.Body.String())
		}
	}

	guest := dbtest.User(t, home, home)
	first, second := dbtest.Role(t, organization), dbtest.Role(t, organization)
	dbtest.Assign(t, guest.ID, organization, first)
	dbtest.Assign(t, guest.ID, organization, second)
	there, atHome := session(guest.ID, organization), session(guest.ID, home)
	unassign(guest.ID, first)
	if !live(there) {
		t.Error("taking one of a guest's two roles ended their session")
	}
	unassign(guest.ID, second)
	if live(there) {
		t.Error("the guest's session in the organization outlived their last role there")
	}
	if !live(atHome) {
		t.Error("the guest's session in their home organization was ended")
	}

	member := dbtest.User(t, organization)
	only := dbtest.Role(t, organization)
	dbtest.Assign(t, member.ID, organization, only)
	own := session(member.ID, organization)
	unassign(member.ID, only)
	if !live(own) {
		t.Error("taking the last role of someone whose home it is ended their session")
	}
}
