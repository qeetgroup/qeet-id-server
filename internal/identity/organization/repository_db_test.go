//go:build integration

package organization

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestANewOrganizationHasItsBuiltinRoles checks that creating an organization
// gives it built-in admin, member and viewer roles beside owner: admin holding
// all but organization.delete, viewer only reads and not secret.read, member nothing.
func TestANewOrganizationHasItsBuiltinRoles(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _, _ := newHandler(t)
	keys := []string{"organization.delete", "secret.read", "audit.read", "user.write"}
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO rbac.permissions (key) SELECT unnest($1::text[]) ON CONFLICT (key) DO NOTHING`, keys); err != nil {
		t.Fatal(err)
	}
	org, err := h.Repo.CreateWithOwner(ctx, CreateInput{Slug: dbtest.Unique("org"), Name: "Acme"}, verifiedAccount(t).ID)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]string{
		"owner":  keys,
		"admin":  {"secret.read", "audit.read", "user.write"},
		"member": {},
		"viewer": {"audit.read"},
	} {
		var held []string
		if err := dbtest.Pool(t).QueryRow(ctx, `
			SELECT coalesce(array_agg(p.key) FILTER (WHERE p.key = ANY($3)), '{}')
			FROM rbac.roles ro
			LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
			LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
			WHERE ro.organization_id = $1 AND ro.is_system AND ro.name = $2`, org.ID, name, keys).Scan(&held); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		slices.Sort(held)
		want = slices.Sorted(slices.Values(want))
		if !slices.Equal(held, want) {
			t.Errorf("the built-in %s role holds %v of %v, want %v", name, held, keys, want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.role_permissions rp JOIN rbac.roles ro ON ro.id = rp.role_id WHERE ro.organization_id = $1 AND ro.name = 'member'`, org.ID); n != 0 {
		t.Errorf("the built-in member role holds %d permissions, want none", n)
	}
}

// TestRegionIsTheDeployments checks that an organization is created in the
// region the deployment runs in, that asking to create one elsewhere is
// refused and creates nothing, and that the region can't be changed, though
// sending it back unchanged with other fields is accepted.
func TestRegionIsTheDeployments(t *testing.T) {
	h, _, _ := newHandler(t)
	h.Repo.SetHostingRegion("ap-south-2")
	a := verifiedAccount(t)
	create := func(region string) *httptest.ResponseRecorder {
		body := map[string]any{"slug": dbtest.Unique("org"), "name": "Acme"}
		if region != "" {
			body["region"] = region
		}
		return dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, uuid.Nil), h.Mount), http.MethodPost, "/organizations", body)
	}

	if rec := create("eu-west-1"); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), CodeRegionUnavailable) || !strings.Contains(rec.Body.String(), "ap-south-2") {
		t.Errorf("create in another region: %d %s, want 422 %s naming ap-south-2", rec.Code, rec.Body.String(), CodeRegionUnavailable)
	}
	var created struct {
		OrganizationID uuid.UUID `json:"organization_id"`
	}
	for _, region := range []string{"", "ap-south-2"} {
		rec := create(region)
		dbtest.Decode(t, rec, &created)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create with region %q: %d %s", region, rec.Code, rec.Body.String())
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM organization.organizations WHERE id = $1 AND region = 'ap-south-2'`, created.OrganizationID); n != 1 {
			t.Errorf("an organization created with region %q isn't in ap-south-2", region)
		}
	}

	admin := dbtest.User(t, created.OrganizationID)
	dbtest.Assign(t, admin.ID, created.OrganizationID, dbtest.Role(t, created.OrganizationID, "organization.read", "organization.write"))
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, created.OrganizationID), h.Mount)
	path := "/organizations/" + created.OrganizationID.String()
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"region": "eu-west-1"}); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), CodeRegionReadOnly) {
		t.Errorf("change the region: %d %s, want 422 %s", rec.Code, rec.Body.String(), CodeRegionReadOnly)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"region": "ap-south-2", "name": "Acme Ltd"}); rec.Code != http.StatusOK {
		t.Errorf("an update sending the region back unchanged: %d %s, want 200", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.organizations WHERE id = $1 AND region = 'ap-south-2' AND name = 'Acme Ltd'`, created.OrganizationID); n != 1 {
		t.Error("the organization's region or name isn't what the updates left")
	}
}

// TestCreateCommitsWithItsAuditRow checks that creating an organization
// records organization.created, with the creator's address, browser and
// request, and its event in the same transaction, and that a creation that
// fails part way leaves no organization and no record behind.
func TestCreateCommitsWithItsAuditRow(t *testing.T) {
	ctx := dbtest.Context(t)
	repo := NewRepository(dbtest.Pool(t))
	owner := verifiedAccount(t)
	actor := audit.Actor{UserID: &owner.ID, Type: "user", IP: "198.51.100.9", UserAgent: "organization-test", RequestID: "req-organization"}
	org, err := repo.Create(ctx, CreateInput{Slug: dbtest.Unique("org"), Name: "Acme"}, owner.ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM audit.events
		WHERE organization_id = $1 AND action = 'organization.created' AND resource_id = $1 AND actor_user_id = $2
		  AND host(ip) = $3 AND user_agent = $4 AND request_id = $5`, org.ID, owner.ID, actor.IP, actor.UserAgent, actor.RequestID); n != 1 {
		t.Errorf("%d organization.created rows as the creator's, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE event_type = 'organization.created' AND aggregate_id = $1`, org.ID); n != 1 {
		t.Errorf("%d organization.created events, want 1", n)
	}

	// An owner with no account fails the owner role's grant, after the
	// organization row is written.
	slug := dbtest.Unique("org")
	if _, err := repo.Create(ctx, CreateInput{Slug: slug, Name: "Nobody's"}, uuid.New(), actor); err == nil {
		t.Fatal("creating an organization for an owner with no account succeeded")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.organizations WHERE slug = $1`, slug); n != 0 {
		t.Errorf("a failed creation left %d organizations, want none", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'organization.created' AND metadata->>'slug' = $1`, slug); n != 0 {
		t.Errorf("a failed creation left %d organization.created rows, want none", n)
	}
}
