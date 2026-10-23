//go:build integration

package group

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestGroupsStayInTheirTenant checks that one tenant can neither read nor
// change another tenant's group or its members, nor add another tenant's user
// to a group of its own.
func TestGroupsStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	memberA := dbtest.User(t, tenantA, tenantA)
	adminB := dbtest.User(t, tenantB, tenantB)
	actor := audit.Actor{Type: "user"}

	groupA, err := svc.Create(ctx, CreateInput{TenantID: tenantA, Name: "Engineering"}, actor)
	if err != nil {
		t.Fatalf("create group in A: %v", err)
	}
	if err := svc.AddMember(ctx, groupA.ID, memberA.ID, tenantA, actor); err != nil {
		t.Fatalf("add member in A: %v", err)
	}
	groupB, err := svc.Create(ctx, CreateInput{TenantID: tenantB, Name: "Support"}, actor)
	if err != nil {
		t.Fatalf("create group in B: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Service: svc}).Mount)
	path := "/groups/" + groupA.ID.String()
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPatch, path, map[string]any{"name": "Renamed"}, http.StatusNotFound},
		{http.MethodPost, path + "/members/" + adminB.ID.String(), nil, http.StatusNotFound},
		{http.MethodDelete, path, nil, http.StatusNotFound},
		{http.MethodGet, "/tenants/" + tenantA.String() + "/groups", nil, http.StatusForbidden},
		// B may not pull A's user into its own group.
		{http.MethodPost, "/groups/" + groupB.ID.String() + "/members/" + memberA.ID.String(), nil, http.StatusNotFound},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	// Removing a member and listing members answer, but only within B.
	dbtest.Do(t, asB, http.MethodDelete, path+"/members/"+memberA.ID.String(), nil)
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, path+"/members", nil)); len(ids) != 0 {
		t.Errorf("tenant B sees %d members of tenant A's group", len(ids))
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+tenantB.String()+"/groups", nil)); slices.Contains(ids, groupA.ID) {
		t.Error("tenant B's group list includes tenant A's group")
	}

	members, err := svc.ListMembers(ctx, groupA.ID, tenantA)
	if err != nil || len(members) != 1 || members[0].UserID != memberA.ID {
		t.Errorf("tenant A's group members = %+v, %v; want only %s", members, err, memberA.ID)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.groups WHERE id = $1 AND name = 'Engineering'`, groupA.ID); n != 1 {
		t.Error("tenant B changed tenant A's group")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.group_members WHERE group_id = $1`, groupB.ID); n != 0 {
		t.Error("tenant A's user was added to tenant B's group")
	}
}

// TestGroupNamesAreUniquePerOrganization checks that a group name, ignoring
// case, can be used once per organization by create, rename, import and
// templates, and again in another organization.
func TestGroupNamesAreUniquePerOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	adminA := dbtest.User(t, tenantA, tenantA)
	actor := audit.Actor{Type: "user"}

	if _, err := svc.Create(ctx, CreateInput{TenantID: tenantA, Name: "Engineering"}, actor); err != nil {
		t.Fatalf("create Engineering in A: %v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{TenantID: tenantA, Name: "engineering"}, actor); !errors.Is(err, errs.ErrGroupNameExists) {
		t.Errorf("create engineering in A: %v, want %v", err, errs.ErrGroupNameExists)
	}
	if _, err := svc.Create(ctx, CreateInput{TenantID: tenantA, Name: " Engineering  "}, actor); !errors.Is(err, errs.ErrGroupNameExists) {
		t.Errorf("create a space-padded Engineering in A: %v, want %v", err, errs.ErrGroupNameExists)
	}
	if _, err := svc.Create(ctx, CreateInput{TenantID: tenantB, Name: "Engineering"}, actor); err != nil {
		t.Errorf("create Engineering in B: %v", err)
	}
	if g, err := svc.Create(ctx, CreateInput{TenantID: tenantA, Name: "  Design "}, actor); err != nil || g.Name != "Design" {
		t.Errorf("create a space-padded Design: %+v, %v; want it named Design", g, err)
	}
	if _, err := svc.Create(ctx, CreateInput{TenantID: tenantA, Name: "  "}, actor); !errors.Is(err, errs.ErrValidationFailed) {
		t.Errorf("create a blank name: %v, want %v", err, errs.ErrValidationFailed)
	}

	platform, err := svc.Create(ctx, CreateInput{TenantID: tenantA, Name: "Platform"}, actor)
	if err != nil {
		t.Fatalf("create Platform in A: %v", err)
	}
	taken, own := "ENGINEERING", "platform"
	if _, err := svc.Update(ctx, platform.ID, tenantA, UpdateInput{Name: &taken}, actor); !errors.Is(err, errs.ErrGroupNameExists) {
		t.Errorf("rename Platform to %s: %v, want %v", taken, err, errs.ErrGroupNameExists)
	}
	if _, err := svc.Update(ctx, platform.ID, tenantA, UpdateInput{Name: &own}, actor); err != nil {
		t.Errorf("rename Platform to %s: %v", own, err)
	}
	blank := " "
	if _, err := svc.Update(ctx, platform.ID, tenantA, UpdateInput{Name: &blank}, actor); !errors.Is(err, errs.ErrValidationFailed) {
		t.Errorf("rename Platform to a blank name: %v, want %v", err, errs.ErrValidationFailed)
	}

	asA := dbtest.Serve(dbtest.Principal(adminA.ID, tenantA), (&Handler{Service: svc}).Mount)
	rec := dbtest.Do(t, asA, http.MethodPost, "/groups", map[string]string{"name": "Engineering"})
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	dbtest.Decode(t, rec, &body)
	if rec.Code != http.StatusConflict || body.Error.Code != errs.CodeGroupNameExists {
		t.Errorf("POST /groups Engineering: %d %q, want 409 %q", rec.Code, body.Error.Code, errs.CodeGroupNameExists)
	}

	res, err := svc.ImportGroups(ctx, tenantA, []ImportRow{{Name: "Ops"}, {Name: "OPS"}}, actor)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Created != 1 || res.Failed != 1 || res.Rows[1].Reason != "a group with this name already exists" {
		t.Errorf("import Ops and OPS: %+v, want one created and one refused as a duplicate", res)
	}

	tmpl, err := svc.CreateTemplate(ctx, tenantA, TemplateInput{Name: "Org", Nodes: []TemplateNode{{Name: "Ops"}}}, actor)
	if err != nil {
		t.Fatalf("create template: %v", err)
	}
	if _, err := svc.ApplyTemplate(ctx, tmpl.ID, tenantA, nil, actor); !errors.Is(err, errs.ErrGroupNameExists) {
		t.Errorf("apply a template naming Ops: %v, want %v", err, errs.ErrGroupNameExists)
	}
}

// TestTemplateGroupNames checks that a template naming one group twice is
// refused when it is saved, and that a template applies once per
// organization, the second apply naming the group that already exists.
func TestTemplateGroupNames(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	tenant := dbtest.Tenant(t)
	actor := audit.Actor{Type: "user"}

	_, err := svc.CreateTemplate(ctx, tenant, TemplateInput{Name: "Departments", Nodes: []TemplateNode{
		{Name: "Sales", Children: []TemplateNode{{Name: "Leads"}}},
		{Name: "Support", Children: []TemplateNode{{Name: " leads"}}},
	}}, actor)
	if e := errs.As(err); e == nil || e.Code != errs.CodeValidation || len(e.Fields) != 1 || e.Fields[0].Code != "duplicate_name" {
		t.Errorf("save a template naming Leads twice: %v, want a duplicate_name validation error", err)
	}

	tmpl, err := svc.CreateTemplate(ctx, tenant, TemplateInput{Name: "Teams", Nodes: []TemplateNode{
		{Name: "Sales", Children: []TemplateNode{{Name: "Sales leads"}}},
	}}, actor)
	if err != nil {
		t.Fatalf("save template: %v", err)
	}
	if _, err := svc.ApplyTemplate(ctx, tmpl.ID, tenant, nil, actor); err != nil {
		t.Fatalf("apply the template: %v", err)
	}
	_, err = svc.ApplyTemplate(ctx, tmpl.ID, tenant, nil, actor)
	if e := errs.As(err); !errors.Is(err, errs.ErrGroupNameExists) || e == nil || !strings.Contains(e.Detail, `"Sales"`) {
		t.Errorf("apply the template again: %v, want %v naming Sales", err, errs.ErrGroupNameExists)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.groups WHERE tenant_id = $1`, tenant); n != 2 {
		t.Errorf("tenant has %d groups after applying twice, want 2", n)
	}
}

// TestNameMigrationRenamesExistingDuplicates checks that migration 0154
// renames all but the oldest of the non-SCIM groups whose names differ only
// in case or surrounding space, so its index can be built. It runs the
// migration again inside a transaction that is rolled back.
func TestNameMigrationRenamesExistingDuplicates(t *testing.T) {
	ctx := dbtest.Context(t)
	up, err := os.ReadFile(filepath.Join("..", "..", "platform", "database", "migrations", "0154_group_name_unique.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DROP INDEX tenant.uq_groups_tenant_name`); err != nil {
		t.Fatalf("drop the index: %v", err)
	}
	base := time.Now().Add(-time.Hour)
	insert := func(tenant uuid.UUID, name string, externalID any, age time.Duration) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := tx.QueryRow(ctx, `
			INSERT INTO tenant.groups (tenant_id, name, external_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id
		`, tenant, name, externalID, base.Add(age)).Scan(&id); err != nil {
			t.Fatalf("insert %q: %v", name, err)
		}
		return id
	}
	oldest := insert(tenant, "Engineering", nil, 0)
	padded := insert(tenant, "engineering ", nil, time.Second)
	upper := insert(tenant, "ENGINEERING", nil, 2*time.Second)
	provisioned := insert(tenant, "Engineering", "ext-1", 3*time.Second)
	elsewhere := insert(other, "Engineering", nil, 4*time.Second)

	if _, err := tx.Exec(ctx, string(up)); err != nil {
		t.Fatalf("run the migration over duplicates: %v", err)
	}
	for id, want := range map[uuid.UUID]string{
		oldest:      "Engineering",
		padded:      "engineering (" + padded.String()[:8] + ")",
		upper:       "ENGINEERING (" + upper.String()[:8] + ")",
		provisioned: "Engineering",
		elsewhere:   "Engineering",
	} {
		var got string
		if err := tx.QueryRow(ctx, `SELECT name FROM tenant.groups WHERE id = $1 AND tenant_id IN ($2, $3)`, id, tenant, other).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("group %s is named %q, want %q", id, got, want)
		}
	}
}
