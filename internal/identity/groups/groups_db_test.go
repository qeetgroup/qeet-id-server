//go:build integration

package group

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestGroupsStayInTheirOrganization checks that one organization can neither read nor
// change another organization's group or its members, nor add another organization's user
// to a group of its own.
func TestGroupsStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	memberA := dbtest.User(t, organizationA, organizationA)
	adminB := dbtest.User(t, organizationB, organizationB)
	actor := audit.Actor{Type: "user"}

	groupA, err := svc.Create(ctx, CreateInput{OrganizationID: organizationA, Name: "Engineering"}, actor)
	if err != nil {
		t.Fatalf("create group in A: %v", err)
	}
	if err := svc.AddMember(ctx, groupA.ID, memberA.ID, organizationA, actor); err != nil {
		t.Fatalf("add member in A: %v", err)
	}
	groupB, err := svc.Create(ctx, CreateInput{OrganizationID: organizationB, Name: "Support"}, actor)
	if err != nil {
		t.Fatalf("create group in B: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), (&Handler{Service: svc, GrantCheck: rbac.NewRepository(dbtest.Pool(t)).CheckGrantGroup}).Mount)
	path := "/groups/" + groupA.ID.String()
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPatch, path, map[string]any{"name": "Renamed"}, http.StatusNotFound},
		{http.MethodPost, path + "/members/" + adminB.ID.String(), nil, http.StatusNotFound},
		{http.MethodDelete, path, nil, http.StatusNotFound},
		{http.MethodGet, "/tenants/" + organizationA.String() + "/groups", nil, http.StatusForbidden},
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
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+organizationB.String()+"/groups", nil)); slices.Contains(ids, groupA.ID) {
		t.Error("tenant B's group list includes tenant A's group")
	}

	members, err := svc.ListMembers(ctx, groupA.ID, organizationA)
	if err != nil || len(members) != 1 || members[0].UserID != memberA.ID {
		t.Errorf("tenant A's group members = %+v, %v; want only %s", members, err, memberA.ID)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.groups WHERE id = $1 AND name = 'Engineering'`, groupA.ID); n != 1 {
		t.Error("tenant B changed tenant A's group")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE group_id = $1`, groupB.ID); n != 0 {
		t.Error("tenant A's user was added to tenant B's group")
	}
}

// TestGroupNamesAreUniquePerOrganization checks that a group name, ignoring
// case, can be used once per organization by create, rename, import and
// templates, and again in another organization.
func TestGroupNamesAreUniquePerOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	adminA := dbtest.User(t, organizationA, organizationA)
	actor := audit.Actor{Type: "user"}

	if _, err := svc.Create(ctx, CreateInput{OrganizationID: organizationA, Name: "Engineering"}, actor); err != nil {
		t.Fatalf("create Engineering in A: %v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{OrganizationID: organizationA, Name: "engineering"}, actor); !errors.Is(err, errs.ErrGroupNameExists) {
		t.Errorf("create engineering in A: %v, want %v", err, errs.ErrGroupNameExists)
	}
	if _, err := svc.Create(ctx, CreateInput{OrganizationID: organizationA, Name: " Engineering  "}, actor); !errors.Is(err, errs.ErrGroupNameExists) {
		t.Errorf("create a space-padded Engineering in A: %v, want %v", err, errs.ErrGroupNameExists)
	}
	if _, err := svc.Create(ctx, CreateInput{OrganizationID: organizationB, Name: "Engineering"}, actor); err != nil {
		t.Errorf("create Engineering in B: %v", err)
	}
	if g, err := svc.Create(ctx, CreateInput{OrganizationID: organizationA, Name: "  Design "}, actor); err != nil || g.Name != "Design" {
		t.Errorf("create a space-padded Design: %+v, %v; want it named Design", g, err)
	}
	if _, err := svc.Create(ctx, CreateInput{OrganizationID: organizationA, Name: "  "}, actor); !errors.Is(err, errs.ErrValidationFailed) {
		t.Errorf("create a blank name: %v, want %v", err, errs.ErrValidationFailed)
	}

	platform, err := svc.Create(ctx, CreateInput{OrganizationID: organizationA, Name: "Platform"}, actor)
	if err != nil {
		t.Fatalf("create Platform in A: %v", err)
	}
	taken, own := "ENGINEERING", "platform"
	if _, err := svc.Update(ctx, platform.ID, organizationA, UpdateInput{Name: &taken}, actor); !errors.Is(err, errs.ErrGroupNameExists) {
		t.Errorf("rename Platform to %s: %v, want %v", taken, err, errs.ErrGroupNameExists)
	}
	if _, err := svc.Update(ctx, platform.ID, organizationA, UpdateInput{Name: &own}, actor); err != nil {
		t.Errorf("rename Platform to %s: %v", own, err)
	}
	blank := " "
	if _, err := svc.Update(ctx, platform.ID, organizationA, UpdateInput{Name: &blank}, actor); !errors.Is(err, errs.ErrValidationFailed) {
		t.Errorf("rename Platform to a blank name: %v, want %v", err, errs.ErrValidationFailed)
	}

	asA := dbtest.Serve(dbtest.Principal(adminA.ID, organizationA), (&Handler{Service: svc, GrantCheck: rbac.NewRepository(dbtest.Pool(t)).CheckGrantGroup}).Mount)
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

	res, err := svc.ImportGroups(ctx, organizationA, []ImportRow{{Name: "Ops"}, {Name: "OPS"}}, actor)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Created != 1 || res.Failed != 1 || res.Rows[1].Reason != "a group with this name already exists" {
		t.Errorf("import Ops and OPS: %+v, want one created and one refused as a duplicate", res)
	}

	tmpl, err := svc.CreateTemplate(ctx, organizationA, TemplateInput{Name: "Org", Nodes: []TemplateNode{{Name: "Ops"}}}, actor)
	if err != nil {
		t.Fatalf("create template: %v", err)
	}
	if _, err := svc.ApplyTemplate(ctx, tmpl.ID, organizationA, ApplyOptions{}, actor); !errors.Is(err, errs.ErrGroupNameExists) {
		t.Errorf("apply a template naming Ops: %v, want %v", err, errs.ErrGroupNameExists)
	}
}

// TestTemplateGroupNames checks that a template naming one group twice is
// refused when it is saved, and that a template applies once per
// organization, the second apply naming the group that already exists.
func TestTemplateGroupNames(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organization := dbtest.Organization(t)
	actor := audit.Actor{Type: "user"}

	_, err := svc.CreateTemplate(ctx, organization, TemplateInput{Name: "Departments", Nodes: []TemplateNode{
		{Name: "Sales", Children: []TemplateNode{{Name: "Leads"}}},
		{Name: "Support", Children: []TemplateNode{{Name: " leads"}}},
	}}, actor)
	if e := errs.As(err); e == nil || e.Code != errs.CodeValidation || len(e.Fields) != 1 || e.Fields[0].Code != "duplicate_name" {
		t.Errorf("save a template naming Leads twice: %v, want a duplicate_name validation error", err)
	}

	tmpl, err := svc.CreateTemplate(ctx, organization, TemplateInput{Name: "Teams", Nodes: []TemplateNode{
		{Name: "Sales", Children: []TemplateNode{{Name: "Sales leads"}}},
	}}, actor)
	if err != nil {
		t.Fatalf("save template: %v", err)
	}
	if _, err := svc.ApplyTemplate(ctx, tmpl.ID, organization, ApplyOptions{}, actor); err != nil {
		t.Fatalf("apply the template: %v", err)
	}
	_, err = svc.ApplyTemplate(ctx, tmpl.ID, organization, ApplyOptions{}, actor)
	if e := errs.As(err); !errors.Is(err, errs.ErrGroupNameExists) || e == nil || !strings.Contains(e.Detail, `"Sales"`) {
		t.Errorf("apply the template again: %v, want %v naming Sales", err, errs.ErrGroupNameExists)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.groups WHERE organization_id = $1`, organization); n != 2 {
		t.Errorf("tenant has %d groups after applying twice, want 2", n)
	}

	// A prefix, or a new name for the top group, applies it again elsewhere.
	created, err := svc.ApplyTemplate(ctx, tmpl.ID, organization, ApplyOptions{Prefix: "Pune · "}, actor)
	if err != nil || len(created) != 2 || created[0].Name != "Pune · Sales" || created[1].Name != "Pune · Sales leads" {
		t.Fatalf("apply with a prefix: %+v, %v; want both groups prefixed", created, err)
	}
	created, err = svc.ApplyTemplate(ctx, tmpl.ID, organization, ApplyOptions{Prefix: "Mumbai · ", RootName: "Office"}, actor)
	if err != nil || len(created) != 2 || created[0].Name != "Mumbai · Office" || created[1].Name != "Mumbai · Sales leads" {
		t.Errorf("apply with a prefix and a top name: %+v, %v", created, err)
	}
	_, err = svc.ApplyTemplate(ctx, tmpl.ID, organization, ApplyOptions{Prefix: strings.Repeat("x", 199)}, actor)
	if e := errs.As(err); e == nil || e.Code != errs.CodeValidation {
		t.Errorf("a prefix making names too long: %v, want a validation error", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.groups WHERE organization_id = $1`, organization); n != 6 {
		t.Errorf("tenant has %d groups, want 6: the refused apply made none", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'group_template.applied' AND metadata->>'prefix' = 'Pune · '`, organization); n != 1 {
		t.Errorf("%d applies audited with their prefix, want 1", n)
	}
}

// TestImportRowCodes checks that every group import row that isn't created
// carries a stable code and the field it concerns, beside its reason, and that
// a child listed before its parent is still created.
func TestImportRowCodes(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organization := dbtest.Organization(t)
	actor := audit.Actor{Type: "user"}
	if _, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Name: "Engineering"}, actor); err != nil {
		t.Fatal(err)
	}
	res, err := svc.ImportGroups(ctx, organization, []ImportRow{
		{Name: "engineering"},
		{Name: "  "},
		{Name: "Backend", Parent: "Platform"},
		{Name: "Platform"},
		{Name: "Orphan", Parent: "Nowhere"},
		{Name: "Ops"},
		{Name: "OPS"},
	}, actor)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	type outcome struct{ status, code, field string }
	got := map[string]outcome{}
	for _, row := range res.Rows {
		if row.Status != "created" && row.Reason == "" {
			t.Errorf("row %q: %s without a reason", row.Name, row.Status)
		}
		got[strings.ToLower(strings.TrimSpace(row.Name))] = outcome{row.Status, row.Code, row.Field}
	}
	for name, want := range map[string]outcome{
		"engineering": {"skipped", CodeImportNameExists, "name"},
		"":            {"failed", CodeImportNameRequired, "name"},
		"backend":     {"created", "", ""},
		"platform":    {"created", "", ""},
		"orphan":      {"failed", CodeImportParentNotFound, "parent"},
	} {
		if got[name] != want {
			t.Errorf("row %q: %+v, want %+v", name, got[name], want)
		}
	}
	var ops []outcome
	for _, row := range res.Rows {
		if strings.EqualFold(row.Name, "ops") {
			ops = append(ops, outcome{row.Status, row.Code, row.Field})
		}
	}
	if !slices.Contains(ops, outcome{"created", "", ""}) || !slices.Contains(ops, outcome{"failed", CodeImportNameExists, "name"}) {
		t.Errorf("Ops and OPS: %+v, want one created and one refused as a duplicate", ops)
	}
	if res.Created != 3 || res.Skipped != 1 || res.Failed != 3 {
		t.Errorf("totals: created %d, skipped %d, failed %d; want 3, 1, 3", res.Created, res.Skipped, res.Failed)
	}
}

// TestGroupsListTheirRoles checks that the list carries each group's roles,
// from one organization only, for a caller who may read roles; that it filters
// by role; and that without role.read neither roles nor role filters are given.
func TestGroupsListTheirRoles(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	svc := NewService(pool)
	group := func(organizationID uuid.UUID, name string) uuid.UUID {
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, $2) RETURNING id`, organizationID, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	role := func(organizationID uuid.UUID, name string) uuid.UUID {
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name) VALUES ($1, $2) RETURNING id`, organizationID, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	grant := func(organizationID, groupID, roleID uuid.UUID) {
		if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organizationID, groupID, roleID); err != nil {
			t.Fatal(err)
		}
	}
	engineering := group(organization, "Engineering")
	group(organization, "Sales")
	editor, viewer := role(organization, "Editor"), role(organization, "Viewer")
	grant(organization, engineering, editor)
	grant(organization, engineering, viewer)
	elsewhere := group(other, "Elsewhere")
	grant(other, elsewhere, role(other, "Owner elsewhere"))

	serve := func(readsRoles bool) http.Handler {
		return dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc, ReadsRoles: func(*http.Request) bool { return readsRoles }}).Mount)
	}
	list := func(h http.Handler, query string) (map[string]string, int) {
		rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+organization.String()+"/groups"+query, nil)
		var page struct {
			Items []Group `json:"items"`
		}
		dbtest.Decode(t, rec, &page)
		out := map[string]string{}
		for _, g := range page.Items {
			roles := "absent"
			if g.Roles != nil {
				names := []string{}
				for _, r := range *g.Roles {
					names = append(names, r.Name)
				}
				roles = strings.Join(names, "+")
			}
			out[g.Name] = roles
		}
		return out, rec.Code
	}
	if got, _ := list(serve(true), ""); got["Engineering"] != "Editor+Viewer" || got["Sales"] != "" || len(got) != 2 {
		t.Errorf("with role.read: %v; want Engineering's two roles, Sales none, and nothing of another organisation", got)
	}
	if got, _ := list(serve(true), "?grants=none"); len(got) != 1 || got["Sales"] != "" {
		t.Errorf("grants=none: %v, want Sales only", got)
	}
	if got, _ := list(serve(true), "?role="+viewer.String()); len(got) != 1 || got["Engineering"] == "absent" {
		t.Errorf("role filter: %v, want Engineering only", got)
	}
	if got, _ := list(serve(false), ""); got["Engineering"] != "absent" || got["Sales"] != "absent" {
		t.Errorf("without role.read: %v, want no roles", got)
	}
	if _, code := list(serve(false), "?grants=some"); code != http.StatusForbidden {
		t.Errorf("a role filter without role.read: %d, want 403", code)
	}
}
