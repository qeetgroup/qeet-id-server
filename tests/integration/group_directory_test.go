//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/identity/groups"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// The directory KPIs need a member count per group. Computing it per group
// would be one round trip each, so List carries it.
func TestGroupService_ListCarriesMemberCount(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("grpcount"))
	svc := group.NewService(testPool)
	actor := audit.Actor{Type: "system"}

	withMembers, err := svc.Create(ctx, group.CreateInput{TenantID: tid, Name: "with-members"}, actor)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	empty, err := svc.Create(ctx, group.CreateInput{TenantID: tid, Name: "empty"}, actor)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i := 0; i < 2; i++ {
		u := createTenantUser(t, ctx, tid, uniqueSlug("m")+"@example.com")
		if err := svc.AddMember(ctx, withMembers.ID, u, tid, actor); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
	}

	list, err := svc.List(ctx, tid)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	counts := map[string]int{}
	for _, g := range list {
		counts[g.Name] = g.MemberCount
	}
	if counts["with-members"] != 2 {
		t.Errorf("member_count = %d, want 2", counts["with-members"])
	}
	if counts["empty"] != 0 {
		t.Errorf("empty group member_count = %d, want 0", counts["empty"])
	}
	_ = empty
}

func TestGroupService_TemplateApplyBuildsTree(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("grptmpl"))
	svc := group.NewService(testPool)
	actor := audit.Actor{Type: "system"}

	tmpl, err := svc.CreateTemplate(ctx, tid, group.TemplateInput{
		Name: "Engineering org",
		Nodes: []group.TemplateNode{{
			Name: "Engineering",
			Children: []group.TemplateNode{
				{Name: "Platform"},
				{Name: "Product", Children: []group.TemplateNode{{Name: "Web"}}},
			},
		}},
	}, actor)
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	if tmpl.GroupCount != 4 {
		t.Errorf("GroupCount = %d, want 4", tmpl.GroupCount)
	}

	created, err := svc.ApplyTemplate(ctx, tmpl.ID, tid, nil, actor)
	if err != nil {
		t.Fatalf("ApplyTemplate: %v", err)
	}
	if len(created) != 4 {
		t.Fatalf("applied %d groups, want 4", len(created))
	}

	byName := map[string]group.Group{}
	for _, g := range created {
		byName[g.Name] = g
	}
	root, ok := byName["Engineering"]
	if !ok || root.ParentID != nil {
		t.Fatal("Engineering should exist at the root")
	}
	platform := byName["Platform"]
	if platform.ParentID == nil || *platform.ParentID != root.ID {
		t.Error("Platform should be a child of Engineering")
	}
	web, product := byName["Web"], byName["Product"]
	if web.ParentID == nil || *web.ParentID != product.ID {
		t.Error("Web should be a child of Product — nesting must survive one level down")
	}
}

// tenant.groups.parent_id has a plain foreign key to groups(id), not a
// tenant-scoped one, so a caller-supplied parent must be checked against the
// caller's own tenant or a template could be grafted under another tenant's
// group.
func TestGroupService_TemplateApplyRejectsForeignParent(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	mine := createTenant(t, ctx, uniqueSlug("grpmine"))
	theirs := createTenant(t, ctx, uniqueSlug("grptheirs"))
	svc := group.NewService(testPool)
	actor := audit.Actor{Type: "system"}

	foreign, err := svc.Create(ctx, group.CreateInput{TenantID: theirs, Name: "their-root"}, actor)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	tmpl, err := svc.CreateTemplate(ctx, mine, group.TemplateInput{
		Name:  "Graft",
		Nodes: []group.TemplateNode{{Name: "mine"}},
	}, actor)
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}

	if _, err := svc.ApplyTemplate(ctx, tmpl.ID, mine, &foreign.ID, actor); !errors.Is(err, errs.ErrGroupNotFound) {
		t.Fatalf("err = %v, want ErrGroupNotFound for a parent in another tenant", err)
	}
	list, err := svc.List(ctx, mine)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("a rejected apply must create nothing, got %d groups", len(list))
	}
}

func TestGroupService_TemplateValidation(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("grpval"))
	svc := group.NewService(testPool)
	actor := audit.Actor{Type: "system"}

	cases := []struct {
		name string
		in   group.TemplateInput
		want error
	}{
		{"unnamed template", group.TemplateInput{Nodes: []group.TemplateNode{{Name: "a"}}}, errs.ErrGroupTemplateUnnamed},
		{"no nodes", group.TemplateInput{Name: "empty"}, errs.ErrGroupTemplateEmpty},
		{"unnamed node", group.TemplateInput{Name: "x", Nodes: []group.TemplateNode{{Name: "  "}}}, errs.ErrGroupTemplateNodeUnnamed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.CreateTemplate(ctx, tid, tc.in, actor); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	deep := group.TemplateNode{Name: "l1"}
	cur := &deep
	for i := 0; i < 7; i++ {
		cur.Children = []group.TemplateNode{{Name: "deeper"}}
		cur = &cur.Children[0]
	}
	if _, err := svc.CreateTemplate(ctx, tid, group.TemplateInput{
		Name: "too deep", Nodes: []group.TemplateNode{deep},
	}, actor); !errors.Is(err, errs.ErrGroupTemplateTooDeep) {
		t.Fatalf("deep template err = %v, want ErrGroupTemplateTooDeep", err)
	}
}

// Import resolves parents by name, and a child may appear before its parent in
// the payload — a CSV isn't guaranteed to be topologically sorted.
func TestGroupService_ImportResolvesOutOfOrderParents(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("grpimp"))
	svc := group.NewService(testPool)
	actor := audit.Actor{Type: "system"}

	res, err := svc.ImportGroups(ctx, tid, []group.ImportRow{
		{Name: "Frontend", Parent: "Engineering"}, // child first
		{Name: "Engineering"},
		{Name: "Orphan", Parent: "Nope"}, // parent never appears
	}, actor)
	if err != nil {
		t.Fatalf("ImportGroups: %v", err)
	}
	if res.Created != 2 {
		t.Errorf("Created = %d, want 2", res.Created)
	}
	if res.Failed != 1 {
		t.Errorf("Failed = %d, want 1", res.Failed)
	}

	list, err := svc.List(ctx, tid)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var engID, frontendParent any
	for _, g := range list {
		if g.Name == "Engineering" {
			engID = g.ID
		}
		if g.Name == "Frontend" && g.ParentID != nil {
			frontendParent = *g.ParentID
		}
	}
	if engID == nil || frontendParent != engID {
		t.Error("Frontend should be parented to Engineering despite arriving first")
	}
}

// A row naming an existing group is a skip, not a failure: re-running an import
// should be safe.
func TestGroupService_ImportSkipsExistingNames(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("grpimp2"))
	svc := group.NewService(testPool)
	actor := audit.Actor{Type: "system"}

	rows := []group.ImportRow{{Name: "Support"}, {Name: "Sales"}}
	if _, err := svc.ImportGroups(ctx, tid, rows, actor); err != nil {
		t.Fatalf("first import: %v", err)
	}
	res, err := svc.ImportGroups(ctx, tid, rows, actor)
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if res.Created != 0 || res.Skipped != 2 || res.Failed != 0 {
		t.Fatalf("re-import = created %d / skipped %d / failed %d, want 0/2/0",
			res.Created, res.Skipped, res.Failed)
	}
}
