//go:build integration

package group

import (
	"errors"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

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
	if e := errs.As(err); !errors.Is(err, ErrNameExists) || e == nil || !strings.Contains(e.Detail, `"Sales"`) {
		t.Errorf("apply the template again: %v, want %v naming Sales", err, ErrNameExists)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.groups WHERE organization_id = $1`, organization); n != 2 {
		t.Errorf("organization has %d groups after applying twice, want 2", n)
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
		t.Errorf("organization has %d groups, want 6: the refused apply made none", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'group_template.applied' AND metadata->>'prefix' = 'Pune · '`, organization); n != 1 {
		t.Errorf("%d applies audited with their prefix, want 1", n)
	}
}
