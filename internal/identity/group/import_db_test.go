//go:build integration

package group

import (
	"slices"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

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
