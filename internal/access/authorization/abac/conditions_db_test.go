//go:build integration

package abac_test

import (
	"encoding/json"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestRoleAndRelationConditionsDecide checks that a policy combining a role
// with a relationship decides on the roles the platform supplies and on the
// relationships stored for the subject, and that without a relationship
// engine a relation condition grants nothing.
func TestRoleAndRelationConditionsDecide(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := abac.NewService(pool)
	relations := rebac.NewService(pool)
	svc.SetRelationCheck(relations.Check)
	organization := dbtest.Organization(t)
	editor, viewer := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	system := audit.Actor{Type: "system"}
	if _, err := relations.Write(ctx, organization, "document:plan", "editor", "user:"+editor.ID.String(), system); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, organization, abac.CreateInput{Name: "Editors who are writers", Effect: "allow", ResourceType: "document", Action: "edit",
		Condition: json.RawMessage(`{"all":[{"role":"writer"},{"relation":{"relation":"editor","object":{"attr":"resource.object"}}}]}`),
		Enabled:   true}, system); err != nil {
		t.Fatal(err)
	}
	decide := func(user string, roles ...any) bool {
		t.Helper()
		d, err := svc.Evaluate(ctx, organization, abac.EvaluationInput{
			Subject:  map[string]any{"id": user, "type": "user", "roles": roles},
			Resource: abac.EvaluationResource{Type: "document", ID: "plan", Attrs: map[string]any{"object": "document:plan"}},
			Action:   "edit",
		})
		if err != nil {
			t.Fatal(err)
		}
		return d.Allow
	}
	if !decide(editor.ID.String(), "writer") {
		t.Error("an editor with the role was refused")
	}
	if decide(editor.ID.String(), "reader") {
		t.Error("an editor without the role was allowed")
	}
	if decide(viewer.ID.String(), "writer") {
		t.Error("someone with the role but no relationship was allowed")
	}
	svc.SetRelationCheck(nil)
	if decide(editor.ID.String(), "writer") {
		t.Error("a relation condition granted without a relationship engine")
	}
}
