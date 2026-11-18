//go:build integration

package abac

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestPolicyVersionsAreKeptWholeAndRestore checks that each save of a policy
// is kept whole as its next version with its author, that the policy names
// its version and last author, and that restoring a version saves it as the
// next one, in its organization only.
func TestPolicyVersionsAreKeptWholeAndRestore(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	asha, ravi := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	byAsha, byRavi := audit.Actor{UserID: &asha.ID, Type: "user"}, audit.Actor{UserID: &ravi.ID, Type: "user"}
	first := json.RawMessage(`{"attr":"resource.region","op":"eq","value":"eu"}`)
	p, err := svc.Create(ctx, organization, CreateInput{Name: "EU only", Effect: "deny", ResourceType: "invoice", Action: "read",
		Condition: first, Priority: 5, Enabled: true}, byAsha)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 || p.UpdatedBy == nil || *p.UpdatedBy != asha.ID {
		t.Errorf("a new policy: version %d, updated by %v; want 1, by Asha", p.Version, p.UpdatedBy)
	}
	p, err = svc.Update(ctx, p.ID, organization, UpdateInput{Name: "EU only", Effect: "deny", ResourceType: "invoice", Action: "read",
		Condition: json.RawMessage(`{}`), Priority: 9, Enabled: false}, byRavi)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 2 || *p.UpdatedBy != ravi.ID {
		t.Errorf("a changed policy: version %d, updated by %v; want 2, by Ravi", p.Version, p.UpdatedBy)
	}
	versions, err := svc.Versions(ctx, p.ID, organization)
	if err != nil || len(versions) != 2 || versions[0].Version != 2 || versions[1].Version != 1 {
		t.Fatalf("versions: %+v, %v; want 2 then 1", versions, err)
	}
	if v := versions[1]; v.Priority != 5 || !v.Enabled || *v.SavedBy != asha.ID || string(v.Condition) != `{"op": "eq", "attr": "resource.region", "value": "eu"}` {
		t.Errorf("version 1: %+v (%s); want the whole first save, by Asha", v, v.Condition)
	}

	restored, err := svc.Restore(ctx, p.ID, organization, 1, byRavi)
	if err != nil {
		t.Fatalf("restore version 1: %v", err)
	}
	if restored.Version != 3 || restored.Priority != 5 || !restored.Enabled || string(restored.Condition) == `{}` {
		t.Errorf("restored policy %+v; want version 3 with version 1's state", restored)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'abac_policy.restored' AND metadata->>'restored_from' = '1'`, organization); n != 1 {
		t.Errorf("%d restores audited, want 1", n)
	}
	if _, err := svc.Restore(ctx, p.ID, organization, 9, byRavi); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("restore a version there isn't: %v, want not found", err)
	}
	if _, err := svc.Versions(ctx, p.ID, other); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("another organization's versions: %v, want not found", err)
	}
	if _, err := svc.Restore(ctx, p.ID, other, 1, byRavi); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("restore from another organization: %v, want not found", err)
	}
}
