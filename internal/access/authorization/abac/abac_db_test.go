//go:build integration

package abac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestTemplatesThroughTheAPI saves the console's attribute-comparing templates
// as the console sends them, and checks the evaluate endpoint decides each as
// its description says, a malformed reference being refused at save.
func TestTemplatesThroughTheAPI(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	api := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: NewService(dbtest.Pool(t))}).Mount)
	base := "/tenants/" + tenant.String() + "/abac"
	save := func(name, effect, resourceType, action, condition string, priority int) *httptest.ResponseRecorder {
		return dbtest.Do(t, api, http.MethodPost, base+"/policies", map[string]any{
			"name": name, "effect": effect, "resource_type": resourceType, "action": action,
			"condition": json.RawMessage(condition), "priority": priority, "enabled": true,
		})
	}

	ids := map[string]uuid.UUID{}
	for _, p := range []struct {
		name, effect, resourceType, action, condition string
		priority                                      int
	}{
		{"sfdc_region_scoped_accounts", "allow", "account", "read", regionScoped, 30},
		{"phi_care_team_read", "allow", "patient_record", "read", careTeam, 70},
		{"sox_payment_sod", "deny", "payment", "approve", creatorMayNotApprove, 95},
		{"approvers_approve", "allow", "payment", "approve", approversApprove, 10},
		{"gov_clearance_gate", "allow", "document", "read", clearance, 80},
	} {
		rec := save(p.name, p.effect, p.resourceType, p.action, p.condition, p.priority)
		if rec.Code != http.StatusCreated {
			t.Fatalf("save %s: status %d (%s)", p.name, rec.Code, rec.Body.String())
		}
		var created Policy
		dbtest.Decode(t, rec, &created)
		ids[p.name] = created.ID
	}

	bad := save("bad_reference", "allow", "account", "read", refLeaf("subject.region", "eq", "tenant.region"), 0)
	if bad.Code != http.StatusUnprocessableEntity || !strings.Contains(bad.Body.String(), errs.CodeABACConditionInvalid) {
		t.Errorf("save a reference to an unknown namespace: status %d (%s), want 422 %s", bad.Code, bad.Body.String(), errs.CodeABACConditionInvalid)
	}

	team := []any{"p1", "p2"}
	for _, tc := range []struct {
		name                 string
		resourceType, action string
		subject, resource    map[string]any
		by                   string // the policy that decides; "" for the default deny
		allow                bool
	}{
		{"rep reads an account in their region", "account", "read", map[string]any{"region": "emea"}, map[string]any{"region": "emea"}, "sfdc_region_scoped_accounts", true},
		{"rep reads an account in another region", "account", "read", map[string]any{"region": "emea"}, map[string]any{"region": "apac"}, "", false},
		{"account has no region", "account", "read", map[string]any{"region": "emea"}, nil, "", false},
		{"clinician reads a patient on their care team", "patient_record", "read", map[string]any{"role": "clinician", "care_team_ids": team}, map[string]any{"patient_id": "p2"}, "phi_care_team_read", true},
		{"clinician reads a patient off their care team", "patient_record", "read", map[string]any{"role": "clinician", "care_team_ids": team}, map[string]any{"patient_id": "p9"}, "", false},
		{"creator approves their own payment", "payment", "approve", map[string]any{"id": "u1", "role": "approver"}, map[string]any{"created_by": "u1"}, "sox_payment_sod", false},
		{"another approver approves it", "payment", "approve", map[string]any{"id": "u2", "role": "approver"}, map[string]any{"created_by": "u1"}, "approvers_approve", true},
		{"payment's creator is unknown", "payment", "approve", map[string]any{"id": "u2", "role": "approver"}, nil, "sox_payment_sod", false},
		{"clearance above the classification", "document", "read", map[string]any{"clearance_level": 3}, map[string]any{"classification_level": 2}, "gov_clearance_gate", true},
		{"clearance below the classification", "document", "read", map[string]any{"clearance_level": 1}, map[string]any{"classification_level": 2}, "", false},
	} {
		rec := dbtest.Do(t, api, http.MethodPost, base+"/evaluate", EvaluationInput{
			Subject:  tc.subject,
			Resource: EvaluationResource{Type: tc.resourceType, ID: "r1", Attrs: tc.resource},
			Action:   tc.action,
		})
		var dec Decision
		dbtest.Decode(t, rec, &dec)
		if rec.Code != http.StatusOK || dec.Allow != tc.allow {
			t.Errorf("%s: status %d, allow %v, want %v (%s)", tc.name, rec.Code, dec.Allow, tc.allow, dec.Reason)
		}
		switch {
		case tc.by == "" && dec.MatchedPolicyID != nil:
			t.Errorf("%s: decided by policy %s, want the default deny", tc.name, dec.MatchedPolicyID)
		case tc.by != "" && (dec.MatchedPolicyID == nil || *dec.MatchedPolicyID != ids[tc.by]):
			t.Errorf("%s: decided by %v, want %s (%s)", tc.name, dec.MatchedPolicyID, tc.by, dec.Reason)
		}
	}
}
