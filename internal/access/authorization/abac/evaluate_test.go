package abac

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestCombine_Templates evaluates the console's attribute-comparing templates
// as stored policies, through the same combining step as the evaluate API.
func TestCombine_Templates(t *testing.T) {
	policy := func(name, effect, cond string) candidate {
		return candidate{id: uuid.New(), name: name, effect: effect, condition: []byte(cond)}
	}
	region := policy("sfdc_region_scoped_accounts", "allow", regionScoped)
	phi := policy("phi_care_team_read", "allow", careTeam)
	sod := policy("sox_payment_sod", "deny", creatorMayNotApprove)
	approvers := policy("approvers_approve", "allow", approversApprove)
	gov := policy("gov_clearance_gate", "allow", clearance)
	for _, p := range []candidate{region, phi, sod, approvers, gov} {
		if err := validateCondition(p.condition); err != nil {
			t.Fatalf("%s does not save: %v", p.name, err)
		}
	}

	team := []any{"p1", "p2"}
	for _, tc := range []struct {
		name              string
		policies          []candidate
		subject, resource map[string]any
		by                *candidate // the policy that decides; nil for the default deny
		allow             bool
	}{
		{"rep reads an account in their region", []candidate{region}, map[string]any{"region": "emea"}, map[string]any{"region": "emea"}, &region, true},
		{"rep reads an account in another region", []candidate{region}, map[string]any{"region": "emea"}, map[string]any{"region": "apac"}, nil, false},
		{"account has no region", []candidate{region}, map[string]any{"region": "emea"}, nil, nil, false},
		{"rep has no region", []candidate{region}, nil, map[string]any{"region": "emea"}, nil, false},

		{"clinician reads a patient on their care team", []candidate{phi}, map[string]any{"role": "clinician", "care_team_ids": team}, map[string]any{"patient_id": "p2"}, &phi, true},
		{"clinician reads a patient off their care team", []candidate{phi}, map[string]any{"role": "clinician", "care_team_ids": team}, map[string]any{"patient_id": "p9"}, nil, false},
		{"non-clinician on the care team", []candidate{phi}, map[string]any{"role": "billing", "care_team_ids": team}, map[string]any{"patient_id": "p2"}, nil, false},
		{"record names no patient", []candidate{phi}, map[string]any{"role": "clinician", "care_team_ids": team}, nil, nil, false},
		{"clinician has no care team", []candidate{phi}, map[string]any{"role": "clinician"}, map[string]any{"patient_id": "p2"}, nil, false},

		{"creator approves their own payment", []candidate{sod, approvers}, map[string]any{"id": "u1", "role": "approver"}, map[string]any{"created_by": "u1"}, &sod, false},
		{"another approver approves it", []candidate{sod, approvers}, map[string]any{"id": "u2", "role": "approver"}, map[string]any{"created_by": "u1"}, &approvers, true},
		{"payment's creator is unknown", []candidate{sod, approvers}, map[string]any{"id": "u2", "role": "approver"}, nil, &sod, false},
		{"approver's id is unknown", []candidate{sod, approvers}, map[string]any{"role": "approver"}, map[string]any{"created_by": "u1"}, &sod, false},
		{"another user, and no allow policy", []candidate{sod}, map[string]any{"id": "u2"}, map[string]any{"created_by": "u1"}, nil, false},

		{"clearance above the classification", []candidate{gov}, map[string]any{"clearance_level": float64(3)}, map[string]any{"classification_level": float64(2)}, &gov, true},
		{"clearance at the classification", []candidate{gov}, map[string]any{"clearance_level": float64(3)}, map[string]any{"classification_level": float64(3)}, &gov, true},
		{"clearance below the classification", []candidate{gov}, map[string]any{"clearance_level": float64(2)}, map[string]any{"classification_level": float64(3)}, nil, false},
		{"document has no classification", []candidate{gov}, map[string]any{"clearance_level": float64(3)}, nil, nil, false},
		{"classification sent as text", []candidate{gov}, map[string]any{"clearance_level": float64(3)}, map[string]any{"classification_level": "2"}, nil, false},
	} {
		dec := combine(tc.policies, attributeBag(EvaluationInput{
			Subject:  tc.subject,
			Resource: EvaluationResource{Type: "record", ID: "r1", Attrs: tc.resource},
			Action:   "act",
		}))
		if dec.Allow != tc.allow {
			t.Errorf("%s: allow = %v, want %v (%s)", tc.name, dec.Allow, tc.allow, dec.Reason)
		}
		switch {
		case tc.by == nil && dec.MatchedPolicyID != nil:
			t.Errorf("%s: decided by policy %s, want the default deny", tc.name, dec.MatchedPolicyID)
		case tc.by != nil && (dec.MatchedPolicyID == nil || *dec.MatchedPolicyID != tc.by.id):
			t.Errorf("%s: decided by %v, want %s (%s)", tc.name, dec.MatchedPolicyID, tc.by.name, dec.Reason)
		}
	}

	dec := combine([]candidate{sod, approvers}, attributeBag(EvaluationInput{Subject: map[string]any{"id": "u2", "role": "approver"}}))
	if !strings.Contains(dec.Reason, "absent") || !strings.Contains(strings.Join(dec.Trace, "\n"), "absent → deny") {
		t.Errorf("a deny applied for an absent attribute must say so: %q %q", dec.Reason, dec.Trace)
	}
}

// TestDecisionReasonCodes checks that each kind of decision carries its reason
// code and names the policy that decided, and that a condition error names the
// policy without the evaluation error.
func TestDecisionReasonCodes(t *testing.T) {
	b := resourceBag(map[string]any{"name": "prod-api"})
	allow := candidate{id: uuid.New(), name: "allow_prod", effect: "allow", priority: 5, condition: []byte(`{"attr":"resource.name","op":"prefix","value":"prod-"}`)}
	deny := candidate{id: uuid.New(), name: "deny_prod", effect: "deny", priority: 9, condition: []byte(`{"attr":"resource.name","op":"prefix","value":"prod-"}`)}
	absent := candidate{id: uuid.New(), name: "deny_owner", effect: "deny", priority: 7, condition: []byte(`{"attr":"resource.owner","op":"eq","value":{"attr":"subject.id"}}`)}
	broken := candidate{id: uuid.New(), name: "broken", effect: "allow", priority: 3, condition: []byte(`{"attr":"resource.name","op":"bogus","value":"x"}`)}
	notEng := candidate{id: uuid.New(), name: "deny_outside_eng", effect: "deny", priority: 6, condition: []byte(`{"attr":"subject.department","op":"ne","value":"eng"}`)}
	allowNotEng := candidate{id: uuid.New(), name: "allow_outside_eng", effect: "allow", priority: 6, condition: notEng.condition}
	for _, tc := range []struct {
		name     string
		policies []candidate
		code     string
		by       *candidate
	}{
		{"an allow policy matches", []candidate{allow}, ReasonAllowedByPolicy, &allow},
		{"a deny policy matches", []candidate{deny, allow}, ReasonDeniedByPolicy, &deny},
		{"a deny compares an absent attribute", []candidate{absent}, ReasonAttributeAbsent, &absent},
		{"a deny compares an absent attribute with a literal", []candidate{notEng, allow}, ReasonAttributeAbsent, &notEng},
		{"an allow compares an absent attribute with a literal", []candidate{allowNotEng}, ReasonNoMatchingAllow, nil},
		{"a condition fails to evaluate", []candidate{broken}, ReasonConditionError, &broken},
		{"nothing matches", nil, ReasonNoMatchingAllow, nil},
	} {
		dec := combine(tc.policies, b)
		if dec.ReasonCode != tc.code {
			t.Errorf("%s: reason code %q, want %q", tc.name, dec.ReasonCode, tc.code)
		}
		var want map[string]any
		if tc.by != nil {
			want = map[string]any{"policy_id": tc.by.id, "policy_name": tc.by.name, "priority": tc.by.priority}
		}
		if fmt.Sprint(dec.ReasonParams) != fmt.Sprint(want) {
			t.Errorf("%s: reason params %v, want %v", tc.name, dec.ReasonParams, want)
		}
	}

	dec := combine([]candidate{broken}, b)
	if shown := dec.Reason + strings.Join(dec.Trace, "\n"); strings.Contains(shown, "unknown operator") || strings.Contains(shown, "bogus") {
		t.Errorf("a condition error showed its evaluation error: %q", shown)
	}
}
