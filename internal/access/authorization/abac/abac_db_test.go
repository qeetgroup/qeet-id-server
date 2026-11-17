//go:build integration

package abac

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// namedRole creates a role called name in organization and returns its id.
func namedRole(t *testing.T, organization uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `INSERT INTO rbac.roles (organization_id, name) VALUES ($1, $2) RETURNING id`, organization, name).Scan(&id); err != nil {
		t.Fatalf("create role %s: %v", name, err)
	}
	return id
}

// group creates a group called name in organization holding roles, with members.
func group(t *testing.T, organization uuid.UUID, name string, roles []uuid.UUID, members ...uuid.UUID) {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, $2) RETURNING id`, organization, name).Scan(&id); err != nil {
		t.Fatalf("create group %s: %v", name, err)
	}
	for _, m := range members {
		if _, err := pool.Exec(ctx, `INSERT INTO organization.group_members (group_id, user_id, organization_id) VALUES ($1, $2, $3)`, id, m, organization); err != nil {
			t.Fatalf("add a member to %s: %v", name, err)
		}
	}
	for _, r := range roles {
		if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organization, id, r); err != nil {
			t.Fatalf("give %s a role: %v", name, err)
		}
	}
}

// session opens a session for user in organization whose sign-in met factor ("" for
// none) and returns its id.
func session(t *testing.T, user, organization uuid.UUID, factor string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		INSERT INTO auth.sessions (user_id, organization_id, second_factor) VALUES ($1, $2, NULLIF($3, '')) RETURNING id
	`, user, organization, factor).Scan(&id); err != nil {
		t.Fatalf("open a session: %v", err)
	}
	return id
}

// TestPlatformAttributes checks that the platform names a person's groups and
// roles in the organization decided in, direct and through a group, and none
// from another; that context.mfa says whether their session met a second
// factor or holds a fresh step-up, and is left out for a session it can't
// read; and that ip is the call's address.
func TestPlatformAttributes(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := NewService(pool)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	person := dbtest.User(t, organization)
	dbtest.Assign(t, person.ID, organization, namedRole(t, organization, "Billing Admin"))
	dbtest.Assign(t, person.ID, other, namedRole(t, other, "Elsewhere"))
	group(t, organization, "Finance", []uuid.UUID{namedRole(t, organization, "Auditor")}, person.ID)
	group(t, organization, "Contractors", nil)
	group(t, other, "Other Team", nil, person.ID)

	subject, ctxAttrs, err := svc.PlatformAttributes(ctx, Request{Subject: person.ID.String(), UserID: person.ID, OrganizationID: organization, IP: "203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(subject["groups"], subject["roles"]); got != "[Finance] [Auditor Billing Admin]" {
		t.Errorf("groups and roles %s, want this organisation's only", got)
	}
	if subject["id"] != person.ID.String() || subject["tenant_id"] != organization.String() || ctxAttrs["ip"] != "203.0.113.7" {
		t.Errorf("subject %v, context %v; want the person, the organisation and the address", subject, ctxAttrs)
	}
	if _, ok := ctxAttrs["mfa"]; ok {
		t.Errorf("context %v: mfa without a session", ctxAttrs)
	}

	stepped := session(t, person.ID, organization, "")
	if _, err := pool.Exec(ctx, `INSERT INTO auth.mfa_verifications (user_id, session_id, method) VALUES ($1, $2, 'totp')`, person.ID, stepped); err != nil {
		t.Fatal(err)
	}
	revoked := session(t, person.ID, organization, "passkey")
	if _, err := pool.Exec(ctx, `UPDATE auth.sessions SET revoked_at = NOW() WHERE id = $1`, revoked); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		r       Request
		want    any
		present bool
	}{
		{"a passkey sign-in", Request{SessionID: session(t, person.ID, organization, "passkey")}, true, true},
		{"a remembered device", Request{SessionID: session(t, person.ID, organization, "trusted_device")}, true, true},
		{"no second factor", Request{SessionID: session(t, person.ID, organization, "")}, false, true},
		{"a fresh step-up", Request{SessionID: stepped}, true, true},
		{"a hosted-login call that proved one", Request{MFA: true}, true, true},
		{"a revoked session", Request{SessionID: revoked}, nil, false},
		{"another organisation's session", Request{SessionID: session(t, person.ID, other, "passkey")}, nil, false},
	} {
		tc.r.Subject, tc.r.UserID, tc.r.OrganizationID = person.ID.String(), person.ID, organization
		_, ctxAttrs, err := svc.PlatformAttributes(ctx, tc.r)
		if mfa, ok := ctxAttrs["mfa"]; err != nil || ok != tc.present || mfa != tc.want {
			t.Errorf("%s: context %v, %v; want mfa %v (present %v)", tc.name, ctxAttrs, err, tc.want, tc.present)
		}
	}
}

// TestLockOutIsJudgedOnTheAuthorsCall checks that a deny on every action for
// a session without a second factor saves for an author whose session met one
// and is refused for one whose session didn't, as it would lock them out, and
// that a deny on a group saves for an author outside it.
func TestLockOutIsJudgedOnTheAuthorsCall(t *testing.T) {
	organization := dbtest.Organization(t)
	author := dbtest.User(t, organization, organization)
	group(t, organization, "Contractors", nil)
	svc := NewService(dbtest.Pool(t))
	save := func(sessionID uuid.UUID, name, condition string) *httptest.ResponseRecorder {
		p := dbtest.Principal(author.ID, organization)
		p.SessionID = &sessionID
		api := dbtest.Serve(p, (&Handler{Service: svc}).Mount)
		return dbtest.Do(t, api, http.MethodPost, "/tenants/"+organization.String()+"/abac/policies", map[string]any{
			"name": name, "effect": "deny", "resource_type": "*", "action": "*", "condition": json.RawMessage(condition), "enabled": true,
		})
	}
	noMFA := `{"attr":"context.mfa","op":"ne","value":true}`
	if rec := save(session(t, author.ID, organization, ""), "deny_without_mfa", noMFA); !strings.Contains(rec.Body.String(), errs.CodeABACPolicyLocksOut) {
		t.Errorf("an author without a second factor saved a deny without one: %d %s", rec.Code, rec.Body.String())
	}
	if rec := save(session(t, author.ID, organization, "mfa"), "deny_without_mfa", noMFA); rec.Code != http.StatusCreated {
		t.Errorf("an author with a second factor saving a deny without one: %d %s", rec.Code, rec.Body.String())
	}
	contractors := `{"attr":"subject.groups","op":"contains","value":"Contractors"}`
	if rec := save(session(t, author.ID, organization, ""), "deny_contractors", contractors); rec.Code != http.StatusCreated {
		t.Errorf("an author outside a group saving a deny on it: %d %s", rec.Code, rec.Body.String())
	}
}

// TestTemplatesThroughTheAPI saves the console's attribute-comparing templates
// as the console sends them, and checks the evaluate endpoint decides each as
// its description says, a malformed reference being refused at save.
func TestTemplatesThroughTheAPI(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	api := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: NewService(dbtest.Pool(t))}).Mount)
	base := "/tenants/" + organization.String() + "/abac"
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

// TestEvaluateADraft checks that the evaluate endpoint decides with a draft
// policy among the stored ones without saving it: a new draft can decide, one
// standing in for a stored policy takes its place, a disabled one only takes
// it out, and a draft for another resource is passed over. An invalid draft
// is refused, and one replacing another organization's policy is not found.
func TestEvaluateADraft(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	svc := NewService(dbtest.Pool(t))
	api := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	base := "/tenants/" + organization.String() + "/abac"
	rec := dbtest.Do(t, api, http.MethodPost, base+"/policies", map[string]any{
		"name": "approvers_approve", "effect": "allow", "resource_type": "payment", "action": "approve",
		"condition": json.RawMessage(approversApprove), "priority": 10, "enabled": true,
	})
	var stored Policy
	dbtest.Decode(t, rec, &stored)
	elsewhere, err := svc.Create(dbtest.Context(t), other, CreateInput{
		Name: "theirs", Effect: "allow", ResourceType: "payment", Action: "approve", Enabled: true,
	}, audit.Actor{})
	if err != nil {
		t.Fatalf("a policy in another organisation: %v", err)
	}

	draft := func(effect, condition string, priority int, enabled bool, replaces *uuid.UUID) map[string]any {
		return map[string]any{
			"name": "trial", "effect": effect, "resource_type": "payment", "action": "approve",
			"condition": json.RawMessage(condition), "priority": priority, "enabled": enabled, "replaces": replaces,
		}
	}
	evaluate := func(d map[string]any) (*httptest.ResponseRecorder, Decision) {
		t.Helper()
		body := map[string]any{
			"subject":  map[string]any{"id": "u2", "role": "approver"},
			"resource": map[string]any{"type": "payment", "id": "p1", "attrs": map[string]any{"amount": 5000}},
			"action":   "approve",
		}
		if d != nil {
			body["draft"] = d
		}
		rec := dbtest.Do(t, api, http.MethodPost, base+"/evaluate", body)
		var dec Decision
		if rec.Code == http.StatusOK {
			dbtest.Decode(t, rec, &dec)
		}
		return rec, dec
	}

	overLimit := `{"attr":"resource.amount","op":"gt","value":1000}`
	treasurers := `{"attr":"subject.role","op":"eq","value":"treasurer"}`
	for _, tc := range []struct {
		name           string
		draft          map[string]any
		allow, byDraft bool
		by             *uuid.UUID
	}{
		{"no draft", nil, true, false, &stored.ID},
		{"a new deny over a limit", draft("deny", overLimit, 50, true, nil), false, true, nil},
		{"a new allow beside the stored one", draft("allow", overLimit, 50, true, nil), true, true, nil},
		{"the stored allow narrowed to treasurers", draft("allow", treasurers, 10, true, &stored.ID), false, false, nil},
		{"the stored allow disabled", draft("allow", approversApprove, 10, false, &stored.ID), false, false, nil},
		{"the stored allow as it is", draft("allow", approversApprove, 10, true, &stored.ID), true, true, &stored.ID},
		{"a deny for another resource", map[string]any{"effect": "deny", "resource_type": "invoice", "action": "approve", "enabled": true}, true, false, &stored.ID},
	} {
		rec, dec := evaluate(tc.draft)
		if rec.Code != http.StatusOK || dec.Allow != tc.allow || dec.MatchedDraft != tc.byDraft {
			t.Errorf("%s: %d allow %v draft %v, want allow %v draft %v (%s)", tc.name, rec.Code, dec.Allow, dec.MatchedDraft, tc.allow, tc.byDraft, rec.Body.String())
			continue
		}
		if (tc.by == nil) != (dec.MatchedPolicyID == nil) || (tc.by != nil && *dec.MatchedPolicyID != *tc.by) {
			t.Errorf("%s: decided by %v, want %v", tc.name, dec.MatchedPolicyID, tc.by)
		}
	}

	if rec, _ := evaluate(draft("allow", `{"attr":"subject.role","op":"near","value":"x"}`, 0, true, nil)); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), errs.CodeABACConditionInvalid) {
		t.Errorf("an invalid draft: %d %s, want 422 %s", rec.Code, rec.Body.String(), errs.CodeABACConditionInvalid)
	}
	if rec, _ := evaluate(draft("allow", approversApprove, 0, true, &elsewhere.ID)); rec.Code != http.StatusNotFound {
		t.Errorf("a draft replacing another organisation's policy: %d %s, want 404", rec.Code, rec.Body.String())
	}
	policies, err := svc.List(dbtest.Context(t), organization)
	if err != nil || len(policies) != 1 {
		t.Errorf("policies after evaluating drafts: %d %v, want only the stored one", len(policies), err)
	}
}
