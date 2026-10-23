package decide

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type fakeRoles struct {
	grants map[string]bool
	err    error
	calls  int
}

func (f *fakeRoles) Check(_ context.Context, _, _ uuid.UUID, perm string) (bool, error) {
	f.calls++
	return f.grants[perm], f.err
}

type fakeRelations struct {
	allow bool
	err   error
	calls int
}

func (f *fakeRelations) Check(context.Context, uuid.UUID, string, string, string) (bool, error) {
	f.calls++
	return f.allow, f.err
}

// fakeAttributes denies (resource, action) pairs listed in deny and allows
// those in allow; a pair in both is denied, as abac's deny-wins does.
type fakeAttributes struct {
	deny, allow map[string]bool
	evalErr     error
	presenceErr error
	evals       int
	lastSubject map[string]any
}

func (f *fakeAttributes) Presence(context.Context, uuid.UUID) (bool, bool, error) {
	return len(f.deny) > 0 || f.evalErr != nil, len(f.allow) > 0, f.presenceErr
}

func (f *fakeAttributes) Evaluate(_ context.Context, _ uuid.UUID, in abac.EvaluationInput) (*abac.Decision, error) {
	f.evals++
	f.lastSubject = in.Subject
	if f.evalErr != nil {
		return nil, f.evalErr
	}
	key := in.Resource.Type + "/" + in.Action
	id := uuid.New()
	switch {
	case f.deny[key]:
		return &abac.Decision{Effect: "deny", MatchedPolicyID: &id, Reason: `explicitly denied by policy "block"`,
			ReasonCode: abac.ReasonDeniedByPolicy, ReasonParams: map[string]any{"policy_name": "block"}}, nil
	case f.allow[key]:
		return &abac.Decision{Allow: true, Effect: "allow", MatchedPolicyID: &id, Reason: `allowed by policy "open"`,
			ReasonCode: abac.ReasonAllowedByPolicy, ReasonParams: map[string]any{"policy_name": "open"}}, nil
	}
	return &abac.Decision{Effect: "deny", Reason: "no matching allow policy", ReasonCode: abac.ReasonNoMatchingAllow,
		Trace: []string{"no matching allow policy found → default deny"}}, nil
}

var (
	tenant = uuid.New()
	uma    = uuid.New()
	ctx    = context.Background()
)

// TestDenyRefusesAtEveryQuestion checks that one ABAC deny refuses the
// permission check, the relationship check and the route guard even though a
// role and a tuple allow, and that the decision names ABAC and the policy.
func TestDenyRefusesAtEveryQuestion(t *testing.T) {
	roles := &fakeRoles{grants: map[string]bool{"doc:write": true}}
	rels := &fakeRelations{allow: true}
	d := New(roles, rels, &fakeAttributes{deny: map[string]bool{"doc/write": true}})

	perm, err := d.Permission(ctx, tenant, uma, "doc:write")
	if err != nil || perm.Allow || perm.Model != ModelABAC || perm.PolicyID == nil || !strings.Contains(perm.Rule, "block") {
		t.Fatalf("permission check = %+v, %v; want refused by the abac policy", perm, err)
	}
	rel, err := d.Relation(ctx, tenant, uma.String(), "doc:42", "write")
	if err != nil || rel.Allow || rel.Model != ModelABAC {
		t.Fatalf("relationship check = %+v, %v; want refused by abac", rel, err)
	}
	if ok, err := d.Check(ctx, uma, tenant, "doc:write"); ok || err != nil {
		t.Fatalf("route guard = %v, %v; want refused", ok, err)
	}
	if roles.calls != 0 || rels.calls != 0 {
		t.Fatalf("allow engines ran %d/%d times after a deny; deny stops evaluation", roles.calls, rels.calls)
	}
}

// TestRoleGrantCountsAtTheRelationshipCheck checks that a role granting
// doc:write allows doc:42#write with no tuple.
func TestRoleGrantCountsAtTheRelationshipCheck(t *testing.T) {
	d := New(&fakeRoles{grants: map[string]bool{"doc:write": true}}, &fakeRelations{}, &fakeAttributes{})
	dec, err := d.Relation(ctx, tenant, uma.String(), "doc:42", "write")
	if err != nil || !dec.Allow || dec.Model != ModelRBAC || dec.Rule != "role grants doc:write" {
		t.Fatalf("relationship check = %+v, %v; want allowed by the role", dec, err)
	}
	// The dot form of the key counts too.
	d = New(&fakeRoles{grants: map[string]bool{"doc.write": true}}, &fakeRelations{}, &fakeAttributes{})
	if dec, _ := d.Relation(ctx, tenant, uma.String(), "doc:42", "write"); !dec.Allow {
		t.Fatalf("doc.write role at the relationship check = %+v, want allowed", dec)
	}
}

// TestAnyAllowPermitsWithoutDeny checks that with no deny, any one engine
// allowing is enough and the decision names which.
func TestAnyAllowPermitsWithoutDeny(t *testing.T) {
	d := New(&fakeRoles{}, &fakeRelations{allow: true}, &fakeAttributes{})
	if dec, _ := d.Relation(ctx, tenant, uma.String(), "doc:42", "write"); !dec.Allow || dec.Model != ModelReBAC || dec.Rule != "write on doc:42" {
		t.Fatalf("tuple only = %+v, want allowed by rebac", dec)
	}
	d = New(&fakeRoles{}, &fakeRelations{}, &fakeAttributes{allow: map[string]bool{"doc/write": true}})
	if dec, _ := d.Permission(ctx, tenant, uma, "doc:write"); !dec.Allow || dec.Model != ModelABAC || dec.PolicyID == nil {
		t.Fatalf("abac allow only = %+v, want allowed by abac", dec)
	}
	d = New(&fakeRoles{}, &fakeRelations{}, &fakeAttributes{})
	if dec, _ := d.Permission(ctx, tenant, uma, "doc:write"); dec.Allow || dec.Model != ModelNone {
		t.Fatalf("nothing grants it = %+v, want refused by default", dec)
	}
}

// TestRouteGuardIgnoresAttributeAllow checks that an ABAC allow does not widen
// the route guard: only a role allows.
func TestRouteGuardIgnoresAttributeAllow(t *testing.T) {
	attrs := &fakeAttributes{allow: map[string]bool{"user/write": true}}
	d := New(&fakeRoles{}, &fakeRelations{}, attrs)
	if ok, err := d.Check(ctx, uma, tenant, "user.write"); ok || err != nil {
		t.Fatalf("route guard with only an abac allow = %v, %v; want refused", ok, err)
	}
	if attrs.evals != 0 {
		t.Fatalf("abac evaluated %d times for a tenant with no deny policy at the route guard, want 0", attrs.evals)
	}
}

// TestNoPoliciesSkipsABAC checks that a tenant with no ABAC policy is decided
// by its roles without any policy evaluation.
func TestNoPoliciesSkipsABAC(t *testing.T) {
	attrs := &fakeAttributes{}
	d := New(&fakeRoles{grants: map[string]bool{"user.read": true}}, &fakeRelations{}, attrs)
	if ok, err := d.Check(ctx, uma, tenant, "user.read"); !ok || err != nil {
		t.Fatalf("route guard = %v, %v; want allowed", ok, err)
	}
	if dec, _ := d.Permission(ctx, tenant, uma, "user.read"); !dec.Allow {
		t.Fatalf("permission check = %+v, want allowed", dec)
	}
	if attrs.evals != 0 {
		t.Fatalf("abac evaluated %d times with no policies, want 0", attrs.evals)
	}
}

// TestNoTenantRefusesBeforeAnyEngine checks that a question with no
// organisation is refused before any engine is consulted.
func TestNoTenantRefusesBeforeAnyEngine(t *testing.T) {
	roles, rels, attrs := &fakeRoles{grants: map[string]bool{"doc:write": true}}, &fakeRelations{allow: true}, &fakeAttributes{}
	d := New(roles, rels, attrs)
	dec, err := d.Relation(ctx, uuid.Nil, uma.String(), "doc:42", "write")
	if err != nil || dec.Allow || dec.Model != ModelTenant {
		t.Fatalf("no tenant = %+v, %v; want refused by tenant scope", dec, err)
	}
	if roles.calls+rels.calls+attrs.evals != 0 {
		t.Fatalf("an engine ran without a tenant")
	}
}

// TestEngineErrorRefuses checks that an error from any engine refuses and is
// returned with the refusal, never with an allow.
func TestEngineErrorRefuses(t *testing.T) {
	boom := errors.New("boom")
	for name, d := range map[string]*Decider{
		"abac presence": New(&fakeRoles{grants: map[string]bool{"doc:write": true}}, &fakeRelations{allow: true}, &fakeAttributes{presenceErr: boom}),
		"abac evaluate": New(&fakeRoles{grants: map[string]bool{"doc:write": true}}, &fakeRelations{allow: true}, &fakeAttributes{evalErr: boom}),
		"rbac":          New(&fakeRoles{grants: map[string]bool{"doc:write": true}, err: boom}, &fakeRelations{allow: true}, &fakeAttributes{}),
		"rebac":         New(&fakeRoles{}, &fakeRelations{allow: true, err: boom}, &fakeAttributes{}),
	} {
		dec, err := d.Relation(ctx, tenant, uma.String(), "doc:42", "write")
		if !errors.Is(err, boom) || dec.Allow {
			t.Errorf("%s error: relationship check = %+v, %v; want refused with the error", name, dec, err)
		}
		if ok, err := d.Check(ctx, uma, tenant, "doc:write"); ok || err == nil {
			if name != "rebac" { // the route guard asks no relationship question
				t.Errorf("%s error: route guard = %v, %v; want refused with an error", name, ok, err)
			}
		}
	}
}

// TestTraceNamesEachModel checks that the trace walks tenant, abac, rbac and
// rebac in order and names the step that decided.
func TestTraceNamesEachModel(t *testing.T) {
	d := New(&fakeRoles{}, &fakeRelations{allow: true}, &fakeAttributes{allow: map[string]bool{"x/y": true}})
	dec, _ := d.Relation(ctx, tenant, uma.String(), "doc:42", "write")
	want := []string{"tenant: ", "abac: ", "rbac: no role grants doc:write", "rbac: no role grants doc.write", "rebac: write on doc:42, allowed"}
	if len(dec.Trace) != len(want) {
		t.Fatalf("trace = %q, want %d steps", dec.Trace, len(want))
	}
	for i, prefix := range want {
		if !strings.HasPrefix(dec.Trace[i], prefix) {
			t.Fatalf("trace[%d] = %q, want prefix %q (trace %q)", i, dec.Trace[i], prefix, dec.Trace)
		}
	}
}

// TestSubjectIsWhoTheServerKnows checks that ABAC gets the subject's id and
// organisation from the platform, so a deny on subject.id binds.
func TestSubjectIsWhoTheServerKnows(t *testing.T) {
	attrs := &fakeAttributes{deny: map[string]bool{"doc/write": true}}
	d := New(&fakeRoles{}, &fakeRelations{}, attrs)
	_, _ = d.Permission(ctx, tenant, uma, "doc:write")
	if attrs.lastSubject["id"] != uma.String() || attrs.lastSubject["type"] != "user" || attrs.lastSubject["tenant_id"] != tenant.String() {
		t.Fatalf("subject = %v", attrs.lastSubject)
	}
}

func TestSplitPermission(t *testing.T) {
	for in, want := range map[string][2]string{
		"doc:write":             {"doc", "write"},
		"user.read":             {"user", "read"},
		"billing:invoices.read": {"billing:invoices", "read"},
		"admin":                 {"", "admin"},
		"trailing.":             {"", "trailing."},
	} {
		if rt, a := SplitPermission(in); rt != want[0] || a != want[1] {
			t.Errorf("SplitPermission(%q) = (%q, %q), want (%q, %q)", in, rt, a, want[0], want[1])
		}
	}
}

// TestForViewerHidesPolicies checks that a caller who may not read policies
// learns that an attribute policy decided, not which one or what it said.
func TestForViewerHidesPolicies(t *testing.T) {
	d := New(&fakeRoles{}, &fakeRelations{}, &fakeAttributes{deny: map[string]bool{"doc/write": true}})
	dec, _ := d.Permission(ctx, tenant, uma, "doc:write")

	reader := &httpx.Principal{UserID: &uma, ActorType: "user"}
	hidden := d.ForViewer(ctx, reader, tenant, dec)
	if hidden.Rule != "an attribute policy" || hidden.PolicyID != nil || hidden.ReasonParams != nil || hidden.ReasonCode != abac.ReasonDeniedByPolicy {
		t.Fatalf("hidden decision = %+v; want why it was refused, not which policy", hidden)
	}
	for _, step := range hidden.Trace {
		if strings.Contains(step, "block") {
			t.Fatalf("hidden trace names the policy: %q", hidden.Trace)
		}
	}

	d.roles = &fakeRoles{grants: map[string]bool{"policy.read": true}}
	if shown := d.ForViewer(ctx, reader, tenant, dec); shown.PolicyID == nil || !strings.Contains(shown.Rule, "block") {
		t.Fatalf("a policy reader sees %+v, want the policy", shown)
	}
	key := &httpx.Principal{ActorType: "api_key", Scopes: []string{"policy.read"}}
	if shown := d.ForViewer(ctx, key, tenant, dec); shown.PolicyID == nil {
		t.Fatalf("an api key with policy.read sees %+v, want the policy", shown)
	}
}

// TestDecisionsCarryReasonCodes checks that each kind of decision carries its
// stable reason code, with what it names.
func TestDecisionsCarryReasonCodes(t *testing.T) {
	permission := func(d *Decider, tenantID uuid.UUID) Decision {
		dec, _ := d.Permission(ctx, tenantID, uma, "doc:write")
		return dec
	}
	for _, tc := range []struct {
		name   string
		dec    Decision
		code   string
		params map[string]any
	}{
		{"no organisation", permission(New(&fakeRoles{}, &fakeRelations{}, &fakeAttributes{}), uuid.Nil), ReasonNoTenant, nil},
		{"a role grants it", permission(New(&fakeRoles{grants: map[string]bool{"doc:write": true}}, &fakeRelations{}, &fakeAttributes{}), tenant),
			ReasonRoleGrant, map[string]any{"permission": "doc:write"}},
		{"an attribute policy refuses it", permission(New(&fakeRoles{}, &fakeRelations{}, &fakeAttributes{deny: map[string]bool{"doc/write": true}}), tenant),
			abac.ReasonDeniedByPolicy, map[string]any{"policy_name": "block"}},
		{"an attribute policy allows it", permission(New(&fakeRoles{}, &fakeRelations{}, &fakeAttributes{allow: map[string]bool{"doc/write": true}}), tenant),
			abac.ReasonAllowedByPolicy, map[string]any{"policy_name": "open"}},
		{"nothing allows it", permission(New(&fakeRoles{}, &fakeRelations{}, &fakeAttributes{}), tenant), ReasonNothingAllows, nil},
	} {
		if tc.dec.ReasonCode != tc.code || fmt.Sprint(tc.dec.ReasonParams) != fmt.Sprint(tc.params) {
			t.Errorf("%s: %s %v; want %s %v", tc.name, tc.dec.ReasonCode, tc.dec.ReasonParams, tc.code, tc.params)
		}
	}
	d := New(&fakeRoles{}, &fakeRelations{allow: true}, &fakeAttributes{})
	dec, _ := d.Relation(ctx, tenant, uma.String(), "doc:42", "write")
	if want := map[string]any{"relation": "write", "object": "doc:42"}; dec.ReasonCode != ReasonRelationGrant || fmt.Sprint(dec.ReasonParams) != fmt.Sprint(want) {
		t.Errorf("a tuple grants it: %s %v; want %s %v", dec.ReasonCode, dec.ReasonParams, ReasonRelationGrant, want)
	}
	if by := dec.DecidedBy(); by["reason_code"] != ReasonRelationGrant || by["reason_params"] == nil {
		t.Errorf("decided_by %v; want the reason code and its parameters", by)
	}
}
