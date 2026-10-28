package authzen

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// noGrants grants nothing, by role or relationship.
type noGrants struct{}

func (noGrants) Check(context.Context, uuid.UUID, uuid.UUID, string) (bool, error) { return false, nil }

func (noGrants) Explain(context.Context, uuid.UUID, uuid.UUID, string) (*rbac.Explanation, error) {
	return &rbac.Explanation{}, nil
}

type noRelations struct{}

func (noRelations) Check(context.Context, uuid.UUID, string, string, string) (bool, error) {
	return false, nil
}

func (noRelations) CheckExplain(context.Context, uuid.UUID, string, string, string) (*rebac.Explanation, error) {
	return &rebac.Explanation{}, nil
}

// secretDenied stands in for a tenant with one deny policy, on a resource
// classified secret, and records what ABAC was asked.
type secretDenied struct{ last abac.EvaluationInput }

func (*secretDenied) Presence(context.Context, uuid.UUID) (bool, bool, error) {
	return true, false, nil
}

func (*secretDenied) PlatformAttributes(_ context.Context, r abac.Request) (map[string]any, map[string]any, error) {
	return abac.SubjectAttributes(r.Subject, r.TenantID), map[string]any{}, nil
}

func (s *secretDenied) Evaluate(_ context.Context, _ uuid.UUID, in abac.EvaluationInput) (*abac.Decision, error) {
	s.last = in
	if in.Resource.Attrs["classification"] == "secret" {
		id := uuid.New()
		return &abac.Decision{Effect: "deny", MatchedPolicyID: &id, Reason: "denied", ReasonCode: abac.ReasonDeniedByPolicy}, nil
	}
	return &abac.Decision{Effect: "deny", ReasonCode: abac.ReasonNoMatchingAllow}, nil
}

// TestEvaluationReadsProperties checks that an evaluation request's subject,
// resource, action and context properties reach ABAC, so a deny on a resource
// property decides, that explain is not taken for a context attribute, and
// that the platform's subject id wins over a property of that name.
func TestEvaluationReadsProperties(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	attrs := &secretDenied{}
	svc := NewService(noGrants{}, noRelations{}, decide.New(noGrants{}, noRelations{}, attrs))
	for _, resourceType := range []string{"document", permissionResourceType} {
		req := EvaluationRequest{
			Subject:  Subject{Type: "user", ID: user.String(), Properties: map[string]any{"department": "sales", "id": "someone-else"}},
			Resource: Resource{Type: resourceType, ID: "d1", Properties: map[string]any{"classification": "secret"}},
			Action:   Action{Name: "doc:read", Properties: map[string]any{"channel": "api"}},
			Context:  map[string]any{"explain": true, "ip": "198.51.100.4"},
		}
		out, err := svc.Evaluate(context.Background(), tenant, req)
		if err != nil {
			t.Fatalf("%s: %v", resourceType, err)
		}
		decidedBy, _ := out.Context["decided_by"].(map[string]any)
		if out.Decision || decidedBy["model"] != decide.ModelABAC {
			t.Errorf("%s: decision %v by %v, want the deny on the resource property", resourceType, out.Decision, decidedBy)
		}
		in := attrs.last
		if in.Subject["department"] != "sales" || in.Subject["id"] != user.String() {
			t.Errorf("%s: subject %v, want the department and the platform's id", resourceType, in.Subject)
		}
		if in.ActionAttrs["channel"] != "api" || in.Context["ip"] != "198.51.100.4" {
			t.Errorf("%s: action %v, context %v; want the properties", resourceType, in.ActionAttrs, in.Context)
		}
		if _, ok := in.Context["explain"]; ok {
			t.Errorf("%s: explain reached ABAC as an attribute", resourceType)
		}

		req.Resource.Properties = map[string]any{"classification": "public"}
		if out, err := svc.Evaluate(context.Background(), tenant, req); err != nil || out.Decision {
			t.Errorf("%s: a public resource: %+v, %v; want refused by default, nothing granting it", resourceType, out, err)
		} else if decidedBy, _ := out.Context["decided_by"].(map[string]any); decidedBy["model"] != decide.ModelNone {
			t.Errorf("%s: a public resource decided by %v, want nothing", resourceType, decidedBy)
		}
	}
}

// onlyGranted grants the one permission key it names, and no relationship.
type onlyGranted struct {
	noGrants
	key string
}

func (g onlyGranted) Check(_ context.Context, _, _ uuid.UUID, permKey string) (bool, error) {
	return permKey == g.key, nil
}

// TestEvaluations checks that each evaluation of a batch takes the request's
// subject, action and context it leaves out, that the answers come in order,
// that the semantic stops after the first deny or permit, that an evaluation
// the caller got wrong is denied with the error in its context, and that a
// bad semantic or too many evaluations refuse the whole request.
func TestEvaluations(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	attrs := &secretDenied{}
	grants := onlyGranted{key: "doc:read"}
	svc := NewService(grants, noRelations{}, decide.New(grants, noRelations{}, attrs))
	ctx := context.Background()
	perm := &Resource{Type: permissionResourceType, ID: "p"}
	batch := func(semantic string, actions ...string) EvaluationsRequest {
		req := EvaluationsRequest{
			Subject:  &Subject{Type: "user", ID: user.String()},
			Resource: perm,
			Context:  map[string]any{"ip": "198.51.100.4"},
		}
		req.Options.EvaluationsSemantic = semantic
		for _, a := range actions {
			req.Evaluations = append(req.Evaluations, Evaluation{Action: &Action{Name: a}})
		}
		return req
	}
	decisions := func(out *EvaluationsResponse) []bool {
		got := []bool{}
		for _, e := range out.Evaluations {
			got = append(got, e.Decision)
		}
		return got
	}

	for _, tc := range []struct {
		semantic string
		actions  []string
		want     []bool
	}{
		{"", []string{"doc:read", "doc:delete", "doc:read"}, []bool{true, false, true}},
		{executeAll, []string{"doc:delete", "doc:read"}, []bool{false, true}},
		{denyOnFirstDeny, []string{"doc:read", "doc:delete", "doc:read"}, []bool{true, false}},
		{permitOnFirstPermit, []string{"doc:delete", "doc:read", "doc:delete"}, []bool{false, true}},
	} {
		out, err := svc.EvaluateAll(ctx, tenant, batch(tc.semantic, tc.actions...))
		if err != nil {
			t.Fatalf("%q: %v", tc.semantic, err)
		}
		if got := decisions(out); !slices.Equal(got, tc.want) {
			t.Errorf("%q over %v: %v, want %v", tc.semantic, tc.actions, got, tc.want)
		}
	}
	if attrs.last.Context["ip"] != "198.51.100.4" {
		t.Errorf("an evaluation without a context: ABAC saw %v, want the request's", attrs.last.Context)
	}

	req := batch(denyOnFirstDeny, "doc:read")
	req.Evaluations = append(req.Evaluations,
		Evaluation{Subject: &Subject{Type: "user"}, Action: &Action{Name: "doc:read"}, Context: map[string]any{"ip": "203.0.113.9"}},
		Evaluation{Action: &Action{Name: "doc:read"}})
	out, err := svc.EvaluateAll(ctx, tenant, req)
	if err != nil {
		t.Fatal(err)
	}
	if got := decisions(out); !slices.Equal(got, []bool{true, false}) {
		t.Fatalf("an evaluation without a subject id: %v, want it denied and the batch stopped", got)
	}
	e, _ := out.Evaluations[1].Context["error"].(map[string]any)
	if e["status"] != 422 || e["code"] != errs.CodeAuthZENSubjectIDRequired {
		t.Errorf("the failed evaluation's context: %v, want 422 %s", out.Evaluations[1].Context, errs.CodeAuthZENSubjectIDRequired)
	}

	if _, err := svc.EvaluateAll(ctx, tenant, batch("all_of_them", "doc:read")); !errors.Is(err, errs.ErrAuthZENSemanticInvalid) {
		t.Errorf("an unknown semantic: %v, want %s", err, errs.CodeAuthZENSemanticInvalid)
	}
	many := make([]string, maxEvaluations+1)
	for i := range many {
		many[i] = "doc:read"
	}
	if _, err := svc.EvaluateAll(ctx, tenant, batch("", many...)); !errors.Is(err, errs.ErrAuthZENTooManyEvaluations) {
		t.Errorf("%d evaluations: %v, want %s", len(many), err, errs.CodeAuthZENTooManyEvaluations)
	}
}

// TestEvaluationsEndpoint checks that the evaluations endpoint answers a
// request without evaluations as a single evaluation, a batch with a decision
// each, and refuses another organisation's path.
func TestEvaluationsEndpoint(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	grants := onlyGranted{key: "doc:read"}
	svc := NewService(grants, noRelations{}, decide.New(grants, noRelations{}, &secretDenied{}))
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), &httpx.Principal{UserID: &user, TenantID: &tenant, ActorType: "user"})))
		})
	})
	(&Handler{Service: svc}).Mount(r)
	post := func(tenantID uuid.UUID, body string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tenants/"+tenantID.String()+"/access/v1/evaluations", strings.NewReader(body)))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	subject := `"subject":{"type":"user","id":"` + user.String() + `"},"resource":{"type":"permission","id":"p"}`

	if code, out := post(tenant, `{`+subject+`,"action":{"name":"doc:read"}}`); code != http.StatusOK || out["decision"] != true || out["evaluations"] != nil {
		t.Errorf("without evaluations: %d %v, want a single decision", code, out)
	}
	code, out := post(tenant, `{`+subject+`,"evaluations":[{"action":{"name":"doc:read"}},{"action":{"name":"doc:delete"}}]}`)
	if list, _ := out["evaluations"].([]any); code != http.StatusOK || len(list) != 2 {
		t.Errorf("a batch of two: %d %v, want two decisions", code, out)
	}
	if code, _ := post(uuid.New(), `{`+subject+`,"evaluations":[{"action":{"name":"doc:read"}}]}`); code != http.StatusForbidden {
		t.Errorf("another organisation's path: %d, want 403", code)
	}
}
