package authzen

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
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
