package abac

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
)

func TestValidateCondition_Empty(t *testing.T) {
	if err := validateCondition(json.RawMessage(`{}`)); err != nil {
		t.Errorf("empty condition must be valid: %v", err)
	}
}

func TestValidateCondition_ValidLeaf(t *testing.T) {
	if err := validateCondition(json.RawMessage(`{"attr":"subject.dept","op":"eq","value":"eng"}`)); err != nil {
		t.Errorf("valid leaf must pass validation: %v", err)
	}
}

func TestValidateCondition_UnknownOp(t *testing.T) {
	if err := validateCondition(json.RawMessage(`{"attr":"subject.dept","op":"badop","value":"eng"}`)); err == nil {
		t.Error("unknown op must fail validation")
	}
}

func TestValidateCondition_MissingOp(t *testing.T) {
	if err := validateCondition(json.RawMessage(`{"attr":"subject.dept","value":"eng"}`)); err == nil {
		t.Error("missing op must fail validation")
	}
}

func TestValidateCondition_ValidNested(t *testing.T) {
	cond := `{"all":[{"any":[{"attr":"subject.role","op":"eq","value":"admin"}]},{"not":{"attr":"subject.suspended","op":"eq","value":true}}]}`
	if err := validateCondition(json.RawMessage(cond)); err != nil {
		t.Errorf("valid nested condition must pass validation: %v", err)
	}
}

func TestValidateCondition_InvalidChild(t *testing.T) {
	cond := `{"all":[{"attr":"subject.role","op":"unknownop","value":"admin"}]}`
	if err := validateCondition(json.RawMessage(cond)); err == nil {
		t.Error("invalid child node must fail validation")
	}
}

// TestLocksOutAuthor checks that a deny aimed away from policy.write, a
// disabled one, an allow, or a save with no user author is never a lock-out,
// without reading the author's attributes (the service here has no database).
func TestLocksOutAuthor(t *testing.T) {
	author, organizationID := uuid.New(), uuid.New()
	actor := audit.Actor{UserID: &author}
	s := &Service{}
	for _, tc := range []struct {
		name                         string
		effect, resourceType, action string
		enabled                      bool
		actor                        audit.Actor
	}{
		{"deny another resource for everyone", "deny", "doc", "*", true, actor},
		{"deny policy reads for everyone", "deny", "policy", "read", true, actor},
		{"disabled deny everything", "deny", "*", "*", false, actor},
		{"allow everything", "allow", "*", "*", true, actor},
		{"a save with no user author (system)", "deny", "*", "*", true, audit.Actor{}},
	} {
		if locked, err := s.locksOutAuthor(context.Background(), organizationID, tc.effect, tc.resourceType, tc.action, tc.enabled, json.RawMessage(`{}`), tc.actor); locked || err != nil {
			t.Errorf("%s: locksOutAuthor = %v, %v; want no lock-out", tc.name, locked, err)
		}
	}
}

// TestRefusesPolicyWrite checks which deny conditions refuse policy.write to a
// caller with given attributes: an unconditional one, one naming them, one
// they meet or one left unknown by an attribute they lack, and not one naming
// someone else or one they don't meet.
func TestRefusesPolicyWrite(t *testing.T) {
	author, other, organizationID := uuid.New(), uuid.New(), uuid.New()
	subject := SubjectAttributes(author.String(), organizationID)
	subject["groups"], subject["roles"] = []any{"admins"}, []any{"owner"}
	withMFA, withoutMFA := map[string]any{"mfa": true, "ip": "203.0.113.7"}, map[string]any{"mfa": false}
	subjectIs := func(id uuid.UUID) string {
		return `{"attr":"subject.id","op":"eq","value":"` + id.String() + `"}`
	}
	noMFA := `{"attr":"context.mfa","op":"ne","value":true}`
	for _, tc := range []struct {
		name     string
		cond     string
		ctxAttrs map[string]any
		want     bool
	}{
		{"for everyone", `{}`, withMFA, true},
		{"for the author", subjectIs(author), withMFA, true},
		{"for someone else", subjectIs(other), withMFA, false},
		{"for a resource's creator", creatorMayNotApprove, withMFA, true},
		{"for an attribute the platform doesn't supply", `{"attr":"subject.department","op":"eq","value":"sales"}`, withMFA, true},
		{"for a group the author is in", `{"attr":"subject.groups","op":"contains","value":"admins"}`, withMFA, true},
		{"for a group the author isn't in", `{"attr":"subject.groups","op":"contains","value":"contractors"}`, withMFA, false},
		{"without MFA, to an author with it", noMFA, withMFA, false},
		{"without MFA, to an author without it", noMFA, withoutMFA, true},
		{"without MFA, when it can't be known", noMFA, map[string]any{}, true},
		{"outside an address range, to an author inside it", `{"not":{"attr":"context.ip","op":"prefix","value":"203.0.113."}}`, withMFA, false},
	} {
		bag := attributeBag(EvaluationInput{
			Subject: subject, Resource: EvaluationResource{Type: policyResourceType}, Action: policyWriteAction, Context: tc.ctxAttrs,
		})
		if got := refusesPolicyWrite(json.RawMessage(tc.cond), bag); got != tc.want {
			t.Errorf("deny %s: refusesPolicyWrite = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestValidateCondition_Reference checks a well-formed reference saves on each
// operator that allows one, and a malformed one is refused at save and fails
// to evaluate.
func TestValidateCondition_Reference(t *testing.T) {
	for _, cond := range []string{
		refLeaf("subject.x", "eq", "resource.y"), refLeaf("subject.x", "ne", "context.y"),
		refLeaf("subject.x", "gt", "resource.y"), refLeaf("subject.x", "gte", "resource.y"),
		refLeaf("subject.x", "lt", "resource.y"), refLeaf("subject.x", "lte", "resource.y"),
		refLeaf("subject.x", "in", "resource.y"), refLeaf("subject.x", "nin", "resource.y"),
		refLeaf("subject.x", "contains", "resource.y"), refLeaf("resource.x", "eq", "subject.x"),
		refLeaf("subject.x", "eq", "context.geo.country"),
		regionScoped, careTeam, creatorMayNotApprove, clearance,
	} {
		if err := validateCondition(json.RawMessage(cond)); err != nil {
			t.Errorf("%s: %v", cond, err)
		}
	}

	bag := AttributeBag{"subject": {"region": "emea", "email": "a@b"}, "resource": {"region": "emea"}}
	for name, cond := range map[string]string{
		"extra key":           `{"attr":"subject.region","op":"eq","value":{"attr":"resource.region","default":"emea"}}`,
		"empty object":        `{"attr":"subject.region","op":"eq","value":{}}`,
		"wrong key":           `{"attr":"subject.region","op":"eq","value":{"Attr":"resource.region"}}`,
		"non-string":          `{"attr":"subject.region","op":"eq","value":{"attr":5}}`,
		"null":                `{"attr":"subject.region","op":"eq","value":{"attr":null}}`,
		"empty":               refLeaf("subject.region", "eq", ""),
		"no namespace":        refLeaf("subject.region", "eq", "region"),
		"unknown namespace":   refLeaf("subject.region", "eq", "organization.region"),
		"empty path":          refLeaf("subject.region", "eq", "resource."),
		"empty segment":       refLeaf("subject.region", "eq", "resource..region"),
		"own attribute":       refLeaf("subject.region", "eq", "subject.region"),
		"regex":               refLeaf("subject.email", "regex", "resource.region"),
		"prefix":              refLeaf("subject.email", "prefix", "resource.region"),
		"suffix":              refLeaf("subject.email", "suffix", "resource.region"),
		"exists":              refLeaf("subject.email", "exists", "resource.region"),
		"nested":              `{"all":[{"not":` + refLeaf("subject.region", "eq", "organization.region") + `}]}`,
		"in an array element": `{"attr":"subject.region","op":"nin","value":[{"attr":"resource.region"}]}`,
	} {
		if err := validateCondition(json.RawMessage(cond)); err == nil {
			t.Errorf("%s: saved %s", name, cond)
		}
		if name == "in an array element" {
			continue // refused at save only: evaluated, it is a literal object
		}
		if _, err := EvaluateCondition(json.RawMessage(cond), "allow", bag); err == nil {
			t.Errorf("%s: evaluated %s without an error", name, cond)
		}
	}
}
