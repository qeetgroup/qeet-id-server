// Package decide composes Qeet ID's three authorization engines: the tenant is
// checked first, then any ABAC deny refuses, then any allow (an RBAC role, a
// ReBAC tuple or an ABAC allow policy) permits. An engine error refuses. ABAC
// runs only for a tenant with a policy that could change the answer.
package decide

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Roles is the RBAC engine (rbac.Repository).
type Roles interface {
	Check(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (bool, error)
}

// Relations is the ReBAC engine (rebac.Service).
type Relations interface {
	Check(ctx context.Context, tenantID uuid.UUID, object, relation, userID string) (bool, error)
}

// Attributes is the ABAC engine (abac.Service).
type Attributes interface {
	Presence(ctx context.Context, tenantID uuid.UUID) (hasDeny, hasAllow bool, err error)
	Evaluate(ctx context.Context, tenantID uuid.UUID, in abac.EvaluationInput) (*abac.Decision, error)
}

// The engine that decided.
const (
	ModelTenant = "tenant" // refused before any engine ran
	ModelABAC   = "abac"   // decided by an ABAC policy
	ModelRBAC   = "rbac"   // decided by a role permission
	ModelReBAC  = "rebac"  // decided by a relationship tuple
	ModelNone   = "none"   // nothing allowed it: refused by default
)

// Decision is one composed answer. Model and Rule name what decided it, and
// PolicyID the ABAC policy when one did. ReasonCode is Rule as a stable code
// (these, or an ABAC decision's), with what it names in ReasonParams. Trace
// lists each step in order, each prefixed with its model.
type Decision struct {
	Allow        bool           `json:"allow"`
	Model        string         `json:"model"`
	Rule         string         `json:"rule,omitempty"`
	ReasonCode   string         `json:"reason_code,omitempty"`
	ReasonParams map[string]any `json:"reason_params,omitempty"`
	PolicyID     *uuid.UUID     `json:"policy_id,omitempty"`
	Trace        []string       `json:"trace,omitempty"`
}

// Decision.ReasonCode values of the composition itself.
const (
	ReasonNoTenant      = "authz.no_tenant"      // no organisation to decide in
	ReasonEngineError   = "authz.engine_error"   // an engine failed, so it refused
	ReasonRoleGrant     = "authz.role_grant"     // a role grants the permission
	ReasonRelationGrant = "authz.relation_grant" // a relationship tuple grants it
	ReasonNothingAllows = "authz.nothing_allows" // nothing allows it: refused by default
)

// DecidedBy is the part of a decision every check response carries: the model
// that decided, and the rule, reason and ABAC policy as the caller may see them.
func (dec Decision) DecidedBy() map[string]any {
	out := map[string]any{"model": dec.Model}
	if dec.Rule != "" {
		out["rule"] = dec.Rule
	}
	if dec.ReasonCode != "" {
		out["reason_code"] = dec.ReasonCode
	}
	if dec.ReasonParams != nil {
		out["reason_params"] = dec.ReasonParams
	}
	if dec.PolicyID != nil {
		out["policy_id"] = dec.PolicyID
	}
	return out
}

// Decider composes the three engines.
type Decider struct {
	roles      Roles
	relations  Relations
	attributes Attributes
}

// New returns a Decider over the three engines.
func New(roles Roles, relations Relations, attributes Attributes) *Decider {
	return &Decider{roles: roles, relations: relations, attributes: attributes}
}

// question is one decision to compose.
type question struct {
	tenantID uuid.UUID // the tenant the decision is for
	subject  string    // the user's id as the engines name it
	userID   uuid.UUID // the same, parsed; uuid.Nil when it isn't a user id RBAC knows

	resourceType, resourceID, action string   // what ABAC policies are matched against
	permissions                      []string // RBAC permission keys, any one of which allows
	object, relation                 string   // the ReBAC question; object "" for none
	abacAllows                       bool     // whether an ABAC allow permits (only deny binds at the route guard)
}

// Permission decides whether userID may use permission in tenantID: an ABAC
// deny refuses; a role granting it, or an ABAC allow policy, permits. ABAC
// sees the permission as resource type and action ("doc:write" is resource
// doc, action write; "user.read" is user, read).
func (d *Decider) Permission(ctx context.Context, tenantID, userID uuid.UUID, permission string) (Decision, error) {
	resourceType, action := SplitPermission(permission)
	return d.decide(ctx, question{
		tenantID: tenantID, subject: userID.String(), userID: userID,
		resourceType: resourceType, action: action,
		permissions: []string{permission},
		abacAllows:  true,
	})
}

// Relation decides whether user (an id) holds relation on object ("type:id")
// in tenantID. An ABAC deny on that type with relation as action refuses; a
// tuple, a role granting "type:relation" or "type.relation", or an ABAC allow
// permits. Roles and relationships are a union: a role grant needs no tuple.
func (d *Decider) Relation(ctx context.Context, tenantID uuid.UUID, user, object, relation string) (Decision, error) {
	objType, objID, _ := strings.Cut(object, ":")
	q := question{
		tenantID: tenantID, subject: user,
		resourceType: objType, resourceID: objID, action: relation,
		object: object, relation: relation,
		abacAllows: true,
	}
	if uid, err := uuid.Parse(user); err == nil {
		q.userID = uid
		q.permissions = []string{objType + ":" + relation, objType + "." + relation}
	}
	return d.decide(ctx, q)
}

// Check is the platform's route guard (an rbac.Checker): a role must grant the
// permission and no ABAC deny may refuse it. An ABAC allow does not widen
// access to Qeet ID's own management API.
func (d *Decider) Check(ctx context.Context, userID, tenantID uuid.UUID, permission string) (bool, error) {
	resourceType, action := SplitPermission(permission)
	dec, err := d.decide(ctx, question{
		tenantID: tenantID, subject: userID.String(), userID: userID,
		resourceType: resourceType, action: action,
		permissions: []string{permission},
	})
	return dec.Allow && err == nil, err
}

func (d *Decider) decide(ctx context.Context, q question) (Decision, error) {
	if q.tenantID == uuid.Nil {
		return Decision{Model: ModelTenant, Rule: "no organisation", ReasonCode: ReasonNoTenant, Trace: []string{"tenant: no organisation, refused"}}, nil
	}
	trace := []string{"tenant: " + q.tenantID.String()}
	refuse := func(model string, err error) (Decision, error) {
		trace = append(trace, fmt.Sprintf("%s: error, refused (%v)", model, err))
		return Decision{Model: model, Rule: "engine error", ReasonCode: ReasonEngineError, Trace: trace}, err
	}

	// Deny first: ABAC, wherever the tenant has a deny policy.
	hasDeny, hasAllow, err := d.attributes.Presence(ctx, q.tenantID)
	if err != nil {
		return refuse(ModelABAC, err)
	}
	var abacAllow *abac.Decision
	if hasDeny || (q.abacAllows && hasAllow) {
		res, err := d.attributes.Evaluate(ctx, q.tenantID, abac.EvaluationInput{
			Subject:  abac.SubjectAttributes(q.subject, q.tenantID),
			Resource: abac.EvaluationResource{Type: q.resourceType, ID: q.resourceID},
			Action:   q.action,
		})
		if err != nil {
			return refuse(ModelABAC, err)
		}
		for _, step := range res.Trace {
			trace = append(trace, "abac: "+step)
		}
		// An explicit deny, or a condition that failed to evaluate (abac fails
		// closed on it), names the policy. The default deny names none.
		if !res.Allow && res.MatchedPolicyID != nil {
			return Decision{Model: ModelABAC, Rule: res.Reason, ReasonCode: res.ReasonCode, ReasonParams: res.ReasonParams, PolicyID: res.MatchedPolicyID, Trace: trace}, nil
		}
		if res.Allow && q.abacAllows {
			abacAllow = res
		}
	} else {
		trace = append(trace, "abac: no policy can change this, skipped")
	}

	// Then allow: any engine.
	if q.userID != uuid.Nil {
		for _, perm := range q.permissions {
			ok, err := d.roles.Check(ctx, q.userID, q.tenantID, perm)
			if err != nil {
				return refuse(ModelRBAC, err)
			}
			if ok {
				trace = append(trace, "rbac: a role grants "+perm+", allowed")
				return Decision{Allow: true, Model: ModelRBAC, Rule: "role grants " + perm, ReasonCode: ReasonRoleGrant,
					ReasonParams: map[string]any{"permission": perm}, Trace: trace}, nil
			}
			trace = append(trace, "rbac: no role grants "+perm)
		}
	}
	if q.object != "" {
		ok, err := d.relations.Check(ctx, q.tenantID, q.object, q.relation, q.subject)
		if err != nil {
			return refuse(ModelReBAC, err)
		}
		if ok {
			trace = append(trace, "rebac: "+q.relation+" on "+q.object+", allowed")
			return Decision{Allow: true, Model: ModelReBAC, Rule: q.relation + " on " + q.object, ReasonCode: ReasonRelationGrant,
				ReasonParams: map[string]any{"relation": q.relation, "object": q.object}, Trace: trace}, nil
		}
		trace = append(trace, "rebac: no "+q.relation+" on "+q.object)
	}
	if abacAllow != nil {
		trace = append(trace, "abac: "+abacAllow.Reason+", allowed")
		return Decision{Allow: true, Model: ModelABAC, Rule: abacAllow.Reason, ReasonCode: abacAllow.ReasonCode,
			ReasonParams: abacAllow.ReasonParams, PolicyID: abacAllow.MatchedPolicyID, Trace: trace}, nil
	}
	trace = append(trace, "none: nothing allows it, refused")
	return Decision{Model: ModelNone, Rule: "nothing allows it", ReasonCode: ReasonNothingAllows, Trace: trace}, nil
}

// SplitPermission reads a permission key as ABAC's resource type and action,
// at its last "." or ":": "doc:write" is (doc, write), "user.read" (user,
// read). A key with neither is an action on no resource type, which only a
// policy for every resource type ("*") matches.
func SplitPermission(permission string) (resourceType, action string) {
	if i := strings.LastIndexAny(permission, ".:"); i > 0 && i < len(permission)-1 {
		return permission[:i], permission[i+1:]
	}
	return "", permission
}

// policyRead is the permission that lets a caller read ABAC policies.
const policyRead = "policy.read"

// ForViewer returns dec as the caller p may see it: the ABAC policy that
// decided (its rule, id and reason parameters), and the ABAC steps of the
// trace, are shown only to a caller who may read policies (policy.read); anyone
// else learns that a policy decided, and why, not which. An error checking that
// hides them.
func (d *Decider) ForViewer(ctx context.Context, p *httpx.Principal, tenantID uuid.UUID, dec Decision) Decision {
	if d.mayReadPolicies(ctx, p, tenantID) {
		return dec
	}
	out := dec
	if out.Model == ModelABAC {
		out.Rule, out.PolicyID, out.ReasonParams = "an attribute policy", nil, nil
	}
	out.Trace = nil
	hidden := false
	for _, step := range dec.Trace {
		if strings.HasPrefix(step, "abac: ") && step != "abac: no policy can change this, skipped" {
			if !hidden {
				out.Trace = append(out.Trace, "abac: attribute policies evaluated")
				hidden = true
			}
			continue
		}
		out.Trace = append(out.Trace, step)
	}
	return out
}

func (d *Decider) mayReadPolicies(ctx context.Context, p *httpx.Principal, tenantID uuid.UUID) bool {
	if p == nil {
		return false
	}
	switch p.ActorType {
	case "", "user":
		if p.UserID == nil || p.ClientID != "" {
			return false
		}
		ok, err := d.roles.Check(ctx, *p.UserID, tenantID, policyRead)
		return ok && err == nil
	default:
		for _, s := range p.Scopes {
			if s == policyRead {
				return true
			}
		}
		return false
	}
}
