package abac

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac/dbgen"
)

// EvaluationResource carries resource-side attributes.
type EvaluationResource struct {
	Type  string         `json:"type"`
	ID    string         `json:"id"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

// EvaluationInput is the payload for a policy evaluation request.
type EvaluationInput struct {
	Subject  map[string]any     `json:"subject"`
	Resource EvaluationResource `json:"resource"`
	Action   string             `json:"action"`
	// ActionAttrs are the action's attributes beside its name, the action
	// namespace (action.name is Action).
	ActionAttrs map[string]any `json:"action_attrs,omitempty"`
	Context     map[string]any `json:"context"`
}

// Decision is the result of an Evaluate call. ReasonCode is one of the authz.* codes below and Reason
// the same in English; ReasonParams names the deciding policy (policy_id, policy_name, priority).
// Trace lists each policy evaluated and why; the evaluate endpoint returns it only with ?explain=true.
type Decision struct {
	Allow           bool           `json:"allow"`
	Effect          string         `json:"effect"`
	MatchedPolicyID *uuid.UUID     `json:"matched_policy_id,omitempty"`
	Reason          string         `json:"reason,omitempty"`
	ReasonCode      string         `json:"reason_code,omitempty"`
	ReasonParams    map[string]any `json:"reason_params,omitempty"`
	Trace           []string       `json:"trace,omitempty"`
	// MatchedDraft is set when an evaluation's draft policy decided.
	MatchedDraft bool `json:"matched_draft,omitempty"`
}

// Decision.ReasonCode values.
const (
	ReasonAllowedByPolicy = "authz.allowed_by_policy" // an allow policy matched
	ReasonDeniedByPolicy  = "authz.denied_by_policy"  // a deny policy matched
	ReasonAttributeAbsent = "authz.attribute_absent"  // a deny policy applied as an attribute it compares is absent
	ReasonConditionError  = "authz.condition_error"   // a policy's condition failed to evaluate, so it refused
	ReasonNoMatchingAllow = "authz.no_matching_allow" // no allow policy matched: refused by default
)

// presenceTTL bounds how long another instance may go on skipping ABAC for an
// organization after a policy is added there; this instance forgets at once.
const presenceTTL = 5 * time.Second

type presenceEntry struct {
	deny, allow bool
	at          time.Time
}

// Presence reports whether the organization has any enabled deny and any enabled
// allow policy, so a decision runs ABAC only where it can change the outcome
// (decide.Decider). Cached per organization for presenceTTL, and forgotten on every
// change made through this service.
func (s *Service) Presence(ctx context.Context, organizationID uuid.UUID) (hasDeny, hasAllow bool, err error) {
	s.presenceMu.Lock()
	e, ok := s.presence[organizationID]
	s.presenceMu.Unlock()
	if ok && time.Since(e.at) < presenceTTL {
		return e.deny, e.allow, nil
	}
	row, err := s.q.CountEnabledPolicies(ctx, organizationID)
	if err != nil {
		return false, false, err
	}
	e = presenceEntry{deny: row.Deny > 0, allow: row.Allow > 0, at: time.Now()}
	s.presenceMu.Lock()
	s.presence[organizationID] = e
	s.presenceMu.Unlock()
	return e.deny, e.allow, nil
}

func (s *Service) forgetPresence(organizationID uuid.UUID) {
	s.presenceMu.Lock()
	delete(s.presence, organizationID)
	s.presenceMu.Unlock()
}

// candidate is the minimal projection fetched for each policy candidate
// during Evaluate; we avoid fetching all columns to keep the hot path lean.
type candidate struct {
	id        uuid.UUID
	name      string
	effect    string
	condition []byte
	priority  int
}

// Evaluate applies organizationID's enabled policies for in's resource type and
// action, highest priority first, deny-wins: a matching deny or a condition
// that fails to evaluate refuses, else a matching allow permits, else deny. A
// condition comparing an absent attribute matches a deny and never an allow.
func (s *Service) Evaluate(ctx context.Context, organizationID uuid.UUID, in EvaluationInput) (*Decision, error) {
	policies, err := s.candidates(ctx, organizationID, in)
	if err != nil {
		return nil, err
	}
	bag, err := s.bagFor(ctx, organizationID, in, policies)
	if err != nil {
		return nil, err
	}
	return combine(policies, bag), nil
}

// bagFor is in's attribute bag with the relationships policies ask about
// answered.
func (s *Service) bagFor(ctx context.Context, organizationID uuid.UUID, in EvaluationInput, policies []candidate) (AttributeBag, error) {
	bag := attributeBag(in)
	conditions := make([][]byte, 0, len(policies))
	for _, p := range policies {
		conditions = append(conditions, p.condition)
	}
	return bag, s.resolveRelations(ctx, organizationID, conditions, bag)
}

// candidates returns organizationID's enabled policies for in's resource type and
// action, highest priority first.
func (s *Service) candidates(ctx context.Context, organizationID uuid.UUID, in EvaluationInput) ([]candidate, error) {
	if strings.TrimSpace(in.Action) == "" {
		return nil, ErrActionRequired
	}
	rows, err := s.q.ListEvaluationCandidates(ctx, dbgen.ListEvaluationCandidatesParams{
		OrganizationID: organizationID,
		ResourceType:   in.Resource.Type,
		Action:         in.Action,
	})
	if err != nil {
		return nil, err
	}
	policies := make([]candidate, 0, len(rows)+1)
	for _, row := range rows {
		policies = append(policies, candidate{
			id:        row.ID,
			name:      row.Name,
			effect:    row.Effect,
			condition: row.Condition,
			priority:  int(row.Priority),
		})
	}
	return policies, nil
}

// Draft is an unsaved policy to evaluate with the stored ones: a new one, or,
// with Replaces, one standing in for a stored policy. It applies as it would
// once saved, so a disabled draft only takes the policy it replaces out. A
// draft without a name is called "draft".
type Draft struct {
	CreateInput
	Replaces *uuid.UUID `json:"replaces"`
}

// EvaluateDraft is Evaluate with draft among organizationID's policies, writing
// nothing. The decision's MatchedDraft is set when the draft decided it; a new
// draft has no MatchedPolicyID.
func (s *Service) EvaluateDraft(ctx context.Context, organizationID uuid.UUID, in EvaluationInput, draft Draft) (*Decision, error) {
	if strings.TrimSpace(draft.Name) == "" {
		draft.Name = "draft"
	}
	cond, err := checkPolicy(draft.Name, draft.Effect, draft.ResourceType, draft.Action, draft.Condition)
	if err != nil {
		return nil, err
	}
	draftID := uuid.Nil
	if draft.Replaces != nil {
		if _, err := s.Get(ctx, *draft.Replaces, organizationID); err != nil {
			return nil, err
		}
		draftID = *draft.Replaces
	}
	stored, err := s.candidates(ctx, organizationID, in)
	if err != nil {
		return nil, err
	}
	policies := stored[:0:0]
	for _, p := range stored {
		if p.id != draftID {
			policies = append(policies, p)
		}
	}
	applies := draft.Enabled &&
		(draft.ResourceType == in.Resource.Type || draft.ResourceType == "*") &&
		(draft.Action == in.Action || draft.Action == "*")
	if applies {
		d := candidate{id: draftID, name: draft.Name, effect: draft.Effect, condition: cond, priority: draft.Priority}
		at := len(policies)
		for i, p := range policies {
			if p.priority < d.priority {
				at = i
				break
			}
		}
		policies = slices.Insert(policies, at, d)
	}
	bag, err := s.bagFor(ctx, organizationID, in, policies)
	if err != nil {
		return nil, err
	}
	decision := combine(policies, bag)
	if applies && decision.MatchedPolicyID != nil && *decision.MatchedPolicyID == draftID {
		decision.MatchedDraft = true
		if draftID == uuid.Nil {
			decision.MatchedPolicyID = nil
			delete(decision.ReasonParams, "policy_id")
		}
	}
	return decision, nil
}

// combine decides policies, in order, against bag deny-wins: a policy that
// applies (truth.applies) with effect deny, or whose condition fails to
// evaluate, refuses; else one that applies with effect allow permits; else
// the answer is deny.
func combine(policies []candidate, bag AttributeBag) *Decision {
	trace := make([]string, 0, len(policies))

	var denyPolicyID *uuid.UUID
	var allowPolicyID *uuid.UUID
	denyReason, denyCode, allowReason := "", "", ""
	var denyParams, allowParams map[string]any
	params := func(p candidate) map[string]any {
		return map[string]any{"policy_id": p.id, "policy_name": p.name, "priority": p.priority}
	}

	for _, p := range policies {
		cond := json.RawMessage(p.condition)
		if len(cond) == 0 {
			cond = json.RawMessage(`{}`)
		}
		t, err := evaluateNode(cond, bag)
		if err != nil {
			// Malformed condition → fail-closed; record as deny. The error stays in
			// the log: it can carry evaluation internals.
			slog.Warn("abac condition error", "policy_id", p.id, "err", err)
			trace = append(trace, fmt.Sprintf("policy %q: condition error → fail-closed deny", p.name))
			if denyPolicyID == nil {
				id := p.id
				denyPolicyID = &id
				denyReason = fmt.Sprintf("condition error in policy %q", p.name)
				denyCode, denyParams = ReasonConditionError, params(p)
			}
			continue
		}
		matched := t.applies(p.effect)
		outcome := "condition not matched"
		switch {
		case t == isUnknown && matched:
			outcome = "an attribute the condition compares is absent → " + p.effect
		case t == isUnknown:
			outcome = "an attribute the condition compares is absent → not matched"
		case matched:
			outcome = "condition matched → " + p.effect
		}
		trace = append(trace, fmt.Sprintf("policy %q (effect=%s, priority=%d): %s", p.name, p.effect, p.priority, outcome))
		if !matched {
			continue
		}
		if p.effect == "deny" && denyPolicyID == nil {
			id := p.id
			denyPolicyID = &id
			denyReason = fmt.Sprintf("explicitly denied by policy %q (priority %d)", p.name, p.priority)
			denyCode, denyParams = ReasonDeniedByPolicy, params(p)
			if t == isUnknown {
				denyReason = fmt.Sprintf("denied by policy %q (priority %d): an attribute it compares is absent", p.name, p.priority)
				denyCode = ReasonAttributeAbsent
			}
		} else if p.effect == "allow" && allowPolicyID == nil {
			id := p.id
			allowPolicyID = &id
			allowReason = fmt.Sprintf("allowed by policy %q (priority %d)", p.name, p.priority)
			allowParams = params(p)
		}
	}

	// Deny wins over any allow.
	if denyPolicyID != nil {
		return &Decision{
			Allow:           false,
			Effect:          "deny",
			MatchedPolicyID: denyPolicyID,
			Reason:          denyReason,
			ReasonCode:      denyCode,
			ReasonParams:    denyParams,
			Trace:           trace,
		}
	}
	if allowPolicyID != nil {
		return &Decision{
			Allow:           true,
			Effect:          "allow",
			MatchedPolicyID: allowPolicyID,
			Reason:          allowReason,
			ReasonCode:      ReasonAllowedByPolicy,
			ReasonParams:    allowParams,
			Trace:           trace,
		}
	}

	trace = append(trace, "no matching allow policy found → default deny")
	return &Decision{
		Allow:      false,
		Effect:     "deny",
		Reason:     "no matching allow policy",
		ReasonCode: ReasonNoMatchingAllow,
		Trace:      trace,
	}
}
