// Package abac stores per-tenant attribute-based access control policies and
// evaluates them deny-wins: among enabled policies for the resource type and
// action (exact or "*"), a matching deny refuses, else a matching allow
// permits, else the answer is deny. Conditions are JSON trees (EvaluateCondition).
package abac

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Domain types

// AttributeBag holds the per-namespace attribute maps for one evaluation.
// The outer key is the namespace ("subject", "resource", "context");
// the inner map carries the concrete attributes for that namespace.
type AttributeBag map[string]map[string]any

// Policy is the read-projection of one abac_policies row.
type Policy struct {
	ID           uuid.UUID       `json:"id"`
	TenantID     uuid.UUID       `json:"tenant_id"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Effect       string          `json:"effect"`
	ResourceType string          `json:"resource_type"`
	Action       string          `json:"action"`
	Condition    json.RawMessage `json:"condition"`
	Priority     int             `json:"priority"`
	Enabled      bool            `json:"enabled"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// CreateInput carries the user-supplied fields for a new policy.
type CreateInput struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Effect       string          `json:"effect"`
	ResourceType string          `json:"resource_type"`
	Action       string          `json:"action"`
	Condition    json.RawMessage `json:"condition"`
	Priority     int             `json:"priority"`
	Enabled      bool            `json:"enabled"`
}

// UpdateInput is a policy's full replacement state for PATCH: every field,
// zero or not, replaces the stored one.
type UpdateInput struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Effect       string          `json:"effect"`
	ResourceType string          `json:"resource_type"`
	Action       string          `json:"action"`
	Condition    json.RawMessage `json:"condition"`
	Priority     int             `json:"priority"`
	Enabled      bool            `json:"enabled"`
}

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
	Context  map[string]any     `json:"context"`
}

// Decision is the result of an Evaluate call. ReasonCode is one of the
// authz.* codes below and Reason the same in English; ReasonParams names the
// policy that decided (policy_id, policy_name, priority). Trace lists, readably,
// each policy evaluated and why; the evaluate endpoint returns it only with
// ?explain=true.
type Decision struct {
	Allow           bool           `json:"allow"`
	Effect          string         `json:"effect"`
	MatchedPolicyID *uuid.UUID     `json:"matched_policy_id,omitempty"`
	Reason          string         `json:"reason,omitempty"`
	ReasonCode      string         `json:"reason_code,omitempty"`
	ReasonParams    map[string]any `json:"reason_params,omitempty"`
	Trace           []string       `json:"trace,omitempty"`
}

// Decision.ReasonCode values.
const (
	ReasonAllowedByPolicy = "authz.allowed_by_policy" // an allow policy matched
	ReasonDeniedByPolicy  = "authz.denied_by_policy"  // a deny policy matched
	ReasonAttributeAbsent = "authz.attribute_absent"  // a deny policy applied as an attribute it compares is absent
	ReasonConditionError  = "authz.condition_error"   // a policy's condition failed to evaluate, so it refused
	ReasonNoMatchingAllow = "authz.no_matching_allow" // no allow policy matched: refused by default
)

// Condition evaluator — pure functions, no I/O.

// reCache holds compiled regexps so each pattern is compiled at most once.
var reCache sync.Map // map[string]*regexp.Regexp

// compileRegex returns a compiled regexp from the cache, or compiles and
// stores it. Returns an error on a bad pattern (fail-closed: caller treats
// that as a non-match).
func compileRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := reCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	reCache.Store(pattern, re)
	return re, nil
}

// resolvePath resolves a dotted attribute path against the bag. The first
// segment names the namespace ("subject", "resource", "context"); remaining
// segments traverse nested maps within that namespace.
// Returns (value, true) if found, (nil, false) if absent at any level.
func resolvePath(attr string, bag AttributeBag) (any, bool) {
	dot := strings.IndexByte(attr, '.')
	if dot <= 0 || dot == len(attr)-1 {
		return nil, false // empty namespace or empty key
	}
	ns := attr[:dot]
	rest := attr[dot+1:]
	nsMap, ok := bag[ns]
	if !ok {
		return nil, false
	}
	// Walk nested map segments separated by '.'.
	parts := strings.Split(rest, ".")
	var cur any = map[string]any(nsMap)
	for _, part := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// toFloat64 coerces a value to float64. JSON numbers decode as float64 from
// encoding/json; integer variants are handled for non-JSON-decoded callers.
func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	default:
		return 0, false
	}
}

// equal performs a type-aware equality comparison. JSON numbers decode as
// float64, so numeric cross-type equality (e.g. int vs float64) is handled.
// Arrays and objects compare by their printed form; == on them would panic.
func equal(a, b any) bool {
	if as, ok := a.(string); ok {
		if bs, ok := b.(string); ok {
			return as == bs
		}
	}
	af, aok := toFloat64(a)
	bf, bok := toFloat64(b)
	if aok && bok {
		return af == bf
	}
	// Fallback: string representation equality covers bool and edge cases.
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// toArray asserts that v is a JSON array ([]any).
func toArray(v any) ([]any, bool) {
	a, ok := v.([]any)
	return a, ok
}

// compare evaluates one comparison operator against an attribute value and an
// expected value. Both values are already decoded Go types (from encoding/json
// or from the attribute bag). Returns an error for unknown operators; numeric
// ops return false (not an error) when either side cannot be coerced to float64.
func compare(op string, attrVal, value any) (bool, error) {
	switch op {
	case "eq":
		return equal(attrVal, value), nil
	case "ne":
		return !equal(attrVal, value), nil

	case "in":
		// attrVal ∈ value  (value must be an array)
		arr, ok := toArray(value)
		if !ok {
			return false, fmt.Errorf("abac: op 'in' requires value to be an array")
		}
		for _, el := range arr {
			if equal(attrVal, el) {
				return true, nil
			}
		}
		return false, nil

	case "nin":
		// attrVal ∉ value  (value must be an array)
		arr, ok := toArray(value)
		if !ok {
			return false, fmt.Errorf("abac: op 'nin' requires value to be an array")
		}
		for _, el := range arr {
			if equal(attrVal, el) {
				return false, nil
			}
		}
		return true, nil

	case "contains":
		// attrVal (string or array) contains value. Every string contains "",
		// so looking for it in a string is an error rather than a match.
		switch v := attrVal.(type) {
		case string:
			s, ok := value.(string)
			if !ok {
				return false, nil
			}
			if s == "" {
				return false, errors.New("abac: op 'contains' can't look for an empty string")
			}
			return strings.Contains(v, s), nil
		case []any:
			for _, el := range v {
				if equal(el, value) {
					return true, nil
				}
			}
			return false, nil
		default:
			return false, nil
		}

	case "gt":
		af, bf, ok := func() (float64, float64, bool) {
			a, aok := toFloat64(attrVal)
			b, bok := toFloat64(value)
			return a, b, aok && bok
		}()
		if !ok {
			return false, nil
		}
		return af > bf, nil

	case "gte":
		af, bf, ok := func() (float64, float64, bool) {
			a, aok := toFloat64(attrVal)
			b, bok := toFloat64(value)
			return a, b, aok && bok
		}()
		if !ok {
			return false, nil
		}
		return af >= bf, nil

	case "lt":
		af, bf, ok := func() (float64, float64, bool) {
			a, aok := toFloat64(attrVal)
			b, bok := toFloat64(value)
			return a, b, aok && bok
		}()
		if !ok {
			return false, nil
		}
		return af < bf, nil

	case "lte":
		af, bf, ok := func() (float64, float64, bool) {
			a, aok := toFloat64(attrVal)
			b, bok := toFloat64(value)
			return a, b, aok && bok
		}()
		if !ok {
			return false, nil
		}
		return af <= bf, nil

	case "prefix", "suffix":
		// The value must be a non-empty string, as "" is an affix of every
		// string; a non-string attribute matches nothing.
		affix, ok := value.(string)
		if !ok || affix == "" {
			return false, fmt.Errorf("abac: op '%s' requires value to be a non-empty string", op)
		}
		av, ok := attrVal.(string)
		if !ok {
			return false, nil
		}
		if op == "prefix" {
			return strings.HasPrefix(av, affix), nil
		}
		return strings.HasSuffix(av, affix), nil

	case "regex":
		av, ok := attrVal.(string)
		if !ok {
			return false, nil
		}
		pattern, ok := value.(string)
		if !ok {
			return false, nil
		}
		if pattern == "" {
			return false, errors.New("abac: op 'regex' requires a non-empty pattern")
		}
		re, err := compileRegex(pattern)
		if err != nil {
			return false, nil //nolint:nilerr // a bad pattern fails closed: it matches nothing
		}
		return re.MatchString(av), nil

	default:
		return false, fmt.Errorf("abac: unknown operator %q", op)
	}
}

// truth is a condition's three-valued result. A leaf comparing two attributes
// is unknown when either is absent or null; all, any and not combine unknown
// as Kleene logic does, so all with a false child is false and any with a true
// child is true. truth.applies turns the result into a policy match.
type truth uint8

const (
	isFalse truth = iota
	isTrue
	isUnknown
)

// truthOf returns the known truth b.
func truthOf(b bool) truth {
	if b {
		return isTrue
	}
	return isFalse
}

// applies reports whether a policy with effect applies when its condition is
// t. Unknown applies to a deny and not to an allow: an absent attribute never
// grants access and never lifts a deny.
func (t truth) applies(effect string) bool {
	return t == isTrue || (t == isUnknown && effect == "deny")
}

// refNamespaces are the namespaces an attribute reference may name.
var refNamespaces = map[string]bool{"subject": true, "resource": true, "context": true}

// refOps are the operators whose value may reference another attribute. Not
// regex, so a pattern never comes from request data, nor prefix and suffix,
// whose value must be a non-empty string literal.
var refOps = map[string]bool{
	"eq": true, "ne": true, "gt": true, "gte": true, "lt": true, "lte": true,
	"in": true, "nin": true, "contains": true,
}

// leafReference returns the attribute a leaf's value references, or "" when
// the value is a literal. An object value is a reference, and must be exactly
// {"attr": "<namespace>.<path>"} naming another attribute, on an op in refOps;
// a string such as "resource.region" stays a literal.
func leafReference(m map[string]json.RawMessage, attr, op string) (string, error) {
	raw := bytes.TrimSpace(m["value"])
	if len(raw) == 0 || raw[0] != '{' {
		return "", nil
	}
	var obj map[string]json.RawMessage
	var ref string
	if json.Unmarshal(raw, &obj) != nil || len(obj) != 1 || json.Unmarshal(obj["attr"], &ref) != nil {
		return "", errors.New(`leaf 'value' object must be an attribute reference {"attr": "<namespace>.<path>"}`)
	}
	if !refOps[op] {
		return "", fmt.Errorf("leaf op %q cannot compare with another attribute", op)
	}
	ns, path, _ := strings.Cut(ref, ".")
	if !refNamespaces[ns] || path == "" || slices.Contains(strings.Split(path, "."), "") {
		return "", fmt.Errorf("leaf 'value' references %q, which is not a subject., resource. or context. attribute", ref)
	}
	if ref == attr {
		return "", errors.New("leaf 'value' references the leaf's own attribute")
	}
	return ref, nil
}

// evalLeaf evaluates one comparison leaf: {"attr":"...","op":"...","value":...}.
// The value is a literal or a reference to another attribute (leafReference).
func evalLeaf(m map[string]json.RawMessage, bag AttributeBag) (truth, error) {
	var attr string
	if err := json.Unmarshal(m["attr"], &attr); err != nil || attr == "" {
		return isFalse, fmt.Errorf("abac: condition leaf 'attr' must be a non-empty string")
	}
	opRaw, ok := m["op"]
	if !ok {
		return isFalse, fmt.Errorf("abac: condition leaf missing 'op'")
	}
	var op string
	if err := json.Unmarshal(opRaw, &op); err != nil {
		return isFalse, fmt.Errorf("abac: condition leaf 'op' must be a string: %w", err)
	}
	ref, err := leafReference(m, attr, op)
	if err != nil {
		return isFalse, fmt.Errorf("abac: condition %w", err)
	}

	// 'exists' only needs the presence test, not the value.
	if op == "exists" {
		_, present := resolvePath(attr, bag)
		return truthOf(present), nil
	}

	attrVal, present := resolvePath(attr, bag)

	// Comparing two attributes: unknown unless both have a value, whatever the
	// op, so a missing one decides nothing (see truth.applies).
	if ref != "" {
		refVal, refPresent := resolvePath(ref, bag)
		if !present || !refPresent || attrVal == nil || refVal == nil {
			return isUnknown, nil
		}
		ok, err := compare(op, attrVal, refVal)
		return truthOf(ok), err
	}

	// Absent attribute: fail-closed for all comparison ops except 'nin'
	// (an absent value is not a member of any set).
	if !present {
		return truthOf(op == "nin"), nil
	}

	var value any
	if vRaw, ok := m["value"]; ok {
		if err := json.Unmarshal(vRaw, &value); err != nil {
			return isFalse, fmt.Errorf("abac: condition leaf 'value': %w", err)
		}
	}

	ok, err = compare(op, attrVal, value)
	return truthOf(ok), err
}

// evaluateNode recursively evaluates one condition node against the attribute
// bag. An empty JSON object {} is a no-op condition (always true), used as
// the default for unconditional policies.
func evaluateNode(raw json.RawMessage, bag AttributeBag) (truth, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" {
		return isTrue, nil // no condition → unconditional match
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return isFalse, fmt.Errorf("abac: condition node must be a JSON object: %w", err)
	}

	switch {
	case m["all"] != nil:
		var children []json.RawMessage
		if err := json.Unmarshal(m["all"], &children); err != nil {
			return isFalse, fmt.Errorf("abac: 'all' must be an array: %w", err)
		}
		result := isTrue // vacuously true for empty array
		for i, child := range children {
			t, err := evaluateNode(child, bag)
			if err != nil {
				return isFalse, fmt.Errorf("abac: all[%d]: %w", i, err)
			}
			if t == isFalse {
				return isFalse, nil // short-circuit AND
			}
			if t == isUnknown {
				result = isUnknown
			}
		}
		return result, nil

	case m["any"] != nil:
		var children []json.RawMessage
		if err := json.Unmarshal(m["any"], &children); err != nil {
			return isFalse, fmt.Errorf("abac: 'any' must be an array: %w", err)
		}
		result := isFalse // false for empty array
		for i, child := range children {
			t, err := evaluateNode(child, bag)
			if err != nil {
				return isFalse, fmt.Errorf("abac: any[%d]: %w", i, err)
			}
			if t == isTrue {
				return isTrue, nil // short-circuit OR
			}
			if t == isUnknown {
				result = isUnknown
			}
		}
		return result, nil

	case m["not"] != nil:
		t, err := evaluateNode(m["not"], bag)
		if err != nil {
			return isFalse, fmt.Errorf("abac: not: %w", err)
		}
		if t == isUnknown {
			return isUnknown, nil
		}
		return truthOf(t == isFalse), nil

	case m["attr"] != nil:
		return evalLeaf(m, bag)

	default:
		return isFalse, fmt.Errorf("abac: condition node has no recognized key ('all', 'any', 'not', 'attr')")
	}
}

// EvaluateCondition reports whether a policy with effect and condition node
// applies to attrs. A node is {"all": [...]}, {"any": [...]}, {"not": node} or
// a leaf such as {"attr": "subject.dept", "op": "eq", "value": "eng"}; an empty
// tree applies. An error means the tree is invalid: callers must deny.
func EvaluateCondition(node json.RawMessage, effect string, attrs AttributeBag) (bool, error) {
	t, err := evaluateNode(node, attrs)
	return err == nil && t.applies(effect), err
}

// validateCondition performs a structural check of a condition tree without
// evaluating it against any attributes. Returns nil if the tree is valid.
func validateCondition(raw json.RawMessage) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("condition must be a JSON object: %w", err)
	}
	switch {
	case m["all"] != nil:
		var children []json.RawMessage
		if err := json.Unmarshal(m["all"], &children); err != nil {
			return fmt.Errorf("'all' must be an array: %w", err)
		}
		for i, c := range children {
			if err := validateCondition(c); err != nil {
				return fmt.Errorf("all[%d]: %w", i, err)
			}
		}
	case m["any"] != nil:
		var children []json.RawMessage
		if err := json.Unmarshal(m["any"], &children); err != nil {
			return fmt.Errorf("'any' must be an array: %w", err)
		}
		for i, c := range children {
			if err := validateCondition(c); err != nil {
				return fmt.Errorf("any[%d]: %w", i, err)
			}
		}
	case m["not"] != nil:
		if err := validateCondition(m["not"]); err != nil {
			return fmt.Errorf("not: %w", err)
		}
	case m["attr"] != nil:
		var attr string
		if err := json.Unmarshal(m["attr"], &attr); err != nil || attr == "" {
			return fmt.Errorf("leaf 'attr' must be a non-empty string")
		}
		if m["op"] == nil {
			return fmt.Errorf("leaf missing 'op'")
		}
		var op string
		if err := json.Unmarshal(m["op"], &op); err != nil {
			return fmt.Errorf("leaf 'op' must be a string: %w", err)
		}
		validOps := map[string]bool{
			"eq": true, "ne": true, "in": true, "nin": true,
			"contains": true, "gt": true, "gte": true, "lt": true, "lte": true,
			"exists": true, "prefix": true, "suffix": true, "regex": true,
		}
		if !validOps[op] {
			return fmt.Errorf("leaf: unknown operator %q", op)
		}
		if _, err := leafReference(m, attr, op); err != nil {
			return err
		}
		var affix string
		if (op == "prefix" || op == "suffix") && (json.Unmarshal(m["value"], &affix) != nil || affix == "") {
			return fmt.Errorf("leaf op %q needs a non-empty string value", op)
		}
		// "" is in every string and an empty pattern matches every string.
		if (op == "contains" || op == "regex") && bytes.Equal(bytes.TrimSpace(m["value"]), []byte(`""`)) {
			return fmt.Errorf("leaf op %q needs a non-empty value", op)
		}
		var elems []json.RawMessage
		if json.Unmarshal(m["value"], &elems) == nil {
			for _, el := range elems {
				if el = bytes.TrimSpace(el); len(el) > 0 && el[0] == '{' {
					return errors.New("leaf 'value' array may not hold an object: an attribute reference must be the whole value")
				}
			}
		}
	default:
		return fmt.Errorf("node has no recognized key ('all', 'any', 'not', 'attr')")
	}
	return nil
}

// Service — CRUD + evaluate.

// Service stores each tenant's ABAC policies and evaluates requests against
// them.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	gate PlanGate

	presenceMu sync.Mutex
	presence   map[uuid.UUID]presenceEntry
}

// NewService returns the ABAC policy service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), presence: map[uuid.UUID]presenceEntry{}}
}

// presenceTTL bounds how long another instance may go on skipping ABAC for a
// tenant after a policy is added there; this instance forgets at once.
const presenceTTL = 5 * time.Second

type presenceEntry struct {
	deny, allow bool
	at          time.Time
}

// Presence reports whether the tenant has any enabled deny and any enabled
// allow policy, so a decision runs ABAC only where it can change the outcome
// (decide.Decider). Cached per tenant for presenceTTL, and forgotten on every
// change made through this service.
func (s *Service) Presence(ctx context.Context, tenantID uuid.UUID) (hasDeny, hasAllow bool, err error) {
	s.presenceMu.Lock()
	e, ok := s.presence[tenantID]
	s.presenceMu.Unlock()
	if ok && time.Since(e.at) < presenceTTL {
		return e.deny, e.allow, nil
	}
	row, err := s.q.CountEnabledPolicies(ctx, tenantID)
	if err != nil {
		return false, false, err
	}
	e = presenceEntry{deny: row.Deny > 0, allow: row.Allow > 0, at: time.Now()}
	s.presenceMu.Lock()
	s.presence[tenantID] = e
	s.presenceMu.Unlock()
	return e.deny, e.allow, nil
}

func (s *Service) forgetPresence(tenantID uuid.UUID) {
	s.presenceMu.Lock()
	delete(s.presence, tenantID)
	s.presenceMu.Unlock()
}

// SubjectAttributes is the subject namespace the platform supplies when it
// decides for a user itself (decide.Decider): who they are, never anything the
// caller chose, so a deny written against subject.id binds wherever it applies.
func SubjectAttributes(userID string, tenantID uuid.UUID) map[string]any {
	return map[string]any{"id": userID, "type": "user", "tenant_id": tenantID.String()}
}

// Resource and action of the policies that guard managing policies: a deny
// that matches its own author here would leave nobody able to remove it.
const (
	policyResourceType = "policy"
	policyWriteAction  = "write"
)

// locksOutAuthor reports whether an enabled deny policy would refuse its own
// author the right to change policies (policy.write), which would leave the
// tenant with nobody able to undo it. A condition error counts as a match: the
// route guard fails closed on it too.
func locksOutAuthor(effect, resourceType, action string, enabled bool, cond json.RawMessage, tenantID uuid.UUID, actor audit.Actor) bool {
	if effect != "deny" || !enabled || actor.UserID == nil {
		return false
	}
	if (resourceType != policyResourceType && resourceType != "*") || (action != policyWriteAction && action != "*") {
		return false
	}
	matched, err := EvaluateCondition(cond, effect, AttributeBag{
		"subject":  SubjectAttributes(actor.UserID.String(), tenantID),
		"resource": {"type": policyResourceType, "id": ""},
		"context":  {},
	})
	return matched || err != nil
}

// PlanGate reports whether a plan-gated feature is in the tenant's plan. It is
// satisfied by operations/entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (s *Service) SetPlanGate(g PlanGate) { s.gate = g }

// toPolicy maps a generated AuthAbacPolicy row to the domain Policy type.
func toPolicy(row dbgen.AuthAbacPolicy) *Policy {
	p := &Policy{
		ID:           row.ID,
		TenantID:     row.TenantID,
		Name:         row.Name,
		Description:  row.Description,
		Effect:       row.Effect,
		ResourceType: row.ResourceType,
		Action:       row.Action,
		Priority:     int(row.Priority),
		Enabled:      row.Enabled,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}
	if len(row.Condition) > 0 {
		p.Condition = json.RawMessage(row.Condition)
	} else {
		p.Condition = json.RawMessage(`{}`)
	}
	return p
}

// Create inserts a new ABAC policy. The audit row and outbox event are
// committed atomically in the same transaction.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, in CreateInput, actor audit.Actor) (*Policy, error) {
	// Plan gate: ABAC (attribute-based access control) is a Pro+ feature.
	if s.gate != nil {
		ok, err := s.gate.FeatureAllowed(ctx, tenantID, "abac")
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "abac"})
		}
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, errs.ErrABACNameRequired
	}
	if in.Effect != "allow" && in.Effect != "deny" {
		return nil, errs.ErrABACEffectInvalid
	}
	if strings.TrimSpace(in.ResourceType) == "" {
		return nil, errs.ErrABACResourceTypeRequired
	}
	if strings.TrimSpace(in.Action) == "" {
		return nil, errs.ErrABACActionRequired
	}
	cond := in.Condition
	if len(cond) == 0 {
		cond = json.RawMessage(`{}`)
	}
	if err := validateCondition(cond); err != nil {
		return nil, errs.ErrABACConditionInvalid
	}
	if locksOutAuthor(in.Effect, in.ResourceType, in.Action, in.Enabled, cond, tenantID, actor) {
		return nil, errs.ErrABACPolicyLocksOut
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	defer s.forgetPresence(tenantID)

	row, err := s.q.WithTx(tx).CreateAbacPolicy(ctx, dbgen.CreateAbacPolicyParams{
		TenantID:     tenantID,
		Name:         in.Name,
		Description:  in.Description,
		Effect:       in.Effect,
		ResourceType: in.ResourceType,
		Action:       in.Action,
		Condition:    []byte(cond),
		Priority:     int32(in.Priority), // #nosec G115 -- only orders the trace; deny wins regardless
		Enabled:      in.Enabled,
	})
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrABACPolicyNameExists
		}
		return nil, err
	}
	p := toPolicy(row)

	if err := audit.Record(ctx, tx, actor.Event(tenantID, "abac_policy.created", "abac_policy", p.ID,
		map[string]any{"name": p.Name, "effect": p.Effect, "resource_type": p.ResourceType, "action": p.Action})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: p.ID,
		Topic:       "abac.events",
		EventType:   "abac_policy.created",
		Payload:     p,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// Get returns one policy by id, scoped to tenant.
func (s *Service) Get(ctx context.Context, id, tenantID uuid.UUID) (*Policy, error) {
	row, err := s.q.GetAbacPolicy(ctx, dbgen.GetAbacPolicyParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toPolicy(row), nil
}

// List returns all policies for a tenant, ordered by priority desc then name.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Policy, error) {
	rows, err := s.q.ListAbacPolicies(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Policy, 0, len(rows))
	for _, row := range rows {
		out = append(out, *toPolicy(row))
	}
	return out, nil
}

// Update replaces all mutable fields of a policy. The audit row and outbox
// event are committed atomically in the same transaction.
func (s *Service) Update(ctx context.Context, id, tenantID uuid.UUID, in UpdateInput, actor audit.Actor) (*Policy, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, errs.ErrABACNameRequired
	}
	if in.Effect != "allow" && in.Effect != "deny" {
		return nil, errs.ErrABACEffectInvalid
	}
	if strings.TrimSpace(in.ResourceType) == "" {
		return nil, errs.ErrABACResourceTypeRequired
	}
	if strings.TrimSpace(in.Action) == "" {
		return nil, errs.ErrABACActionRequired
	}
	cond := in.Condition
	if len(cond) == 0 {
		cond = json.RawMessage(`{}`)
	}
	if err := validateCondition(cond); err != nil {
		return nil, errs.ErrABACConditionInvalid
	}
	if locksOutAuthor(in.Effect, in.ResourceType, in.Action, in.Enabled, cond, tenantID, actor) {
		return nil, errs.ErrABACPolicyLocksOut
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	defer s.forgetPresence(tenantID)

	row, err := s.q.WithTx(tx).UpdateAbacPolicy(ctx, dbgen.UpdateAbacPolicyParams{
		Name:         in.Name,
		Description:  in.Description,
		Effect:       in.Effect,
		ResourceType: in.ResourceType,
		Action:       in.Action,
		Condition:    []byte(cond),
		Priority:     int32(in.Priority), // #nosec G115 -- only orders the trace; deny wins regardless
		Enabled:      in.Enabled,
		ID:           id,
		TenantID:     tenantID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrABACPolicyNameExists
		}
		return nil, err
	}
	p := toPolicy(row)

	if err := audit.Record(ctx, tx, actor.Event(tenantID, "abac_policy.updated", "abac_policy", p.ID,
		map[string]any{"name": p.Name, "effect": p.Effect, "resource_type": p.ResourceType, "action": p.Action})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: p.ID,
		Topic:       "abac.events",
		EventType:   "abac_policy.updated",
		Payload:     p,
	}); err != nil {
		return nil, err
	}
	return p, tx.Commit(ctx)
}

// Delete removes one policy by id, scoped to tenant.
func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	defer s.forgetPresence(tenantID)

	name, err := s.q.WithTx(tx).DeleteAbacPolicy(ctx, dbgen.DeleteAbacPolicyParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}

	if err := audit.Record(ctx, tx, actor.Event(tenantID, "abac_policy.deleted", "abac_policy", id,
		map[string]any{"name": name})); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: id,
		Topic:       "abac.events",
		EventType:   "abac_policy.deleted",
		Payload:     map[string]any{"id": id, "tenant_id": tenantID, "name": name},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
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

// Evaluate applies tenantID's enabled policies for in's resource type and
// action, highest priority first, deny-wins: a matching deny or a condition
// that fails to evaluate refuses, else a matching allow permits, else deny. A
// condition comparing an absent attribute matches a deny and never an allow.
func (s *Service) Evaluate(ctx context.Context, tenantID uuid.UUID, in EvaluationInput) (*Decision, error) {
	if strings.TrimSpace(in.Action) == "" {
		return nil, errs.ErrABACActionRequired
	}

	rows, err := s.q.ListEvaluationCandidates(ctx, dbgen.ListEvaluationCandidatesParams{
		TenantID:     tenantID,
		ResourceType: in.Resource.Type,
		Action:       in.Action,
	})
	if err != nil {
		return nil, err
	}

	var policies []candidate
	for _, row := range rows {
		policies = append(policies, candidate{
			id:        row.ID,
			name:      row.Name,
			effect:    row.Effect,
			condition: row.Condition,
			priority:  int(row.Priority),
		})
	}
	return combine(policies, attributeBag(in)), nil
}

// attributeBag builds the bag policies see for in, with the resource's type,
// id and attrs merged into one namespace.
func attributeBag(in EvaluationInput) AttributeBag {
	resourceAttrs := map[string]any{
		"type": in.Resource.Type,
		"id":   in.Resource.ID,
	}
	for k, v := range in.Resource.Attrs {
		resourceAttrs[k] = v
	}
	subject := in.Subject
	if subject == nil {
		subject = map[string]any{}
	}
	ctxAttrs := in.Context
	if ctxAttrs == nil {
		ctxAttrs = map[string]any{}
	}
	return AttributeBag{
		"subject":  subject,
		"resource": resourceAttrs,
		"context":  ctxAttrs,
	}
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

// HTTP handler

// Handler serves the ABAC policy HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the ABAC policy routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/abac/policies", h.list)
	r.Post("/tenants/{tenantID}/abac/policies", h.create)
	r.Get("/tenants/{tenantID}/abac/policies/{id}", h.getPolicy)
	r.Patch("/tenants/{tenantID}/abac/policies/{id}", h.update)
	r.Delete("/tenants/{tenantID}/abac/policies/{id}", h.del)
	r.Post("/tenants/{tenantID}/abac/evaluate", h.evalHandler)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.Create(r.Context(), tenantID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (h *Handler) getPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	p, err := h.Service.Get(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.Update(r.Context(), id, tenantID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Delete(r.Context(), id, tenantID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) evalHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in EvaluationInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	decision, err := h.Service.Evaluate(r.Context(), tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Omit the trace unless ?explain=true, mirroring the rebac/authzen convention.
	if r.URL.Query().Get("explain") != "true" {
		decision.Trace = nil
	}
	httpx.WriteJSON(w, http.StatusOK, decision)
}
