// Package abac is the attribute-based access control (ABAC) engine for
// Qeet ID. It stores per-tenant policies and evaluates them at request time.
//
// A policy pairs an effect (allow/deny) with a resource-type, an action, and
// an optional condition tree. Conditions are recursive JSON trees:
//
//	{"all": [...nodes]}           AND — every child must be true
//	{"any": [...nodes]}           OR  — at least one child must be true
//	{"not": node}                 NOT — inverts the child
//	{"attr":"subject.dept","op":"eq","value":"eng"}  comparison leaf
//
// Attribute paths use dot-notation with a leading namespace ("subject.*",
// "resource.*", "context.*"). All thirteen operators are supported:
// eq, ne, in, nin, contains, gt, gte, lt, lte, exists, prefix, suffix, regex.
//
// Decision algorithm (deny-wins):
//  1. Collect all enabled policies whose resource_type and action match (exact
//     or "*" wildcard), ordered by priority desc.
//  2. Evaluate each policy's condition against the request attribute bag.
//  3. If ANY matching policy has effect=deny → DENY (explicit deny wins).
//  4. If ANY matching policy has effect=allow → ALLOW.
//  5. Default → DENY.
//
// Mutating service methods write the audit row in the same tx as the change.
package abac

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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

// UpdateInput carries the replacement fields for PATCH (all non-zero values
// replace the existing row; the caller must send the full desired state).
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

// Decision is the result of an Evaluate call.
type Decision struct {
	Allow           bool       `json:"allow"`
	Effect          string     `json:"effect"`
	MatchedPolicyID *uuid.UUID `json:"matched_policy_id,omitempty"`
	Reason          string     `json:"reason,omitempty"`
	// Trace is a human-readable grant-path explanation listing which policies
	// were evaluated and why the decision was reached. Returned only when the
	// caller requests ?explain=true, mirroring the rebac/authzen convention.
	Trace []string `json:"trace,omitempty"`
}

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
func equal(a, b any) bool {
	if a == b {
		return true
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
		// attrVal (string or array) contains value.
		switch v := attrVal.(type) {
		case string:
			s, ok := value.(string)
			if !ok {
				return false, nil
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

	case "prefix":
		av, _ := attrVal.(string)
		bv, _ := value.(string)
		return strings.HasPrefix(av, bv), nil

	case "suffix":
		av, _ := attrVal.(string)
		bv, _ := value.(string)
		return strings.HasSuffix(av, bv), nil

	case "regex":
		av, ok := attrVal.(string)
		if !ok {
			return false, nil
		}
		pattern, ok := value.(string)
		if !ok {
			return false, nil
		}
		re, err := compileRegex(pattern)
		if err != nil {
			// fail-closed on bad pattern — matches nothing
			return false, nil
		}
		return re.MatchString(av), nil

	default:
		return false, fmt.Errorf("abac: unknown operator %q", op)
	}
}

// evalLeaf evaluates one comparison leaf: {"attr":"...","op":"...","value":...}.
func evalLeaf(m map[string]json.RawMessage, bag AttributeBag) (bool, error) {
	var attr string
	if err := json.Unmarshal(m["attr"], &attr); err != nil || attr == "" {
		return false, fmt.Errorf("abac: condition leaf 'attr' must be a non-empty string")
	}
	opRaw, ok := m["op"]
	if !ok {
		return false, fmt.Errorf("abac: condition leaf missing 'op'")
	}
	var op string
	if err := json.Unmarshal(opRaw, &op); err != nil {
		return false, fmt.Errorf("abac: condition leaf 'op' must be a string: %w", err)
	}

	// 'exists' only needs the presence test, not the value.
	if op == "exists" {
		_, present := resolvePath(attr, bag)
		return present, nil
	}

	attrVal, present := resolvePath(attr, bag)

	// Absent attribute: fail-closed for all comparison ops except 'nin'
	// (an absent value is not a member of any set).
	if !present {
		if op == "nin" {
			return true, nil
		}
		return false, nil
	}

	var value any
	if vRaw, ok := m["value"]; ok {
		if err := json.Unmarshal(vRaw, &value); err != nil {
			return false, fmt.Errorf("abac: condition leaf 'value': %w", err)
		}
	}

	return compare(op, attrVal, value)
}

// evaluateNode recursively evaluates one condition node against the attribute
// bag. An empty JSON object {} is a no-op condition (always true), used as
// the default for unconditional policies.
func evaluateNode(raw json.RawMessage, bag AttributeBag) (bool, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" {
		return true, nil // no condition → unconditional match
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return false, fmt.Errorf("abac: condition node must be a JSON object: %w", err)
	}

	switch {
	case m["all"] != nil:
		var children []json.RawMessage
		if err := json.Unmarshal(m["all"], &children); err != nil {
			return false, fmt.Errorf("abac: 'all' must be an array: %w", err)
		}
		for i, child := range children {
			ok, err := evaluateNode(child, bag)
			if err != nil {
				return false, fmt.Errorf("abac: all[%d]: %w", i, err)
			}
			if !ok {
				return false, nil // short-circuit AND
			}
		}
		return true, nil // vacuously true for empty array

	case m["any"] != nil:
		var children []json.RawMessage
		if err := json.Unmarshal(m["any"], &children); err != nil {
			return false, fmt.Errorf("abac: 'any' must be an array: %w", err)
		}
		for i, child := range children {
			ok, err := evaluateNode(child, bag)
			if err != nil {
				return false, fmt.Errorf("abac: any[%d]: %w", i, err)
			}
			if ok {
				return true, nil // short-circuit OR
			}
		}
		return false, nil // false for empty array

	case m["not"] != nil:
		result, err := evaluateNode(m["not"], bag)
		if err != nil {
			return false, fmt.Errorf("abac: not: %w", err)
		}
		return !result, nil

	case m["attr"] != nil:
		return evalLeaf(m, bag)

	default:
		return false, fmt.Errorf("abac: condition node has no recognized key ('all', 'any', 'not', 'attr')")
	}
}

// EvaluateCondition evaluates a condition tree against an attribute bag.
// Returns (true, nil) on match, (false, nil) on non-match, and an error if
// the condition tree is structurally invalid or uses an unknown operator.
// On error, callers MUST default to DENY (fail-closed).
func EvaluateCondition(node json.RawMessage, attrs AttributeBag) (bool, error) {
	return evaluateNode(node, attrs)
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
	default:
		return fmt.Errorf("node has no recognized key ('all', 'any', 'not', 'attr')")
	}
	return nil
}

// Service — CRUD + evaluate.

type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool, q: dbgen.New(pool)} }

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
	if strings.TrimSpace(in.Name) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("name is required")
	}
	if in.Effect != "allow" && in.Effect != "deny" {
		return nil, errs.ErrUnprocessable.WithDetail("effect must be 'allow' or 'deny'")
	}
	if strings.TrimSpace(in.ResourceType) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("resource_type is required")
	}
	if strings.TrimSpace(in.Action) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("action is required")
	}
	cond := in.Condition
	if len(cond) == 0 {
		cond = json.RawMessage(`{}`)
	}
	if err := validateCondition(cond); err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("condition: " + err.Error())
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row, err := s.q.WithTx(tx).CreateAbacPolicy(ctx, dbgen.CreateAbacPolicyParams{
		TenantID:     tenantID,
		Name:         in.Name,
		Description:  in.Description,
		Effect:       in.Effect,
		ResourceType: in.ResourceType,
		Action:       in.Action,
		Condition:    []byte(cond),
		Priority:     int32(in.Priority),
		Enabled:      in.Enabled,
	})
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrConflict.WithDetail("a policy with that name already exists in this tenant")
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
		return nil, errs.ErrUnprocessable.WithDetail("name is required")
	}
	if in.Effect != "allow" && in.Effect != "deny" {
		return nil, errs.ErrUnprocessable.WithDetail("effect must be 'allow' or 'deny'")
	}
	if strings.TrimSpace(in.ResourceType) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("resource_type is required")
	}
	if strings.TrimSpace(in.Action) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("action is required")
	}
	cond := in.Condition
	if len(cond) == 0 {
		cond = json.RawMessage(`{}`)
	}
	if err := validateCondition(cond); err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("condition: " + err.Error())
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row, err := s.q.WithTx(tx).UpdateAbacPolicy(ctx, dbgen.UpdateAbacPolicyParams{
		Name:         in.Name,
		Description:  in.Description,
		Effect:       in.Effect,
		ResourceType: in.ResourceType,
		Action:       in.Action,
		Condition:    []byte(cond),
		Priority:     int32(in.Priority),
		Enabled:      in.Enabled,
		ID:           id,
		TenantID:     tenantID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrConflict.WithDetail("a policy with that name already exists in this tenant")
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

// Evaluate selects all enabled policies matching the request and applies the
// deny-wins algorithm. The returned Decision always has Allow set; Trace is
// populated only when at least one policy was evaluated (or on default deny).
func (s *Service) Evaluate(ctx context.Context, tenantID uuid.UUID, in EvaluationInput) (*Decision, error) {
	if strings.TrimSpace(in.Action) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("action is required")
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

	// Build the attribute bag: merge resource type+id+attrs into one namespace.
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
	bag := AttributeBag{
		"subject":  subject,
		"resource": resourceAttrs,
		"context":  ctxAttrs,
	}

	trace := make([]string, 0, len(policies))

	var denyPolicyID *uuid.UUID
	var allowPolicyID *uuid.UUID
	denyReason := ""
	allowReason := ""

	for _, p := range policies {
		cond := json.RawMessage(p.condition)
		if len(cond) == 0 {
			cond = json.RawMessage(`{}`)
		}
		matched, err := EvaluateCondition(cond, bag)
		if err != nil {
			// Malformed condition → fail-closed; record as deny.
			trace = append(trace, fmt.Sprintf("policy %q: condition error (%v) → fail-closed deny", p.name, err))
			if denyPolicyID == nil {
				id := p.id
				denyPolicyID = &id
				denyReason = fmt.Sprintf("condition error in policy %q: %v", p.name, err)
			}
			continue
		}
		if matched {
			trace = append(trace, fmt.Sprintf("policy %q (effect=%s, priority=%d): condition matched → %s",
				p.name, p.effect, p.priority, p.effect))
			if p.effect == "deny" && denyPolicyID == nil {
				id := p.id
				denyPolicyID = &id
				denyReason = fmt.Sprintf("explicitly denied by policy %q (priority %d)", p.name, p.priority)
			} else if p.effect == "allow" && allowPolicyID == nil {
				id := p.id
				allowPolicyID = &id
				allowReason = fmt.Sprintf("allowed by policy %q (priority %d)", p.name, p.priority)
			}
		} else {
			trace = append(trace, fmt.Sprintf("policy %q (effect=%s, priority=%d): condition not matched",
				p.name, p.effect, p.priority))
		}
	}

	// Deny wins over any allow.
	if denyPolicyID != nil {
		return &Decision{
			Allow:           false,
			Effect:          "deny",
			MatchedPolicyID: denyPolicyID,
			Reason:          denyReason,
			Trace:           trace,
		}, nil
	}
	if allowPolicyID != nil {
		return &Decision{
			Allow:           true,
			Effect:          "allow",
			MatchedPolicyID: allowPolicyID,
			Reason:          allowReason,
			Trace:           trace,
		}, nil
	}

	trace = append(trace, "no matching allow policy found → default deny")
	return &Decision{
		Allow:  false,
		Effect: "deny",
		Reason: "no matching allow policy",
		Trace:  trace,
	}, nil
}

// HTTP handler

type Handler struct {
	Service *Service
}

// requirePathTenant validates the tenantID path param against the principal's
// tenant scope and returns the tenant UUID on success.
func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

// actorOf captures the audit provenance from the principal and request headers.
func actorOf(r *http.Request) audit.Actor {
	a := audit.Actor{Type: "user", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		a.UserID = p.UserID
		if p.ActorType != "" {
			a.Type = p.ActorType
		}
	}
	return a
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/abac/policies", h.list)
	r.Post("/tenants/{tenantID}/abac/policies", h.create)
	r.Get("/tenants/{tenantID}/abac/policies/{id}", h.getPolicy)
	r.Patch("/tenants/{tenantID}/abac/policies/{id}", h.update)
	r.Delete("/tenants/{tenantID}/abac/policies/{id}", h.del)
	r.Post("/tenants/{tenantID}/abac/evaluate", h.evalHandler)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
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
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.Create(r.Context(), tenantID, in, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (h *Handler) getPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
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
	tenantID, err := requirePathTenant(r)
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
	p, err := h.Service.Update(r.Context(), id, tenantID, in, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Delete(r.Context(), id, tenantID, actorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) evalHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
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
