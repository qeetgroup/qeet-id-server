package abac

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

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
	case m["role"] != nil:
		var name string
		if err := json.Unmarshal(m["role"], &name); err != nil || strings.TrimSpace(name) == "" {
			return errors.New("'role' must be a non-empty role name")
		}
	case m["relation"] != nil:
		if _, _, _, err := parseRelation(m["relation"]); err != nil {
			return err
		}
	default:
		return fmt.Errorf("node has no recognized key ('all', 'any', 'not', 'attr', 'role', 'relation')")
	}
	return nil
}

// Resource and action of the policies that guard managing policies: a deny
// that matches its own author here would leave nobody able to remove it.
const (
	policyResourceType = "policy"
	policyWriteAction  = "write"
)

// locksOutAuthor reports whether an enabled deny policy would refuse its own
// author the right to change policies (policy.write) at the route guard, on
// the attributes it would see for the author's call now; that would leave the
// organization with nobody able to undo it. See refusesPolicyWrite.
func (s *Service) locksOutAuthor(ctx context.Context, organizationID uuid.UUID, effect, resourceType, action string, enabled bool, cond json.RawMessage, actor audit.Actor) (bool, error) {
	if effect != "deny" || !enabled || actor.UserID == nil {
		return false, nil
	}
	if (resourceType != policyResourceType && resourceType != "*") || (action != policyWriteAction && action != "*") {
		return false, nil
	}
	subject, ctxAttrs, err := s.PlatformAttributes(ctx, OwnRequest(ctx, *actor.UserID, organizationID))
	if err != nil {
		return false, err
	}
	bag := attributeBag(EvaluationInput{
		Subject: subject, Resource: EvaluationResource{Type: policyResourceType}, Action: policyWriteAction, Context: ctxAttrs,
	})
	if err := s.resolveRelations(ctx, organizationID, [][]byte{cond}, bag); err != nil {
		return false, err
	}
	return refusesPolicyWrite(cond, bag), nil
}

// refusesPolicyWrite reports whether a deny with cond refuses policy.write to a
// caller with the attributes in bag, as the route guard would. A condition
// error counts: the route guard fails closed on it too.
func refusesPolicyWrite(cond json.RawMessage, bag AttributeBag) bool {
	matched, err := EvaluateCondition(cond, "deny", bag)
	return matched || err != nil
}

// checkPolicy refuses a policy missing its name, resource type or action, with
// an unknown effect, or with an invalid condition, and returns the condition
// to store: {} when there is none.
func checkPolicy(name, effect, resourceType, action string, cond json.RawMessage) (json.RawMessage, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrNameRequired
	}
	if effect != "allow" && effect != "deny" {
		return nil, ErrEffectInvalid
	}
	if strings.TrimSpace(resourceType) == "" {
		return nil, ErrResourceTypeRequired
	}
	if strings.TrimSpace(action) == "" {
		return nil, ErrActionRequired
	}
	if len(cond) == 0 {
		cond = json.RawMessage(`{}`)
	}
	if err := validateCondition(cond); err != nil {
		return nil, ErrConditionInvalid
	}
	return cond, nil
}
