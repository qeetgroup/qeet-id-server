package abac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

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

// truth is a condition's three-valued result. A leaf is unknown when the
// attribute it compares, or one its value references, is absent or null; only
// exists, which tests presence, is always known. all, any and not combine
// unknown as Kleene logic does, so all with a false child is false and any with
// a true child is true. truth.applies turns the result into a policy match.
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
var refNamespaces = map[string]bool{"subject": true, "resource": true, "action": true, "context": true}

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
		return "", fmt.Errorf("leaf 'value' references %q, which is not a subject., resource., action. or context. attribute", ref)
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

	// A missing attribute decides nothing either, whatever the op: ne and nin
	// would otherwise hold for it and let an allow grant or lift a deny.
	if !present || attrVal == nil {
		return isUnknown, nil
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

	case m["role"] != nil:
		return evalRole(m["role"], bag)

	case m["relation"] != nil:
		return evalRelation(m["relation"], bag)

	default:
		return isFalse, fmt.Errorf("abac: condition node has no recognized key ('all', 'any', 'not', 'attr', 'role', 'relation')")
	}
}

// evalRole evaluates {"role": "<name>"}: whether subject.roles, the roles the
// platform supplies by name, holds name. Unknown when it supplies none.
func evalRole(raw json.RawMessage, bag AttributeBag) (truth, error) {
	var name string
	if err := json.Unmarshal(raw, &name); err != nil || name == "" {
		return isFalse, errors.New("abac: condition 'role' must be a non-empty string")
	}
	roles, present := resolvePath("subject.roles", bag)
	list, ok := toArray(roles)
	if !present || !ok {
		return isUnknown, nil
	}
	return truthOf(slices.ContainsFunc(list, func(r any) bool { return r == name })), nil
}

// EvaluateCondition reports whether a policy with effect and condition node
// applies to attrs: a tree of all, any, not and leaves such as {"attr":
// "subject.dept", "op": "eq", "value": "eng"}, {} always applying. One left
// unknown by a missing attribute (see truth) fails closed: it applies to a deny
// and not to an allow. An error means the tree is invalid: callers must deny.
func EvaluateCondition(node json.RawMessage, effect string, attrs AttributeBag) (bool, error) {
	t, err := evaluateNode(node, attrs)
	return err == nil && t.applies(effect), err
}
