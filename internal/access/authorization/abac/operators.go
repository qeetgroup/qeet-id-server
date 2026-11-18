package abac

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

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
	case "in", "nin":
		return compareMembership(op, attrVal, value)
	case "contains":
		return compareContains(attrVal, value)
	case "gt", "gte", "lt", "lte":
		return compareNumbers(op, attrVal, value), nil
	case "prefix", "suffix":
		return compareAffix(op, attrVal, value)
	case "regex":
		return compareRegex(attrVal, value)
	default:
		return false, fmt.Errorf("abac: unknown operator %q", op)
	}
}

// compareMembership is op "in" (attrVal ∈ value) or "nin" (attrVal ∉ value);
// value must be an array.
func compareMembership(op string, attrVal, value any) (bool, error) {
	arr, ok := toArray(value)
	if !ok {
		return false, fmt.Errorf("abac: op '%s' requires value to be an array", op)
	}
	for _, el := range arr {
		if equal(attrVal, el) {
			return op == "in", nil
		}
	}
	return op == "nin", nil
}

// compareContains is op "contains": attrVal (string or array) contains value.
// Every string contains "", so looking for it in a string is an error rather
// than a match.
func compareContains(attrVal, value any) (bool, error) {
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
}

// compareNumbers is op "gt", "gte", "lt" or "lte" between attrVal and value;
// false unless both are numbers.
func compareNumbers(op string, attrVal, value any) bool {
	a, aok := toFloat64(attrVal)
	b, bok := toFloat64(value)
	if !aok || !bok {
		return false
	}
	switch op {
	case "gt":
		return a > b
	case "gte":
		return a >= b
	case "lt":
		return a < b
	default:
		return a <= b
	}
}

// compareAffix is op "prefix" or "suffix". The value must be a non-empty
// string, as "" is an affix of every string; a non-string attribute matches
// nothing.
func compareAffix(op string, attrVal, value any) (bool, error) {
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
}

// compareRegex is op "regex": a string attribute matches the non-empty
// pattern value. A bad pattern fails closed: it matches nothing.
func compareRegex(attrVal, value any) (bool, error) {
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
}
