package abac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// relationsKey is where a bag holds the relationships its policies ask about,
// resolved before evaluation (Service.resolveRelations); no attribute path
// reaches it.
const relationsKey = "#relations"

// relationLeaf is {"relation": "<relation>", "object": "<type>:<id>"}, or with
// object an attribute reference {"attr": "<namespace>.<path>"} naming it.
type relationLeaf struct {
	Relation string          `json:"relation"`
	Object   json.RawMessage `json:"object"`
}

// parseRelation returns a relation leaf's relation and its object, or the
// attribute it references for one.
func parseRelation(raw json.RawMessage) (relation, object, ref string, err error) {
	var leaf relationLeaf
	if err := json.Unmarshal(raw, &leaf); err != nil || strings.TrimSpace(leaf.Relation) == "" || len(leaf.Object) == 0 {
		return "", "", "", errors.New(`condition 'relation' must be {"relation": "<relation>", "object": "<type>:<id>"}`)
	}
	if json.Unmarshal(leaf.Object, &object) == nil {
		if t, id, ok := strings.Cut(object, ":"); !ok || t == "" || id == "" {
			return "", "", "", fmt.Errorf("condition 'relation' object %q must be <type>:<id>", object)
		}
		return leaf.Relation, object, "", nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(leaf.Object, &obj) != nil || len(obj) != 1 || json.Unmarshal(obj["attr"], &ref) != nil {
		return "", "", "", errors.New(`condition 'relation' object must be "<type>:<id>" or an attribute reference {"attr": "<namespace>.<path>"}`)
	}
	ns, path, _ := strings.Cut(ref, ".")
	if !refNamespaces[ns] || path == "" || slices.Contains(strings.Split(path, "."), "") {
		return "", "", "", fmt.Errorf("condition 'relation' object references %q, which is not a subject., resource., action. or context. attribute", ref)
	}
	return leaf.Relation, "", ref, nil
}

// relationObject is the object a relation leaf asks about in bag, "" when it
// references an attribute bag lacks.
func relationObject(object, ref string, bag AttributeBag) string {
	if ref == "" {
		return object
	}
	v, _ := resolvePath(ref, bag)
	o, _ := v.(string)
	return o
}

// evalRelation evaluates a relation leaf: whether the subject has the relation
// on the object, as resolved into bag. Unknown when it couldn't be resolved: no
// subject id, no object, or no relationship engine.
func evalRelation(raw json.RawMessage, bag AttributeBag) (truth, error) {
	relation, object, ref, err := parseRelation(raw)
	if err != nil {
		return isFalse, fmt.Errorf("abac: %w", err)
	}
	object = relationObject(object, ref, bag)
	held, ok := bag[relationsKey][object+"#"+relation].(bool)
	if object == "" || !ok {
		return isUnknown, nil
	}
	return truthOf(held), nil
}

// relationLeaves calls found for each relation leaf in a condition tree.
func relationLeaves(raw json.RawMessage, found func(relation, object, ref string)) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	for _, key := range []string{"all", "any"} {
		var children []json.RawMessage
		if json.Unmarshal(m[key], &children) == nil {
			for _, c := range children {
				relationLeaves(c, found)
			}
		}
	}
	if m["not"] != nil {
		relationLeaves(m["not"], found)
	}
	if m["relation"] != nil {
		if relation, object, ref, err := parseRelation(m["relation"]); err == nil {
			found(relation, object, ref)
		}
	}
}

// RelationCheck answers whether userID has relation on object (type:id) in
// organizationID. Satisfied by rebac.Service.Check.
type RelationCheck func(ctx context.Context, organizationID uuid.UUID, object, relation, userID string) (bool, error)

// SetRelationCheck sets how relation conditions are answered; without one
// they are unknown, so a deny holding one applies and an allow grants nothing.
func (s *Service) SetRelationCheck(c RelationCheck) { s.relations = c }

// resolveRelations answers, into bag, each relationship the conditions ask
// about for the bag's subject, so evaluation needs no lookups of its own.
func (s *Service) resolveRelations(ctx context.Context, organizationID uuid.UUID, conditions [][]byte, bag AttributeBag) error {
	subject, _ := bag["subject"]["id"].(string)
	if s.relations == nil || subject == "" {
		return nil
	}
	answers := map[string]any{}
	var failed error
	for _, cond := range conditions {
		relationLeaves(cond, func(relation, object, ref string) {
			object = relationObject(object, ref, bag)
			key := object + "#" + relation
			if _, done := answers[key]; done || object == "" || failed != nil {
				return
			}
			held, err := s.relations(ctx, organizationID, object, relation, subject)
			switch {
			case errors.Is(err, errs.ErrReBACObjectInvalid):
				// An object that isn't type:id holds no relationship: left unknown.
			case err != nil:
				failed = err
			default:
				answers[key] = held
			}
		})
	}
	bag[relationsKey] = answers
	return failed
}
