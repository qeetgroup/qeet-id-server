package rebac

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// maxDepth bounds userset expansion (defense-in-depth alongside the visited set).
const maxDepth = 25

// maxExpansions bounds the distinct object#relation pairs one check expands,
// one read each, so a wide relationship set can't make a check run unbounded
// queries.
const maxExpansions = 1000

// maxRequestExpansions bounds the reads of every check made with a context
// from WithRequestBudget together, as an AuthZEN batch makes up to 100.
const maxRequestExpansions = 5000

type requestBudgetKey struct{}

// WithRequestBudget returns ctx carrying one budget of maxRequestExpansions
// reads that every check made with it draws on, so a request making many
// checks is bounded as one check is.
func WithRequestBudget(ctx context.Context) context.Context {
	left := new(atomic.Int64)
	left.Store(maxRequestExpansions)
	return context.WithValue(ctx, requestBudgetKey{}, left)
}

// objectRef is a parsed "type:id".
type objectRef struct{ Type, ID string }

// subjectRef is a parsed subject: a direct user (Relation == "") or a userset.
type subjectRef struct{ Type, ID, Relation string }

// parseObject parses "document:readme" into {document, readme}. The id may
// itself contain ':' (only the first ':' splits type from id).
func parseObject(s string) (objectRef, bool) {
	s = strings.TrimSpace(s)
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return objectRef{}, false
	}
	return objectRef{Type: s[:i], ID: s[i+1:]}, true
}

// parseSubject parses "user:<id>" (direct) or "group:eng#member" (userset).
func parseSubject(s string) (subjectRef, bool) {
	s = strings.TrimSpace(s)
	rel := ""
	if h := strings.LastIndexByte(s, '#'); h >= 0 {
		rel = s[h+1:]
		s = s[:h]
		if rel == "" {
			return subjectRef{}, false
		}
	}
	o, ok := parseObject(s)
	if !ok {
		return subjectRef{}, false
	}
	return subjectRef{Type: o.Type, ID: o.ID, Relation: rel}, true
}

// tuple is the subject side of a relationship, as fetched for an (object,relation).
type tuple struct {
	subjectType, subjectID, subjectRelation string
}

// fetcher returns the subjects directly granted `relation` on object type/id.
type fetcher func(objectType, objectID, relation string) ([]tuple, error)

// ExplainStep is one hop in a ReBAC grant path: the tuple that was walked to
// move the resolution one step closer to the user, in root-to-leaf order.
type ExplainStep struct {
	Object   string `json:"object"`
	Relation string `json:"relation"`
	Subject  string `json:"subject"`
	Depth    int    `json:"depth"`
}

// Explanation is the structured "why?" for a single Check: the same boolean
// Check returns, plus the chain of relation tuples that produced it (empty on
// denial). Mirrors RBAC's Explanation shape (see rbac.Explanation).
type Explanation struct {
	Allowed bool          `json:"allowed"`
	Path    []ExplainStep `json:"path,omitempty"`
}

// resolve answers whether userID has relation on objType:objID by expanding direct and userset
// tuples, returning the root-to-leaf chain that granted it. visited keeps the shallowest depth of each
// object#relation, so cycles stop and a shorter path is still walked; past maxExpansions it stops
// with ErrReBACCheckTooComplex. Pure given the fetcher.
func resolve(fetch fetcher, objType, objID, relation, userID string, visited map[string]int, depth int) (bool, []ExplainStep, error) {
	if depth > maxDepth {
		return false, nil, nil
	}
	key := objType + ":" + objID + "#" + relation
	at, seen := visited[key]
	if seen && at <= depth {
		return false, nil, nil
	}
	if !seen && len(visited) >= maxExpansions {
		return false, nil, ErrCheckTooComplex
	}
	visited[key] = depth

	tuples, err := fetch(objType, objID, relation)
	if err != nil {
		return false, nil, err
	}
	for _, t := range tuples {
		if t.subjectRelation == "" {
			// Direct subject.
			if t.subjectType == "user" && t.subjectID == userID {
				step := ExplainStep{
					Object:   objType + ":" + objID,
					Relation: relation,
					Subject:  subjectString(t.subjectType, t.subjectID, ""),
					Depth:    depth,
				}
				return true, []ExplainStep{step}, nil
			}
			continue
		}
		// Userset: the user qualifies if they hold subjectRelation on the
		// referenced object.
		ok, path, err := resolve(fetch, t.subjectType, t.subjectID, t.subjectRelation, userID, visited, depth+1)
		if err != nil {
			return false, nil, err
		}
		if ok {
			step := ExplainStep{
				Object:   objType + ":" + objID,
				Relation: relation,
				Subject:  subjectString(t.subjectType, t.subjectID, t.subjectRelation),
				Depth:    depth,
			}
			return true, append([]ExplainStep{step}, path...), nil
		}
	}
	return false, nil, nil
}

// tupleFetcher returns a fetcher scoped to one organization, backed by the database
// and reading each object#relation once, however often a walk meets it. Each
// read draws on ctx's request budget (WithRequestBudget), if it carries one.
// FetchSubjects is the hot-path query for Check/Explain/Expand.
func (s *Service) tupleFetcher(ctx context.Context, organizationID uuid.UUID) fetcher {
	read := map[string][]tuple{}
	left, _ := ctx.Value(requestBudgetKey{}).(*atomic.Int64)
	return func(objectType, objectID, rel string) ([]tuple, error) {
		key := objectType + ":" + objectID + "#" + rel
		if ts, ok := read[key]; ok {
			return ts, nil
		}
		if left != nil && left.Add(-1) < 0 {
			return nil, ErrCheckTooComplex
		}
		rows, err := s.q.FetchSubjects(ctx, dbgen.FetchSubjectsParams{
			OrganizationID: organizationID,
			ObjectType:     objectType,
			ObjectID:       objectID,
			Relation:       rel,
		})
		if err != nil {
			return nil, err
		}
		ts := make([]tuple, len(rows))
		for i, r := range rows {
			ts[i] = tuple{subjectType: r.SubjectType, subjectID: r.SubjectID, subjectRelation: r.SubjectRelation}
		}
		read[key] = ts
		return ts, nil
	}
}

// Check answers whether userID has relation on object (type:id) for an organization.
func (s *Service) Check(ctx context.Context, organizationID uuid.UUID, object, relation, userID string) (bool, error) {
	o, ok := parseObject(object)
	if !ok {
		return false, errs.ErrReBACObjectInvalid
	}
	allowed, _, err := resolve(s.tupleFetcher(ctx, organizationID), o.Type, o.ID, relation, userID, map[string]int{}, 0)
	return allowed, err
}

// CheckExplain resolves the same decision as Check but also returns the
// root-to-leaf chain of relation tuples that granted it (empty on denial) —
// the ReBAC counterpart to rbac.Repository.Explain.
func (s *Service) CheckExplain(ctx context.Context, organizationID uuid.UUID, object, relation, userID string) (*Explanation, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrReBACObjectInvalid
	}
	allowed, path, err := resolve(s.tupleFetcher(ctx, organizationID), o.Type, o.ID, relation, userID, map[string]int{}, 0)
	if err != nil {
		return nil, err
	}
	return &Explanation{Allowed: allowed, Path: path}, nil
}
