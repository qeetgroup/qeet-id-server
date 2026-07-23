// Package rebac is fine-grained, relationship-based authorization (ReBAC),
// a Zanzibar/OpenFGA-style subset: relationship tuples plus a recursive Check.
//
// A tuple asserts "subject is `relation` of object". A subject is either a
// direct user (user:<id>) or a userset (<type>:<id>#<relation>) — meaning
// everyone with that relation on that object. Check answers "does user U have
// `relation` on object?" by walking direct tuples and expanding usersets
// recursively, with a depth cap and a visited-set so cycles can't loop forever.
// It complements RBAC (coarse roles) and ABAC (policy attributes); per-tenant.
//
// Expand (and the /relation-tuples/graph endpoint) reuse the same traversal to
// return the full reachable graph — "who/what can reach this resource?".
package rebac

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// maxDepth bounds userset expansion (defense-in-depth alongside the visited set).
const maxDepth = 25

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

// resolve answers "does user `userID` have `relation` on objType:objID?" by
// expanding direct + userset tuples, and — when found — the root-to-leaf chain
// of tuples that granted it. Pure given the fetcher, so it's unit-tested
// independently of the database.
func resolve(fetch fetcher, objType, objID, relation, userID string, visited map[string]bool, depth int) (bool, []ExplainStep, error) {
	if depth > maxDepth {
		return false, nil, nil
	}
	key := objType + ":" + objID + "#" + relation
	if visited[key] {
		return false, nil, nil
	}
	visited[key] = true

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

type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool, q: dbgen.New(pool)} }

// Tuple is the API/read projection of a stored relationship.
type Tuple struct {
	ID       uuid.UUID `json:"id"`
	Object   string    `json:"object"`
	Relation string    `json:"relation"`
	Subject  string    `json:"subject"`
}

func subjectString(typ, id, rel string) string {
	if rel == "" {
		return typ + ":" + id
	}
	return typ + ":" + id + "#" + rel
}

// Write upserts a relationship tuple. object = "type:id", subject =
// "user:<id>" or "type:id#relation".
func (s *Service) Write(ctx context.Context, tenantID uuid.UUID, object, relation, subject string) (*Tuple, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrUnprocessable.WithDetail("object must be \"type:id\"")
	}
	subj, ok := parseSubject(subject)
	if !ok {
		return nil, errs.ErrUnprocessable.WithDetail("subject must be \"user:id\" or \"type:id#relation\"")
	}
	if strings.TrimSpace(relation) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("relation is required")
	}
	id, err := s.q.InsertRelationTuple(ctx, dbgen.InsertRelationTupleParams{
		TenantID:        tenantID,
		ObjectType:      o.Type,
		ObjectID:        o.ID,
		Relation:        relation,
		SubjectType:     subj.Type,
		SubjectID:       subj.ID,
		SubjectRelation: subj.Relation,
	})
	if err != nil {
		return nil, err
	}
	return &Tuple{ID: id, Object: object, Relation: relation, Subject: subjectString(subj.Type, subj.ID, subj.Relation)}, nil
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	n, err := s.q.DeleteRelationTuple(ctx, dbgen.DeleteRelationTupleParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// List returns the tuples on a given object (type:id).
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, object string) ([]Tuple, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrUnprocessable.WithDetail("object must be \"type:id\"")
	}
	rows, err := s.q.ListRelationTuplesByObject(ctx, dbgen.ListRelationTuplesByObjectParams{
		TenantID:   tenantID,
		ObjectType: o.Type,
		ObjectID:   o.ID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Tuple, 0, len(rows))
	for _, row := range rows {
		out = append(out, Tuple{
			ID:       row.ID,
			Object:   object,
			Relation: row.Relation,
			Subject:  subjectString(row.SubjectType, row.SubjectID, row.SubjectRelation),
		})
	}
	return out, nil
}

// tupleFetcher returns a fetcher scoped to one tenant, backed by the database.
// FetchSubjects is the hot-path query for Check/Explain/Expand.
func (s *Service) tupleFetcher(ctx context.Context, tenantID uuid.UUID) fetcher {
	return func(objectType, objectID, rel string) ([]tuple, error) {
		rows, err := s.q.FetchSubjects(ctx, dbgen.FetchSubjectsParams{
			TenantID:   tenantID,
			ObjectType: objectType,
			ObjectID:   objectID,
			Relation:   rel,
		})
		if err != nil {
			return nil, err
		}
		ts := make([]tuple, len(rows))
		for i, r := range rows {
			ts[i] = tuple{subjectType: r.SubjectType, subjectID: r.SubjectID, subjectRelation: r.SubjectRelation}
		}
		return ts, nil
	}
}

// Check answers whether userID has relation on object (type:id) for a tenant.
func (s *Service) Check(ctx context.Context, tenantID uuid.UUID, object, relation, userID string) (bool, error) {
	o, ok := parseObject(object)
	if !ok {
		return false, errs.ErrUnprocessable.WithDetail("object must be \"type:id\"")
	}
	allowed, _, err := resolve(s.tupleFetcher(ctx, tenantID), o.Type, o.ID, relation, userID, map[string]bool{}, 0)
	return allowed, err
}

// CheckExplain resolves the same decision as Check but also returns the
// root-to-leaf chain of relation tuples that granted it (empty on denial) —
// the ReBAC counterpart to rbac.Repository.Explain.
func (s *Service) CheckExplain(ctx context.Context, tenantID uuid.UUID, object, relation, userID string) (*Explanation, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrUnprocessable.WithDetail("object must be \"type:id\"")
	}
	allowed, path, err := resolve(s.tupleFetcher(ctx, tenantID), o.Type, o.ID, relation, userID, map[string]bool{}, 0)
	if err != nil {
		return nil, err
	}
	return &Explanation{Allowed: allowed, Path: path}, nil
}

// --- graph types ---

// GraphNode is a vertex in a relationship graph (a "type:id" identity).
type GraphNode struct {
	ID    string `json:"id"`    // e.g. "document:readme"
	Type  string `json:"type"`  // e.g. "document"
	Label string `json:"label"` // e.g. "readme"
}

// GraphEdge is a directed relationship between two nodes.
type GraphEdge struct {
	From     string `json:"from"`     // "type:id"
	To       string `json:"to"`       // "type:id"
	Relation string `json:"relation"` // the named relation
}

// Graph is the result of an Expand call: all nodes and directed edges reachable
// from a root object+relation up to some depth. Suitable for graph rendering.
type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// graphNodeID formats a GraphNode ID from type+id parts.
func graphNodeID(typ, id string) string { return typ + ":" + id }

// expand is the pure recursive helper for Expand — builds nodes+edges by BFS
// through the fetcher, capped at maxExpandDepth hops. visited tracks "node+relation"
// pairs already enqueued to prevent cycle-induced infinite loops.
const maxExpandDepth = 10

func expand(fetch fetcher, objType, objID, relation string, depth int, visited map[string]bool, nodes map[string]GraphNode, edges *[]GraphEdge) error {
	if depth > maxExpandDepth {
		return nil
	}
	key := objType + ":" + objID + "#" + relation
	if visited[key] {
		return nil
	}
	visited[key] = true

	fromID := graphNodeID(objType, objID)
	if _, ok := nodes[fromID]; !ok {
		nodes[fromID] = GraphNode{ID: fromID, Type: objType, Label: objID}
	}

	tuples, err := fetch(objType, objID, relation)
	if err != nil {
		return err
	}
	for _, t := range tuples {
		toID := graphNodeID(t.subjectType, t.subjectID)
		if _, ok := nodes[toID]; !ok {
			nodes[toID] = GraphNode{ID: toID, Type: t.subjectType, Label: t.subjectID}
		}
		// Edge label: the named relation (augmented with the userset relation if
		// this is a userset reference, so "viewer via group#member" reads clearly).
		edgeRelation := relation
		if t.subjectRelation != "" {
			edgeRelation = relation + " → " + t.subjectRelation
		}
		*edges = append(*edges, GraphEdge{From: fromID, To: toID, Relation: edgeRelation})

		// Recurse into usersets: "group:eng#member" means we also expand
		// group:eng at its own "member" relation.
		if t.subjectRelation != "" {
			if err := expand(fetch, t.subjectType, t.subjectID, t.subjectRelation, depth+1, visited, nodes, edges); err != nil {
				return err
			}
		}
	}
	return nil
}

// Expand builds a graph of all subject nodes reachable from object+relation.
// depth is capped at maxExpandDepth. The result's Nodes and Edges are
// deduplicated. This is the "who/what can reach this resource?" query, answering
// it as a graph rather than as a single boolean.
func (s *Service) Expand(ctx context.Context, tenantID uuid.UUID, object, relation string, depth int) (*Graph, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrUnprocessable.WithDetail("object must be \"type:id\"")
	}
	if strings.TrimSpace(relation) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("relation is required")
	}
	if depth <= 0 || depth > maxExpandDepth {
		depth = maxExpandDepth
	}
	nodes := map[string]GraphNode{}
	edges := make([]GraphEdge, 0)
	visited := map[string]bool{}
	if err := expand(s.tupleFetcher(ctx, tenantID), o.Type, o.ID, relation, 0, visited, nodes, &edges); err != nil {
		return nil, err
	}

	nodeList := make([]GraphNode, 0, len(nodes))
	for _, n := range nodes {
		nodeList = append(nodeList, n)
	}
	return &Graph{Nodes: nodeList, Edges: edges}, nil
}

// ListBySubject returns all tuples in which a given subject (type:id) appears —
// the reverse-lookup counterpart of List (which anchors on the object side).
// Uses the idx_relation_tuple_subject index added in migration 0078.
func (s *Service) ListBySubject(ctx context.Context, tenantID uuid.UUID, subject string) ([]Tuple, error) {
	subj, ok := parseSubject(subject)
	if !ok {
		return nil, errs.ErrUnprocessable.WithDetail("subject must be \"type:id\" or \"type:id#relation\"")
	}
	rows, err := s.q.ListRelationTuplesBySubject(ctx, dbgen.ListRelationTuplesBySubjectParams{
		TenantID:    tenantID,
		SubjectType: subj.Type,
		SubjectID:   subj.ID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Tuple, 0, len(rows))
	for _, row := range rows {
		out = append(out, Tuple{
			ID:       row.ID,
			Object:   graphNodeID(row.ObjectType, row.ObjectID),
			Relation: row.Relation,
			Subject:  subjectString(subj.Type, subj.ID, row.SubjectRelation),
		})
	}
	return out, nil
}

// --- handlers ---

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/relation-tuples", h.list)
	r.Post("/tenants/{tenantID}/relation-tuples", h.write)
	r.Delete("/tenants/{tenantID}/relation-tuples/{id}", h.del)
	r.Post("/tenants/{tenantID}/relation-tuples/check", h.check)
	r.Get("/tenants/{tenantID}/relation-tuples/graph", h.graph)
}

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

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	object := q.Get("object")
	subject := q.Get("subject")
	switch {
	case object != "" && subject != "":
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("supply either object or subject, not both"))
	case object != "":
		out, err := h.Service.List(r.Context(), tenantID, object)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	case subject != "":
		out, err := h.Service.ListBySubject(r.Context(), tenantID, subject)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	default:
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("object or subject query param required"))
	}
}

func (h *Handler) write(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Object   string `json:"object"`
		Relation string `json:"relation"`
		Subject  string `json:"subject"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	t, err := h.Service.Write(r.Context(), tenantID, in.Object, in.Relation, in.Subject)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, t)
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
	if err := h.Service.Delete(r.Context(), id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Object   string `json:"object"`
		Relation string `json:"relation"`
		UserID   string `json:"user_id"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.UserID == "" || in.Relation == "" {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("user_id and relation are required"))
		return
	}
	if r.URL.Query().Get("explain") == "true" {
		exp, err := h.Service.CheckExplain(r.Context(), tenantID, in.Object, in.Relation, in.UserID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, exp)
		return
	}
	allowed, err := h.Service.Check(r.Context(), tenantID, in.Object, in.Relation, in.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"allowed": allowed})
}

// graph expands a subgraph rooted at an object+relation, returning nodes+edges.
//
// GET /v1/tenants/{tenantID}/relation-tuples/graph?object=<type:id>&relation=<rel>[&depth=<n>]
//
// Answers "who/what can reach this resource, through which chain of
// relationships?" — the ReBAC equivalent of a privilege-path graph.
func (h *Handler) graph(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	object := q.Get("object")
	relation := q.Get("relation")
	if object == "" || relation == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("object and relation query params required"))
		return
	}
	depth := maxExpandDepth
	if d := q.Get("depth"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 {
			depth = n
		}
	}
	g, err := h.Service.Expand(r.Context(), tenantID, object, relation, depth)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}
