// Package rebac is per-tenant relationship-based authorization (ReBAC), a
// Zanzibar-style subset. A tuple says a subject (user:<id>, or the userset
// <type>:<id>#<relation>) holds a relation on an object; Check walks tuples and
// expands usersets recursively, with a depth cap and a visited set for cycles.
package rebac

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
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

// Service manages the relationship tuples.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns the relationship service.
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

// Write upserts a relationship tuple, recorded as actor's. object = "type:id",
// subject = "user:<id>" or "type:id#relation".
func (s *Service) Write(ctx context.Context, tenantID uuid.UUID, object, relation, subject string, actor audit.Actor) (*Tuple, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrReBACObjectInvalid
	}
	subj, ok := parseSubject(subject)
	if !ok {
		return nil, errs.ErrReBACSubjectInvalid
	}
	if strings.TrimSpace(relation) == "" {
		return nil, errs.ErrReBACRelationRequired
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	id, err := s.q.WithTx(tx).InsertRelationTuple(ctx, dbgen.InsertRelationTupleParams{
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
	tuple := &Tuple{ID: id, Object: object, Relation: relation, Subject: subjectString(subj.Type, subj.ID, subj.Relation)}
	metadata := map[string]any{"object": tuple.Object, "relation": tuple.Relation, "subject": tuple.Subject}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "rebac.tuple_written", "relation_tuple", tuple.ID, metadata)); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: tuple.ID, Topic: "authorization.events", EventType: "rebac.tuple_written", Payload: map[string]any{"tuple_id": tuple.ID, "tenant_id": tenantID, "object": tuple.Object, "relation": tuple.Relation, "subject": tuple.Subject}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return tuple, nil
}

// Delete removes one of the tenant's relationship tuples, recorded as actor's.
func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteRelationTuple(ctx, dbgen.DeleteRelationTupleParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "rebac.tuple_deleted", "relation_tuple", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "authorization.events", EventType: "rebac.tuple_deleted", Payload: map[string]any{"tuple_id": id, "tenant_id": tenantID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// List returns the tuples on a given object (type:id).
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, object string) ([]Tuple, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrReBACObjectInvalid
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
		return false, errs.ErrReBACObjectInvalid
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
		return nil, errs.ErrReBACObjectInvalid
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

// maxExpandDepth caps how many userset hops Expand follows.
const maxExpandDepth = 10

// expand returns the nodes and edges reachable from objType:objID#relation,
// following at most limit userset hops. It walks breadth first, so each
// object#relation is expanded once, at its fewest hops, and cycles end.
func expand(fetch fetcher, objType, objID, relation string, limit int) (map[string]GraphNode, []GraphEdge, error) {
	type step struct {
		typ, id, relation string
		depth             int
	}
	nodes := map[string]GraphNode{}
	edges := make([]GraphEdge, 0)
	addNode := func(typ, id string) string {
		nid := graphNodeID(typ, id)
		if _, ok := nodes[nid]; !ok {
			nodes[nid] = GraphNode{ID: nid, Type: typ, Label: id}
		}
		return nid
	}
	queue := []step{{objType, objID, relation, 0}}
	queued := map[string]bool{objType + ":" + objID + "#" + relation: true}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		fromID := addNode(cur.typ, cur.id)
		tuples, err := fetch(cur.typ, cur.id, cur.relation)
		if err != nil {
			return nil, nil, err
		}
		for _, t := range tuples {
			toID := addNode(t.subjectType, t.subjectID)
			// A userset edge names both relations, so "viewer → member" reads
			// as "viewer via group#member".
			edgeRelation := cur.relation
			if t.subjectRelation != "" {
				edgeRelation = cur.relation + " → " + t.subjectRelation
			}
			edges = append(edges, GraphEdge{From: fromID, To: toID, Relation: edgeRelation})

			// "group:eng#member" also expands group:eng at its "member" relation.
			key := t.subjectType + ":" + t.subjectID + "#" + t.subjectRelation
			if t.subjectRelation != "" && cur.depth < limit && !queued[key] {
				queued[key] = true
				queue = append(queue, step{t.subjectType, t.subjectID, t.subjectRelation, cur.depth + 1})
			}
		}
	}
	return nodes, edges, nil
}

// Expand returns the graph of every subject reachable from object#relation
// ("who can reach this resource?"), following usersets up to depth hops
// (maxExpandDepth when depth is out of range). Each node appears once.
func (s *Service) Expand(ctx context.Context, tenantID uuid.UUID, object, relation string, depth int) (*Graph, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrReBACObjectInvalid
	}
	if strings.TrimSpace(relation) == "" {
		return nil, errs.ErrReBACRelationRequired
	}
	if depth <= 0 || depth > maxExpandDepth {
		depth = maxExpandDepth
	}
	nodes, edges, err := expand(s.tupleFetcher(ctx, tenantID), o.Type, o.ID, relation, depth)
	if err != nil {
		return nil, err
	}

	nodeList := make([]GraphNode, 0, len(nodes))
	for _, n := range nodes {
		nodeList = append(nodeList, n)
	}
	return &Graph{Nodes: nodeList, Edges: edges}, nil
}

// ListBySubject returns every tuple in which subject (type:id) appears, the
// reverse of List.
func (s *Service) ListBySubject(ctx context.Context, tenantID uuid.UUID, subject string) ([]Tuple, error) {
	subj, ok := parseSubject(subject)
	if !ok {
		return nil, errs.ErrReBACSubjectInvalid
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

// Handler serves the relationship-tuple routes. Decider answers the
// relationship check across every engine: an attribute (ABAC) deny refuses,
// and a role grant counts without a tuple.
type Handler struct {
	Service *Service
	Decider *decide.Decider
}

// Mount registers the relationship routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/relation-tuples", h.list)
	r.Post("/tenants/{tenantID}/relation-tuples", h.write)
	r.Delete("/tenants/{tenantID}/relation-tuples/{id}", h.del)
	r.Post("/tenants/{tenantID}/relation-tuples/check", h.check)
	r.Get("/tenants/{tenantID}/relation-tuples/graph", h.graph)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	object := q.Get("object")
	subject := q.Get("subject")
	switch {
	case object != "" && subject != "":
		httpx.WriteError(w, r, errs.ErrReBACObjectSubjectExclusive)
	case object != "":
		out, err := h.Service.List(r.Context(), tenantID, object)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, paging.List(out))
	case subject != "":
		out, err := h.Service.ListBySubject(r.Context(), tenantID, subject)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, paging.List(out))
	default:
		httpx.WriteError(w, r, errs.ErrReBACObjectOrSubjectRequired)
	}
}

func (h *Handler) write(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
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
	t, err := h.Service.Write(r.Context(), tenantID, in.Object, in.Relation, in.Subject, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, t)
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

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
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
		httpx.WriteError(w, r, errs.ErrReBACUserIDRelationRequired)
		return
	}
	if _, ok := parseObject(in.Object); !ok {
		httpx.WriteError(w, r, errs.ErrReBACObjectInvalid)
		return
	}
	dec, err := h.Decider.Relation(r.Context(), tenantID, in.UserID, in.Object, in.Relation)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	dec = h.Decider.ForViewer(r.Context(), httpx.PrincipalFromCtx(r.Context()), tenantID, dec)
	out := map[string]any{"allowed": dec.Allow, "decided_by": dec.DecidedBy()}
	if r.URL.Query().Get("explain") == "true" {
		exp, err := h.Service.CheckExplain(r.Context(), tenantID, in.Object, in.Relation, in.UserID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if len(exp.Path) > 0 {
			out["path"] = exp.Path
		}
		out["trace"] = dec.Trace
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// graph answers GET /v1/tenants/{tenantID}/relation-tuples/graph with Expand's
// graph for ?object=<type:id>&relation=<rel>[&depth=<n>]: who or what can reach
// the resource, and through which relationships.
func (h *Handler) graph(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	object := q.Get("object")
	relation := q.Get("relation")
	if object == "" || relation == "" {
		httpx.WriteError(w, r, errs.ErrReBACObjectRelationRequired)
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
