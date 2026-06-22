// Package rebac is fine-grained, relationship-based authorization (ReBAC),
// a Zanzibar/OpenFGA-style subset: relationship tuples plus a recursive Check.
//
// A tuple asserts "subject is `relation` of object". A subject is either a
// direct user (user:<id>) or a userset (<type>:<id>#<relation>) — meaning
// everyone with that relation on that object. Check answers "does user U have
// `relation` on object?" by walking direct tuples and expanding usersets
// recursively, with a depth cap and a visited-set so cycles can't loop forever.
// It complements RBAC (coarse roles) and ABAC (policy attributes); per-tenant.
package rebac

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
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

// resolve answers "does user `userID` have `relation` on objType:objID?" by
// expanding direct + userset tuples. Pure given the fetcher, so it's unit-tested
// independently of the database.
func resolve(fetch fetcher, objType, objID, relation, userID string, visited map[string]bool, depth int) (bool, error) {
	if depth > maxDepth {
		return false, nil
	}
	key := objType + ":" + objID + "#" + relation
	if visited[key] {
		return false, nil
	}
	visited[key] = true

	tuples, err := fetch(objType, objID, relation)
	if err != nil {
		return false, err
	}
	for _, t := range tuples {
		if t.subjectRelation == "" {
			// Direct subject.
			if t.subjectType == "user" && t.subjectID == userID {
				return true, nil
			}
			continue
		}
		// Userset: the user qualifies if they hold subjectRelation on the
		// referenced object.
		ok, err := resolve(fetch, t.subjectType, t.subjectID, t.subjectRelation, userID, visited, depth+1)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

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
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO auth.relation_tuples
			(tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation)
		DO UPDATE SET tenant_id = EXCLUDED.tenant_id
		RETURNING id
	`, tenantID, o.Type, o.ID, relation, subj.Type, subj.ID, subj.Relation).Scan(&id)
	if err != nil {
		return nil, err
	}
	return &Tuple{ID: id, Object: object, Relation: relation, Subject: subjectString(subj.Type, subj.ID, subj.Relation)}, nil
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM auth.relation_tuples WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
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
	rows, err := s.pool.Query(ctx, `
		SELECT id, relation, subject_type, subject_id, subject_relation
		FROM auth.relation_tuples
		WHERE tenant_id = $1 AND object_type = $2 AND object_id = $3
		ORDER BY relation, subject_type, subject_id
	`, tenantID, o.Type, o.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Tuple, 0)
	for rows.Next() {
		var t Tuple
		var st, si, sr string
		if err := rows.Scan(&t.ID, &t.Relation, &st, &si, &sr); err != nil {
			return nil, err
		}
		t.Object = object
		t.Subject = subjectString(st, si, sr)
		out = append(out, t)
	}
	return out, rows.Err()
}

// Check answers whether userID has relation on object (type:id) for a tenant.
func (s *Service) Check(ctx context.Context, tenantID uuid.UUID, object, relation, userID string) (bool, error) {
	o, ok := parseObject(object)
	if !ok {
		return false, errs.ErrUnprocessable.WithDetail("object must be \"type:id\"")
	}
	fetch := func(objectType, objectID, rel string) ([]tuple, error) {
		rows, err := s.pool.Query(ctx, `
			SELECT subject_type, subject_id, subject_relation
			FROM auth.relation_tuples
			WHERE tenant_id = $1 AND object_type = $2 AND object_id = $3 AND relation = $4
		`, tenantID, objectType, objectID, rel)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var ts []tuple
		for rows.Next() {
			var t tuple
			if err := rows.Scan(&t.subjectType, &t.subjectID, &t.subjectRelation); err != nil {
				return nil, err
			}
			ts = append(ts, t)
		}
		return ts, rows.Err()
	}
	return resolve(fetch, o.Type, o.ID, relation, userID, map[string]bool{}, 0)
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
	object := r.URL.Query().Get("object")
	if object == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("object query param required"))
		return
	}
	out, err := h.Service.List(r.Context(), tenantID, object)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
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
	allowed, err := h.Service.Check(r.Context(), tenantID, in.Object, in.Relation, in.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"allowed": allowed})
}
