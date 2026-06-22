// Package group provides org/team hierarchy inside a tenant. Permissions
// granted at group level are out of scope for this iteration (RBAC stays
// user-level); the data model captures the shape ahead of need.
//
// Mutating service methods own their transaction and write the audit row in
// the same tx, so the audit trail commits atomically with the change and
// handlers stay thin.
package group

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
	"github.com/qeetgroup/qeet-id/platform/outbox"
)

type Group struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	ParentID    *uuid.UUID `json:"parent_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

type CreateInput struct {
	TenantID    uuid.UUID  `json:"tenant_id"`
	ParentID    *uuid.UUID `json:"parent_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
}

func (s *Service) Create(ctx context.Context, in CreateInput, actor audit.Actor) (*Group, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var g Group
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenant.groups (tenant_id, parent_id, name, description)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, parent_id, name, description, created_at
	`, in.TenantID, in.ParentID, in.Name, in.Description).
		Scan(&g.ID, &g.TenantID, &g.ParentID, &g.Name, &g.Description, &g.CreatedAt); err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(g.TenantID, "group.created", "group", g.ID,
		map[string]any{"name": g.Name, "parent_id": g.ParentID})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: g.ID, Topic: "group.events", EventType: "group.created", Payload: g}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Group, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, parent_id, name, description, created_at
		FROM tenant.groups WHERE tenant_id = $1 ORDER BY name
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.TenantID, &g.ParentID, &g.Name, &g.Description, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var name string
	err = tx.QueryRow(ctx, `
		DELETE FROM tenant.groups WHERE id = $1 AND tenant_id = $2 RETURNING name
	`, id, tenantID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "group.deleted", "group", id,
		map[string]any{"name": name})); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "group.events", EventType: "group.deleted", Payload: map[string]any{"id": id, "tenant_id": tenantID, "name": name}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) AddMember(ctx context.Context, groupID, userID, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Only add to a group that belongs to this tenant.
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant.groups WHERE id = $1 AND tenant_id = $2)`, groupID, tenantID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errs.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant.group_members (group_id, user_id, tenant_id)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING
	`, groupID, userID, tenantID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "group.member_added", "group", groupID,
		map[string]any{"user_id": userID})); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: groupID, Topic: "group.events", EventType: "group.member_added", Payload: map[string]any{"group_id": groupID, "user_id": userID, "tenant_id": tenantID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) RemoveMember(ctx context.Context, groupID, userID, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		DELETE FROM tenant.group_members WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3
	`, groupID, userID, tenantID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "group.member_removed", "group", groupID,
		map[string]any{"user_id": userID})); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: groupID, Topic: "group.events", EventType: "group.member_removed", Payload: map[string]any{"group_id": groupID, "user_id": userID, "tenant_id": tenantID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Member is a group_members row enriched with the user's email +
// display_name so the admin UI can render meaningful rows without a
// per-member follow-up call.
type Member struct {
	UserID      uuid.UUID `json:"user_id"`
	Email       string    `json:"email"`
	DisplayName *string   `json:"display_name"`
}

func (s *Service) ListMembers(ctx context.Context, groupID, tenantID uuid.UUID) ([]Member, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT gm.user_id, u.email, u.display_name
		FROM tenant.group_members gm
		JOIN "user".users u ON u.id = gm.user_id
		WHERE gm.group_id = $1 AND gm.tenant_id = $2 AND u.deleted_at IS NULL
		ORDER BY u.email
	`, groupID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/groups", h.create)
	r.Get("/tenants/{tenantID}/groups", h.list)
	r.Delete("/groups/{id}", h.delete)
	r.Post("/groups/{id}/members/{userID}", h.addMember)
	r.Delete("/groups/{id}/members/{userID}", h.removeMember)
	r.Get("/groups/{id}/members", h.listMembers)
}

// actorOf captures the request's audit provenance from the principal + headers.
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

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tenantID // scope from principal, never the body
	g, err := h.Service.Create(r.Context(), in, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, g)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if tid != tenantID {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("tenant mismatch"))
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Delete(r.Context(), id, tenantID, actorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) addMember(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	uid, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid userID"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.AddMember(r.Context(), id, uid, tenantID, actorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) removeMember(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	uid, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid userID"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RemoveMember(r.Context(), id, uid, tenantID, actorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListMembers(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}
