// Package group provides org/team hierarchy inside a tenant. Permissions
// granted at group level are out of scope for this iteration (RBAC stays
// user-level); the data model captures the shape ahead of need.
//
// Mutating methods take a pgx.Tx so handlers can wrap the mutation +
// audit row in a single transaction.
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

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
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

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

type CreateInput struct {
	TenantID    uuid.UUID  `json:"tenant_id"`
	ParentID    *uuid.UUID `json:"parent_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
}

func (s *Service) Create(ctx context.Context, tx pgx.Tx, in CreateInput) (*Group, error) {
	var g Group
	err := tx.QueryRow(ctx, `
		INSERT INTO tenant.groups (tenant_id, parent_id, name, description)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, parent_id, name, description, created_at
	`, in.TenantID, in.ParentID, in.Name, in.Description).
		Scan(&g.ID, &g.TenantID, &g.ParentID, &g.Name, &g.Description, &g.CreatedAt)
	if err != nil {
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

// Delete returns the (tenantID, name) of the deleted group so the caller
// has the data for the audit row without an extra read.
func (s *Service) Delete(ctx context.Context, tx pgx.Tx, id uuid.UUID) (uuid.UUID, string, error) {
	var tenantID uuid.UUID
	var name string
	err := tx.QueryRow(ctx, `
		DELETE FROM tenant.groups WHERE id = $1 RETURNING tenant_id, name
	`, id).Scan(&tenantID, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", errs.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	return tenantID, name, nil
}

func (s *Service) AddMember(ctx context.Context, tx pgx.Tx, groupID, userID, tenantID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO tenant.group_members (group_id, user_id, tenant_id)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING
	`, groupID, userID, tenantID)
	return err
}

func (s *Service) RemoveMember(ctx context.Context, tx pgx.Tx, groupID, userID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM tenant.group_members WHERE group_id = $1 AND user_id = $2
	`, groupID, userID)
	return err
}

// Member is a group_members row enriched with the user's email +
// display_name so the admin UI can render meaningful rows without a
// per-member follow-up call.
type Member struct {
	UserID      uuid.UUID `json:"user_id"`
	Email       string    `json:"email"`
	DisplayName *string   `json:"display_name"`
}

func (s *Service) ListMembers(ctx context.Context, groupID uuid.UUID) ([]Member, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT gm.user_id, u.email, u.display_name
		FROM tenant.group_members gm
		JOIN "user".users u ON u.id = gm.user_id
		WHERE gm.group_id = $1 AND u.deleted_at IS NULL
		ORDER BY u.email
	`, groupID)
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

func auditActor(r *http.Request) (*uuid.UUID, string) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		return nil, "system"
	}
	at := p.ActorType
	if at == "" {
		at = "user"
	}
	return p.UserID, at
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	g, err := h.Service.Create(ctx, tx, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	tid := g.TenantID
	rid := g.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "group.created",
		ResourceType: "group",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"name": g.Name, "parent_id": g.ParentID},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
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
	out, err := h.Service.List(r.Context(), tid)
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
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	tenantID, name, err := h.Service.Delete(ctx, tx, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	rid := id
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "group.deleted",
		ResourceType: "group",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"name": name},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
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
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("tenant scope required"))
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.AddMember(ctx, tx, id, uid, *p.TenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	tid := *p.TenantID
	rid := id
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "group.member_added",
		ResourceType: "group",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"user_id": uid},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
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
	p := httpx.PrincipalFromCtx(r.Context())
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.RemoveMember(ctx, tx, id, uid); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	var tid *uuid.UUID
	if p != nil {
		tid = p.TenantID
	}
	rid := id
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "group.member_removed",
		ResourceType: "group",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"user_id": uid},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
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
	out, err := h.Service.ListMembers(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}
