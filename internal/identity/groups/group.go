// Package group provides org/team hierarchy inside a tenant. Group-level
// permission grants are out of scope for now (RBAC stays user-level); the model
// just captures the shape ahead of need. Mutating methods own their transaction
// and write the audit row in the same tx, so the trail commits atomically.
package group

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/groups/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	q    *dbgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

type CreateInput struct {
	TenantID    uuid.UUID  `json:"tenant_id"`
	ParentID    *uuid.UUID `json:"parent_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
}

type UpdateInput struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ParentID    *uuid.UUID `json:"parent_id"`
}

// uuidPtrToPgtype converts a *uuid.UUID to the pgtype.UUID used by generated code.
func uuidPtrToPgtype(p *uuid.UUID) pgtype.UUID {
	if p == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: [16]byte(*p), Valid: true}
}

// pgtypeToUUIDPtr converts a pgtype.UUID returned by generated code to *uuid.UUID.
func pgtypeToUUIDPtr(p pgtype.UUID) *uuid.UUID {
	if !p.Valid {
		return nil
	}
	uid := uuid.UUID(p.Bytes)
	return &uid
}

func groupFromInsertRow(row dbgen.InsertGroupRow) Group {
	return Group{
		ID:          row.ID,
		TenantID:    row.TenantID,
		ParentID:    pgtypeToUUIDPtr(row.ParentID),
		Name:        row.Name,
		Description: row.Description,
		CreatedAt:   row.CreatedAt,
	}
}

func groupFromUpdateRow(row dbgen.UpdateGroupRow) Group {
	return Group{
		ID:          row.ID,
		TenantID:    row.TenantID,
		ParentID:    pgtypeToUUIDPtr(row.ParentID),
		Name:        row.Name,
		Description: row.Description,
		CreatedAt:   row.CreatedAt,
	}
}

func groupFromListRow(row dbgen.ListGroupsRow) Group {
	return Group{
		ID:          row.ID,
		TenantID:    row.TenantID,
		ParentID:    pgtypeToUUIDPtr(row.ParentID),
		Name:        row.Name,
		Description: row.Description,
		CreatedAt:   row.CreatedAt,
	}
}

func (s *Service) Create(ctx context.Context, in CreateInput, actor audit.Actor) (*Group, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row, err := s.q.WithTx(tx).InsertGroup(ctx, dbgen.InsertGroupParams{
		TenantID:    in.TenantID,
		ParentID:    uuidPtrToPgtype(in.ParentID),
		Name:        in.Name,
		Description: in.Description,
	})
	if err != nil {
		return nil, err
	}
	g := groupFromInsertRow(row)
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
	rows, err := s.q.ListGroups(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Group, 0, len(rows))
	for _, row := range rows {
		out = append(out, groupFromListRow(row))
	}
	return out, nil
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	name, err := s.q.WithTx(tx).DeleteGroup(ctx, dbgen.DeleteGroupParams{ID: id, TenantID: tenantID})
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

func (s *Service) Update(ctx context.Context, id, tenantID uuid.UUID, in UpdateInput, actor audit.Actor) (*Group, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row, err := s.q.WithTx(tx).UpdateGroup(ctx, dbgen.UpdateGroupParams{
		Name:        in.Name,
		Description: in.Description,
		ParentID:    uuidPtrToPgtype(in.ParentID),
		ID:          id,
		TenantID:    tenantID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g := groupFromUpdateRow(row)
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "group.updated", "group", id,
		map[string]any{"name": in.Name, "parent_id": in.ParentID})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "group.events", EventType: "group.updated", Payload: g}); err != nil {
		return nil, err
	}
	return &g, tx.Commit(ctx)
}

func (s *Service) AddMember(ctx context.Context, groupID, userID, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Only add to a group that belongs to this tenant.
	exists, err := s.q.WithTx(tx).GroupExists(ctx, dbgen.GroupExistsParams{ID: groupID, TenantID: tenantID})
	if err != nil {
		return err
	}
	if !exists {
		return errs.ErrNotFound
	}
	if err := s.q.WithTx(tx).InsertGroupMember(ctx, dbgen.InsertGroupMemberParams{
		GroupID: groupID, UserID: userID, TenantID: tenantID,
	}); err != nil {
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

	if err := s.q.WithTx(tx).DeleteGroupMember(ctx, dbgen.DeleteGroupMemberParams{
		GroupID: groupID, UserID: userID, TenantID: tenantID,
	}); err != nil {
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
	rows, err := s.q.ListGroupMembers(ctx, dbgen.ListGroupMembersParams{GroupID: groupID, TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(rows))
	for _, row := range rows {
		out = append(out, Member{
			UserID:      row.UserID,
			Email:       row.Email,
			DisplayName: row.DisplayName,
		})
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
	r.Patch("/groups/{id}", h.update)
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

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
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
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	g, err := h.Service.Update(r.Context(), id, tenantID, in, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
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
