package tenant

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
	"github.com/qeetgroup/qeet-identity/internal/platform/outbox"
)

type Handler struct {
	Repo     *Repository
	Validate *validator.Validate
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants", h.list)
	r.Post("/tenants", h.create)
	r.Get("/tenants/{id}", h.get)
	r.Patch("/tenants/{id}", h.update)
	r.Delete("/tenants/{id}", h.delete)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, next, err := h.Repo.List(r.Context(), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items":       out,
		"next_cursor": next,
	})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail(err.Error()))
		return
	}
	t, err := h.Repo.Create(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Audit + outbox in a follow-up tx so failure here doesn't roll back
	// the user-visible create. Each module ships its own pattern; tenants
	// are infrequent so the simpler shape is fine.
	go h.publishCreated(r, t)
	httpx.WriteJSON(w, http.StatusCreated, t)
}

func (h *Handler) publishCreated(r *http.Request, t *Tenant) {
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	p := httpx.PrincipalFromCtx(ctx)
	var actor *uuid.UUID
	if p != nil {
		actor = p.UserID
	}
	id := t.ID
	_ = audit.Record(ctx, tx, audit.Event{
		TenantID:     &id,
		ActorUserID:  actor,
		Action:       "tenant.created",
		ResourceType: "tenant",
		ResourceID:   &id,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"slug": t.Slug, "name": t.Name},
	})
	_ = outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: t.ID,
		Topic:       "tenant.events",
		EventType:   "tenant.created",
		Payload:     t,
	})
	_ = tx.Commit(ctx)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	t, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail(err.Error()))
		return
	}
	t, err := h.Repo.Update(r.Context(), id, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Repo.SoftDelete(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
