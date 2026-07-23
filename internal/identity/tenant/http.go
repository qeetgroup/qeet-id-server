package tenant

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// tokenIssuer is the slice of auth.Service this handler needs (mockable).
type tokenIssuer interface {
	IssuePair(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, method string) (*auth.TokenPair, error)
}

type Handler struct {
	Repo     *Repository
	Validate *validator.Validate
	// Mints a tenant-scoped token after create so the client switches in.
	AuthService tokenIssuer
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants", h.list)
	r.Post("/tenants", h.create)
	r.Get("/tenants/{id}", h.get)
	r.Patch("/tenants/{id}", h.update)
	r.Delete("/tenants/{id}", h.delete)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, next, err := h.Repo.List(r.Context(), *p.UserID, limit, r.URL.Query().Get("cursor"))
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
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	// The creator becomes the tenant's owner (role + membership) in one tx.
	t, err := h.Repo.CreateWithOwner(r.Context(), in, *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Audit + outbox in a follow-up tx so failure there doesn't roll back the create.
	go h.publishCreated(r, t)

	// Mint a pair scoped to the new tenant so the caller switches in; tenant still returned if it fails.
	resp := map[string]any{
		"tenant":    t,
		"tenant_id": t.ID,
		"roles":     []string{"owner"},
	}
	if h.AuthService != nil {
		if pair, err := h.AuthService.IssuePair(r.Context(), *p.UserID, t.ID, httpx.ClientIP(r), r.UserAgent(), "tenant_create"); err == nil {
			resp["access_token"] = pair.AccessToken
			resp["token_type"] = pair.TokenType
			resp["expires_at"] = pair.ExpiresAt
			resp["refresh_token"] = pair.RefreshToken
			resp["session_id"] = pair.SessionID
			resp["user_id"] = pair.UserID
		}
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

func (h *Handler) publishCreated(r *http.Request, t *Tenant) {
	// Detach from the request context: this runs in a goroutine after the
	// response is sent, so r.Context() is already cancelled.
	ctx := context.WithoutCancel(r.Context())
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		slog.Warn("tenant.created publish: begin", "err", err, "tenant_id", t.ID)
		return
	}
	defer tx.Rollback(ctx)
	p := httpx.PrincipalFromCtx(ctx)
	var actor *uuid.UUID
	if p != nil {
		actor = p.UserID
	}
	id := t.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &id,
		ActorUserID:  actor,
		Action:       "tenant.created",
		ResourceType: "tenant",
		ResourceID:   &id,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"slug": t.Slug, "name": t.Name},
	}); err != nil {
		slog.Warn("tenant.created publish: audit", "err", err, "tenant_id", t.ID)
		return
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: t.ID,
		Topic:       "tenant.events",
		EventType:   "tenant.created",
		Payload:     t,
	}); err != nil {
		slog.Warn("tenant.created publish: outbox", "err", err, "tenant_id", t.ID)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Warn("tenant.created publish: commit", "err", err, "tenant_id", t.ID)
	}
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
		httpx.WriteError(w, r, httpx.ValidationError(err))
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
