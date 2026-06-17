package user

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id/internal/audit"
	"github.com/qeetgroup/qeet-id/internal/platform/errs"
	"github.com/qeetgroup/qeet-id/internal/platform/httpx"
	"github.com/qeetgroup/qeet-id/internal/platform/outbox"
	"github.com/qeetgroup/qeet-id/internal/platform/password"
)

// mfaResetter clears a user's MFA factors (admin account-recovery). Kept as an
// interface so the user package needn't import the mfa package.
type mfaResetter interface {
	ResetForUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error
}

type Handler struct {
	Repo     *Repository
	Validate *validator.Validate
	// PasswordPolicy enforces the tenant's password complexity rules on a
	// password change. Optional; nil skips the check (e.g. tests). Kept as a
	// function so the user package needn't depend on the authpolicy package.
	PasswordPolicy func(ctx context.Context, tenantID uuid.UUID, password string) error
	// MFA resets a user's second factors (admin recovery). Optional.
	MFA mfaResetter
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/users", h.list)
	r.Get("/users/deleted", h.listDeleted)
	r.Post("/users", h.create)
	r.Get("/users/{id}", h.get)
	r.Patch("/users/{id}", h.update)
	r.Delete("/users/{id}", h.delete)
	r.Post("/users/{id}/password", h.setPassword)
	r.Delete("/users/{id}/mfa", h.resetMFA)
	r.Post("/users/{id}/restore", h.restore)
	r.Delete("/users/{id}/purge", h.purge)
}

// resetMFA clears a user's MFA factors so a locked-out user can re-enroll.
// Admin-only (gated on user.write by the RBAC enforcer); audited.
func (h *Handler) resetMFA(w http.ResponseWriter, r *http.Request) {
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
	if h.MFA == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.MFA.ResetForUser(ctx, tx, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var actorID *uuid.UUID
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenantID,
		ActorUserID:  actorID,
		Action:       "mfa.admin_reset",
		ResourceType: "user",
		ResourceID:   &id,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "The user's multi-factor authentication has been reset. They can re-enroll at next sign-in.",
	})
}

func (h *Handler) listDeleted(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("tenant scope required"))
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, err := h.Repo.ListDeleted(r.Context(), *p.TenantID, limit)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// auditUserAction records a best-effort audit row for a recycle-bin action.
func (h *Handler) auditUserAction(r *http.Request, action string, target uuid.UUID) {
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	p := httpx.PrincipalFromCtx(ctx)
	var actorID *uuid.UUID
	var tenantID *uuid.UUID
	if p != nil {
		actorID = p.UserID
		tenantID = p.TenantID
	}
	id := target
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantID,
		ActorUserID:  actorID,
		Action:       action,
		ResourceType: "user",
		ResourceID:   &id,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

func (h *Handler) restore(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Repo.Restore(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditUserAction(r, "user.restored", id)
	u, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *Handler) purge(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Repo.Purge(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditUserAction(r, "user.purged", id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("tenant scope required"))
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, next, err := h.Repo.ListByTenant(r.Context(), *p.TenantID, limit, r.URL.Query().Get("cursor"))
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
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	var hash string
	if in.Password != "" {
		ph, err := password.Hash(in.Password)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		hash = ph
	}
	u, err := h.Repo.CreateWithCredential(r.Context(), in, hash)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	go h.publishCreated(r, u)
	httpx.WriteJSON(w, http.StatusCreated, u)
}

func (h *Handler) publishCreated(r *http.Request, u *User) {
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	actor := httpx.PrincipalFromCtx(ctx)
	var actorID *uuid.UUID
	if actor != nil {
		actorID = actor.UserID
	}
	id := u.ID
	tenant := u.TenantID
	_ = audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenant,
		ActorUserID:  actorID,
		Action:       "user.created",
		ResourceType: "user",
		ResourceID:   &id,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"email": u.Email},
	})
	_ = outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: u.ID,
		Topic:       "user.events",
		EventType:   "user.created",
		Payload:     u,
	})
	_ = tx.Commit(ctx)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	u, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
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
	u, err := h.Repo.Update(r.Context(), id, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
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

type setPasswordInput struct {
	Password string `json:"password" validate:"required,min=8,max=256"`
}

func (h *Handler) setPassword(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in setPasswordInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	// Enforce the tenant's password-complexity policy when set.
	if h.PasswordPolicy != nil {
		if tenantID, terr := httpx.RequireTenant(r); terr == nil {
			if perr := h.PasswordPolicy(r.Context(), tenantID, in.Password); perr != nil {
				httpx.WriteError(w, r, perr)
				return
			}
		}
	}
	hash, err := password.Hash(in.Password)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Repo.SetPassword(r.Context(), id, hash); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
