package invite

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/domains/access/authentication"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

// tokenIssuer is the slice of auth.Service this handler needs (mockable).
type tokenIssuer interface {
	IssuePair(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, method string) (*auth.TokenPair, error)
}

type Handler struct {
	Service     *Service
	AuthService tokenIssuer
	Validate    *validator.Validate
}

// MountAuthed mounts the admin-side CRUD that requires authentication.
func (h *Handler) MountAuthed(r chi.Router) {
	r.Post("/invites", h.create)
	r.Get("/tenants/{tenantID}/invites", h.list)
	r.Delete("/invites/{id}", h.revoke)
}

// MountPublic mounts the invitee-facing accept endpoint.
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/invites/accept", h.accept)
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
	var invitedBy *uuid.UUID
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		invitedBy = p.UserID
	}
	iv, token, err := h.Service.Create(r.Context(), in, invitedBy)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Return the raw token to the caller too — admins frequently want to
	// copy the link directly when email isn't trustworthy yet.
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"invite": iv,
		"token":  token,
	})
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

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Revoke(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) accept(w http.ResponseWriter, r *http.Request) {
	var in AcceptInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	res, err := h.Service.Accept(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.AuthService.IssuePair(r.Context(), res.UserID, res.TenantID, httpx.ClientIP(r), r.UserAgent(), "invite_accept")
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}
