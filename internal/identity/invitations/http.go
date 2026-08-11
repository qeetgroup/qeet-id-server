package invite

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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

// MountAuthed mounts the admin-side CRUD that requires authentication, plus the
// invitee-facing self-service accept for a user who is already signed in.
func (h *Handler) MountAuthed(r chi.Router) {
	r.Post("/invites", h.create)
	r.Get("/tenants/{tenantID}/invites", h.list)
	r.Post("/invites/{id}/resend", h.resend)
	r.Delete("/invites/{id}", h.revoke)
	// Self-service (possibly org-less): discover pending invites addressed to
	// my email, and accept one — by token (email link) or by id (from the
	// inbox) — joining with my existing account.
	r.Get("/me/invites", h.listMine)
	r.Post("/me/invites/accept", h.acceptAuthenticated)
	r.Post("/me/invites/{id}/accept", h.acceptMineByID)
	r.Post("/me/invites/{id}/decline", h.declineMine)
}

// MountPublic mounts the invitee-facing accept endpoint.
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/invites/accept", h.accept)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tid
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

func (h *Handler) resend(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	tid, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	iv, token, err := h.Service.Resend(r.Context(), tid, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
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
	tid, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Revoke(r.Context(), tid, id); err != nil {
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

// listMine returns pending invitations addressed to the signed-in user's email.
func (h *Handler) listMine(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	items, err := h.Service.ListForUser(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// declineMine dismisses a pending invite from the caller's inbox.
func (h *Handler) declineMine(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.DeclineForUser(r.Context(), *p.UserID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Invitation declined."})
}

// acceptMineByID accepts a pending invite chosen from the caller's inbox.
func (h *Handler) acceptMineByID(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	res, err := h.Service.AcceptAuthenticatedByID(r.Context(), *p.UserID, id)
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

type acceptAuthedInput struct {
	Token string `json:"token" validate:"required"`
}

// acceptAuthenticated joins the caller's existing account to the invited tenant
// and returns a tenant-scoped token pair so the client can switch straight in.
func (h *Handler) acceptAuthenticated(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in acceptAuthedInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	res, err := h.Service.AcceptAuthenticated(r.Context(), *p.UserID, in.Token)
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
