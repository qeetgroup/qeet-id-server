package verification

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/users/{id}/verify/email/start", h.startEmail)
	r.Post("/users/{id}/verify/email/confirm", h.confirmEmail)
	r.Post("/users/{id}/verify/phone/start", h.startPhone)
	r.Post("/users/{id}/verify/phone/confirm", h.confirmPhone)
	// Self-service email change (send code to the new address, then confirm).
	r.Post("/me/email/change/start", h.startEmailChange)
	r.Post("/me/email/change/confirm", h.confirmEmailChange)
}

type startEmailChangeInput struct {
	Email string `json:"email"`
}

func (h *Handler) startEmailChange(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in startEmailChangeInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.StartEmailChange(r.Context(), *p.UserID, in.Email); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "We've sent a verification code to your new email.",
	})
}

func (h *Handler) confirmEmailChange(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in confirmInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	email, err := h.Service.ConfirmEmailChange(r.Context(), *p.UserID, in.Code)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "Your email address has been updated.",
		"email":   email,
	})
}

// selfID resolves the target user from the path and enforces that it's the
// caller: verification is self-service only. Without this, any authenticated
// user could start/confirm verification against another user's id (an IDOR) —
// {id} is NOT a {tenantID}, so the central EnforceTenantScope guard never fires.
func selfID(r *http.Request) (uuid.UUID, error) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		return uuid.Nil, errs.ErrUnauthorized
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid id")
	}
	if id != *p.UserID {
		return uuid.Nil, errs.ErrForbidden
	}
	return *p.UserID, nil
}

func (h *Handler) startEmail(w http.ResponseWriter, r *http.Request) {
	uid, err := selfID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Always verify the address on file — never a body-supplied one. Trusting a
	// request body here would let a user mint a "verified" state for an address
	// they don't own; there is no self-service email-change flow yet.
	if err := h.Service.StartEmail(r.Context(), uid, ""); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "We've sent a verification code to your email.",
	})
}

type confirmInput struct {
	Code string `json:"code"`
}

func (h *Handler) confirmEmail(w http.ResponseWriter, r *http.Request) {
	uid, err := selfID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in confirmInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.ConfirmEmail(r.Context(), uid, in.Code); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Your email has been verified."})
}

type startPhoneInput struct {
	Phone string `json:"phone"`
}

func (h *Handler) startPhone(w http.ResponseWriter, r *http.Request) {
	uid, err := selfID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in startPhoneInput
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &in); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if err := h.Service.StartPhone(r.Context(), uid, in.Phone); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "We've sent a verification code by SMS.",
	})
}

func (h *Handler) confirmPhone(w http.ResponseWriter, r *http.Request) {
	uid, err := selfID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in confirmInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.ConfirmPhone(r.Context(), uid, in.Code); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Your phone number has been verified."})
}
