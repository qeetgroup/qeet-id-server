package verification

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the verification HTTP API.
type Handler struct {
	Service *Service
	// Throttle, if set, wraps the code-sending routes in a tighter per-user limit.
	Throttle func(http.Handler) http.Handler
}

// Mount registers the verification routes on r.
func (h *Handler) Mount(r chi.Router) {
	// A code-sending route dispatches an SMS/email to a caller-supplied address,
	// so it's throttled harder than the generic per-user bucket to prevent
	// toll-fraud / bombing. Confirm routes stay on the default limiter.
	sending := r
	if h.Throttle != nil {
		sending = r.With(h.Throttle)
	}
	sending.Post("/users/{id}/verify/email/start", h.startEmail)
	r.Post("/users/{id}/verify/email/confirm", h.confirmEmail)
	sending.Post("/users/{id}/verify/phone/start", h.startPhone)
	r.Post("/users/{id}/verify/phone/confirm", h.confirmPhone)
	// Self-service email change (send code to the new address, then confirm).
	sending.Post("/me/email/change/start", h.startEmailChange)
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
	if err := h.Service.StartEmailChange(r.Context(), *p.UserID, in.Email, requesterOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "Check your new email address for a verification code.",
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
	email, err := h.Service.ConfirmEmailChange(r.Context(), *p.UserID, in.Code, requesterOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "Your email address has been updated.",
		"email":   email,
	})
}

// requesterOf is the signed-in caller, for the audit rows the service writes.
func requesterOf(r *http.Request) Requester {
	who := Requester{Actor: audit.Actor{
		Type: "user", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
	}}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		who.Actor.UserID = p.UserID
		if p.ActorType != "" {
			who.Actor.Type = p.ActorType
		}
		who.TenantID = p.TenantID
	}
	return who
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
	// they don't own; moving to another address is the email-change flow.
	if err := h.Service.StartEmail(r.Context(), uid, "", requesterOf(r)); err != nil {
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
	if err := h.Service.ConfirmEmail(r.Context(), uid, in.Code, requesterOf(r)); err != nil {
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
