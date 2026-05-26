package recovery

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-identity/internal/auth"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type Handler struct {
	Service     *Service
	AuthService *auth.Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/auth/forgot-password", h.forgot)
	r.Post("/auth/reset-password", h.reset)
	r.Post("/auth/magic-link/start", h.magicStart)
	r.Post("/auth/magic-link/consume", h.magicConsume)
}

type forgotInput struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Email    string    `json:"email"`
}

func (h *Handler) forgot(w http.ResponseWriter, r *http.Request) {
	var in forgotInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.StartPasswordReset(r.Context(), in.TenantID, in.Email); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

type resetInput struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (h *Handler) reset(w http.ResponseWriter, r *http.Request) {
	var in resetInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ac := AuditCtx{IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if err := h.Service.ConfirmPasswordReset(r.Context(), in.Token, in.NewPassword, ac); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type magicStartInput struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Email    string    `json:"email"`
}

func (h *Handler) magicStart(w http.ResponseWriter, r *http.Request) {
	var in magicStartInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.StartMagicLink(r.Context(), in.TenantID, in.Email); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

type magicConsumeInput struct {
	Token string `json:"token"`
}

func (h *Handler) magicConsume(w http.ResponseWriter, r *http.Request) {
	var in magicConsumeInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ac := AuditCtx{IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	res, err := h.Service.ConsumeMagicLink(r.Context(), in.Token, ac)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.AuthService.IssuePair(r.Context(), res.UserID, res.TenantID, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if pair == nil {
		httpx.WriteError(w, r, errs.ErrInternal)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}
