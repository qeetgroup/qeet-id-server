package recovery

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
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
	// Enumeration-safe: identical response whether or not the email exists.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "If an account exists for that email, we've sent a password reset link.",
	})
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
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "Your password has been reset. You can now sign in with your new password.",
	})
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
	// Enumeration-safe: identical response whether or not the email exists.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "If an account exists for that email, we've sent a sign-in link.",
	})
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
	pair, err := h.AuthService.IssuePair(r.Context(), res.UserID, res.TenantID, httpx.ClientIP(r), r.UserAgent(), "magic_link")
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
