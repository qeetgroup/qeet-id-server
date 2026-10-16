package recovery

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
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
	// DevMode surfaces the reset token in the forgot-password response for local
	// development (SERVICE_ENV=dev), so the flow is completable without a real
	// email provider. Never enabled in production.
	DevMode bool
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/auth/forgot-password", h.forgot)
	r.Post("/auth/reset-password", h.reset)
	r.Post("/auth/magic-link/start", h.magicStart)
	r.Post("/auth/magic-link/consume", h.magicConsume)
}

type forgotInput struct {
	Email string `json:"email"`
	// TenantID is accepted because hosted login and the React SDK send it, and
	// is not used: email is unique platform-wide, so the look-up needs no tenant.
	TenantID string `json:"tenant_id,omitempty"`
	// App is where the reset was requested from: "hosted_login" makes the
	// emailed link open hosted login's reset page. Anything else, or nothing,
	// keeps the console link — the documented default.
	App string `json:"app,omitempty"`
	// ReturnTo (hosted login only) is where to continue after the reset. It is
	// kept only if it is this service's own OAuth authorize endpoint.
	ReturnTo string `json:"return_to,omitempty"`
}

// authorizeReturnTo keeps a return_to only if it points at this service's own
// OAuth authorize endpoint — the URL the authorize redirect gives hosted login
// (same host as this request), and the same rule hosted login applies. Anything
// else returns "" (dropped), so an emailed link can never send the user to a
// caller-chosen site.
func authorizeReturnTo(r *http.Request, raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host != r.Host ||
		!strings.HasSuffix(u.Path, "/oauth/authorize") {
		return ""
	}
	return u.String()
}

func (h *Handler) forgot(w http.ResponseWriter, r *http.Request) {
	var in forgotInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	raw, err := h.Service.StartPasswordResetFrom(r.Context(), in.Email, ResetOrigin{
		App:      in.App,
		ReturnTo: authorizeReturnTo(r, in.ReturnTo),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Enumeration-safe: identical response whether or not the email exists.
	resp := map[string]any{
		"message": "If an account exists for that email, we've sent a password reset link.",
	}
	// Dev only: hand back the token so the reset link works without a real email
	// provider. Guarded by DevMode — never leaks a live token in production.
	if h.DevMode && raw != "" {
		resp["dev_reset_token"] = raw
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
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
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}
