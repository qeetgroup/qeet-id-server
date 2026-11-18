package authentication

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// BotEvaluator scores an auth attempt's User-Agent for bot-likeness and records
// the verdict (detect-only — it never blocks). Kept as an interface so auth
// doesn't import the bot package; satisfied by *bot.Service.
type BotEvaluator interface {
	Evaluate(ctx context.Context, email, ip, ua string)
}

// Handler serves the sign-in and session HTTP API.
type Handler struct {
	Service  *Service
	Validate *validator.Validate
	// CookieSecure marks the hosted-login SSO cookie Secure (HTTPS-only).
	// Set from SERVICE_ENV != "dev".
	CookieSecure bool
	// Bot scores login/session attempts for bot-likeness.
	Bot BotEvaluator
	// GeoCountryHeader names a header set by a trusted proxy (for example
	// Cloudflare's CF-IPCountry) with the client's country, used for
	// impossible-travel checks. Empty disables that signal.
	GeoCountryHeader string
	// Throttle wraps sensitive self-service routes (password change/set) with a
	// tight per-user rate limit to blunt online guessing.
	Throttle func(http.Handler) http.Handler
	// ActOnCheck refuses an administrator changing the sign-in methods of a
	// member who outranks them (rbac CheckActOn); nil refuses every change.
	ActOnCheck func(ctx context.Context, caller *httpx.Principal, organizationID, targetID uuid.UUID) error
}

// evalBot runs the bot scorer for an auth attempt. The scorer holds the
// request's UA + client IP and records suspicious verdicts.
func (h *Handler) evalBot(r *http.Request, email string) {
	h.Bot.Evaluate(r.Context(), email, httpx.ClientIP(r), r.UserAgent())
}

// geoCountry reads the configured trusted-proxy header, or "" when unset —
// callers must treat "" as "no signal," never as a risk signal itself.
func (h *Handler) geoCountry(r *http.Request) string {
	if h.GeoCountryHeader == "" {
		return ""
	}
	return r.Header.Get(h.GeoCountryHeader)
}

// Mount registers the sign-in and session routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/auth/signup", h.signup)
	r.Post("/auth/login", h.login)
	r.Post("/auth/mfa", h.mfaLogin)
	// Second-factor helpers, for either sign-in flow: send an email/SMS
	// code, begin a passkey assertion, send a push approval request.
	r.Post("/auth/mfa/send", h.mfaSendCode)
	r.Post("/auth/mfa/passkey/begin", h.mfaPasskeyBegin)
	r.Post("/auth/mfa/push", h.mfaPush)
	r.Post("/auth/mfa/enroll", h.mfaEnroll)
	r.Post("/auth/refresh", h.refresh)
	// Hosted-login SSO session (HttpOnly cookie) for the OAuth authorize flow.
	r.Post("/auth/session", h.createSession)
	r.Post("/auth/session/mfa", h.createSessionMFA)
	r.Post("/auth/register", h.register)
	r.Delete("/auth/session", h.destroySession)
}

// MountAuthed mounts endpoints that require the RequireAuth middleware.
func (h *Handler) MountAuthed(r chi.Router) {
	r.Post("/auth/logout", h.logout)
	r.Post("/auth/switch-organization", h.switchOrganization)
	r.Get("/auth/sessions", h.listSessions)
	r.Get("/auth/trusted-devices/count", h.trustedDeviceCount)
	r.Get("/auth/trusted-devices", h.listOwnTrustedDevices)
	r.Delete("/auth/trusted-devices", h.forgetOwnTrustedDevices)
	r.Delete("/auth/trusted-devices/{id}", h.forgetOwnTrustedDevices)
	// An administrator's view of a member's remembered devices, in the
	// administrator's own organization (user.read / user.credentials).
	r.Get("/users/{id}/trusted-devices", h.listMemberTrustedDevices)
	r.Delete("/users/{id}/trusted-devices", h.forgetMemberTrustedDevices)
	r.Delete("/users/{id}/trusted-devices/{deviceID}", h.forgetMemberTrustedDevices)
	r.Post("/auth/sessions/revoke-others", h.revokeOtherSessions)
	r.Post("/auth/sessions/revoke-all", h.revokeAllSessions)
	r.Delete("/auth/sessions/{id}", h.revokeSession)
	r.Get("/auth/me", h.me)
	r.Get("/auth/password", h.passwordStatus)
	r.Get("/auth/sign-in-methods", h.signInMethods)
	r.With(h.Throttle).Post("/auth/password", h.changePassword)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"user_id":         p.UserID,
		"organization_id": p.OrganizationID,
		"session_id":      p.SessionID,
		"actor":           p.ActorType,
		"scopes":          p.Scopes,
	})
}

// Check refuses a handler without the password-change throttle or the bot
// scorer, so bootstrap stops at start rather than serve without them.
func (h *Handler) Check() error {
	switch {
	case h.Throttle == nil:
		return errors.New("auth: the sign-in handler needs a throttle")
	case h.Bot == nil:
		return errors.New("auth: the sign-in handler needs a bot scorer")
	}
	return nil
}
