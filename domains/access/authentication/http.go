package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

// BotEvaluator scores an auth attempt's User-Agent for bot-likeness and records
// the verdict (detect-only — it never blocks). nil = bot detection off. Kept as
// an interface so auth doesn't import the bot package; satisfied by *bot.Service.
type BotEvaluator interface {
	Evaluate(ctx context.Context, email, ip, ua string)
}

type Handler struct {
	Service  *Service
	Validate *validator.Validate
	// CookieSecure marks the hosted-login SSO cookie Secure (HTTPS-only).
	// Set from SERVICE_ENV != "dev".
	CookieSecure bool
	// Bot, when set, scores login/session attempts for bot-likeness.
	Bot BotEvaluator
}

// evalBot runs the bot scorer for an auth attempt when detection is wired. The
// scorer holds the request's UA + client IP and records suspicious verdicts.
func (h *Handler) evalBot(r *http.Request, email string) {
	if h.Bot != nil {
		h.Bot.Evaluate(r.Context(), email, httpx.ClientIP(r), r.UserAgent())
	}
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/auth/signup", h.signup)
	r.Post("/auth/login", h.login)
	r.Post("/auth/mfa", h.mfaLogin)
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
	r.Post("/auth/switch-tenant", h.switchTenant)
	r.Get("/auth/sessions", h.listSessions)
	r.Delete("/auth/sessions/{id}", h.revokeSession)
	r.Get("/auth/me", h.me)
}

type signupInput struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8,max=256"`
	DisplayName string `json:"display_name" validate:"omitempty,max=200"`
}

func (h *Handler) signup(w http.ResponseWriter, r *http.Request) {
	// Signup is enumeration-sensitive — both the response shape and
	// the response timing must be indistinguishable for "email
	// exists" vs "email is new" so attackers can't probe accounts
	// from the signup form. We achieve this with:
	//
	//   1) A neutral 422 response on conflict (no "already exists"
	//      detail in the body — the verbose error string lived here
	//      historically and leaked).
	//   2) A 250ms timing floor on every signup attempt, capturing
	//      the bcrypt + insert path's slowest case.
	const signupFloor = 250 * time.Millisecond
	start := time.Now()
	defer httpx.ConstantTimeFloor(r.Context(), start, signupFloor)

	var in signupInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	pair, u, _, err := h.Service.Signup(r.Context(), SignupInput{
		Email:       in.Email,
		Password:    in.Password,
		DisplayName: in.DisplayName,
		IP:          httpx.ClientIP(r),
		UserAgent:   r.UserAgent(),
	})
	if err != nil {
		// Conflict (existing email) used to surface "email already
		// exists" verbatim. Neutralise to a generic 422 so the response
		// is indistinguishable from other validation failures. Other
		// backend errors (DB unavailable, etc.) still bubble up so
		// legitimate operational issues aren't hidden.
		if e := errs.As(err); e != nil && e.Code == errs.ErrConflict.Code {
			httpx.WriteError(w, r, errs.ErrUnprocessable.WithMessage(
				"We couldn't complete your signup. If you already have an account, try signing in or resetting your password."))
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	// Tenant-less: no tenant or roles; the user creates one from the UI.
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"user":          u,
		"access_token":  pair.AccessToken,
		"token_type":    pair.TokenType,
		"expires_at":    pair.ExpiresAt,
		"refresh_token": pair.RefreshToken,
		"session_id":    pair.SessionID,
		"user_id":       pair.UserID,
	})
}

type loginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=1"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var in loginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	h.evalBot(r, in.Email)
	res, err := h.Service.Login(r.Context(), LoginInput{
		Email:     in.Email,
		Password:  in.Password,
		IP:        httpx.ClientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if res.MFARequired {
		// Password ok, but a second factor is required. No tokens yet — the
		// client completes the challenge at POST /v1/auth/mfa.
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"mfa_required": true,
			"mfa_token":    res.MFAToken,
			"methods":      res.Methods,
		})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res.Pair)
}

type mfaLoginInput struct {
	MFAToken string `json:"mfa_token" validate:"required"`
	Code     string `json:"code" validate:"required"`
	// Remember opts into adaptive MFA on the hosted flow: trust this device so
	// future logins from it can skip the second factor (honoured only when the
	// tenant has enabled it). Ignored by the token-flow /v1/auth/mfa endpoint.
	Remember bool `json:"remember"`
}

// mfaLogin completes a two-step login: it exchanges the mfa_token from /login
// plus a TOTP or recovery code for a full token pair.
func (h *Handler) mfaLogin(w http.ResponseWriter, r *http.Request) {
	var in mfaLoginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	pair, err := h.Service.CompleteMFALogin(r.Context(), in.MFAToken, in.Code, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

type sessionInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=1"`
}

// createSession is the hosted-login credential endpoint. On success it sets the
// HttpOnly SSO cookie (qe_ls) and returns the user id — no tokens in the body.
// It is what the hosted login app posts to before the OAuth consent step. When
// the user has a second factor enrolled it returns an MFA challenge instead and
// withholds the cookie until the challenge is completed at POST
// /v1/auth/session/mfa — without this the cookie flow would bypass MFA that the
// token flow enforces.
func (h *Handler) createSession(w http.ResponseWriter, r *http.Request) {
	var in sessionInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	h.evalBot(r, in.Email)
	// A trusted-device cookie (when the tenant allows adaptive MFA) lets an
	// enrolled user skip the second factor on a previously-remembered device.
	trusted := ""
	if c, cerr := r.Cookie(TrustedDeviceCookie); cerr == nil {
		trusted = c.Value
	}
	res, err := h.Service.BeginLoginSession(r.Context(), in.Email, in.Password, httpx.ClientIP(r), r.UserAgent(), trusted)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if res.MFARequired {
		// Password ok, but a second factor is required. No cookie yet — the
		// client completes the challenge at POST /v1/auth/session/mfa.
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"mfa_required": true,
			"mfa_token":    res.MFAToken,
			"methods":      res.Methods,
		})
		return
	}
	SetLoginSessionCookie(w, res.RawCookie, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user_id": res.UserID})
}

// createSessionMFA completes a two-step hosted login: it exchanges the mfa_token
// from createSession plus a TOTP or recovery code for the SSO cookie. It is the
// cookie-flow analogue of mfaLogin (which returns a token pair).
func (h *Handler) createSessionMFA(w http.ResponseWriter, r *http.Request) {
	var in mfaLoginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	userID, tenantID, raw, err := h.Service.CompleteMFALoginSession(r.Context(), in.MFAToken, in.Code, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	SetLoginSessionCookie(w, raw, h.CookieSecure)
	// Trust this device when asked — MaybeRememberDevice is a no-op unless the
	// tenant has opted into adaptive MFA, so a client-supplied flag can't grant
	// trust the policy forbids.
	if in.Remember {
		if draw, derr := h.Service.MaybeRememberDevice(r.Context(), userID, tenantID, r.UserAgent()); derr == nil && draw != "" {
			SetTrustedDeviceCookie(w, draw, h.CookieSecure)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user_id": userID})
}

type registerInput struct {
	TenantID    uuid.UUID `json:"tenant_id" validate:"required"`
	Email       string    `json:"email" validate:"required,email"`
	Password    string    `json:"password" validate:"required,min=8,max=256"`
	DisplayName string    `json:"display_name" validate:"omitempty,max=200"`
}

// register is the hosted end-user signup endpoint (B2C self-registration). It
// creates the user in the client's tenant — gated by that tenant's
// self_registration_enabled policy — and on success sets the SSO cookie so the
// new user continues straight into the OAuth authorize flow. Like signup it is
// enumeration-safe: a conflict on an existing email returns a neutral 422 under
// a timing floor so the response can't distinguish "exists" from "new".
func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	const registerFloor = 250 * time.Millisecond
	start := time.Now()
	defer httpx.ConstantTimeFloor(r.Context(), start, registerFloor)

	var in registerInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	u, raw, err := h.Service.RegisterInTenant(r.Context(), in.TenantID, in.Email, in.Password, in.DisplayName, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		if e := errs.As(err); e != nil && e.Code == errs.ErrConflict.Code {
			httpx.WriteError(w, r, errs.ErrUnprocessable.WithMessage(
				"We couldn't complete your signup. If you already have an account, try signing in or resetting your password."))
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	SetLoginSessionCookie(w, raw, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"user_id": u.ID})
}

// destroySession is hosted logout: revoke the SSO session and clear the cookie.
func (h *Handler) destroySession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(LoginSessionCookie); err == nil {
		_ = h.Service.RevokeLoginSession(r.Context(), c.Value)
	}
	ClearLoginSessionCookie(w, h.CookieSecure)
	w.WriteHeader(http.StatusNoContent)
}

type refreshInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	var in refreshInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	pair, err := h.Service.Refresh(r.Context(), RefreshInput{
		RefreshToken: in.RefreshToken,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if err := h.Service.Logout(r.Context(), *p.SessionID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "You've been signed out."})
}

type switchTenantInput struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
}

// switchTenant returns a token pair scoped to a tenant the caller belongs to (403 otherwise).
func (h *Handler) switchTenant(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in switchTenantInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	tid, err := uuid.Parse(in.TenantID)
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenant_id"))
		return
	}
	pair, err := h.Service.SwitchTenant(r.Context(), *p.UserID, tid, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  pair.AccessToken,
		"token_type":    pair.TokenType,
		"expires_at":    pair.ExpiresAt,
		"refresh_token": pair.RefreshToken,
		"session_id":    pair.SessionID,
		"user_id":       pair.UserID,
		"tenant_id":     tid,
	})
}

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	out, err := h.Service.ListSessions(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) revokeSession(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Logout(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Session revoked."})
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"user_id":    p.UserID,
		"tenant_id":  p.TenantID,
		"session_id": p.SessionID,
		"actor":      p.ActorType,
		"scopes":     p.Scopes,
	})
}
