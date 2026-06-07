package auth

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/internal/platform/errs"
	"github.com/qeetgroup/qeet-id/internal/platform/httpx"
)

type Handler struct {
	Service  *Service
	Validate *validator.Validate
	// CookieSecure marks the hosted-login SSO cookie Secure (HTTPS-only).
	// Set from SERVICE_ENV != "dev".
	CookieSecure bool
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/auth/signup", h.signup)
	r.Post("/auth/login", h.login)
	r.Post("/auth/refresh", h.refresh)
	// Hosted-login SSO session (HttpOnly cookie) for the OAuth authorize flow.
	r.Post("/auth/session", h.createSession)
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
	pair, err := h.Service.Login(r.Context(), LoginInput{
		Email:     in.Email,
		Password:  in.Password,
		IP:        httpx.ClientIP(r),
		UserAgent: r.UserAgent(),
	})
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
// It is what the hosted login app posts to before the OAuth consent step.
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
	u, err := h.Service.CheckPassword(r.Context(), in.Email, in.Password)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	raw, err := h.Service.CreateLoginSession(r.Context(), u.ID, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	SetLoginSessionCookie(w, raw, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user_id": u.ID})
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
