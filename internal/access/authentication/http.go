package auth

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	// GeoCountryHeader, when set, is the name of a request header a trusted
	// upstream proxy (e.g. Cloudflare's CF-IPCountry) sets to the client's
	// resolved country — the sole geo signal impossible-travel risk assessment
	// consumes. Empty (the default) means no geo signal is available and that
	// signal never fires; there is no server-side GeoIP lookup, by design (see
	// domains/access/threat-detection/risk).
	GeoCountryHeader string
	// Throttle wraps sensitive self-service routes (password change/set) with a
	// tight per-user rate limit to blunt online guessing. Nil = no extra throttle.
	Throttle func(http.Handler) http.Handler
}

// evalBot runs the bot scorer for an auth attempt when detection is wired. The
// scorer holds the request's UA + client IP and records suspicious verdicts.
func (h *Handler) evalBot(r *http.Request, email string) {
	if h.Bot != nil {
		h.Bot.Evaluate(r.Context(), email, httpx.ClientIP(r), r.UserAgent())
	}
}

// geoCountry reads the configured trusted-proxy header, or "" when unset —
// callers must treat "" as "no signal," never as a risk signal itself.
func (h *Handler) geoCountry(r *http.Request) string {
	if h.GeoCountryHeader == "" {
		return ""
	}
	return r.Header.Get(h.GeoCountryHeader)
}

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
	r.Post("/auth/switch-tenant", h.switchTenant)
	r.Get("/auth/sessions", h.listSessions)
	r.Get("/auth/trusted-devices/count", h.trustedDeviceCount)
	r.Post("/auth/sessions/revoke-others", h.revokeOtherSessions)
	r.Post("/auth/sessions/revoke-all", h.revokeAllSessions)
	r.Delete("/auth/sessions/{id}", h.revokeSession)
	r.Get("/auth/me", h.me)
	r.Get("/auth/password", h.passwordStatus)
	r.Get("/auth/sign-in-methods", h.signInMethods)
	if h.Throttle != nil {
		r.With(h.Throttle).Post("/auth/password", h.changePassword)
	} else {
		r.Post("/auth/password", h.changePassword)
	}
}

type signupInput struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,max=256"` // length + rules: the service's password check
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
		httpx.WriteJSON(w, http.StatusOK, res.Body())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res.Pair)
}

// mfaLoginInput meets a sign-in's second-factor challenge with exactly one
// proof: a code (authenticator app, recovery, or an emailed/texted code), a
// passkey assertion from the ceremony begun for the challenge, or push: true
// once the push request sent for it is approved. An enrolment challenge is met
// by the code confirming the authenticator app set up for it, or skip: true
// while the setup may be put off.
type mfaLoginInput struct {
	MFAToken string        `json:"mfa_token" validate:"required"`
	Code     string        `json:"code"`
	Passkey  *PasskeyProof `json:"passkey"`
	Push     bool          `json:"push"`
	Skip     bool          `json:"skip"`
	// Remember opts into adaptive MFA on the hosted flow: trust this device so
	// future logins from it can skip the second factor (honoured only when the
	// tenant has enabled it). Ignored by the token-flow /v1/auth/mfa endpoint.
	Remember bool `json:"remember"`
}

// mfaLogin completes a two-step login: it exchanges the mfa_token from /login
// plus a proof for a full token pair — with the new recovery codes when the
// proof confirmed an authenticator app set up for the challenge.
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
	proof, err := in.proof()
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, codes, err := h.Service.CompleteMFALoginWith(r.Context(), in.MFAToken, proof, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if len(codes) > 0 {
		httpx.WriteJSON(w, http.StatusOK, struct {
			*TokenPair
			RecoveryCodes []string `json:"recovery_codes"`
		}{pair, codes})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

type sessionInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=1"`
	// ClientID is the OAuth client the hosted login is serving; its tenant's
	// sign-in lockout settings apply. Optional (none = the platform defaults).
	ClientID string `json:"client_id" validate:"omitempty,max=255"`
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
	res, err := h.Service.BeginLoginSession(r.Context(), SignInAttempt{
		Email:    in.Email,
		Password: in.Password,
		IP:       httpx.ClientIP(r),
		ClientID: in.ClientID,
	}, r.UserAgent(), trusted, h.geoCountry(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if res.MFARequired {
		// Password ok, but a second factor is required. No cookie yet — the
		// client completes the challenge at POST /v1/auth/session/mfa.
		httpx.WriteJSON(w, http.StatusOK, res.Body())
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
	proof, err := in.proof()
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.CompleteMFALoginSessionWith(r.Context(), in.MFAToken, proof, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	SetLoginSessionCookie(w, res.RawCookie, h.CookieSecure)
	// Trust this device when asked — MaybeRememberDevice is a no-op unless the
	// tenant has opted into adaptive MFA, so a client-supplied flag can't grant
	// trust the policy forbids. A skipped setup met no factor, so earns none.
	if in.Remember && !res.Deferred {
		if draw, derr := h.Service.MaybeRememberDevice(r.Context(), res.UserID, res.TenantID, r.UserAgent()); derr == nil && draw != "" {
			SetTrustedDeviceCookie(w, draw, h.CookieSecure)
		}
	}
	body := map[string]any{"user_id": res.UserID}
	if len(res.RecoveryCodes) > 0 {
		body["recovery_codes"] = res.RecoveryCodes
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

type registerInput struct {
	TenantID    uuid.UUID `json:"tenant_id" validate:"required"`
	Email       string    `json:"email" validate:"required,email"`
	Password    string    `json:"password" validate:"required,max=256"` // length + rules: the service's password check
	DisplayName string    `json:"display_name" validate:"omitempty,max=200"`
}

// register is the hosted end-user signup endpoint (B2C self-registration). It
// creates the user in the client's tenant — gated by that tenant's
// self_registration_enabled policy — and on success sets the SSO cookie so the
// new user continues straight into the OAuth authorize flow. Where the tenant
// requires MFA it answers an enrolment challenge instead (completed at POST
// /v1/auth/session/mfa), so the first session follows the setup. Like signup it is
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
	u, res, err := h.Service.RegisterInTenant(r.Context(), in.TenantID, in.Email, in.Password, in.DisplayName, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		if e := errs.As(err); e != nil && e.Code == errs.ErrConflict.Code {
			httpx.WriteError(w, r, errs.ErrUnprocessable.WithMessage(
				"We couldn't complete your signup. If you already have an account, try signing in or resetting your password."))
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	if res.MFARequired {
		body := res.Body()
		body["user_id"] = u.ID
		httpx.WriteJSON(w, http.StatusCreated, body)
		return
	}
	SetLoginSessionCookie(w, res.RawCookie, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"user_id": u.ID})
}

// destroySession is the hosted login signing itself out: it ends the browser's
// SSO session and what it started (EndLoginSession) and clears the cookie. A
// request without a session cookie ends nothing and still answers 204. If the
// sign-out cannot be completed the cookie is kept, so the browser can retry
// instead of believing it is signed out.
func (h *Handler) destroySession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(LoginSessionCookie); err == nil {
		if _, err := h.Service.EndLoginSession(r.Context(), EndLoginSessionInput{
			Cookie: c.Value, InitiatedBy: SignOutByHostedLogin,
			IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		}); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
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

type changePasswordInput struct {
	// Optional: required only when the account already has a password. A
	// password-less account (social / passkey signup) omits it to SET one.
	CurrentPassword string `json:"current_password" validate:"omitempty"`
	NewPassword     string `json:"new_password" validate:"required,max=256"` // length + rules: the service's password check
}

// signInMethods reports how many ways the caller can sign in, so a client can
// disable or explain removing the last one before trying. The server refuses
// that removal anyway.
func (h *Handler) signInMethods(w http.ResponseWriter, r *http.Request) {
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	m, err := h.Service.SignInMethods(r.Context(), userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"password":          m.Password,
		"passkeys":          m.Passkeys,
		"linked_identities": m.LinkedIdentities,
		"total":             m.Total(),
	})
}

// passwordStatus reports whether the caller has a password set, so the account
// UI can offer "set a password" vs "change password".
func (h *Handler) passwordStatus(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	has, err := h.Service.HasPassword(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"has_password": has})
}

// changePassword rotates (or sets) a signed-in user's password — self-service
// and tenant-independent (works before any org). Re-proving the current
// password is required only when one is already set; either way, other sessions
// are revoked.
func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in changePasswordInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if h.Validate != nil {
		if err := h.Validate.Struct(in); err != nil {
			httpx.WriteError(w, r, httpx.ValidationError(err))
			return
		}
	}
	if err := h.Service.ChangePassword(r.Context(), ChangePasswordInput{
		UserID: *p.UserID, KeepSessionID: *p.SessionID, TenantID: p.TenantID,
		Current: in.CurrentPassword, Next: in.NewPassword,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Your password has been updated."})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.SessionID == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if err := h.Service.Logout(r.Context(), *p.SessionID, *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "You've been signed out."})
}

type switchTenantInput struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
}

// switchTenant → POST /v1/auth/switch-tenant. Replaces the caller's session
// with one in another organization they belong to (Service.SwitchTenant); the
// session in the presented access token is the one that ends.
func (h *Handler) switchTenant(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
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
	pair, err := h.Service.SwitchTenant(r.Context(), SwitchTenantInput{
		UserID: *p.UserID, FromSessionID: *p.SessionID, TenantID: tid,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(),
	})
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
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	current := uuid.Nil
	if p.SessionID != nil {
		current = *p.SessionID
	}
	out, err := h.Service.ListSessionsPageFor(r.Context(), *p.UserID, current, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) revokeSession(w http.ResponseWriter, r *http.Request) {
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
	// Scope to the caller: revoking a session you don't own is a silent no-op.
	if err := h.Service.Logout(r.Context(), id, *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Session revoked."})
}

// revokeOtherSessions → POST /v1/auth/sessions/revoke-others. Ends all of the
// caller's sessions except the one behind the presented access token, in one
// step, and reports how many ended ({"revoked": n}, the same shape as the admin
// revoke-all). Access tokens already issued to the ended sessions stay valid
// until they expire; their refresh tokens stop working at once.
func (h *Handler) revokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	n, err := h.Service.RevokeOtherSessions(r.Context(), RevokeOtherSessionsInput{
		UserID: *p.UserID, CurrentSessionID: *p.SessionID, TenantID: p.TenantID,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

// revokeAllSessions → POST /v1/auth/sessions/revoke-all. Signs the caller out
// everywhere — every API and console session including the one behind the
// presented access token, every hosted-login session, every application grant
// — in one step, and reports how many ended: {"revoked": total} (the shape of
// the other bulk revocations) plus the count per place. Access tokens already
// issued stay valid until they expire; renewal stops at once. A repeat
// succeeds with zeros.
func (h *Handler) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	ended, err := h.Service.RevokeAllSessions(r.Context(), RevokeAllSessionsInput{
		UserID: *p.UserID, SessionID: *p.SessionID, TenantID: p.TenantID,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Every hosted-login session has ended server-side, whichever browser holds
	// it; a browser calling directly also drops its cookie.
	ClearLoginSessionCookie(w, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"revoked":                ended.Total(),
		"sessions":               ended.Sessions,
		"hosted_login_sessions":  ended.LoginSessions,
		"app_grants":             ended.AppGrants,
		"trusted_devices":        ended.TrustedDevices,
		"pending_authorizations": ended.PendingAuthorizations,
	})
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

// trustedDeviceCount reports how many live trusted devices the caller's tenant
// has. Scoped from the principal, never a path or query parameter, so one tenant
// can't read another's estate.
func (h *Handler) trustedDeviceCount(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.CountTrustedDevices(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// proof is the one proof the input carries, or a validation error naming the
// problem.
func (in mfaLoginInput) proof() (MFAProof, error) {
	n := 0
	if in.Code != "" {
		n++
	}
	if in.Passkey != nil {
		n++
	}
	if in.Push {
		n++
	}
	if in.Skip {
		n++
	}
	if n != 1 {
		return MFAProof{}, errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "code", Code: "required",
			Message: "Give exactly one of a code, a passkey assertion, push, or skip.",
		}})
	}
	return MFAProof{Code: in.Code, Passkey: in.Passkey, Push: in.Push, Skip: in.Skip}, nil
}

type mfaTokenInput struct {
	MFAToken string    `json:"mfa_token" validate:"required"`
	FactorID uuid.UUID `json:"factor_id"`
}

func (h *Handler) decodeMFAToken(w http.ResponseWriter, r *http.Request) (mfaTokenInput, bool) {
	var in mfaTokenInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return in, false
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return in, false
	}
	return in, true
}

// mfaSendCode sends a code to one of the challenged person's email or SMS
// factors (factor_id, from the challenge's factors).
func (h *Handler) mfaSendCode(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decodeMFAToken(w, r)
	if !ok {
		return
	}
	if err := h.Service.SendMFACode(r.Context(), in.MFAToken, in.FactorID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"sent": true})
}

// mfaPasskeyBegin starts the passkey assertion that can meet the challenge.
func (h *Handler) mfaPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decodeMFAToken(w, r)
	if !ok {
		return
	}
	sessionID, options, err := h.Service.BeginMFAPasskey(r.Context(), in.MFAToken)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"session_id": sessionID, "publicKey": options})
}

// mfaPush sends the push approval request that can meet the challenge; the
// client then completes with push: true, which answers mfa.push_pending until
// the request is approved.
func (h *Handler) mfaPush(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decodeMFAToken(w, r)
	if !ok {
		return
	}
	expires, err := h.Service.StartMFAPush(r.Context(), in.MFAToken, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"expires_at": expires})
}

// mfaEnroll starts the authenticator app that meets an enrolment challenge
// and returns its secret and otpauth:// provisioning URL; a code from the app
// then completes the challenge.
func (h *Handler) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decodeMFAToken(w, r)
	if !ok {
		return
	}
	out, err := h.Service.StartMFAEnrollment(r.Context(), in.MFAToken, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
