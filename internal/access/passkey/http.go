package passkey

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// requesterOf is the signed-in caller of r.
func requesterOf(r *http.Request) Requester {
	who := Requester{Actor: audit.ActorOf(r)}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil && p.OrganizationID != nil && *p.OrganizationID != uuid.Nil {
		who.OrganizationID = p.OrganizationID
	}
	return who
}

// Handler serves the passkey routes. CookieSecure marks the hosted-login SSO
// cookie Secure (HTTPS-only).
type Handler struct {
	Service      *Service
	CookieSecure bool
}

// Mount mounts the signed-in passkey routes. The hosted login calls each of
// them (list, rename, remove and the two enrolment steps) with its session
// cookie rather than a bearer token (see the router's hosted-login session
// routes).
func (h *Handler) Mount(r chi.Router) {
	r.Get("/passkeys", h.list)
	r.Patch("/passkeys/{id}", h.rename)
	r.Delete("/passkeys/{id}", h.delete)
	r.Post("/passkeys/register/begin", h.registerBegin)
	r.Post("/passkeys/register/finish", h.registerFinish)
}

// MountPublic mounts the passwordless login and signup ceremonies (no JWT —
// the caller isn't authenticated yet).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/passkeys/login/begin", h.loginBegin)
	r.Post("/passkeys/login/finish", h.loginFinish)
	r.Post("/passkeys/login/session", h.loginSession)
	r.Post("/signup/passkey/begin", h.signupBegin)
	r.Post("/signup/passkey/finish", h.signupFinish)
	r.Post("/register/passkey/begin", h.organizationSignupBegin)
	r.Post("/register/passkey/finish", h.organizationSignupFinish)
	r.Post("/invites/accept/passkey/begin", h.inviteSignupBegin)
	r.Post("/invites/accept/passkey/finish", h.inviteSignupFinish)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	out, err := h.Service.List(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// enrollment_allowed tells a UI whether to offer adding a passkey.
	allowed, err := h.Service.EnrolmentAllowed(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct {
		paging.Result[Credential]
		EnrollmentAllowed bool `json:"enrollment_allowed"`
	}{paging.List(out), allowed})
}

type renameInput struct {
	Name string `json:"name"`
}

// rename sets the name of one of the caller's own passkeys and returns it.
func (h *Handler) rename(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in renameInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cred, err := h.Service.Rename(r.Context(), id, userID, in.Name, requesterOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cred)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Delete(r.Context(), id, userID, requesterOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) registerBegin(w http.ResponseWriter, r *http.Request) {
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sessionID, options, err := h.Service.BeginRegister(r.Context(), userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

type registerFinishInput struct {
	SessionID  uuid.UUID       `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

func (h *Handler) registerFinish(w http.ResponseWriter, r *http.Request) {
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in registerFinishInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.FinishRegister(r.Context(), userID, in.SessionID, in.Credential, in.Name, requesterOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type loginBeginInput struct {
	Email string `json:"email"`
}

// binding ties a passkey sign-in to the browser that began it: only that
// browser can finish it at the hosted form (loginSession).
func (h *Handler) binding() httpx.BindingCookie {
	return httpx.BindingCookie{Name: "qe_passkey", Secure: h.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: sessionTTL}
}

func (h *Handler) loginBegin(w http.ResponseWriter, r *http.Request) {
	var in loginBeginInput
	// Body is optional: an empty body means discoverable (usernameless) login.
	if r.ContentLength != 0 {
		if err := httpx.DecodeStrictJSON(r, &in); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	sessionID, options, err := h.Service.BeginLogin(r.Context(), in.Email)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.binding().Add(w, r, sessionID.String())
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

type loginFinishInput struct {
	SessionID  uuid.UUID       `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

// loginFinish is the token form of passkey sign-in, for a server-side caller
// such as the console: it returns the token pair and sets no cookie, which is
// why it may skip the cross-site check. A browser on the hosted login uses
// loginSession instead, so no token pair reaches a page's script.
func (h *Handler) loginFinish(w http.ResponseWriter, r *http.Request) {
	var in loginFinishInput
	if err := httpx.DecodeStrictJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.Service.FinishLogin(r.Context(), in.SessionID, in.Credential, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

// loginSession is the hosted form of passkey sign-in: it sets the hosted-login
// SSO cookie, so the sign-in can drive the OAuth authorize flow, and returns
// only the user id. Only the browser that began the ceremony can finish it
// here; for any other the ceremony is left untouched.
func (h *Handler) loginSession(w http.ResponseWriter, r *http.Request) {
	var in loginFinishInput
	if err := httpx.DecodeStrictJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ceremony := in.SessionID.String()
	if !h.binding().Holds(r, ceremony) {
		httpx.WriteError(w, r, ErrBrowserMismatch)
		return
	}
	userID, raw, err := h.Service.FinishLoginSession(r.Context(), in.SessionID, in.Credential, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.binding().Remove(w, r, ceremony)
	auth.SetLoginSessionCookie(w, raw, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user_id": userID})
}

type signupBeginInput struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// signupBegin starts an organization-less passkey-first signup, the passwordless
// POST /auth/signup. Like the password endpoints it answers no sooner than
// 250ms and reports errors through writeSignupError.
func (h *Handler) signupBegin(w http.ResponseWriter, r *http.Request) {
	const signupFloor = 250 * time.Millisecond
	start := time.Now()
	defer httpx.ConstantTimeFloor(r.Context(), start, signupFloor)

	var in signupBeginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sessionID, options, err := h.Service.BeginSignup(r.Context(), in.Email, in.DisplayName)
	if err != nil {
		writeSignupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

type signupFinishInput struct {
	SessionID  uuid.UUID       `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

func (h *Handler) signupFinish(w http.ResponseWriter, r *http.Request) {
	var in signupFinishInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, userID, err := h.Service.FinishSignup(r.Context(), in.SessionID, in.Credential, in.Name, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		writeSignupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"user_id":       userID,
		"access_token":  pair.AccessToken,
		"token_type":    pair.TokenType,
		"expires_at":    pair.ExpiresAt,
		"refresh_token": pair.RefreshToken,
		"session_id":    pair.SessionID,
	})
}

type organizationSignupBeginInput struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	Email          string    `json:"email"`
	DisplayName    string    `json:"display_name"`
}

// organizationSignupBegin starts an organization-scoped passkey-first signup — the
// passwordless counterpart to POST /auth/register (hosted self-registration).
func (h *Handler) organizationSignupBegin(w http.ResponseWriter, r *http.Request) {
	const signupFloor = 250 * time.Millisecond
	start := time.Now()
	defer httpx.ConstantTimeFloor(r.Context(), start, signupFloor)

	var in organizationSignupBeginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.OrganizationID == uuid.Nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("organization_id is required"))
		return
	}
	sessionID, options, err := h.Service.BeginOrganizationSignup(r.Context(), in.OrganizationID, in.Email, in.DisplayName)
	if err != nil {
		writeSignupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

func (h *Handler) organizationSignupFinish(w http.ResponseWriter, r *http.Request) {
	var in signupFinishInput
	if err := httpx.DecodeStrictJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, raw, err := h.Service.FinishOrganizationSignup(r.Context(), in.SessionID, in.Credential, in.Name, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		writeSignupError(w, r, err)
		return
	}
	auth.SetLoginSessionCookie(w, raw, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"user_id": userID})
}

// writeSignupError answers an email that already has an account with the
// neutral 422 the password sign-up endpoints use (auth.NeutralSignupError), so
// the answer can't reveal whether an email is registered.
func writeSignupError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.WriteError(w, r, auth.NeutralSignupError(err))
}
