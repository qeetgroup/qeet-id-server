package auth

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type sessionInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=1"`
	// ClientID is the OAuth client the hosted login is serving; its organization's
	// sign-in lockout settings apply. Optional (none = the platform defaults).
	ClientID string `json:"client_id" validate:"omitempty,max=255"`
}

// createSession is the hosted-login credential endpoint. On success it sets the
// HttpOnly SSO cookie (qe_ls) and returns the user ID, with no tokens in the
// body. When the user needs a second factor it returns an MFA challenge instead,
// completed at POST /v1/auth/session/mfa.
func (h *Handler) createSession(w http.ResponseWriter, r *http.Request) {
	var in sessionInput
	if err := httpx.DecodeStrictJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	h.evalBot(r, in.Email)
	// A trusted-device cookie (when the organization allows adaptive MFA) lets an
	// enrolled user skip the second factor on a previously-remembered device.
	trusted := ""
	if c, cerr := r.Cookie(TrustedDeviceCookie); cerr == nil {
		trusted = c.Value
	}
	res, err := h.Service.BeginLoginSession(r.Context(), SignInAttempt{
		Email:    in.Email,
		Password: in.Password,
		ClientID: in.ClientID,
		Actor:    audit.ActorOf(r),
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
	if err := httpx.DecodeStrictJSON(r, &in); err != nil {
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
	// organization has opted into adaptive MFA, so a client-supplied flag can't grant
	// trust the policy forbids. A skipped setup met no factor, so earns none.
	if in.Remember && !res.Deferred {
		if draw, ttl, derr := h.Service.MaybeRememberDevice(r.Context(), res.UserID, res.OrganizationID, r.UserAgent()); derr == nil && draw != "" {
			SetTrustedDeviceCookie(w, draw, ttl, h.CookieSecure)
		}
	}
	body := map[string]any{"user_id": res.UserID}
	if len(res.RecoveryCodes) > 0 {
		body["recovery_codes"] = res.RecoveryCodes
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

// destroySession signs the browser out of the hosted login and clears the
// cookie. Without a session cookie it still answers 204. If sign-out fails the
// cookie is kept so the browser can retry.
func (h *Handler) destroySession(w http.ResponseWriter, r *http.Request) {
	var uris []string
	if c, err := r.Cookie(LoginSessionCookie); err == nil {
		ended, err := h.Service.EndLoginSession(r.Context(), EndLoginSessionInput{
			Cookie: c.Value, InitiatedBy: SignOutByHostedLogin, Actor: audit.ActorOf(r),
		})
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		uris = ended.FrontChannelLogoutURIs
	}
	ClearLoginSessionCookie(w, h.CookieSecure)
	if len(uris) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// The hosted login loads these to sign the browser out of each application.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"frontchannel_logout_uris": uris})
}
