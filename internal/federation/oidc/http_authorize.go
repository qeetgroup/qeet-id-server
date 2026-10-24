package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// authorize handles GET /oauth/authorize. It identifies the user by the SSO
// cookie and redirects to the hosted login, to the consent screen, or back to
// the client's redirect_uri with a code.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirect := q.Get("redirect_uri")
	state := q.Get("state")
	scopes := strings.Fields(q.Get("scope"))

	// Nothing about this request is trusted until its redirect_uri is one the
	// client registered: until then the error is shown here, never sent there.
	if !h.Service.RegisteredRedirect(r.Context(), clientID, redirect) {
		httpx.WriteError(w, r, errs.ErrOIDCRedirectURINotRegistered)
		return
	}
	if err := checkAuthorizeRequest(q); err != nil {
		h.authorizeError(w, r, clientID, redirect, state, err)
		return
	}
	silent := slices.Contains(prompts(q), "none")

	loginSessionID, userID, signedInAt, ok := h.loginSessionAt(r)
	now := time.Now()
	switch {
	case !ok && silent:
		h.authorizeError(w, r, clientID, redirect, state, oauthErr("login_required", "no active sign-in"))
		return
	case !ok:
		http.Redirect(w, r, h.LoginBaseURL+"/login?return_to="+url.QueryEscape(h.currentURL(r)), http.StatusFound)
		return
	case signInRequired(q, signedInAt, now) && silent:
		h.authorizeError(w, r, clientID, redirect, state, oauthErr("login_required", "a fresh sign-in is required"))
		return
	case signInRequired(q, signedInAt, now):
		// prompt=login or max_age: sign in again, then come back to this request.
		http.Redirect(w, r, h.LoginBaseURL+"/login?prompt=login&return_to="+url.QueryEscape(h.reauthReturnTo(r, now)), http.StatusFound)
		return
	}

	// The application's organisation may require a second factor this sign-in
	// didn't meet. The hosted sign-in asks for the requirement of the
	// application it serves, so the browser signs in again for this request,
	// once; a fresh sign-in that still hasn't met one is refused.
	switch err := h.factorShortfall(r.Context(), loginSessionID, userID, clientID); {
	case err == nil:
	case !isFactorShortfall(err):
		h.authorizeError(w, r, clientID, redirect, state, err)
		return
	case silent:
		h.authorizeError(w, r, clientID, redirect, state, oauthErr("interaction_required", "the organisation requires a second factor"))
		return
	case !signedInForRequest(q, signedInAt):
		http.Redirect(w, r, h.LoginBaseURL+"/login?prompt=login&return_to="+url.QueryEscape(h.reauthReturnTo(r, now)), http.StatusFound)
		return
	default:
		h.authorizeError(w, r, clientID, redirect, state, oauthErr("access_denied", "the organisation requires a second factor"))
		return
	}

	has, err := h.Service.HasConsent(r.Context(), userID, clientID, scopes)
	if err != nil {
		h.authorizeError(w, r, clientID, redirect, state, err)
		return
	}
	if !has && silent {
		h.authorizeError(w, r, clientID, redirect, state, oauthErr("consent_required", "consent is required"))
		return
	}
	if !has || slices.Contains(prompts(q), "consent") {
		// Hand off to the hosted consent screen with only the id of the request
		// stored here; the decision acts on the stored values, not on anything
		// the browser sends back.
		id, err := h.Service.StartConsentRequest(r.Context(), loginSessionID, userID, ConsentRequest{
			ClientID: clientID, RedirectURI: redirect, Scopes: scopes, State: state,
			Nonce: q.Get("nonce"), CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
			Resource: q.Get("resource"),
		})
		if err != nil {
			h.authorizeError(w, r, clientID, redirect, state, err)
			return
		}
		http.Redirect(w, r, h.LoginBaseURL+"/consent?request_id="+url.QueryEscape(id.String()), http.StatusFound)
		return
	}

	code, _, err := h.Service.AuthorizeInLoginSession(r.Context(), AuthorizeInput{
		LoginSessionID: loginSessionID, UserID: userID, ClientID: clientID, RedirectURI: redirect, Scopes: scopes,
		Nonce: q.Get("nonce"), CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
		IP: httpx.ClientIP(r), Resource: q.Get("resource"), AuthTime: signedInAt,
	})
	if err != nil {
		h.authorizeError(w, r, clientID, redirect, state, err)
		return
	}
	// RFC 9207: identify the issuer in the authorization response.
	http.Redirect(w, r, appendQuery(redirect, "code", code, "state", state, "iss", h.Service.issuer.JWTIssuer()), http.StatusFound) // #nosec G710 -- redirect_uri matched exactly against the registered list
}

// authorizeError reports a failure before a code was issued. Per RFC 6749
// §4.1.2.1 it redirects to the client's redirect_uri, but only when that URI is
// registered; otherwise it renders the error, so it is never an open redirect.
func (h *Handler) authorizeError(w http.ResponseWriter, r *http.Request, clientID, redirect, state string, err error) {
	if redirect == "" || !h.Service.RegisteredRedirect(r.Context(), clientID, redirect) {
		httpx.WriteError(w, r, err)
		return
	}
	oauthCode := "server_error"
	var oe *oauthError
	switch {
	case errors.As(err, &oe):
		oauthCode = oe.Code
	case errors.Is(err, errs.ErrOIDCUserTenantMismatch),
		errors.Is(err, errs.ErrAuthAddressNotAllowed):
		oauthCode = "access_denied"
	case errors.Is(err, errs.ErrOIDCScopeNotPermitted):
		oauthCode = "invalid_scope"
	case errors.Is(err, errs.ErrOIDCGrantTypeNotAllowed):
		oauthCode = "unauthorized_client"
	case errors.Is(err, errs.ErrOIDCCodeChallengeRequired),
		errors.Is(err, errs.ErrOIDCCodeChallengeInvalid),
		errors.Is(err, errs.ErrOIDCCodeChallengeMethodUnsupported),
		errors.Is(err, errs.ErrOIDCNonceRequired),
		errors.Is(err, errs.ErrOIDCNonceInvalid):
		oauthCode = "invalid_request"
	case errors.Is(err, errs.ErrOIDCRedirectURIInvalid):
		// The URI validated as registered above, so this is some other
		// redirect-shaped rejection; do not bounce it back.
		httpx.WriteError(w, r, err)
		return
	}
	http.Redirect(w, r, appendQuery(redirect, // #nosec G710 -- redirect_uri matched exactly against the registered list
		"error", oauthCode, "state", state, "iss", h.Service.issuer.JWTIssuer()), http.StatusFound)
}

type decisionInput struct {
	RequestID string `json:"request_id"`
	Approve   bool   `json:"approve"`
	// The request's own values, as an older consent screen echoed them. They
	// are optional and never used: one that is sent must match the stored
	// request, or the decision is refused.
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// matches reports whether every echoed value that was sent equals the stored
// request's.
func (in decisionInput) matches(req *ConsentRequest) bool {
	same := func(sent, stored string) bool { return sent == "" || sent == stored }
	return same(in.ClientID, req.ClientID) && same(in.RedirectURI, req.RedirectURI) &&
		same(strings.Join(strings.Fields(in.Scope), " "), strings.Join(req.Scopes, " ")) &&
		same(in.State, req.State) && same(in.Nonce, req.Nonce) &&
		same(in.CodeChallenge, req.CodeChallenge) && same(in.CodeChallengeMethod, req.CodeChallengeMethod)
}

// decision records the user's choice on the hosted consent screen and returns,
// as JSON, the URL to navigate to: a code on approval, or error=access_denied.
// The request's values come from storage, never from the browser.
func (h *Handler) decision(w http.ResponseWriter, r *http.Request) {
	loginSessionID, userID, ok := h.loginSession(r)
	if !ok {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in decisionInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(in.RequestID)
	if err != nil {
		httpx.WriteError(w, r, errs.ErrOIDCConsentRequestInvalid)
		return
	}
	req, err := h.Service.TakeConsentRequest(r.Context(), id, loginSessionID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if req.UserID != userID || !in.matches(req) {
		httpx.WriteError(w, r, errs.ErrOIDCConsentRequestInvalid)
		return
	}
	// The client may have dropped the address since the request was stored.
	if !h.Service.RegisteredRedirect(r.Context(), req.ClientID, req.RedirectURI) {
		httpx.WriteError(w, r, errs.ErrOIDCRedirectURINotRegistered)
		return
	}
	if !in.Approve {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"redirect": appendQuery(req.RedirectURI, "error", "access_denied", "state", req.State, "iss", h.Service.issuer.JWTIssuer()),
		})
		return
	}
	if err := h.factorShortfall(r.Context(), loginSessionID, userID, req.ClientID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.GrantConsent(r.Context(), userID, req.ClientID, req.Scopes); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	_, _, signedInAt, _ := h.loginSessionAt(r)
	code, _, err := h.Service.AuthorizeInLoginSession(r.Context(), AuthorizeInput{
		LoginSessionID: loginSessionID, UserID: userID, ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		Scopes: req.Scopes, Nonce: req.Nonce, CodeChallenge: req.CodeChallenge, CodeChallengeMethod: req.CodeChallengeMethod,
		IP: httpx.ClientIP(r), Resource: req.Resource, AuthTime: signedInAt,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"redirect": appendQuery(req.RedirectURI, "code", code, "state", req.State, "iss", h.Service.issuer.JWTIssuer()),
	})
}

// consentRequest is what the hosted consent screen shows: the client and the
// scopes of the stored request, for the browser that started it.
func (h *Handler) consentRequest(w http.ResponseWriter, r *http.Request) {
	loginSessionID, _, ok := h.loginSession(r)
	if !ok {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	id, err := uuid.Parse(r.URL.Query().Get("request_id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrOIDCConsentRequestInvalid)
		return
	}
	req, err := h.Service.GetConsentRequest(r.Context(), id, loginSessionID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"request_id": req.ID,
		"client_id":  req.ClientID,
		"scope":      strings.Join(req.Scopes, " "),
	})
}

// factorShortfall is what stops a code or token being issued for clientID's
// organisation through the hosted-login session: nil, or the second factor
// the organisation still requires (see auth.Service.LoginSessionFactorShortfall).
func (h *Handler) factorShortfall(ctx context.Context, loginSessionID, userID uuid.UUID, clientID string) error {
	tenantID, err := h.Service.ClientTenant(ctx, clientID)
	if err != nil {
		return err
	}
	return h.Sessions.LoginSessionFactorShortfall(ctx, loginSessionID, userID, tenantID)
}

// isFactorShortfall reports whether err is a second factor still required.
func isFactorShortfall(err error) bool {
	return errors.Is(err, errs.ErrStepUpRequired) || errors.Is(err, errs.ErrMFAEnrollmentRequired)
}
