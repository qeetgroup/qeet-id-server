package oidc

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func (h *Handler) tokenCode(w http.ResponseWriter, r *http.Request) {
	if err := httpx.ParseForm(r, httpx.MaxFormBodyBytes); err != nil {
		writeTokenError(w, r, err)
		return
	}
	// RFC 8707 §2 — validate the optional resource indicator if present.
	// The resource must be an absolute URI with a scheme; fragment components
	// are forbidden. An unrecognised or malformed value yields invalid_target.
	resource := r.Form.Get("resource")
	if resource != "" {
		u, parseErr := url.Parse(resource)
		if parseErr != nil || !u.IsAbs() || u.Fragment != "" {
			writeTokenError(w, r, oauthErr("invalid_target", "resource must be an absolute URI without a fragment"))
			return
		}
	}
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		clientID, clientSecret = u, p
	}
	grantType := r.Form.Get("grant_type")
	if resource != "" && (grantType == grantTypeDeviceCode || grantType == grantTypeCIBA) {
		// Explicitly refused, never silently dropped: these flows bind no resource.
		writeTokenError(w, r, oauthErr("invalid_target", "resource indicators aren't supported on the device and backchannel flows"))
		return
	}
	var resp *TokenResponse
	var err error
	switch grantType {
	case "authorization_code":
		resp, err = h.Service.ExchangeCode(r.Context(),
			clientID, clientSecret,
			r.Form.Get("code"), r.Form.Get("redirect_uri"), r.Form.Get("code_verifier"), resource)
	case "refresh_token":
		resp, err = h.Service.RefreshToken(r.Context(),
			clientID, clientSecret, r.Form.Get("refresh_token"), resource)
	case grantTypeTokenExchange:
		resp, err = h.Service.TokenExchange(r.Context(),
			clientID, clientSecret,
			r.Form.Get("subject_token"), r.Form.Get("subject_token_type"),
			r.Form.Get("requested_token_type"), r.Form.Get("scope"),
			r.Form.Get("actor_token"), r.Form.Get("actor_token_type"), resource)
	case grantTypeDeviceCode:
		// RFC 8628 §3.4 polling: a confidential client authenticates; for a public
		// one the device_code is the proof.
		resp, err = h.Service.DeviceToken(r.Context(), clientID, clientSecret, r.Form.Get("device_code"), httpx.ClientIP(r))
	case grantTypeCIBA:
		// OpenID CIBA §10 polling, answered like device_code polling.
		resp, err = h.Service.BackchannelToken(r.Context(), clientID, clientSecret, r.Form.Get("auth_req_id"))
	case "":
		err = oauthErr("invalid_request", "grant_type is required")
	default:
		err = errs.ErrOIDCGrantTypeUnsupported
	}
	if err != nil {
		writeTokenError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// tokenErrorCodes are the RFC 6749 §5.2 codes of the grants' own errors; any
// other client error is invalid_request.
var tokenErrorCodes = map[string]string{
	errs.CodeOIDCClientAuthFailed:               "invalid_client",
	errs.CodeOIDCGrantTypeUnsupported:           "unsupported_grant_type",
	errs.CodeOIDCGrantTypeNotAllowed:            "unauthorized_client",
	errs.CodeOIDCAuthCodeInvalid:                "invalid_grant",
	errs.CodeOIDCAuthCodeUsed:                   "invalid_grant",
	errs.CodeOIDCAuthCodeExpired:                "invalid_grant",
	errs.CodeOIDCRedirectURIMismatch:            "invalid_grant",
	errs.CodeOIDCCodeChallengeRequired:          "invalid_grant",
	errs.CodeOIDCCodeChallengeMethodUnsupported: "invalid_grant",
	errs.CodeOIDCCodeVerifierRequired:           "invalid_grant",
	errs.CodeOIDCCodeVerifierInvalid:            "invalid_grant",
	errs.CodeOIDCRefreshTokenInvalid:            "invalid_grant",
	errs.CodeOIDCRefreshTokenClientMismatch:     "invalid_grant",
	errs.CodeOIDCRefreshTokenRevoked:            "invalid_grant",
	errs.CodeOIDCRefreshTokenExpired:            "invalid_grant",
	errs.CodeOIDCRefreshTokenReuse:              "invalid_grant",
	errs.CodeAuthAccountSuspended:               "invalid_grant",
	errs.CodeOIDCUserTenantMismatch:             "invalid_grant",
	errs.CodeOIDCScopeExceedsSubject:            "invalid_scope",
}

// writeTokenError answers a failed token request in the RFC 6749 §5.2 shape,
// with a Basic challenge on invalid_client when the client sent Basic
// credentials. An internal error keeps the generic answer.
func writeTokenError(w http.ResponseWriter, r *http.Request, err error) {
	var oe *oauthError
	if !errors.As(err, &oe) {
		e := errs.As(err)
		if e == nil || e.Code == errs.CodeInternal {
			httpx.WriteError(w, r, err)
			return
		}
		code, ok := tokenErrorCodes[e.Code]
		if !ok {
			code = "invalid_request"
		}
		oe = oauthErr(code, e.Message)
	}
	if _, _, basic := r.BasicAuth(); basic && oe.Code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Basic realm="qeet"`)
	}
	writeOAuthError(w, oe)
}

// clientCreds parses OAuth client credentials from the form body or HTTP Basic
// auth (the two RFC 6749 §2.3.1 mechanisms). Shared by revoke + introspect.
func (h *Handler) clientCreds(r *http.Request) (id, secret string, err error) {
	if err := httpx.ParseForm(r, httpx.MaxFormBodyBytes); err != nil {
		return "", "", err
	}
	id = r.Form.Get("client_id")
	secret = r.Form.Get("client_secret")
	if u, p, has := r.BasicAuth(); has {
		id, secret = u, p
	}
	return id, secret, nil
}

// revoke is the RFC 7009 token-revocation endpoint. It always answers 200 with
// an empty body on success (including for unknown tokens).
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := h.clientCreds(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RevokeToken(r.Context(), clientID, clientSecret, r.Form.Get("token"), r.Form.Get("token_type_hint")); err != nil {
		var oe *oauthError
		if errors.As(err, &oe) {
			writeOAuthError(w, oe)
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// introspect is the RFC 7662 token-introspection endpoint.
func (h *Handler) introspect(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := h.clientCreds(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	resp, err := h.Service.Introspect(r.Context(), clientID, clientSecret, r.Form.Get("token"), r.Form.Get("token_type_hint"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
