package oidc

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// The authorization request directives the endpoint honours, as discovery
// advertises them.
var (
	responseTypesSupported = []string{"code"}
	responseModesSupported = []string{"query"}
	promptValuesSupported  = []string{"none", "login", "consent"}
)

// loginAfterParam marks a request sent back from a forced sign-in: a hosted
// sign-in at or after the time it names satisfies prompt=login and max_age, so
// the round trip ends. It is a short-lived token the server signs, so it can't
// be added by hand to skip the sign-in.
const loginAfterParam = "login_after"

// loginAfterTTL is how long a forced sign-in may take before its marker no
// longer ends the round trip.
const loginAfterTTL = 30 * time.Minute

// loginAfterMarker is the signed login_after value for a forced sign-in sent
// at now.
func (s *Service) loginAfterMarker(now time.Time) (string, error) {
	return s.issuer.Sign(jwt.MapClaims{
		"iss": s.issuer.JWTIssuer(),
		"typ": loginAfterParam,
		"la":  now.Unix(),
		"iat": now.Unix(),
		"exp": now.Add(loginAfterTTL).Unix(),
	})
}

// loginAfter is the time q's login_after marker names, or zero when it has
// none this server signed and still lives.
func (s *Service) loginAfter(q url.Values) time.Time {
	raw := q.Get(loginAfterParam)
	if raw == "" {
		return time.Time{}
	}
	claims, err := s.issuer.VerifySigned(raw)
	if err != nil || claims["typ"] != loginAfterParam {
		return time.Time{}
	}
	la, ok := claims["la"].(float64)
	if !ok {
		return time.Time{}
	}
	return time.Unix(int64(la), 0)
}

// checkAuthorizeRequest refuses what the endpoint doesn't do, instead of
// silently ignoring it: a missing or unsupported response_type, request
// objects, and any response_mode but query.
func checkAuthorizeRequest(q url.Values) error {
	switch rt := q.Get("response_type"); {
	case rt == "":
		return oauthErr("invalid_request", "response_type is required")
	case rt != "code":
		return oauthErr("unsupported_response_type", "only response_type=code is supported")
	}
	if q.Get("request") != "" {
		return oauthErr("request_not_supported", "request objects are not supported")
	}
	if q.Get("request_uri") != "" {
		return oauthErr("request_uri_not_supported", "request_uri is not supported")
	}
	if rm := q.Get("response_mode"); rm != "" && rm != "query" {
		return oauthErr("invalid_request", "only response_mode=query is supported")
	}
	if ma := q.Get("max_age"); ma != "" {
		if n, err := strconv.Atoi(ma); err != nil || n < 0 {
			return oauthErr("invalid_request", "max_age must be a non-negative number of seconds")
		}
	}
	return nil
}

// prompts is the request's prompt values.
func prompts(q url.Values) []string { return strings.Fields(q.Get("prompt")) }

// signInRequired reports whether the request needs a fresh sign-in although a
// hosted-login session exists: prompt=login, or a session older than max_age.
// A sign-in at or after loginAfter (the verified marker set when we sent the
// browser to sign in for this request; zero: none) satisfies both.
func signInRequired(q url.Values, loginAfter, signedInAt, now time.Time) bool {
	if signedInForRequest(loginAfter, signedInAt) {
		return false
	}
	if slices.Contains(prompts(q), "login") {
		return true
	}
	if ma, err := strconv.Atoi(q.Get("max_age")); err == nil && now.Sub(signedInAt) > time.Duration(ma)*time.Second {
		return true
	}
	return false
}

// signedInForRequest reports whether the hosted sign-in happened at or after
// loginAfter (zero: no marker): the browser was sent to sign in for this
// request and has.
func signedInForRequest(loginAfter, signedInAt time.Time) bool {
	return !loginAfter.IsZero() && !signedInAt.Before(loginAfter)
}

// reauthReturnTo is the authorize URL to come back to after a forced sign-in:
// the same request, marked so the fresh sign-in ends the round trip.
func (h *Handler) reauthReturnTo(r *http.Request, now time.Time) (string, error) {
	marker, err := h.Service.loginAfterMarker(now)
	if err != nil {
		return "", err
	}
	u := *r.URL
	q := u.Query()
	q.Set(loginAfterParam, marker)
	u.RawQuery = q.Encode()
	return httpx.PublicOrigin(r, h.PublicBaseURL) + u.RequestURI(), nil
}

// reauth sends the browser to sign in again for this request.
func (h *Handler) reauth(w http.ResponseWriter, r *http.Request, now time.Time) {
	back, err := h.reauthReturnTo(r, now)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	http.Redirect(w, r, h.LoginBaseURL+"/sign-in?prompt=login&return_to="+url.QueryEscape(back), http.StatusFound)
}
