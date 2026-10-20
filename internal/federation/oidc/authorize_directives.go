package oidc

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The authorization request directives the endpoint honours, as discovery
// advertises them (QTID-163).
var (
	responseTypesSupported = []string{"code"}
	responseModesSupported = []string{"query"}
	promptValuesSupported  = []string{"none", "login", "consent"}
)

// loginAfterParam marks a request sent back from a forced sign-in: a hosted
// sign-in at or after this Unix time satisfies prompt=login and max_age, so
// the round trip ends.
const loginAfterParam = "login_after"

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
// A sign-in at or after the login_after marker (set when we sent the browser
// to sign in for this request) satisfies both.
func signInRequired(q url.Values, signedInAt, now time.Time) bool {
	if la, err := strconv.ParseInt(q.Get(loginAfterParam), 10, 64); err == nil && !signedInAt.Before(time.Unix(la, 0)) {
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

// reauthReturnTo is the authorize URL to come back to after a forced sign-in:
// the same request, marked so the fresh sign-in ends the round trip.
func reauthReturnTo(r *http.Request, now time.Time) string {
	u := *r.URL
	q := u.Query()
	q.Set(loginAfterParam, strconv.FormatInt(now.Unix(), 10))
	u.RawQuery = q.Encode()
	return externalScheme(r) + "://" + r.Host + u.RequestURI()
}
