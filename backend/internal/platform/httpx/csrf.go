package httpx

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// CSRF protects mutation routes from cross-site request forgery. The
// strategy is **double-submit cookie + strict origin check**:
//
//   1. On any unauthenticated GET we issue a `qe_csrf` cookie carrying
//      a random 32-byte token (SameSite=Strict, Secure outside dev).
//   2. Mutation requests (POST/PUT/PATCH/DELETE) must echo the same
//      token in the `X-CSRF-Token` header. The middleware compares
//      header and cookie under constant-time equality and rejects on
//      mismatch.
//   3. If an `Origin` (or `Referer` fallback) header is present we
//      additionally require it to match one of the configured
//      allow-listed origins. This stops drive-by POSTs entirely on
//      modern browsers.
//
// We deliberately keep the middleware *additive*: requests that
// authenticate purely via `Authorization: Bearer …` (today's default)
// are skipped because they aren't browser-attackable in the cookie
// sense. The hooks land now so the day cookie-bearing sessions ship
// (IMPROVEMENTS §1.1 done-when), the wiring is already on every
// mutation route.

const (
	csrfCookieName = "qe_csrf"
	csrfHeaderName = "X-CSRF-Token"
)

var errCSRFFailed = errors.New("csrf check failed")

// CSRFConfig tunes the middleware behaviour. AllowedOrigins is matched
// scheme + host + (optional) port. CookieSecure should be true outside
// dev so the cookie is only sent over HTTPS.
type CSRFConfig struct {
	AllowedOrigins []string
	CookieSecure   bool
	// CookieDomain is set on issuance so a single token works across
	// sub-domains (e.g. admin.qeetid.com / api.qeetid.com). Leave empty
	// to scope strictly to the issuing host.
	CookieDomain string
	// ExemptPaths are URL-path prefixes the double-submit/origin check is
	// skipped for. Reserved for endpoints that are authenticated by another
	// mechanism and are legitimately invoked cross-site by a third party —
	// e.g. a SAML Assertion Consumer Service, which the IdP form-POSTs to and
	// which is protected by XML-signature validation, not a CSRF cookie.
	ExemptPaths []string
}

// CSRF returns a chi-compatible middleware enforcing the rules above.
// It is safe to mount globally — read-only methods short-circuit
// without touching cookies, and bearer-token requests bypass entirely.
func CSRF(cfg CSRFConfig) func(http.Handler) http.Handler {
	allowed := normaliseOrigins(cfg.AllowedOrigins)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ensure every browser response carries the token so a
			// subsequent mutation has a cookie to echo. Issuing on
			// every GET means SPAs don't need a dedicated bootstrap
			// endpoint.
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				ensureCSRFCookie(w, r, cfg)
				next.ServeHTTP(w, r)
				return
			}

			// Bearer-token requests aren't browser-CSRF-attackable in
			// the cookie sense. Skip the check so M2M API key /
			// service-JWT traffic isn't burdened with token plumbing.
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				next.ServeHTTP(w, r)
				return
			}

			// Explicitly-exempt paths (e.g. SAML ACS) are authenticated by
			// another mechanism and are invoked cross-site by design.
			for _, p := range cfg.ExemptPaths {
				if strings.HasPrefix(r.URL.Path, p) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Origin / Referer check. Browsers always send at least
			// one of them on cross-site mutations; missing both is
			// either a server-to-server call (handled above by the
			// bearer skip) or an old browser we don't trust.
			if err := checkOrigin(r, allowed); err != nil {
				WriteJSON(w, http.StatusForbidden, map[string]string{
					"error":   "csrf_failed",
					"message": err.Error(),
				})
				return
			}

			// Double-submit token check.
			if err := checkToken(r); err != nil {
				WriteJSON(w, http.StatusForbidden, map[string]string{
					"error":   "csrf_failed",
					"message": err.Error(),
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func ensureCSRFCookie(w http.ResponseWriter, r *http.Request, cfg CSRFConfig) {
	if c, _ := r.Cookie(csrfCookieName); c != nil && len(c.Value) >= 22 {
		return
	}
	tok, err := newCSRFToken()
	if err != nil {
		return // best-effort; failure to seed leaves later POSTs to retry
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    tok,
		Path:     "/",
		Domain:   cfg.CookieDomain,
		Secure:   cfg.CookieSecure,
		HttpOnly: false, // JS needs to read this to echo it on XHR
		SameSite: http.SameSiteStrictMode,
		MaxAge:   60 * 60 * 12, // 12h — refreshed on every GET
	})
}

func checkToken(r *http.Request) error {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return errors.New("missing csrf cookie")
	}
	header := r.Header.Get(csrfHeaderName)
	if header == "" {
		return errors.New("missing csrf header")
	}
	// Constant-time equality so an attacker can't probe via timing.
	if !hmac.Equal([]byte(cookie.Value), []byte(header)) {
		return errCSRFFailed
	}
	return nil
}

func checkOrigin(r *http.Request, allowed map[string]struct{}) error {
	candidate := r.Header.Get("Origin")
	if candidate == "" {
		// Fall back to Referer for browsers that strip Origin on
		// same-site navigations.
		candidate = r.Header.Get("Referer")
	}
	if candidate == "" {
		return errors.New("missing Origin and Referer")
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Host == "" {
		return errors.New("malformed Origin")
	}
	key := strings.ToLower(u.Scheme + "://" + u.Host)
	if _, ok := allowed[key]; !ok {
		return errors.New("origin not allow-listed")
	}
	return nil
}

func normaliseOrigins(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(strings.TrimSuffix(raw, "/"))
		if raw == "" || raw == "*" {
			continue
		}
		out[strings.ToLower(raw)] = struct{}{}
	}
	return out
}

func newCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Bind to a server-side static keyed hash so we can identify
	// tampered tokens deterministically later (e.g. for a /csrf/rotate
	// flow). The mac itself isn't security-critical here — the random
	// half already is — it just gives us a versionable shape.
	mac := hmac.New(sha256.New, []byte("qeet-csrf-v1"))
	mac.Write(b)
	suffix := mac.Sum(nil)[:8]
	return base64.RawURLEncoding.EncodeToString(append(b, suffix...)), nil
}
