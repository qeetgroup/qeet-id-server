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

const (
	csrfCookieName = "qe_csrf"
	csrfHeaderName = "X-CSRF-Token"
)

var errCSRFFailed = errors.New("csrf check failed")

// matchExemptPath reports whether path is covered by a CSRF exemption entry.
// A trailing "/" makes the entry a prefix; a "*" segment matches exactly one
// path segment; otherwise the whole path must match.
func matchExemptPath(pattern, path string) bool {
	if !strings.Contains(pattern, "*") {
		if strings.HasSuffix(pattern, "/") {
			return strings.HasPrefix(path, pattern)
		}
		return path == pattern
	}
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	if len(patternParts) != len(pathParts) {
		return false
	}
	for i, part := range patternParts {
		if part != "*" && part != pathParts[i] {
			return false
		}
	}
	return true
}

// CSRFConfig tunes the middleware behaviour. AllowedOrigins is matched
// scheme + host + (optional) port. CookieSecure should be true outside
// dev so the cookie is only sent over HTTPS.
type CSRFConfig struct {
	AllowedOrigins []string
	CookieSecure   bool
	// CookieDomain is set on issuance so a single token works across
	// sub-domains (e.g. admin.id.qeet.in / api.id.qeet.in). Leave empty
	// to scope strictly to the issuing host.
	CookieDomain string
	// ExemptPaths skip the check, for routes another mechanism authenticates and a
	// third party posts to cross-site, such as a SAML ACS. An entry ending in "/" is
	// a prefix and "*" matches one segment; prefer exact paths, since a prefix also
	// exempts any mutation added under it later.
	ExemptPaths []string
}

// CSRF returns middleware that guards against cross-site request forgery. GET,
// HEAD and OPTIONS pass, setting the qe_csrf cookie if missing. Other methods
// need an allow-listed Origin (or Referer) and the cookie echoed in X-CSRF-Token,
// unless they carry a Bearer or ApiKey credential or match ExemptPaths.
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

			// A browser never sends a bearer token or API key on its own, and
			// a cross-site page can't add an Authorization header without a
			// CORS preflight, so these can't be forged; server-side callers
			// send no Origin. Basic doesn't count: browsers replay it.
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") || strings.HasPrefix(h, "ApiKey ") {
				next.ServeHTTP(w, r)
				return
			}

			// Explicitly-exempt paths (e.g. SAML ACS) are authenticated by
			// another mechanism and are invoked cross-site by design.
			for _, p := range cfg.ExemptPaths {
				if matchExemptPath(p, r.URL.Path) {
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
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- double-submit token, JS-readable by design
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
	// The MAC suffix only gives tokens a versioned shape; the random bytes carry
	// the security.
	mac := hmac.New(sha256.New, []byte("qeet-csrf-v1"))
	mac.Write(b)
	suffix := mac.Sum(nil)[:8]
	return base64.RawURLEncoding.EncodeToString(append(b, suffix...)), nil
}

// MatchExemptPathForTest exposes the exemption matcher so the composition root
// can assert no authenticated route is covered by an entry.
func MatchExemptPathForTest(pattern, path string) bool { return matchExemptPath(pattern, path) }
