package httpx

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const (
	csrfCookieName = "qe_csrf"
	csrfHeaderName = "X-CSRF-Token"

	// The per-browser nonce every token is bound to. HttpOnly, and over HTTPS
	// __Host- prefixed, so a sibling subdomain can neither read nor toss one.
	csrfNonceCookie       = "qe_csrf_nonce"
	csrfNonceCookieSecure = "__Host-qe_csrf_nonce"

	csrfMACPurpose = "csrf-token-v2"
	csrfVersion    = "v2"
	csrfRandomSize = 32
	csrfTokenTTL   = 12 * 60 * 60
	csrfNonceTTL   = 30 * 24 * 60 * 60
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

// CSRFKey MACs tokens with a server secret. Satisfied by *envelope.Cipher (an
// HKDF subkey of the data key, so tokens survive its rotation).
type CSRFKey interface {
	MAC(purpose string, msg []byte) (keyID string, mac []byte)
	CheckMAC(purpose, keyID string, msg, mac []byte) bool
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
	Key         CSRFKey // required
	// SessionCookie names the session cookie a token is also bound to (qe_ls).
	SessionCookie string
	// A response setting or clearing SessionCookie or one of RotateCookies, or
	// a successful one on a RotatePaths path, carries a new token.
	RotateCookies []string
	RotatePaths   []string
}

// CSRF returns middleware that guards against cross-site request forgery with
// a signed double-submit token (OWASP), bound to the browser's nonce and its
// session. GET, HEAD and OPTIONS pass, setting the qe_csrf cookie if missing
// or not valid for them. Other methods need an allow-listed Origin (or
// Referer) and a valid cookie echoed in X-CSRF-Token, unless they carry a
// Bearer or ApiKey credential or match ExemptPaths. It panics without a Key.
func CSRF(cfg CSRFConfig) func(http.Handler) http.Handler {
	if cfg.Key == nil {
		panic("httpx: CSRF needs a key")
	}
	c := &csrf{cfg: cfg, allowed: normaliseOrigins(cfg.AllowedOrigins), nonceName: csrfNonceCookie}
	if cfg.CookieSecure {
		c.nonceName = csrfNonceCookieSecure
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &csrfRotator{ResponseWriter: w, csrf: c, r: r, rotatePath: c.rotates(r)}
			// Ensure every browser response carries a token so a subsequent
			// mutation has a cookie to echo. Issuing on every GET means SPAs
			// don't need a dedicated bootstrap endpoint.
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				c.ensure(rw, r)
				next.ServeHTTP(rw, r)
				return
			}

			// A browser never sends a bearer token or API key on its own, and
			// a cross-site page can't add an Authorization header without a
			// CORS preflight, so these can't be forged; server-side callers
			// send no Origin. Basic doesn't count: browsers replay it.
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") || strings.HasPrefix(h, "ApiKey ") {
				next.ServeHTTP(rw, r)
				return
			}

			// Explicitly-exempt paths (e.g. SAML ACS) are authenticated by
			// another mechanism and are invoked cross-site by design.
			for _, p := range cfg.ExemptPaths {
				if matchExemptPath(p, r.URL.Path) {
					next.ServeHTTP(rw, r)
					return
				}
			}

			// Origin / Referer check. Browsers always send at least
			// one of them on cross-site mutations; missing both is
			// either a server-to-server call (handled above by the
			// bearer skip) or an old browser we don't trust.
			if err := checkOrigin(r, c.allowed); err != nil {
				WriteError(w, r, ErrCSRFFailed.WithDetail(err.Error()))
				return
			}

			// Double-submit token check.
			if err := c.checkToken(r); err != nil {
				WriteError(w, r, ErrCSRFFailed.WithDetail(err.Error()))
				return
			}

			next.ServeHTTP(rw, r)
		})
	}
}

type csrf struct {
	cfg       CSRFConfig
	allowed   map[string]struct{}
	nonceName string
}

// binding is what a token is bound to: the browser's nonce and its session ("" for none).
type binding struct {
	nonce   string
	session string
}

func cookieValue(r *http.Request, name string) string {
	if name == "" {
		return ""
	}
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

func (c *csrf) bindingOf(r *http.Request) binding {
	return binding{nonce: cookieValue(r, c.nonceName), session: cookieValue(r, c.cfg.SessionCookie)}
}

// fingerprint is fixed-length, so two fields of a MAC'd message can't run together.
func fingerprint(value string) string {
	if value == "" {
		return "-"
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func browserMessage(random []byte, b binding) []byte {
	return append([]byte("browser|"+fingerprint(b.nonce)+"|"), random...)
}

func sessionMessage(random []byte, b binding) []byte {
	return append([]byte("session|"+fingerprint(b.nonce)+"|"+fingerprint(b.session)+"|"), random...)
}

// newToken is "v2.<key id>.<random>.<browser MAC>.<session MAC>".
func (c *csrf) newToken(b binding) (string, error) {
	random := make([]byte, csrfRandomSize)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	keyID, browserMAC := c.cfg.Key.MAC(csrfMACPurpose, browserMessage(random, b))
	_, sessionMAC := c.cfg.Key.MAC(csrfMACPurpose, sessionMessage(random, b))
	enc := base64.RawURLEncoding
	return strings.Join([]string{csrfVersion, keyID, enc.EncodeToString(random), enc.EncodeToString(browserMAC), enc.EncodeToString(sessionMAC)}, "."), nil
}

// valid reports whether token was issued for b. Without a session only the
// browser is checked, so an expired session's token still works pre-sign-in.
func (c *csrf) valid(token string, b binding) bool {
	parts := strings.Split(token, ".")
	if b.nonce == "" || len(parts) != 5 || parts[0] != csrfVersion {
		return false
	}
	enc := base64.RawURLEncoding
	random, err1 := enc.DecodeString(parts[2])
	browserMAC, err2 := enc.DecodeString(parts[3])
	sessionMAC, err3 := enc.DecodeString(parts[4])
	if err1 != nil || err2 != nil || err3 != nil || len(random) != csrfRandomSize {
		return false
	}
	if !c.cfg.Key.CheckMAC(csrfMACPurpose, parts[1], browserMessage(random, b), browserMAC) {
		return false
	}
	return b.session == "" || c.cfg.Key.CheckMAC(csrfMACPurpose, parts[1], sessionMessage(random, b), sessionMAC)
}

func (c *csrf) ensure(rw *csrfRotator, r *http.Request) {
	b := c.bindingOf(r)
	if b.nonce != "" && c.valid(cookieValue(r, csrfCookieName), b) {
		return
	}
	c.issue(rw.Header(), b)
}

// issue sets a new token for b, minting b's nonce if it has none. Best effort.
func (c *csrf) issue(header http.Header, b binding) {
	if b.nonce == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return
		}
		b.nonce = base64.RawURLEncoding.EncodeToString(raw)
	}
	tok, err := c.newToken(b)
	if err != nil {
		return
	}
	dropSetCookie(header, csrfCookieName, c.nonceName)
	// Renewed with each token, so it outlives every token bound to it.
	header.Add("Set-Cookie", (&http.Cookie{ // #nosec G124 -- Secure is off only in dev
		Name:     c.nonceName,
		Value:    b.nonce,
		Path:     "/",
		Secure:   c.cfg.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   csrfNonceTTL,
	}).String())
	header.Add("Set-Cookie", (&http.Cookie{ // #nosec G124 -- double-submit token, JS-readable by design
		Name:     csrfCookieName,
		Value:    tok,
		Path:     "/",
		Domain:   c.cfg.CookieDomain,
		Secure:   c.cfg.CookieSecure,
		HttpOnly: false, // JS needs to read this to echo it on XHR
		SameSite: http.SameSiteStrictMode,
		MaxAge:   csrfTokenTTL,
	}).String())
}

func dropSetCookie(header http.Header, names ...string) {
	lines := header.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	header.Del("Set-Cookie")
	for _, line := range lines {
		keep := true
		for _, name := range names {
			if strings.HasPrefix(line, name+"=") {
				keep = false
			}
		}
		if keep {
			header.Add("Set-Cookie", line)
		}
	}
}

func (c *csrf) checkToken(r *http.Request) error {
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
	if !c.valid(header, c.bindingOf(r)) {
		return errors.New("csrf token not issued for this browser and session")
	}
	return nil
}

func (c *csrf) rotates(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	for _, p := range c.cfg.RotatePaths {
		if r.URL.Path == p {
			return true
		}
	}
	return false
}

// csrfRotator issues a new token just before a rotating response's headers go out.
type csrfRotator struct {
	http.ResponseWriter
	csrf       *csrf
	r          *http.Request
	rotatePath bool
	wrote      bool
}

func (w *csrfRotator) WriteHeader(code int) {
	w.before(code)
	w.ResponseWriter.WriteHeader(code)
}

func (w *csrfRotator) Write(b []byte) (int, error) {
	w.before(http.StatusOK)
	return w.ResponseWriter.Write(b)
}

func (w *csrfRotator) Flush() {
	w.before(http.StatusOK)
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *csrfRotator) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *csrfRotator) before(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	b := w.csrf.bindingOf(w.r)
	changed := false
	for _, line := range w.Header().Values("Set-Cookie") {
		set, err := http.ParseSetCookie(line)
		if err != nil {
			continue
		}
		switch {
		case set.Name == w.csrf.cfg.SessionCookie && set.Name != "":
			changed = true
			b.session = set.Value
			if set.MaxAge < 0 {
				b.session = ""
			}
		case contains(w.csrf.cfg.RotateCookies, set.Name):
			changed = true
		case set.Name == w.csrf.nonceName:
			b.nonce = set.Value // issued earlier in this response
		}
	}
	if changed || (w.rotatePath && code >= 200 && code < 300) {
		w.csrf.issue(w.Header(), b)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
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

// MatchExemptPathForTest exposes the exemption matcher so the composition root
// can assert no authenticated route is covered by an entry.
func MatchExemptPathForTest(pattern, path string) bool { return matchExemptPath(pattern, path) }
