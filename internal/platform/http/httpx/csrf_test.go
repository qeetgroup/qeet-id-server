package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
)

// noopHandler returns 200 so test cases can distinguish "passed
// middleware" (200) from "blocked" (403).
var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

const (
	testOrigin  = "https://app.id.qeet.in"
	testSession = "qe_ls"
	testPortal  = "portal_session"
)

func testKey(t *testing.T, secret string) *envelope.Cipher {
	t.Helper()
	key, err := envelope.New([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// testConfig is the check as the server mounts it.
func testConfig(t *testing.T) CSRFConfig {
	t.Helper()
	return CSRFConfig{
		AllowedOrigins: []string{testOrigin}, Key: testKey(t, "0123456789abcdef0123456789abcdef"),
		SessionCookie: testSession, RotateCookies: []string{testPortal}, RotatePaths: []string{"/v1/auth/switch-organization"},
	}
}

func withCSRF(t *testing.T, cfg CSRFConfig) http.Handler {
	t.Helper()
	return CSRF(cfg)(noopHandler)
}

// browser keeps the cookies it is given, as a browser does.
type browser struct {
	cookies map[string]string
}

func newBrowser() *browser { return &browser{cookies: map[string]string{}} }

func (b *browser) keep(rec *httptest.ResponseRecorder) {
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
			continue
		}
		b.cookies[c.Name] = c.Value
	}
}

func (b *browser) request(method, path string, echo bool) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", testOrigin)
	}
	if echo {
		req.Header.Set(csrfHeaderName, b.cookies[csrfCookieName])
	}
	return req
}

func (b *browser) do(h http.Handler, method, path string, echo bool) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, b.request(method, path, echo))
	b.keep(rec)
	return rec
}

// signedIn returns a browser holding a token, in session when it isn't "".
func signedIn(t *testing.T, h http.Handler, session string) *browser {
	t.Helper()
	b := newBrowser()
	if session != "" {
		b.cookies[testSession] = session
	}
	if rec := b.do(h, http.MethodGet, "/healthz", false); rec.Code != http.StatusOK || b.cookies[csrfCookieName] == "" {
		t.Fatalf("GET /healthz: %d, token %q; want a token", rec.Code, b.cookies[csrfCookieName])
	}
	return b
}

// TestCSRF_GETIssuesTokenAndNonce checks the token and nonce cookies a GET sets.
func TestCSRF_GETIssuesTokenAndNonce(t *testing.T) {
	for _, secure := range []bool{false, true} {
		cfg := testConfig(t)
		cfg.CookieSecure, cfg.CookieDomain = secure, ".id.qeet.in"
		rec := httptest.NewRecorder()
		withCSRF(t, cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		cookies := map[string]*http.Cookie{}
		for _, c := range rec.Result().Cookies() {
			cookies[c.Name] = c
		}
		nonceName := csrfNonceCookie
		if secure {
			nonceName = csrfNonceCookieSecure
		}
		token, nonce := cookies[csrfCookieName], cookies[nonceName]
		if rec.Code != http.StatusOK || token == nil || nonce == nil {
			t.Fatalf("secure %v: GET %d with cookies %v; want the token and the nonce", secure, rec.Code, cookies)
		}
		if token.HttpOnly || token.Domain != "id.qeet.in" || token.SameSite != http.SameSiteStrictMode || token.Secure != secure {
			t.Errorf("secure %v: token cookie %+v; want JS-readable, on the shared domain, SameSite=Strict", secure, token)
		}
		if !nonce.HttpOnly || nonce.Domain != "" || nonce.Path != "/" || nonce.Secure != secure {
			t.Errorf("secure %v: nonce cookie %+v; want HttpOnly, host-only, Path=/", secure, nonce)
		}
	}
}

func TestCSRF_ValidTokenAccepted(t *testing.T) {
	h := withCSRF(t, testConfig(t))
	for _, session := range []string{"", "session-a"} {
		b := signedIn(t, h, session)
		if rec := b.do(h, http.MethodPost, "/v1/auth/login", true); rec.Code != http.StatusOK {
			t.Errorf("session %q: a valid token: %d %s, want 200", session, rec.Code, rec.Body)
		}
		if rec := b.do(h, http.MethodGet, "/v1/me", false); len(rec.Result().Cookies()) != 0 {
			t.Errorf("session %q: a GET re-issued a valid token: %v", session, rec.Result().Cookies())
		}
	}
}

// TestCSRF_TokenIsBoundToItsSession checks that a matching cookie and header pair
// from session A, another browser or another key is refused.
func TestCSRF_TokenIsBoundToItsSession(t *testing.T) {
	h := withCSRF(t, testConfig(t))
	a := signedIn(t, h, "session-a")
	b := signedIn(t, h, "session-b")

	a.cookies[testSession] = "session-b"
	if rec := a.do(h, http.MethodPost, "/v1/passkeys/register/begin", true); rec.Code != http.StatusForbidden {
		t.Errorf("session A's token for session B: %d, want 403", rec.Code)
	}
	b.cookies[csrfCookieName] = a.cookies[csrfCookieName]
	if rec := b.do(h, http.MethodPost, "/v1/passkeys/register/begin", true); rec.Code != http.StatusForbidden {
		t.Errorf("another browser's token: %d, want 403", rec.Code)
	}
	c := signedIn(t, h, "session-c")
	for name, forged := range map[string]string{
		"old shape":     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"made up":       "v2.0011223344556677.cmFuZG9t.bWFj.bWFj",
		"another key's": tokenUnder(t, testKey(t, "fedcba9876543210fedcba9876543210"), c, "session-c"),
	} {
		c.cookies[csrfCookieName] = forged
		if rec := c.do(h, http.MethodPost, "/v1/passkeys/register/begin", true); rec.Code != http.StatusForbidden {
			t.Errorf("a %s token: %d, want 403", name, rec.Code)
		}
	}
	d := signedIn(t, h, "")
	delete(d.cookies, csrfNonceCookie)
	if rec := d.do(h, http.MethodPost, "/v1/auth/login", true); rec.Code != http.StatusForbidden {
		t.Errorf("a token without its nonce: %d, want 403", rec.Code)
	}
}

func tokenUnder(t *testing.T, key CSRFKey, b *browser, session string) string {
	t.Helper()
	tok, err := (&csrf{cfg: CSRFConfig{Key: key}}).newToken(binding{nonce: b.cookies[csrfNonceCookie], session: session})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestCSRF_TokensRotate checks that sign-in, sign-out, the organization switch and
// a portal session issue a new token, and an expired session's token still works.
func TestCSRF_TokensRotate(t *testing.T) {
	cfg := testConfig(t)
	var setSession, clearSession, setPortal bool
	h := CSRF(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch {
		case setSession:
			http.SetCookie(w, &http.Cookie{Name: testSession, Value: "session-new", Path: "/", HttpOnly: true})
		case clearSession:
			http.SetCookie(w, &http.Cookie{Name: testSession, Path: "/", MaxAge: -1})
		case setPortal:
			http.SetCookie(w, &http.Cookie{Name: testPortal, Value: "portal", Path: "/v1/admin-portal"})
		}
		w.WriteHeader(http.StatusOK)
	}))
	b := signedIn(t, h, "")
	before := b.cookies[csrfCookieName]

	setSession = true
	if rec := b.do(h, http.MethodPost, "/v1/auth/session", true); rec.Code != http.StatusOK {
		t.Fatalf("sign in: %d", rec.Code)
	}
	setSession = false
	signedInToken := b.cookies[csrfCookieName]
	if signedInToken == before || b.cookies[testSession] != "session-new" {
		t.Fatal("signing in didn't issue a new token")
	}
	stale := withOnlyCookie(b.request(http.MethodPost, "/v1/passkeys/register/begin", false), csrfCookieName, before)
	stale.Header.Set(csrfHeaderName, before)
	staleRec := httptest.NewRecorder()
	h.ServeHTTP(staleRec, stale)
	if staleRec.Code != http.StatusForbidden {
		t.Error("the token from before sign-in still works in the session")
	}
	if rec := b.do(h, http.MethodPost, "/v1/passkeys/register/begin", true); rec.Code != http.StatusOK {
		t.Errorf("the token issued at sign-in: %d, want 200", rec.Code)
	}

	if rec := b.do(h, http.MethodPost, "/v1/auth/switch-organization", true); rec.Code != http.StatusOK || b.cookies[csrfCookieName] == signedInToken {
		t.Errorf("organization switch: %d, token renewed %v; want a new one", rec.Code, b.cookies[csrfCookieName] != signedInToken)
	}
	switched := b.cookies[csrfCookieName]
	setPortal = true
	b.do(h, http.MethodPost, "/v1/admin-portal/session", true)
	setPortal = false
	if b.cookies[csrfCookieName] == switched {
		t.Error("setting the portal session didn't issue a new token")
	}

	expired := newBrowser()
	for k, v := range b.cookies {
		expired.cookies[k] = v
	}
	delete(expired.cookies, testSession)
	if rec := expired.do(h, http.MethodPost, "/v1/auth/login", true); rec.Code != http.StatusOK {
		t.Errorf("a session's token once its cookie expired: %d, want 200", rec.Code)
	}

	clearSession = true
	if rec := b.do(h, http.MethodPost, "/v1/auth/session/end", true); rec.Code != http.StatusOK {
		t.Fatalf("sign out: %d", rec.Code)
	}
	clearSession = false
	if _, ok := b.cookies[testSession]; ok || b.cookies[csrfCookieName] == "" {
		t.Fatal("signing out didn't clear the session and issue a token")
	}
	if rec := b.do(h, http.MethodPost, "/v1/auth/login", true); rec.Code != http.StatusOK {
		t.Errorf("the token issued at sign-out: %d, want 200", rec.Code)
	}

	other := signedIn(t, h, "session-x")
	other.cookies[testSession] = "session-y"
	if rec := other.do(h, http.MethodGet, "/v1/me", false); len(rec.Result().Cookies()) == 0 {
		t.Error("a GET in another session kept a token it doesn't accept")
	}
	if rec := other.do(h, http.MethodPost, "/v1/passkeys/register/begin", true); rec.Code != http.StatusOK {
		t.Errorf("the token the GET issued: %d, want 200", rec.Code)
	}
}

func withOnlyCookie(r *http.Request, name, value string) *http.Request {
	out := r.Clone(r.Context())
	out.Header.Del("Cookie")
	for _, c := range r.Cookies() {
		if c.Name != name {
			out.AddCookie(c)
		}
	}
	out.AddCookie(&http.Cookie{Name: name, Value: value})
	return out
}

// TestCSRF_KeyIsNotInTheSource checks that the key comes only from the configuration.
func TestCSRF_KeyIsNotInTheSource(t *testing.T) {
	func() {
		defer func() {
			if recover() == nil {
				t.Error("CSRF started without a key")
			}
		}()
		CSRF(CSRFConfig{AllowedOrigins: []string{testOrigin}})
	}()
	source, err := os.ReadFile("csrf.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"hmac.New(", "qeet-csrf-v1"} {
		if strings.Contains(string(source), banned) {
			t.Errorf("csrf.go contains %q: the key must come from the configuration", banned)
		}
	}
	var _ CSRFKey = (*envelope.Cipher)(nil) // the server's data key signs them
}

func TestCSRF_POSTWithoutCookieRejected(t *testing.T) {
	h := withCSRF(t, testConfig(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", testOrigin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without cookie must be 403, got %d", rec.Code)
	}
}

// TestCSRF_RejectionUsesErrorEnvelope checks that both refusals, origin and
// token, answer the canonical {error: {code, ...}} body clients branch on.
func TestCSRF_RejectionUsesErrorEnvelope(t *testing.T) {
	h := withCSRF(t, testConfig(t))
	for name, origin := range map[string]string{"origin": "https://evil.example.com", "token": testOrigin} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var body struct {
			Error struct {
				Code   string `json:"code"`
				Detail string `json:"detail"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusForbidden ||
			body.Error.Code != CodeCSRFFailed || body.Error.Detail == "" {
			t.Errorf("%s refusal: status %d body %s, want 403 with error.code csrf_failed and a detail", name, rec.Code, rec.Body)
		}
	}
}

func TestCSRF_OriginChecked(t *testing.T) {
	h := withCSRF(t, testConfig(t))
	b := signedIn(t, h, "")
	for origin, want := range map[string]int{"": http.StatusForbidden, "https://evil.example.com": http.StatusForbidden, testOrigin: http.StatusOK} {
		req := b.request(http.MethodPost, "/", true)
		req.Header.Del("Origin")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Origin %q: %d, want %d", origin, rec.Code, want)
		}
	}
	req := b.request(http.MethodPost, "/", true)
	req.Header.Del("Origin")
	req.Header.Set("Referer", testOrigin+"/users")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Referer fallback should pass when Origin is absent, got %d", rec.Code)
	}
}

func TestCSRF_POSTTokenMismatchRejected(t *testing.T) {
	h := withCSRF(t, testConfig(t))
	b := signedIn(t, h, "")
	req := b.request(http.MethodPost, "/", false)
	req.Header.Set(csrfHeaderName, tokenUnder(t, testConfig(t).Key, b, ""))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a header unlike the cookie must be 403, even a valid token, got %d", rec.Code)
	}
}

func TestCSRF_BearerBypass(t *testing.T) {
	h := withCSRF(t, testConfig(t))
	// No cookie, no Origin — but a bearer token. M2M API key / service
	// JWT traffic should sail through.
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer eyJ...")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer requests must bypass CSRF, got %d", rec.Code)
	}
}

// TestCSRF_APIKeyBypassButNotBasic: the server libraries authorise with
// `Authorization: ApiKey …` and send no Origin, so their writes were refused.
// An API key passes like a bearer token; Basic credentials, which a browser can
// replay on its own, still need the check.
func TestCSRF_APIKeyBypassButNotBasic(t *testing.T) {
	h := withCSRF(t, testConfig(t))
	for scheme, want := range map[string]int{
		"ApiKey qk_live_abc": http.StatusOK,
		"Basic dXNlcjpwYXNz": http.StatusForbidden,
		"ApiKeyqk_live_abc":  http.StatusForbidden,
		"apikey qk_live_abc": http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", scheme)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Authorization %q with no cookie or Origin = %d, want %d", scheme, rec.Code, want)
		}
	}
}

// TestCSRF_StreamsStillFlush checks that event streams can still flush.
func TestCSRF_StreamsStillFlush(t *testing.T) {
	var flushable, controllable bool
	h := CSRF(testConfig(t))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, flushable = w.(http.Flusher)
		controllable = http.NewResponseController(w).Flush() == nil
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/activity/stream", nil))
	if !flushable || !controllable {
		t.Errorf("flushable %v, controllable %v; want both", flushable, controllable)
	}
}

func TestCSRF_NormaliseOriginsTrimsSlashAndCases(t *testing.T) {
	got := normaliseOrigins([]string{
		"https://api.id.qeet.in/",
		"  https://Web.Id.Qeet.in   ",
		"*",
		"",
	})
	wantKeys := []string{"https://api.id.qeet.in", "https://web.id.qeet.in"}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("expected key %q in normalised set, got %v", k, got)
		}
	}
	if len(got) != 2 {
		t.Errorf("normalised set must drop empty + wildcard, got %v", got)
	}
}

func TestNewCSRFTokenIsRandom(t *testing.T) {
	c := &csrf{cfg: testConfig(t)}
	b := binding{nonce: "nonce", session: "session"}
	a, err := c.newToken(b)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.newToken(b)
	if err != nil {
		t.Fatal(err)
	}
	if a == again || !c.valid(a, b) || !c.valid(again, b) {
		t.Fatal("two tokens for one browser and session must differ and both be valid")
	}
}

func TestCSRF_ExemptPathBypassesMutationCheck(t *testing.T) {
	cfg := testConfig(t)
	cfg.ExemptPaths = []string{"/saml/acs/"}
	mw := withCSRF(t, cfg)

	// Exempt path: cross-site POST with no cookie/origin (as an IdP would
	// form-POST a SAML assertion) must pass — it's signature-authenticated.
	exempt := httptest.NewRequest(http.MethodPost, "/saml/acs/abc123", strings.NewReader("SAMLResponse=x"))
	exempt.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, exempt)
	if rec.Code != http.StatusOK {
		t.Fatalf("exempt SAML ACS path must bypass CSRF, got %d", rec.Code)
	}

	// A non-exempt mutation with no cookie/origin is still rejected.
	other := httptest.NewRequest(http.MethodPost, "/saml/exchange", strings.NewReader("{}"))
	rec2 := httptest.NewRecorder()
	mw.ServeHTTP(rec2, other)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("non-exempt path must still enforce CSRF, got %d", rec2.Code)
	}
}

func TestMatchExemptPath(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		// Exact entries must not behave like prefixes. This is the regression
		// that let POST /v1/social/providers ride a "/v1/social/" exemption.
		{"/v1/oauth/bc-authorize", "/v1/oauth/bc-authorize", true},
		{"/v1/oauth/bc-authorize", "/v1/oauth/bc-authorize/decision", false},
		{"/v1/social/exchange", "/v1/social/exchange", true},
		{"/v1/social/exchange", "/v1/social/providers", false},

		// Trailing slash keeps prefix behaviour where a family really is public.
		{"/v1/auth/magic-link/", "/v1/auth/magic-link/start", true},
		{"/v1/auth/magic-link/", "/v1/auth/magic-link/consume", true},
		{"/v1/auth/magic-link/", "/v1/auth/magic-linkX", false},
		{"/saml/acs/", "/saml/acs/2f1c8b4e-0000-0000-0000-000000000000", true},

		// "*" spans exactly one segment.
		{"/v1/social/*/callback", "/v1/social/apple/callback", true},
		{"/v1/social/*/callback", "/v1/social/google/callback", true},
		{"/v1/social/*/callback", "/v1/social/apple/link/start", false},
		{"/v1/social/*/callback", "/v1/social/callback", false},
		{"/v1/social/*/callback", "/v1/social/a/b/callback", false},
	}
	for _, tc := range cases {
		if got := matchExemptPath(tc.pattern, tc.path); got != tc.want {
			t.Errorf("matchExemptPath(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}
