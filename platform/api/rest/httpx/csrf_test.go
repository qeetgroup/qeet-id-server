package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// noopHandler returns 200 so test cases can distinguish "passed
// middleware" (200) from "blocked" (403).
var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func withCSRF(t *testing.T, cfg CSRFConfig) http.Handler {
	t.Helper()
	return CSRF(cfg)(noopHandler)
}

func TestCSRF_GETIssuesCookie(t *testing.T) {
	h := withCSRF(t, CSRFConfig{AllowedOrigins: []string{"https://app.id.qeet.in"}})
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET should pass, got %d", rec.Code)
	}
	if cookies := rec.Result().Cookies(); len(cookies) == 0 || cookies[0].Name != csrfCookieName {
		t.Fatalf("expected csrf cookie to be set on GET, got cookies=%v", cookies)
	}
}

func TestCSRF_GETKeepsExistingCookie(t *testing.T) {
	h := withCSRF(t, CSRFConfig{AllowedOrigins: []string{"https://app.id.qeet.in"}})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: strings.Repeat("a", 32)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Result().Cookies(); len(got) != 0 {
		t.Fatalf("must not reissue cookie when one exists, got %v", got)
	}
}

func TestCSRF_POSTWithoutCookieRejected(t *testing.T) {
	h := withCSRF(t, CSRFConfig{AllowedOrigins: []string{"https://app.id.qeet.in"}})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "https://app.id.qeet.in")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without cookie must be 403, got %d", rec.Code)
	}
}

func TestCSRF_POSTWithoutOriginRejected(t *testing.T) {
	h := withCSRF(t, CSRFConfig{AllowedOrigins: []string{"https://app.id.qeet.in"}})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tok"})
	req.Header.Set(csrfHeaderName, "tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without Origin/Referer must be 403, got %d", rec.Code)
	}
}

func TestCSRF_POSTWrongOriginRejected(t *testing.T) {
	h := withCSRF(t, CSRFConfig{AllowedOrigins: []string{"https://app.id.qeet.in"}})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tok"})
	req.Header.Set(csrfHeaderName, "tok")
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed Origin must be 403, got %d", rec.Code)
	}
}

func TestCSRF_POSTTokenMismatchRejected(t *testing.T) {
	h := withCSRF(t, CSRFConfig{AllowedOrigins: []string{"https://app.id.qeet.in"}})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "cookie-token"})
	req.Header.Set(csrfHeaderName, "different-token")
	req.Header.Set("Origin", "https://app.id.qeet.in")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("token mismatch must be 403, got %d", rec.Code)
	}
}

func TestCSRF_POSTValid(t *testing.T) {
	h := withCSRF(t, CSRFConfig{AllowedOrigins: []string{"https://app.id.qeet.in"}})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "matched-token"})
	req.Header.Set(csrfHeaderName, "matched-token")
	req.Header.Set("Origin", "https://app.id.qeet.in")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid CSRF flow must pass, got %d", rec.Code)
	}
}

func TestCSRF_BearerBypass(t *testing.T) {
	h := withCSRF(t, CSRFConfig{AllowedOrigins: []string{"https://app.id.qeet.in"}})
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

func TestCSRF_RefererFallback(t *testing.T) {
	h := withCSRF(t, CSRFConfig{AllowedOrigins: []string{"https://api.id.qeet.in"}})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tok"})
	req.Header.Set(csrfHeaderName, "tok")
	// No Origin header, but Referer is present and on the allow-list.
	req.Header.Set("Referer", "https://api.id.qeet.in/users")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Referer fallback should pass when Origin is absent, got %d", rec.Code)
	}
}

func TestCSRF_NormaliseOriginsTrimsSlashAndCases(t *testing.T) {
	got := normaliseOrigins([]string{
		"https://api.id.qeet.in/",
		"  https://Web.Id.Qeet.in   ",
		"*",
		"",
	})
	wantKeys := []string{"https://id.qeet.in", "https://web.id.qeet.in"}
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
	a, err := newCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two consecutive tokens must differ")
	}
	if len(a) < 40 {
		t.Errorf("token unexpectedly short: %d", len(a))
	}
}

func TestCSRF_ExemptPathBypassesMutationCheck(t *testing.T) {
	mw := withCSRF(t, CSRFConfig{
		AllowedOrigins: []string{"https://admin.id.qeet.in"},
		ExemptPaths:    []string{"/saml/acs/"},
	})

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
