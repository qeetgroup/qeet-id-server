package adminportal

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPortalSessionCookieSecurityAttributes(t *testing.T) {
	handler := &Handler{CookieSecure: true}
	recorder := httptest.NewRecorder()
	expiresAt := time.Now().Add(20 * time.Minute)
	handler.setSessionCookie(recorder, "opaque-session", expiresAt)
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("portal cookie security attributes: %+v", cookie)
	}
	if cookie.Path != portalCookiePath || cookie.MaxAge <= 0 || cookie.MaxAge > 20*60 {
		t.Fatalf("portal cookie scope/lifetime: %+v", cookie)
	}
}
