package principal

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// tokenRequest posts form to the client_credentials token endpoint, with Basic
// credentials when user is not empty.
func tokenRequest(t *testing.T, h http.Handler, form url.Values, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// wantTokenError checks that rec is an RFC 6749 §5.2 error with status, code
// and WWW-Authenticate challenge ("" for none).
func wantTokenError(t *testing.T, rec *httptest.ResponseRecorder, status int, code, challenge string) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %d response: %v (%s)", rec.Code, err, rec.Body.String())
	}
	description, _ := body["error_description"].(string)
	if rec.Code != status || body["error"] != code || description == "" || len(body) != 2 {
		t.Errorf("response %d %s, want %d with error %q and a description", rec.Code, rec.Body.String(), status, code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != challenge {
		t.Errorf("WWW-Authenticate %q, want %q", got, challenge)
	}
}

// TestTokenEndpointRefusesInOAuthShape checks the answers to requests refused
// before a principal is looked up.
func TestTokenEndpointRefusesInOAuthShape(t *testing.T) {
	router := chi.NewRouter()
	(&Handler{Service: &Service{}}).MountToken(router)
	cc := url.Values{"grant_type": {"client_credentials"}}

	wantTokenError(t, tokenRequest(t, router, url.Values{"client_id": {"x"}}, "", ""), http.StatusBadRequest, "invalid_request", "")
	wantTokenError(t, tokenRequest(t, router, url.Values{"grant_type": {"password"}}, "", ""), http.StatusBadRequest, "unsupported_grant_type", "")
	wantTokenError(t, tokenRequest(t, router, cc, "", ""), http.StatusUnauthorized, "invalid_client", "")
	wantTokenError(t, tokenRequest(t, router, cc, "not-a-principal-id", "secret"), http.StatusUnauthorized, "invalid_client", `Basic realm="qeet"`)
	oversized := url.Values{"grant_type": {"client_credentials"}, "pad": {strings.Repeat("x", int(httpx.MaxFormBodyBytes))}}
	wantTokenError(t, tokenRequest(t, router, oversized, "", ""), http.StatusBadRequest, "invalid_request", "")
}

// TestWriteTokenError checks the answers to a disabled principal and to an
// internal error.
func TestWriteTokenError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.SetBasicAuth("id", "secret")
	rec := httptest.NewRecorder()
	writeTokenError(rec, req, errs.ErrPrincipalDisabled)
	wantTokenError(t, rec, http.StatusBadRequest, "unauthorized_client", "")

	rec = httptest.NewRecorder()
	writeTokenError(rec, req, errors.New("connection refused"))
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusInternalServerError || body.Error.Code != errs.CodeInternal {
		t.Errorf("internal error = %d %s, want the generic 500", rec.Code, rec.Body.String())
	}
}
