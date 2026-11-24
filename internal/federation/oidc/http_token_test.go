package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestClientAuthenticatedEndpointsRejectOversizedForms(t *testing.T) {
	handler := &Handler{}
	router := chi.NewRouter()
	handler.MountPublic(router)
	body := "token=" + strings.Repeat("x", int(httpx.MaxFormBodyBytes)+1)

	for _, path := range []string{"/oauth/revoke", "/oauth/introspect"} {
		t.Run(path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

// TestTokenEndpointRefusesMalformedRequestsInOAuthShape checks the token
// endpoint's answers to requests refused before any grant runs.
func TestTokenEndpointRefusesMalformedRequestsInOAuthShape(t *testing.T) {
	router := chi.NewRouter()
	(&Handler{}).MountToken(router)
	for _, tc := range []struct {
		name, body, want string
	}{
		{"no grant_type", "code=abc", "invalid_request"},
		{"an unknown grant_type", "grant_type=password", "unsupported_grant_type"},
		{"a resource on client_credentials", "grant_type=client_credentials&resource=https://api.example.com", "invalid_target"},
		{"a malformed resource", "grant_type=authorization_code&resource=relative/path", "invalid_target"},
		{"a resource on device polling", "grant_type=" + grantTypeDeviceCode + "&resource=https://api.example.com", "invalid_target"},
		{"an oversized form", "grant_type=refresh_token&refresh_token=" + strings.Repeat("x", int(httpx.MaxFormBodyBytes)), "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status %d, want 400", rec.Code)
			}
			if code, _ := decodeTokenError(t, rec); code != tc.want {
				t.Errorf("error %q, want %q", code, tc.want)
			}
		})
	}
}

// TestWriteTokenError checks how the grants' errors are answered: in the RFC
// 6749 §5.2 shape, invalid_client as 401 with a Basic challenge for a Basic
// client, and an internal error as the generic 500.
func TestWriteTokenError(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		basic     bool
		status    int
		code      string
		challenge string
	}{
		{"bad Basic credentials", errs.ErrOIDCClientAuthFailed, true, http.StatusUnauthorized, "invalid_client", `Basic realm="qeet"`},
		{"bad form credentials", errs.ErrOIDCClientAuthFailed, false, http.StatusUnauthorized, "invalid_client", ""},
		{"a service principal's wrong secret", errs.ErrPrincipalInvalidCredentials, true, http.StatusUnauthorized, "invalid_client", `Basic realm="qeet"`},
		{"an agent's wrong secret", errs.ErrAgentTokenInvalid, false, http.StatusUnauthorized, "invalid_client", ""},
		{"a disabled service principal", errs.ErrPrincipalDisabled, true, http.StatusBadRequest, "unauthorized_client", ""},
		{"a suspended agent", errs.ErrAgentInactive, false, http.StatusBadRequest, "unauthorized_client", ""},
		{"an expired code", ErrAuthCodeExpired, true, http.StatusBadRequest, "invalid_grant", ""},
		{"a wrong code_verifier", ErrCodeVerifierInvalid, false, http.StatusBadRequest, "invalid_grant", ""},
		{"an invalid refresh token", ErrRefreshTokenInvalid, false, http.StatusBadRequest, "invalid_grant", ""},
		{"a suspended account", errs.ErrAuthAccountSuspended, false, http.StatusBadRequest, "invalid_grant", ""},
		{"a grant the client may not use", ErrGrantTypeNotAllowed, false, http.StatusBadRequest, "unauthorized_client", ""},
		{"a scope beyond the subject's", ErrScopeExceedsSubject, false, http.StatusBadRequest, "invalid_scope", ""},
		{"an invalid subject token", ErrSubjectTokenInvalid, false, http.StatusBadRequest, "invalid_request", ""},
		{"an unregistered resource", oauthErr("invalid_target", "resource is not registered"), false, http.StatusBadRequest, "invalid_target", ""},
		{"a poll too soon", oauthErr("slow_down", "polling too frequently"), false, http.StatusBadRequest, "slow_down", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
			if tc.basic {
				req.SetBasicAuth("qci_client", "secret")
			}
			rec := httptest.NewRecorder()
			writeTokenError(rec, req, tc.err)
			if rec.Code != tc.status {
				t.Errorf("status %d, want %d", rec.Code, tc.status)
			}
			code, description := decodeTokenError(t, rec)
			if code != tc.code || description == "" {
				t.Errorf("error %q (%q), want %q with a description", code, description, tc.code)
			}
			// Whichever kind of client failed, invalid_client reads the same.
			if code == "invalid_client" && description != errs.ErrOIDCClientAuthFailed.Message {
				t.Errorf("invalid_client described %q, want %q", description, errs.ErrOIDCClientAuthFailed.Message)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tc.challenge {
				t.Errorf("WWW-Authenticate %q, want %q", got, tc.challenge)
			}
		})
	}

	rec := httptest.NewRecorder()
	writeTokenError(rec, httptest.NewRequest(http.MethodPost, "/oauth/token", nil), errors.New("connection refused"))
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusInternalServerError || body.Error.Code != errs.CodeInternal {
		t.Errorf("internal error = %d %s, want the generic 500", rec.Code, rec.Body.String())
	}
}
