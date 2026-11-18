//go:build integration

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestMFAChallengeOverHTTP checks the two-step sign-in through the API: the
// password alone issues no tokens, a wrong code is counted and leaves the
// challenge, the right code opens a session recorded as password_mfa, a
// challenge is spent by its first success, and five wrong codes refuse even a
// fresh challenge met with the right code.
func TestMFAChallengeOverHTTP(t *testing.T) {
	svc := newService(t)
	svc.mfa = heldFactor{code: "246810"}
	b := newBrowser(t, publicRoutes(newHandler(svc)))
	a, _ := member(t)
	challenge := func() string {
		t.Helper()
		rec := b.do(http.MethodPost, "/auth/login", loginBody(a.Email, testPassword))
		var body struct {
			MFARequired bool     `json:"mfa_required"`
			MFAToken    string   `json:"mfa_token"`
			Methods     []string `json:"methods"`
			AccessToken string   `json:"access_token"`
		}
		dbtest.Decode(t, rec, &body)
		if rec.Code != http.StatusOK || !body.MFARequired || body.MFAToken == "" || body.AccessToken != "" ||
			len(body.Methods) != 1 || body.Methods[0] != "totp" {
			t.Fatalf("sign in holding a second factor: %d %s, want a totp challenge and no token", rec.Code, rec.Body.String())
		}
		return body.MFAToken
	}
	mfa := func(body map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		return b.do(http.MethodPost, "/auth/mfa", body)
	}

	token := challenge()
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, a.ID); n != 0 {
		t.Fatalf("the password alone opened %d sessions", n)
	}
	for _, tc := range []struct {
		name   string
		body   map[string]any
		status int
		code   string
	}{
		{"no proof", map[string]any{"mfa_token": token}, http.StatusUnprocessableEntity, errs.CodeValidation},
		{"two proofs", map[string]any{"mfa_token": token, "code": "246810", "push": true}, http.StatusUnprocessableEntity, errs.CodeValidation},
		{"a malformed token", map[string]any{"mfa_token": "not-a-token", "code": "246810"}, http.StatusBadRequest, errs.CodeAuthSessionInvalid},
		{"an unknown token", map[string]any{"mfa_token": uuid.NewString(), "code": "246810"}, http.StatusUnauthorized, errs.CodeAuthMFAChallengeExpired},
		{"a wrong code", map[string]any{"mfa_token": token, "code": "000000"}, http.StatusUnauthorized, errs.CodeMFACodeInvalid},
	} {
		if rec := mfa(tc.body); !answered(rec, tc.status, tc.code) {
			t.Errorf("complete with %s: %d %s, want %d %s", tc.name, rec.Code, rec.Body.String(), tc.status, tc.code)
		}
	}
	for _, path := range []string{"/auth/mfa/send", "/auth/mfa/passkey/begin", "/auth/mfa/push", "/auth/mfa/enroll"} {
		if rec := b.do(http.MethodPost, path, map[string]any{"mfa_token": uuid.NewString()}); !answered(rec, http.StatusUnauthorized, errs.CodeAuthMFAChallengeExpired) {
			t.Errorf("%s for an unknown challenge: %d %s, want 401 %s", path, rec.Code, rec.Body.String(), errs.CodeAuthMFAChallengeExpired)
		}
	}
	if rec := b.do(http.MethodPost, "/auth/mfa/enroll", map[string]any{"mfa_token": token}); !answered(rec, http.StatusBadRequest, errs.CodeBadRequest) {
		t.Errorf("start an enrolment for a challenge that is not one: %d %s, want 400", rec.Code, rec.Body.String())
	}

	rec := mfa(map[string]any{"mfa_token": token, "code": "246810"})
	if rec.Code != http.StatusOK {
		t.Fatalf("complete with the right code: %d %s", rec.Code, rec.Body.String())
	}
	var pair TokenPair
	dbtest.Decode(t, rec, &pair)
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND user_id = $2 AND second_factor = 'mfa'`, pair.SessionID, a.ID); n != 1 {
		t.Error("the session does not record its second factor")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.login_succeeded' AND resource_id = $1
		AND metadata->>'method' = 'password_mfa'`, pair.SessionID); n != 1 {
		t.Error("the sign-in was not audited as password_mfa")
	}
	if rec := mfa(map[string]any{"mfa_token": token, "code": "246810"}); !answered(rec, http.StatusUnauthorized, errs.CodeAuthMFAChallengeExpired) {
		t.Errorf("complete a spent challenge again: %d %s, want 401 %s", rec.Code, rec.Body.String(), errs.CodeAuthMFAChallengeExpired)
	}

	token = challenge()
	for i := range maxMFALoginAttempts {
		rec := mfa(map[string]any{"mfa_token": token, "code": "000000"})
		if i < maxMFALoginAttempts-1 && !answered(rec, http.StatusUnauthorized, errs.CodeMFACodeInvalid) {
			t.Fatalf("wrong code %d: %d %s, want 401", i+1, rec.Code, rec.Body.String())
		}
		if i == maxMFALoginAttempts-1 && !answered(rec, http.StatusTooManyRequests, errs.CodeMFAAttemptsExceeded) {
			t.Fatalf("wrong code %d: %d %s, want 429 %s", i+1, rec.Code, rec.Body.String(), errs.CodeMFAAttemptsExceeded)
		}
	}
	if rec := mfa(map[string]any{"mfa_token": challenge(), "code": "246810"}); !answered(rec, http.StatusTooManyRequests, errs.CodeMFAAttemptsExceeded) {
		t.Errorf("the right code on a fresh challenge after five wrong ones: %d %s, want 429 %s", rec.Code, rec.Body.String(), errs.CodeMFAAttemptsExceeded)
	}
}
