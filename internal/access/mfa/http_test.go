package mfa

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTOTPStatusUnauthenticated checks that the TOTP status endpoint refuses
// an anonymous caller with 401, before touching the database.
func TestTOTPStatusUnauthenticated(t *testing.T) {
	h := &Handler{Service: &Service{}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/mfa/totp", nil)
	h.totpStatus(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// TestCheckNeedsThePairingThrottle checks that the MFA handler is refused at
// start without the throttle on pairing-code claims, where a wrong code is a
// guess.
func TestCheckNeedsThePairingThrottle(t *testing.T) {
	if err := (&Handler{}).Check(); err == nil {
		t.Error("Check without the pairing throttle: nil; want an error")
	}
	if err := (&Handler{PairingThrottle: func(h http.Handler) http.Handler { return h }}).Check(); err != nil {
		t.Errorf("Check with the pairing throttle: %v", err)
	}
}
