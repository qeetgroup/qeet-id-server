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
