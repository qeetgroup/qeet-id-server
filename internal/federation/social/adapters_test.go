package social

import (
	"encoding/json"
	"testing"
)

// TestUserInfoClaimMapping verifies the subset of userinfo claims we map onto a
// local identity: sub/email/name are decoded; extra claims are ignored.
func TestUserInfoClaimMapping(t *testing.T) {
	raw := `{"sub":"abc-123","email":"u@example.com","email_verified":true,"name":"Jane","picture":"x","extra":1}`
	var ui userInfo
	if err := json.Unmarshal([]byte(raw), &ui); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ui.Subject != "abc-123" || ui.Email != "u@example.com" || !ui.EmailVerified || ui.Name != "Jane" {
		t.Errorf("claim mapping wrong: %+v", ui)
	}
}
