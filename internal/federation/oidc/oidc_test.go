package oidc

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

func testIssuer(t *testing.T) *tokens.Issuer {
	t.Helper()
	keyPEM, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	i, err := tokens.NewIssuer(keyPEM, "https://id.test", "https://id.test", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return i
}

// decodeTokenError decodes an RFC 6749 §5.2 error body, failing on any other
// shape.
func decodeTokenError(t *testing.T, rec *httptest.ResponseRecorder) (code, description string) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %d response: %v (%s)", rec.Code, err, rec.Body.String())
	}
	code, ok := body["error"].(string)
	if !ok || code == "" {
		t.Fatalf("response %s has no string error", rec.Body.String())
	}
	for key := range body {
		if key != "error" && key != "error_description" {
			t.Errorf("response %s has member %q", rec.Body.String(), key)
		}
	}
	description, _ = body["error_description"].(string)
	return code, description
}
