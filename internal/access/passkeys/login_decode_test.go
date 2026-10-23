package passkey

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestLoginBeginAcceptsEmail checks that the /v1/passkeys/login/begin body
// accepts an "email" field, for the username-first flow.
func TestLoginBeginAcceptsEmail(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/passkeys/login/begin", strings.NewReader(`{"email":"owner@acme.test"}`))
	var in loginBeginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		t.Fatalf("decoding {\"email\":...} should succeed, got: %v", err)
	}
	if in.Email != "owner@acme.test" {
		t.Fatalf("email = %q, want owner@acme.test", in.Email)
	}
}
