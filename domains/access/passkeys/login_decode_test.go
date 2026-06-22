package passkey

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id/platform/httpx"
)

// Regression for P2-06: /v1/passkeys/login/begin must accept a JSON body with
// an "email" field (username-first flow). A stale build without this field
// rejected it as an unknown field; this locks the contract in.
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
