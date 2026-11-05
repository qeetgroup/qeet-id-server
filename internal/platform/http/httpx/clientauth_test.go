package httpx

import (
	"net/http/httptest"
	"testing"
)

// TestClientBasicAuthDecodesFormEncoding checks that Basic client credentials
// are form-decoded as RFC 6749 §2.3.1 requires, that the URL-safe values the
// server issues pass through unchanged, and that a request without Basic
// credentials reports none.
func TestClientBasicAuthDecodesFormEncoding(t *testing.T) {
	cases := []struct {
		name, user, pass, wantID, wantSecret string
	}{
		{"issued values", "qci_7f1c0c5e-1a2b-4c3d-9e8f-0a1b2c3d4e5f", "pQ3-x_Z9", "qci_7f1c0c5e-1a2b-4c3d-9e8f-0a1b2c3d4e5f", "pQ3-x_Z9"},
		{"reserved characters encoded", "my%3Aclient", "s%2Fe%2Bc%3Dret%25", "my:client", "s/e+c=ret%"},
		{"invalid encoding kept", "client", "100%", "client", "100%"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/v1/oauth/token", nil)
		r.SetBasicAuth(c.user, c.pass)
		id, secret, ok := ClientBasicAuth(r)
		if !ok || id != c.wantID || secret != c.wantSecret {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q, true)", c.name, id, secret, ok, c.wantID, c.wantSecret)
		}
	}
	if _, _, ok := ClientBasicAuth(httptest.NewRequest("POST", "/v1/oauth/token", nil)); ok {
		t.Error("no Basic credentials reported as present")
	}
}
