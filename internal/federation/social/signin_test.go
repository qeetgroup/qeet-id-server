package social

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
)

// TestCallbackURL_SchemeAndPath builds the public redirect_uri that must match
// between BeginLogin and the upstream token exchange: on PublicBaseURL when
// set, else on the Host with the scheme from X-Forwarded-Proto.
func TestCallbackURL_SchemeAndPath(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		fwdProto   string
		configured string
		want       string
	}{
		{"configured origin", "evil.example", "", "https://api.qeet.com", "https://api.qeet.com/v1/social/google/callback"},
		{"plain localhost", "localhost:8080", "", "", "http://localhost:8080/v1/social/google/callback"},
		{"forwarded https", "api.qeet.com", "https", "", "https://api.qeet.com/v1/social/google/callback"},
		{"forwarded http stays http", "api.local", "http", "", "http://api.local/v1/social/google/callback"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/social/google/start", nil)
			req.Host = c.host
			if c.fwdProto != "" {
				req.Header.Set("X-Forwarded-Proto", c.fwdProto)
			}
			h := &Handler{PublicBaseURL: c.configured}
			if got := h.callbackURL(req, "google"); got != c.want {
				t.Errorf("callbackURL = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSocialPKCE_ChallengeIsS256 documents that BeginLogin's PKCE challenge is
// BASE64URL(SHA256(verifier)) — the verifier is the raw token, the challenge is
// codes.Hash of it. The upstream provider re-derives this from the verifier we
// send at the token endpoint, so the relationship must hold exactly.
func TestSocialPKCE_ChallengeIsS256(t *testing.T) {
	verifier, challenge, err := codes.URLToken()
	if err != nil {
		t.Fatalf("URLToken: %v", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Errorf("challenge = %q, want S256(%q) = %q", challenge, verifier, want)
	}
	if codes.Hash(verifier) != challenge {
		t.Error("codes.Hash(verifier) must equal the challenge half of URLToken")
	}
	if strings.Contains(challenge, "=") {
		t.Errorf("challenge must be unpadded base64url, got %q", challenge)
	}
}

// TestSocialScopes pins the OIDC scope set requested at the upstream provider.
func TestSocialScopes(t *testing.T) {
	for _, s := range []string{"openid", "email", "profile"} {
		if !strings.Contains(socialScopes, s) {
			t.Errorf("socialScopes %q must request %q", socialScopes, s)
		}
	}
}
