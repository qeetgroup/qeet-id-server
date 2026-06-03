package social

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
)

// TestCallbackURL_SchemeAndPath builds the public redirect_uri that must match
// between BeginLogin and the upstream token exchange. https is selected via TLS
// or the X-Forwarded-Proto header (behind a proxy), http otherwise.
func TestCallbackURL_SchemeAndPath(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		fwdProto string
		tls      bool
		want     string
	}{
		{"plain http", "api.local", "", false, "http://api.local/v1/social/google/callback"},
		{"forwarded https", "api.qeet.com", "https", false, "https://api.qeet.com/v1/social/google/callback"},
		{"forwarded http stays http", "api.local", "http", false, "http://api.local/v1/social/google/callback"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/social/google/start", nil)
			req.Host = c.host
			if c.fwdProto != "" {
				req.Header.Set("X-Forwarded-Proto", c.fwdProto)
			}
			if got := callbackURL(req, "google"); got != c.want {
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

// TestUserInfoClaimMapping verifies the subset of userinfo claims we map onto a
// local identity: sub/email/name are decoded; extra claims are ignored.
func TestUserInfoClaimMapping(t *testing.T) {
	raw := `{"sub":"abc-123","email":"u@example.com","name":"Jane","picture":"x","extra":1}`
	var ui userInfo
	if err := json.Unmarshal([]byte(raw), &ui); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ui.Subject != "abc-123" || ui.Email != "u@example.com" || ui.Name != "Jane" {
		t.Errorf("claim mapping wrong: %+v", ui)
	}
}

func TestNewService_TrimsTrailingSlash(t *testing.T) {
	// appBaseURL is used to build the SPA callback redirect; a trailing slash
	// would yield a double-slash path, so it must be trimmed.
	s := NewService(nil, nil, "https://app.qeet.com/")
	if s.appBaseURL != "https://app.qeet.com" {
		t.Errorf("appBaseURL = %q, want trailing slash trimmed", s.appBaseURL)
	}
}
