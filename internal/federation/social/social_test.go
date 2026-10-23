package social

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func githubTestClient(t *testing.T, emails string) *oauthClient {
	t.Helper()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"id":123,"login":"alice","name":"Alice","email":"unverified-profile@example.com"}`
		if request.URL.String() == githubEmailsURL {
			body = emails
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})
	return &oauthClient{http: &http.Client{Transport: transport}}
}

// TestDiscoveryChecksAuthorizationEndpoint checks that a discovery document is
// used, and cached, only when its authorization_endpoint is an absolute https
// URL with a host and no userinfo or fragment.
func TestDiscoveryChecksAuthorizationEndpoint(t *testing.T) {
	for _, c := range []struct {
		endpoint string
		ok       bool
	}{
		{"https://idp.example.com/authorize", true},
		{"https://idp.example.com:8443/oauth2/v1/authorize?tenant=a", true},
		{"http://idp.example.com/authorize", false},
		{"javascript:alert(1)", false},
		{"data:text/html,hi", false},
		{"//idp.example.com/authorize", false},
		{"/authorize", false},
		{"https:///authorize", false},
		{"https:idp.example.com/authorize", false},
		{"https://user:pass@idp.example.com/authorize", false},
		{"https://idp.example.com/authorize#frag", false},
		{"https://idp.example.com/authorize#", false},
		{"https://idp.example.com/\tauthorize", false},
	} {
		t.Run(c.endpoint, func(t *testing.T) {
			doc, _ := json.Marshal(discoveryDoc{AuthorizationEndpoint: c.endpoint, TokenEndpoint: "https://idp.example.com/token"})
			client := &oauthClient{cache: map[string]cachedDoc{}, http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(doc))), Request: r}, nil
			})}}
			const discoveryURL = "https://idp.example.com/.well-known/openid-configuration"
			got, err := client.discovery(context.Background(), discoveryURL)
			if c.ok && (err != nil || got.AuthorizationEndpoint != c.endpoint) {
				t.Fatalf("discovery = (%+v, %v), want the document", got, err)
			}
			if !c.ok {
				if err == nil {
					t.Fatalf("discovery = (%+v, nil), want an error", got)
				}
				if _, cached := client.cache[discoveryURL]; cached {
					t.Fatal("refused document was cached")
				}
			}
		})
	}
}

func TestGitHubUserinfoUsesOnlyVerifiedEmail(t *testing.T) {
	client := githubTestClient(t, `[
		{"email":"unverified-profile@example.com","primary":true,"verified":false},
		{"email":"verified@example.com","primary":false,"verified":true}
	]`)
	info, err := client.githubUserinfo(context.Background(), "token")
	if err != nil {
		t.Fatalf("github userinfo: %v", err)
	}
	if info.Email != "verified@example.com" || !info.EmailVerified {
		t.Fatalf("GitHub assurance = %+v, want verified endpoint email", info)
	}
}

func TestGitHubUserinfoRejectsProfileEmailWithoutVerification(t *testing.T) {
	client := githubTestClient(t, `[{"email":"unverified-profile@example.com","primary":true,"verified":false}]`)
	info, err := client.githubUserinfo(context.Background(), "token")
	if err != nil {
		t.Fatalf("github userinfo: %v", err)
	}
	if info.Email != "" || info.EmailVerified {
		t.Fatalf("unverified GitHub profile email was trusted: %+v", info)
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

// TestValidateReturnTo checks that return_to accepts only "", a path with a
// single leading "/", and URLs on an allowed origin.
func TestValidateReturnTo(t *testing.T) {
	s := &Service{}
	s.SetAllowedReturnOrigins("https://login.qeet.in", "https://console.qeet.in/")

	for _, c := range []struct {
		name     string
		returnTo string
		ok       bool
	}{
		{"empty", "", true},
		{"path", "/oauth/authorize?client_id=abc&scope=openid+email", true},
		{"root", "/", true},
		{"encoded query", "/oauth/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcb", true},
		{"allowed origin", "https://login.qeet.in/oauth/authorize", true},
		{"allowed origin, upper case", "https://LOGIN.QEET.IN/oauth/authorize", true},
		{"allowed origin, root", "https://console.qeet.in/", true},

		{"other origin", "https://other.example/", false},
		{"other scheme", "http://login.qeet.in/oauth/authorize", false},
		{"longer host", "https://login.qeet.in.other.example/", false},
		{"other origin with allowed query", "https://other.example/?next=https://login.qeet.in", false},
		{"userinfo on allowed origin", "https://user@login.qeet.in/", false},
		{"userinfo host", "https://login.qeet.in@other.example/", false},
		{"no host", "javascript:alert(1)", false},
		{"opaque", "https:login.qeet.in/x", false},
		{"relative without slash", "oauth/authorize", false},
		{"double slash", "//other.example/path", false},
		{"slash backslash", `/\other.example/path`, false},
		{"backslash later", `/a\b`, false},
		{"tab after slash", "/\t/other.example/path", false},
		{"newline after slash", "/\n/other.example/path", false},
		{"carriage return after slash", "/\r/other.example/path", false},
		{"leading space", " //other.example/path", false},
		{"leading tab", "\t//other.example/path", false},
		{"space in path", "/a b", false},
		{"trailing newline", "/oauth/authorize\n", false},
		{"nul", "/a\x00b", false},
		{"delete", "/a\x7fb", false},
		{"C1 control", "/a\u0085b", false},
		{"no-break space", "/ /other.example", false},
		{"ideographic space", "/　/other.example", false},
		{"invalid utf-8", "/a\xffb", false},
		{"tab in allowed origin", "https://login.qeet.in/\t/x", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := s.validateReturnTo(c.returnTo)
			if c.ok && err != nil {
				t.Errorf("validateReturnTo(%q) = %v, want nil", c.returnTo, err)
			}
			if !c.ok && err == nil {
				t.Errorf("validateReturnTo(%q) = nil, want rejection", c.returnTo)
			}
		})
	}
}

// TestValidateReturnToWithNoAllowlist pins the safe default: with no origins
// configured, only root-relative paths are accepted.
func TestValidateReturnToWithNoAllowlist(t *testing.T) {
	s := &Service{}
	if err := s.validateReturnTo("/oauth/authorize"); err != nil {
		t.Errorf("root-relative path = %v, want nil", err)
	}
	if err := s.validateReturnTo("https://login.qeet.in/"); err == nil {
		t.Error("absolute URL with no allowlist = nil, want rejection")
	}
}
