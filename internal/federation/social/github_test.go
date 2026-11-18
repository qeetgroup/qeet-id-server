package social

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

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
