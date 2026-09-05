package egress

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
)

type staticResolver map[string][]net.IP

func (r staticResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	return r[host], nil
}

func TestPublicPolicyURLValidation(t *testing.T) {
	policy := NewPolicy(Options{})
	for _, raw := range []string{
		"https://example.com/hook",
		"https://203.0.113.10/callback",
	} {
		if _, err := policy.ValidateHTTPURL(raw); err != nil {
			t.Errorf("public URL %q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://example.com/hook",
		"https://localhost/hook",
		"https://127.0.0.1/hook",
		"https://[::1]/hook",
		"https://10.0.0.1/hook",
		"https://169.254.169.254/latest/meta-data",
		"https://user@example.com/hook",
		"https://example.com/hook#fragment",
	} {
		if _, err := policy.ValidateHTTPURL(raw); err == nil {
			t.Errorf("unsafe URL %q accepted", raw)
		}
	}
}

func TestDialRejectsMixedDNSAnswers(t *testing.T) {
	policy := NewPolicy(Options{Resolver: staticResolver{
		"mixed.example": {net.ParseIP("203.0.113.10"), net.ParseIP("127.0.0.1")},
	}})
	if _, err := policy.resolveAllowed(context.Background(), "mixed.example"); err == nil {
		t.Fatal("hostname with a private rebinding answer was accepted")
	}
}

func TestRedirectTargetIsRevalidated(t *testing.T) {
	policy := NewPolicy(Options{})
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "127.0.0.1", Path: "/secret"}}
	if err := policy.CheckRedirect(req, []*http.Request{{URL: &url.URL{Scheme: "https", Host: "example.com"}}}); err == nil {
		t.Fatal("redirect to loopback was accepted")
	}
}

func FuzzValidateHTTPURL(f *testing.F) {
	for _, seed := range []string{
		"https://example.com/hook",
		"http://127.0.0.1",
		"https://[::ffff:127.0.0.1]/",
		"https://2130706433/",
		"file:///etc/passwd",
	} {
		f.Add(seed)
	}
	policy := NewPolicy(Options{})
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = policy.ValidateHTTPURL(raw)
	})
}
