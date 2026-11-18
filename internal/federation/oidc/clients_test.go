package oidc

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestValidateClientInput(t *testing.T) {
	valid := CreateClientInput{
		Type:           "confidential",
		RedirectURIs:   []string{"https://client.example/callback"},
		PostLogoutURIs: []string{"https://client.example/signed-out"},
		GrantTypes:     []string{"authorization_code", "refresh_token"},
	}
	if err := validateClientInput(valid); err != nil {
		t.Fatalf("valid client rejected: %v", err)
	}
	loopback := valid
	loopback.Type = "public"
	loopback.RedirectURIs = []string{"http://127.0.0.1:49152/callback", "http://localhost:3000/callback"}
	if err := validateClientInput(loopback); err != nil {
		t.Fatalf("loopback native callback rejected: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*CreateClientInput)
	}{
		{"unknown client type", func(in *CreateClientInput) { in.Type = "browser" }},
		{"unknown grant", func(in *CreateClientInput) { in.GrantTypes = []string{"password"} }},
		{"authorization code without redirect", func(in *CreateClientInput) { in.RedirectURIs = nil }},
		{"non-loopback http redirect", func(in *CreateClientInput) { in.RedirectURIs = []string{"http://client.example/callback"} }},
		{"redirect fragment", func(in *CreateClientInput) { in.RedirectURIs = []string{"https://client.example/callback#fragment"} }},
		{"redirect userinfo", func(in *CreateClientInput) { in.RedirectURIs = []string{"https://user@client.example/callback"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			if err := validateClientInput(in); err == nil {
				t.Fatal("invalid client input was accepted")
			}
		})
	}
}

func TestValidateRegisteredRedirectURI(t *testing.T) {
	valid := []string{
		"https://app.example.com/callback",
		"https://app.example.com/callback?next=%2Fhome",
		"http://127.0.0.1:8080/cb",
		"http://[::1]:8080/cb",
		"http://localhost:3000/cb",
		"com.example.app:/oauth2redirect",
		"com.example.app://oauth2redirect",
		"in.qeet.console:/cb",
	}
	for _, uri := range valid {
		if err := validateRegisteredRedirectURI(uri); err != nil {
			t.Errorf("validateRegisteredRedirectURI(%q) = %v, want nil", uri, err)
		}
	}

	invalid := []string{
		"",
		"/callback",                          // relative
		"https://app.example.com/cb#frag",    // fragment is the response's
		"https://user:pw@app.example.com/cb", // userinfo
		"http://example.com/cb",              // non-loopback cleartext
		"http://169.254.169.254/cb",          // link-local, not loopback
		"myapp:/cb",                          // no dot: not reverse-DNS
		"javascript:alert(1)",                // reserved scheme
		"data:text/html,x",                   // reserved scheme
		"ftp://example.com/cb",               // reserved scheme
		".com.example:/cb",                   // malformed scheme
		"com..example:/cb",                   // malformed scheme
	}
	for _, uri := range invalid {
		if err := validateRegisteredRedirectURI(uri); err == nil {
			t.Errorf("validateRegisteredRedirectURI(%q) = nil, want error", uri)
		}
	}
}

// TestRedirectRegistered checks that a redirect matches a registered one
// exactly, except that an http redirect to a loopback IP literal may name any
// port (RFC 8252 §7.3), and nothing else about it may differ.
func TestRedirectRegistered(t *testing.T) {
	registered := []string{
		"https://app.example.test/callback",
		"http://127.0.0.1/cb",
		"http://[::1]:8080/cb?app=1",
		"http://localhost:3000/cb",
	}
	for _, uri := range []string{
		"https://app.example.test/callback",
		"http://127.0.0.1/cb",
		"http://127.0.0.1:53682/cb",
		"http://127.0.0.1:1/cb",
		"http://[::1]/cb?app=1",
		"http://[::1]:61000/cb?app=1",
		"http://localhost:3000/cb",
	} {
		if !redirectRegistered(registered, uri, "public") {
			t.Errorf("%s: not matched", uri)
		}
	}
	for _, uri := range []string{
		"https://app.example.test:8443/callback", // not loopback: the port must match
		"http://127.0.0.1:53682/cb/",
		"http://127.0.0.1:53682/other",
		"http://127.0.0.1:53682/cb?x=1",
		"http://127.0.0.1:53682/cb#frag",
		"http://127.0.0.2:53682/cb",
		"http://[::1]:61000/cb",
		"https://127.0.0.1:53682/cb",
		"HTTP://127.0.0.1:53682/cb",
		"http://localhost:4000/cb", // a name, not an IP literal
		"http://user@127.0.0.1:53682/cb",
		"http://127.0.0.1:/cb",
		"http://127.0.0.1:65536/cb",
		"http://127.0.0.1:+80/cb",
		"http://127.0.0.1.evil.test:53682/cb",
		"http://[::1]x:61000/cb?app=1",
	} {
		if redirectRegistered(registered, uri, "public") {
			t.Errorf("%s: matched", uri)
		}
	}
}

// TestLoopbackAnyPortOnlyForPublicClients checks that only a public (native)
// application's loopback redirect may name another port: a confidential web
// application's must match exactly, so a local process on another port can't
// receive its codes.
func TestLoopbackAnyPortOnlyForPublicClients(t *testing.T) {
	registered := []string{"http://127.0.0.1:8080/cb", "http://[::1]/cb"}
	for _, uri := range []string{"http://127.0.0.1:53682/cb", "http://[::1]:61000/cb"} {
		if !redirectRegistered(registered, uri, "public") {
			t.Errorf("%s for a public application: not matched", uri)
		}
		if redirectRegistered(registered, uri, "confidential") {
			t.Errorf("%s for a confidential application: matched", uri)
		}
	}
	for _, uri := range registered {
		if !redirectRegistered(registered, uri, "confidential") {
			t.Errorf("%s exactly, for a confidential application: not matched", uri)
		}
	}
}

// TestPublicClientsCantHoldConfidentialFlows checks that a public client, which
// authenticates with a client_id alone, can't hold flows that need client auth.
func TestPublicClientsCantHoldConfidentialFlows(t *testing.T) {
	base := CreateClientInput{Type: "public", RedirectURIs: []string{"https://spa.example/cb"}}
	for _, grant := range []string{"token_exchange", grantTypeTokenExchange, grantTypeCIBA} {
		in := base
		in.GrantTypes = []string{"authorization_code", grant}
		if err := validateClientInput(in); !errors.Is(err, ErrUnsupportedFlow) {
			t.Errorf("public + %s: err = %v, want %v", grant, err, ErrUnsupportedFlow)
		}
		in.Type = "confidential"
		if err := validateClientInput(in); err != nil {
			t.Errorf("confidential + %s rejected: %v", grant, err)
		}
	}
}

// FuzzValidateRegisteredRedirectURI checks that redirect-URI validation never
// panics, and that every accepted URI is absolute, has no userinfo or fragment,
// and is HTTPS, HTTP loopback or a reverse-DNS private-use scheme.
func FuzzValidateRegisteredRedirectURI(f *testing.F) {
	for _, seed := range []string{
		"https://app.example.com/callback",
		"https://app.example.com/callback?next=%2Fhome",
		"HTTPS://APP.EXAMPLE.COM/CB",
		"https://app.example.com:8443/cb",
		"https://xn--bcher-kva.example/cb",
		"https://[2001:db8::1]/cb",
		"https:///cb",
		"https://:443/cb",
		"https://app.example.com/cb#",
		"https://app.example.com/cb#frag",
		"https://user:pw@app.example.com/cb",
		"https://@app.example.com/cb",
		"https://app.example.com/%zz",
		"https://app.example.com\x00/cb",
		" https://app.example.com/cb",
		"http://127.0.0.1:8080/cb",
		"http://127.0.0.2/cb",
		"http://127.1/cb",
		"http://0x7f.0.0.1/cb",
		"http://[::1]:8080/cb",
		"http://[::ffff:127.0.0.1]/cb",
		"http://[fe80::1%25en0]/cb",
		"http://localhost:3000/cb",
		"http://LOCALHOST/cb",
		"http://localhost./cb",
		"http://localhost.example.com/cb",
		"http://example.com/cb",
		"http://169.254.169.254/cb",
		"com.example.app:/oauth2redirect",
		"com.example.app://oauth2redirect",
		"COM.EXAMPLE.APP:/cb",
		"in.qeet.console:/cb",
		"com.example.app:",
		"com.example.app:/cb#x",
		"com.example-app+dev.v2:/cb",
		"myapp:/cb",
		".com.example:/cb",
		"com..example:/cb",
		"com.example.:/cb",
		"com.ex_ample:/cb",
		"javascript:alert(1)",
		"data:text/html,x",
		"ftp://example.com/cb",
		"file:///etc/passwd",
		"/callback",
		"//app.example.com/cb",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if validateRegisteredRedirectURI(raw) != nil {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.User != nil || u.Fragment != "" {
			t.Fatalf("accepted %q, which is not an absolute URI without userinfo or fragment", raw)
		}
		switch scheme := strings.ToLower(u.Scheme); scheme {
		case "https":
			if u.Hostname() == "" {
				t.Fatalf("accepted HTTPS URI %q without a host", raw)
			}
		case "http":
			host := strings.ToLower(u.Hostname())
			if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
				t.Fatalf("accepted HTTP URI %q with a non-loopback host", raw)
			}
		default:
			if _, reserved := reservedRedirectSchemes[scheme]; reserved || !strings.Contains(scheme, ".") {
				t.Fatalf("accepted %q with scheme %q", raw, scheme)
			}
		}
	})
}
