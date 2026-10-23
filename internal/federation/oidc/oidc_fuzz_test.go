package oidc

import (
	"net"
	"net/url"
	"strings"
	"testing"
)

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
