package httpx

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublicOrigin(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		fwdProto   string
		tls        bool
		configured string
		want       string
	}{
		{"configured wins over Host", "evil.example", "", false, "https://api.acme.com", "https://api.acme.com"},
		{"configured trailing slash", "api.acme.com", "", false, "https://api.acme.com/", "https://api.acme.com"},
		{"forwarded https", "api.acme.com", "https", false, "", "https://api.acme.com"},
		{"forwarded http", "api.acme.com", "http", false, "", "http://api.acme.com"},
		{"forwarded junk ignored", "api.acme.com", "gopher", false, "", "https://api.acme.com"},
		{"tls", "api.acme.com", "", true, "", "https://api.acme.com"},
		{"plain localhost", "localhost:8080", "", false, "", "http://localhost:8080"},
		{"plain loopback", "127.0.0.1:8080", "", false, "", "http://127.0.0.1:8080"},
		{"plain other host", "api.acme.com", "", false, "", "https://api.acme.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			r.Host = c.host
			if c.fwdProto != "" {
				r.Header.Set("X-Forwarded-Proto", c.fwdProto)
			}
			if c.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := PublicOrigin(r, c.configured); got != c.want {
				t.Errorf("PublicOrigin = %q, want %q", got, c.want)
			}
		})
	}
}
