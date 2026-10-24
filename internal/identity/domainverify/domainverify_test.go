package domainverify

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"  ACME.com ":            "acme.com",
		"https://acme.com/login": "acme.com",
		"http://acme.com":        "acme.com",
		"acme.com:8443":          "acme.com",
		"acme.com.":              "acme.com",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidDomain(t *testing.T) {
	valid := []string{"acme.com", "sso.acme.co.uk", "a-b.example.com"}
	for _, d := range valid {
		if !validDomain(d) {
			t.Errorf("validDomain(%q) = false, want true", d)
		}
	}
	invalid := []string{"", "nodot", "has space.com", "acme.com/path", "user@acme.com", "UPPER.com"}
	for _, d := range invalid {
		if validDomain(d) {
			t.Errorf("validDomain(%q) = true, want false", d)
		}
	}
}

// TestDeriveStatus checks that a domain whose last check failed needs
// attention, while one never checked is only pending.
func TestDeriveStatus(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		d    Domain
		want string
	}{
		{"verified wins over a stale error", Domain{VerifiedAt: &now, LastError: "old failure"}, "verified"},
		{"a failed check needs attention", Domain{LastError: "DNS TXT record not found"}, "attention"},
		{"never checked is simply pending", Domain{}, "pending"},
		{"checked with no error is still pending", Domain{LastCheckedAt: &now}, "pending"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.d
			d.deriveStatus()
			if d.Status != tc.want {
				t.Fatalf("Status = %q, want %q", d.Status, tc.want)
			}
		})
	}
}

// TestLoginRecordsAreDeterministic checks that a tenant's DNS instructions are
// the same on every call, so records an operator created stay valid.
func TestLoginRecordsAreDeterministic(t *testing.T) {
	id := uuid.MustParse("fa139717-1577-496e-823a-6a335738898a")
	a := loginRecords(id, "auth.acme.com")
	b := loginRecords(id, "auth.acme.com")

	if len(a) != 2 || a[0].Type != "CNAME" || a[1].Type != "TXT" {
		t.Fatalf("unexpected records: %+v", a)
	}
	if a[0].Name != "auth.acme.com" || a[0].Value != "fa139717.tenants.id.qeet.in" {
		t.Errorf("CNAME = %s -> %s", a[0].Name, a[0].Value)
	}
	if a[1].Value != "qeetid-verify=fa139717" {
		t.Errorf("TXT value = %s", a[1].Value)
	}
	if a[0] != b[0] || a[1] != b[1] {
		t.Error("records must be identical across calls")
	}
}

// txtResolver answers every TXT lookup with its records.
type txtResolver []string

func (r txtResolver) LookupTXT(context.Context, string) ([]string, error) { return r, nil }

// hostedLogin starts an HTTPS server answering /healthz with status and body,
// and returns a login-probe client that reaches it for any hostname. The
// server's certificate is valid for example.com, and trusted only if trusted.
func hostedLogin(t *testing.T, status int, body string, trusted bool) *http.Client {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	transport := srv.Client().Transport.(*http.Transport).Clone()
	if !trusted {
		transport.TLSClientConfig = nil
	}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	client := loginProbeClient(egress.DevelopmentPolicy())
	client.Transport = transport
	return client
}

// TestLoginDomainStages checks that a custom login domain moves from pending
// to active only as each stage is observed: its DNS records, a certificate
// valid for it, and the hosted login answering on it.
func TestLoginDomainStages(t *testing.T) {
	tenant := uuid.MustParse("fa139717-1577-496e-823a-6a335738898a")
	published := txtResolver{"qeetid-verify=fa139717"}
	healthy := `{"status":"ok","service":"qeet-id-hosted"}`
	for _, tc := range []struct {
		name                       string
		host                       string
		dns                        txtResolver
		web                        *http.Client
		status, tlsState, endpoint string
	}{
		{"no domain", "", published, hostedLogin(t, http.StatusOK, healthy, true), "not_configured", "not_started", "not_available"},
		{"not a hostname", "example.com:22", published, hostedLogin(t, http.StatusOK, healthy, true), "pending", "not_started", "not_available"},
		{"records not published", "example.com", txtResolver{"qeetid-verify=0000"}, hostedLogin(t, http.StatusOK, healthy, true), "pending", "not_started", "not_available"},
		{"no certificate for the domain", "example.com", published, hostedLogin(t, http.StatusOK, healthy, false), "pending", "pending", "not_available"},
		{"not the hosted login", "example.com", published, hostedLogin(t, http.StatusNotFound, "", true), "pending", "issued", "not_available"},
		{"another service", "example.com", published, hostedLogin(t, http.StatusOK, `{"status":"ok","service":"other"}`, true), "pending", "issued", "not_available"},
		{"the hosted login", "example.com", published, hostedLogin(t, http.StatusOK, healthy, true), "active", "issued", "live"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{resolver: tc.dns, web: tc.web}
			st := s.loginDomainStatus(t.Context(), tenant, tc.host)
			if st.Status != tc.status || st.TLSState != tc.tlsState || st.EndpointState != tc.endpoint {
				t.Errorf("status %s, TLS %s, endpoint %s; want %s, %s, %s",
					st.Status, st.TLSState, st.EndpointState, tc.status, tc.tlsState, tc.endpoint)
			}
			wantURL := ""
			if tc.endpoint == "live" {
				wantURL = "https://example.com"
			}
			if st.EndpointURL != wantURL {
				t.Errorf("endpoint URL %q, want %q", st.EndpointURL, wantURL)
			}
		})
	}
}
