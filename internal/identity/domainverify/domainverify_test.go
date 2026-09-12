package domainverify

import (
	"testing"
	"time"

	"github.com/google/uuid"
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

// The console renders three states, and the difference between "pending" and
// "attention" is whether a check has actually run and failed — not merely that
// the domain is unverified.
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

// The DNS instructions must be stable for a tenant: an operator who has already
// created the CNAME shouldn't find it invalidated on the next page load.
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
