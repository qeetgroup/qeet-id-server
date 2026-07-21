package domainverify

import "testing"

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
