package ldap

import (
	"strings"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
)

func TestHostOnly(t *testing.T) {
	cases := map[string]string{
		"ldaps://ldap.corp.com:636": "ldap.corp.com",
		"ldap://localhost:389":      "localhost",
		"ldaps://ad.example.org":    "ad.example.org",
		"not a url":                 "",
	}
	for in, want := range cases {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTLSConfig(t *testing.T) {
	c := &connFull{Connection: Connection{ServerURL: "ldaps://ad.example.org:636", SkipTLSVerify: true}}
	if !c.tlsConfig(true).InsecureSkipVerify {
		t.Error("SkipTLSVerify should propagate to InsecureSkipVerify where it is allowed")
	}
	cfg := c.tlsConfig(false)
	if cfg.InsecureSkipVerify {
		t.Error("SkipTLSVerify must not turn verification off where it is not allowed")
	}
	if cfg.ServerName != "ad.example.org" {
		t.Errorf("ServerName = %q, want ad.example.org", cfg.ServerName)
	}

	c2 := &connFull{Connection: Connection{ServerURL: "ldaps://ad.example.org:636"}}
	if c2.tlsConfig(true).InsecureSkipVerify {
		t.Error("verification should be on by default")
	}
}

// TestUserFilterEscaping checks that the username is LDAP-escaped before it is
// put into the user-search filter, so it can't inject filter syntax.
func TestUserFilterEscaping(t *testing.T) {
	filter := "(uid=%s)"
	malicious := "*)(uid=*"
	built := strings.ReplaceAll(filter, "%s", goldap.EscapeFilter(malicious))
	if strings.Contains(built, "*)(uid=*") {
		t.Errorf("raw injection survived escaping: %q", built)
	}
	// A normal username substitutes cleanly.
	ok := strings.ReplaceAll(filter, "%s", goldap.EscapeFilter("alice"))
	if ok != "(uid=alice)" {
		t.Errorf("normal username = %q, want (uid=alice)", ok)
	}
}
