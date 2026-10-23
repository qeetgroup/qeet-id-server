package auth

import (
	"context"
	"testing"
)

func TestSourceNetwork(t *testing.T) {
	for ip, want := range map[string]string{
		"203.0.113.7":                    "203.0.113.7",
		" 203.0.113.7 ":                  "203.0.113.7",
		"::ffff:203.0.113.7":             "203.0.113.7", // IPv4-mapped is the IPv4 source
		"2001:db8:1:2:aaaa:bbbb:cccc:d":  "2001:db8:1:2::/64",
		"2001:db8:1:2::9":                "2001:db8:1:2::/64", // same /64: same network
		"2001:db8:1:3::9":                "2001:db8:1:3::/64",
		"fe80::1%eth0":                   "fe80::/64",
		"":                               "",
		"not-an-address":                 "",
		"203.0.113.7:4000":               "",
		"2001:db8:1:2:aaaa:bbbb:cccc:dd": "2001:db8:1:2::/64",
	} {
		if got := SourceNetwork(ip); got != want {
			t.Errorf("SourceNetwork(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestVerifyPassword_NoStoredPasswordNeverMatches(t *testing.T) {
	for _, plain := range []string{"", "anything"} {
		if ok, err := verifyPassword(context.Background(), "", plain); ok || err != nil {
			t.Errorf("verifyPassword with no stored hash = %v, %v for %q; want false, nil", ok, err, plain)
		}
	}
	if timingHash() == "" {
		t.Error("no timing hash: an address with no account would answer faster than a wrong password")
	}
}
