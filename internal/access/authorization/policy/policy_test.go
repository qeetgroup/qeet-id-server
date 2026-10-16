package policy

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// TestPolicyAllowed_DecisionMatrix is the IP allow/deny decision engine: a
// table of (allowlist, denylist, ip) → allow/deny, covering default-deny vs
// default-allow semantics and denylist precedence.
func TestPolicyAllowed_DecisionMatrix(t *testing.T) {
	cases := []struct {
		name  string
		allow []string
		deny  []string
		ip    string
		want  bool
	}{
		// Empty allowlist means "allow everything except the denylist".
		{"empty lists allow all", nil, nil, "203.0.113.7", true},
		{"empty allowlist permits any IP", []string{}, []string{}, "8.8.8.8", true},

		// Allowlist gates: only members pass.
		{"in allowlist CIDR", []string{"10.0.0.0/8"}, nil, "10.1.2.3", true},
		{"outside allowlist CIDR denied", []string{"10.0.0.0/8"}, nil, "192.168.1.1", false},
		{"in one of several allow CIDRs", []string{"10.0.0.0/8", "192.168.0.0/16"}, nil, "192.168.5.5", true},

		// Denylist precedence: a denied IP loses even if the allowlist would admit it.
		{"deny beats allow", []string{"10.0.0.0/8"}, []string{"10.0.0.5/32"}, "10.0.0.5", false},
		{"deny with empty allowlist", nil, []string{"10.0.0.0/8"}, "10.5.5.5", false},
		{"deny miss falls through to allow-all", nil, []string{"10.0.0.0/8"}, "11.0.0.1", true},

		// Single-IP literal entries (not CIDR) match by exact string.
		{"single-ip allow literal", []string{"203.0.113.9"}, nil, "203.0.113.9", true},
		{"single-ip allow literal miss", []string{"203.0.113.9"}, nil, "203.0.113.10", false},
		{"single-ip deny literal", nil, []string{"203.0.113.9"}, "203.0.113.9", false},

		// IPv6.
		{"ipv6 in allow CIDR", []string{"2001:db8::/32"}, nil, "2001:db8::1", true},
		{"ipv6 outside allow CIDR", []string{"2001:db8::/32"}, nil, "2001:dead::1", false},
		{"ipv6 deny precedence", []string{"2001:db8::/32"}, []string{"2001:db8::1/128"}, "2001:db8::1", false},

		// Boundary: /32 host route admits exactly one address.
		{"host route exact", []string{"10.0.0.1/32"}, nil, "10.0.0.1", true},
		{"host route neighbour", []string{"10.0.0.1/32"}, nil, "10.0.0.2", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &Policy{IPAllowlist: c.allow, IPDenylist: c.deny}
			ip := net.ParseIP(c.ip)
			if ip == nil {
				t.Fatalf("bad test IP %q", c.ip)
			}
			if got := p.Allowed(ip); got != c.want {
				t.Errorf("Allowed(%s) = %v, want %v (allow=%v deny=%v)", c.ip, got, c.want, c.allow, c.deny)
			}
		})
	}
}

func TestPolicyAllowed_NilIPIsPermitted(t *testing.T) {
	// A missing/unparseable client IP must not hard-fail the request.
	p := &Policy{IPAllowlist: []string{"10.0.0.0/8"}, IPDenylist: []string{"0.0.0.0/0"}}
	if !p.Allowed(nil) {
		t.Error("a nil IP should be allowed (fail-open on unknown client IP)")
	}
}

func TestCIDRContains(t *testing.T) {
	cases := []struct {
		cidr string
		ip   string
		want bool
	}{
		{"10.0.0.0/8", "10.255.255.255", true},
		{"10.0.0.0/8", "11.0.0.0", false},
		{"192.168.1.0/24", "192.168.1.42", true},
		{"192.168.1.0/24", "192.168.2.1", false},
		// A bare IP is treated as an exact-match literal.
		{"203.0.113.5", "203.0.113.5", true},
		{"203.0.113.5", "203.0.113.6", false},
		// Empty/garbage CIDR never matches.
		{"", "1.2.3.4", false},
		{"not-a-cidr", "1.2.3.4", false},
	}
	for _, c := range cases {
		t.Run(c.cidr+"_"+c.ip, func(t *testing.T) {
			if got := cidrContains(c.cidr, net.ParseIP(c.ip)); got != c.want {
				t.Errorf("cidrContains(%q, %q) = %v, want %v", c.cidr, c.ip, got, c.want)
			}
		})
	}
}

func TestPolicyAllowed_DenyOnlyDoesNotGate(t *testing.T) {
	// Regression: a denylist with no allowlist must NOT flip into default-deny
	// for non-denied addresses (empty allowlist == allow-all-but-denied).
	p := &Policy{IPDenylist: []string{"198.51.100.0/24"}}
	if !p.Allowed(net.ParseIP("198.51.101.1")) {
		t.Error("non-denied IP should pass when there's no allowlist")
	}
	if p.Allowed(net.ParseIP("198.51.100.7")) {
		t.Error("denied IP must be blocked")
	}
}

// TestDurationJSON: session bounds are written as duration strings the console
// edits, and read back from those or from the nanoseconds earlier responses
// carried.
func TestDurationJSON(t *testing.T) {
	for in, want := range map[time.Duration]string{
		720 * time.Hour:  `"720h"`,
		90 * time.Minute: `"90m"`,
		90 * time.Second: `"1m30s"`,
	} {
		got, err := json.Marshal(Duration(in))
		if err != nil || string(got) != want {
			t.Errorf("marshal %v = %s, %v; want %s", in, got, err, want)
		}
	}
	for raw, want := range map[string]time.Duration{
		`"720h"`:           720 * time.Hour,
		`"30m"`:            30 * time.Minute,
		`2592000000000000`: 720 * time.Hour,
	} {
		var d Duration
		if err := json.Unmarshal([]byte(raw), &d); err != nil || time.Duration(d) != want {
			t.Errorf("unmarshal %s = %v, %v; want %v", raw, time.Duration(d), err, want)
		}
	}
	var d Duration
	if err := json.Unmarshal([]byte(`"a month"`), &d); err == nil {
		t.Error("an unparseable duration was accepted")
	}
}

// TestNormalizeFillsDefaultsAndRefusesOutOfRange: bounds left out take the
// platform defaults, the idle timeout no longer than the maximum age; values
// out of range are named.
func TestNormalizeFillsDefaultsAndRefusesOutOfRange(t *testing.T) {
	r := &Repository{sessionMaxAge: 720 * time.Hour, sessionIdle: 24 * time.Hour}
	p := Policy{PasswordMinLength: 8, PasswordComplexity: "standard", MFAEnforcement: "optional", SessionMaxAge: Duration(2 * time.Hour)}
	if bad := r.normalize(&p); len(bad) != 0 {
		t.Fatalf("valid policy refused: %+v", bad)
	}
	if time.Duration(p.SessionIdleTimeout) != 2*time.Hour || p.IPAllowlist == nil || p.IPDenylist == nil {
		t.Errorf("defaults not filled: idle %v allow %v deny %v", time.Duration(p.SessionIdleTimeout), p.IPAllowlist, p.IPDenylist)
	}
	p = Policy{PasswordMinLength: 4, PasswordComplexity: "basic", MFAEnforcement: "disabled",
		SessionMaxAge: Duration(30 * time.Minute), SessionIdleTimeout: Duration(time.Hour)}
	got := map[string]bool{}
	for _, f := range r.normalize(&p) {
		got[f.Field] = true
	}
	for _, want := range []string{"session_max_age", "session_idle_timeout", "password_min_length", "password_complexity", "mfa_enforcement"} {
		if !got[want] {
			t.Errorf("%s out of range was not named (named: %v)", want, got)
		}
	}
}
