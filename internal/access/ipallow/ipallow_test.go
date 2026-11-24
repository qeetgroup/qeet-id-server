package ipallow

import (
	"testing"

	"github.com/google/uuid"
)

func rule(cidr, action string) Rule { return Rule{CIDR: cidr, Action: action} }

func TestEvaluate_NoRules(t *testing.T) {
	if ok, _ := Evaluate(nil, "1.2.3.4"); !ok {
		t.Error("no rules should allow everything")
	}
}

func TestEvaluate_AllowList(t *testing.T) {
	rules := []Rule{rule("10.0.0.0/8", "allow"), rule("203.0.113.0/24", "allow")}
	if ok, _ := Evaluate(rules, "10.1.2.3"); !ok {
		t.Error("address inside an allow range should pass")
	}
	if ok, why := Evaluate(rules, "8.8.8.8"); ok {
		t.Errorf("address outside all allow ranges should be blocked, got allowed (%s)", why)
	}
}

func TestEvaluate_DenyWins(t *testing.T) {
	// In allow range, but also denied → blocked.
	rules := []Rule{rule("10.0.0.0/8", "allow"), rule("10.6.6.0/24", "deny")}
	if ok, why := Evaluate(rules, "10.6.6.6"); ok {
		t.Errorf("deny must win over allow, got allowed (%s)", why)
	}
	if ok, _ := Evaluate(rules, "10.1.1.1"); !ok {
		t.Error("allow range, not denied → pass")
	}
}

func TestEvaluate_DenyOnly(t *testing.T) {
	// Only deny rules: everything not denied passes (no allow list to satisfy).
	rules := []Rule{rule("185.220.100.0/22", "deny")}
	if ok, _ := Evaluate(rules, "1.2.3.4"); !ok {
		t.Error("non-denied address with no allow list should pass")
	}
	if ok, _ := Evaluate(rules, "185.220.101.5"); ok {
		t.Error("denied address should be blocked")
	}
}

func TestEvaluate_BareHostAndIPv6(t *testing.T) {
	rules := []Rule{rule("1.2.3.4", "allow"), rule("2001:db8::/32", "allow")}
	if ok, _ := Evaluate(rules, "1.2.3.4"); !ok {
		t.Error("bare host /32 should match exactly")
	}
	if ok, _ := Evaluate(rules, "1.2.3.5"); ok {
		t.Error("different host should not match a /32")
	}
	if ok, _ := Evaluate(rules, "2001:db8::1"); !ok {
		t.Error("IPv6 inside prefix should match")
	}
}

// TestDecide_UnreadableAddressIsRefused checks that an address that can't be
// read is refused, whatever the rules.
func TestDecide_UnreadableAddressIsRefused(t *testing.T) {
	for _, rules := range [][]Rule{nil, {rule("10.0.0.0/8", "allow")}, {rule("10.0.0.0/8", "deny")}} {
		for _, addr := range []string{"", "not-an-ip", "10.0.0.1:443"} {
			if d := Decide(rules, addr); d.Allowed || d.Reason != ReasonUnknownAddr {
				t.Errorf("Decide(%v, %q) = %+v, want refused as %s", rules, addr, d, ReasonUnknownAddr)
			}
		}
	}
}

// TestDecide_NamesTheRuleResponsible checks that a refusal names the deny rule
// responsible, that deny beats a matching allow, and that a refusal outside
// every allow rule names no rule.
func TestDecide_NamesTheRuleResponsible(t *testing.T) {
	deny := Rule{ID: uuid.New(), CIDR: "192.0.2.0/24", Action: "deny"}
	rules := []Rule{rule("192.0.2.0/24", "allow"), deny, rule("198.51.100.0/24", "allow")}
	d := Decide(rules, "192.0.2.10")
	if d.Allowed || d.Reason != ReasonDenyRule || d.Rule == nil || d.Rule.ID != deny.ID {
		t.Fatalf("deny and allow both match: %+v, want refused by rule %s", d, deny.ID)
	}
	if d := Decide(rules, "203.0.113.5"); d.Allowed || d.Reason != ReasonNotAllowed || d.Rule != nil {
		t.Fatalf("outside every allow rule: %+v, want refused with no rule", d)
	}
	if d := Decide(rules, "198.51.100.7"); !d.Allowed || d.Rule != nil {
		t.Fatalf("inside an allow rule: %+v, want allowed", d)
	}
}

// TestDecide_IPv4MappedAddress checks that an IPv4-mapped IPv6 address is
// judged as its IPv4 form.
func TestDecide_IPv4MappedAddress(t *testing.T) {
	if d := Decide([]Rule{rule("192.0.2.0/24", "deny")}, "::ffff:192.0.2.10"); d.Allowed {
		t.Fatal("an IPv4-mapped address got past the deny rule for its IPv4 form")
	}
}
