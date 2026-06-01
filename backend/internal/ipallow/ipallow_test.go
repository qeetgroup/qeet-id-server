package ipallow

import "testing"

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

func TestEvaluate_UnparseableFailsOpen(t *testing.T) {
	rules := []Rule{rule("10.0.0.0/8", "allow")}
	if ok, _ := Evaluate(rules, "not-an-ip"); !ok {
		t.Error("unparseable address should fail open (not lock out)")
	}
}
