//go:build integration

package ipallow

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRulesAreManagedOverHTTP checks that an organization's address rules are
// added, listed, checked, removed and switched on and off over HTTP; that a
// change locking the caller out is refused and not kept; that changes are
// audited; and that another organization can't see or remove them.
func TestRulesAreManagedOverHTTP(t *testing.T) {
	svc := NewService(dbtest.Pool(t))
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	base := "/organizations/" + organization.String() + "/ip-rules"
	// Every request comes from httptest's 192.0.2.1, the caller the lock-out guard protects.
	add := func(cidr, action string) Rule {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodPost, base, map[string]string{"cidr": cidr, "label": "test", "action": action})
		if rec.Code != http.StatusCreated {
			t.Fatalf("add %s %q: %d %s", action, cidr, rec.Code, rec.Body.String())
		}
		var r Rule
		dbtest.Decode(t, rec, &r)
		return r
	}
	list := func(h http.Handler, path string) (bool, string) {
		t.Helper()
		var page struct {
			Enabled bool   `json:"enabled"`
			Items   []Rule `json:"items"`
		}
		dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, path, nil), &page)
		cidrs := make([]string, len(page.Items))
		for i, r := range page.Items {
			cidrs[i] = r.CIDR
		}
		return page.Enabled, fmt.Sprint(cidrs)
	}
	check := func(h http.Handler, path, ip string) CheckResult {
		t.Helper()
		var res CheckResult
		dbtest.Decode(t, dbtest.Do(t, h, http.MethodPost, path+"/check", map[string]string{"ip": ip}), &res)
		return res
	}
	setEnabled := func(on bool) int {
		return dbtest.Do(t, h, http.MethodPut, base+"/config", map[string]bool{"enabled": on}).Code
	}

	if enabled, cidrs := list(h, base); enabled || cidrs != "[]" {
		t.Errorf("a new organization's rules: enabled %v, %s; want off and none", enabled, cidrs)
	}
	for _, cidr := range []string{"", "not-an-address", "10.0.0.0/33", "300.1.1.1"} {
		rec := dbtest.Do(t, h, http.MethodPost, base, map[string]string{"cidr": cidr, "action": "deny"})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), CodeRiskCIDRInvalid) {
			t.Errorf("add %q: %d %s, want 422 %s", cidr, rec.Code, rec.Body.String(), CodeRiskCIDRInvalid)
		}
	}
	if r := add(" 198.51.100.0/24 ", ""); r.Action != "allow" || r.CIDR != "198.51.100.0/24" || r.OrganizationID != organization {
		t.Errorf("a rule added without an action: %+v; want an allow rule for the trimmed range", r)
	}
	if res := check(h, base, "203.0.113.9"); res.Enabled || !res.Allowed || res.ReasonCode != CodeEnforcementOff {
		t.Errorf("check with the rules off: %+v; want allowed as %s", res, CodeEnforcementOff)
	}
	rec := dbtest.Do(t, h, http.MethodPut, base+"/config", map[string]bool{"enabled": true})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), CodeRiskRulesLockOutCaller) {
		t.Errorf("switch on rules that refuse the caller: %d %s, want 409 %s", rec.Code, rec.Body.String(), CodeRiskRulesLockOutCaller)
	}
	if rec := dbtest.Do(t, h, http.MethodPut, base+"/config", map[string]bool{"enable": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("config with a misspelt field: %d, want 400", rec.Code)
	}

	office := add("192.0.2.0/24", "allow")
	host := add("192.0.2.200", "deny")
	add("2001:db8::/32", "allow")
	if code := setEnabled(true); code != http.StatusOK {
		t.Fatalf("switch on rules that allow the caller: %d", code)
	}
	for _, tc := range []struct {
		ip, code string
		allowed  bool
	}{
		{"192.0.2.50", "ip.allowed", true},
		{"192.0.2.200", "ip.deny_rule", false},
		{"2001:db8::5", "ip.allowed", true},
		{"2001:db9::1", "ip.not_in_allow_rules", false},
		{"203.0.113.9", "ip.not_in_allow_rules", false},
		{"nonsense", "ip.address_unknown", false},
	} {
		if res := check(h, base, tc.ip); !res.Enabled || res.Allowed != tc.allowed || res.ReasonCode != tc.code {
			t.Errorf("check %s: %+v; want allowed %v as %s", tc.ip, res, tc.allowed, tc.code)
		}
	}
	if res := check(h, base, "192.0.2.200"); res.ReasonParams["cidr"] != "192.0.2.200" {
		t.Errorf("a refusal by a single-address deny rule names %v, want that rule", res.ReasonParams)
	}

	rec = dbtest.Do(t, h, http.MethodPost, base, map[string]string{"cidr": "192.0.2.0/28", "action": "deny"})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), CodeRiskRulesLockOutCaller) {
		t.Errorf("add a deny rule covering the caller: %d %s, want 409", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+office.ID.String(), nil); rec.Code != http.StatusConflict {
		t.Errorf("remove the allow rule covering the caller: %d, want 409", rec.Code)
	}
	if _, cidrs := list(h, base); cidrs != "[198.51.100.0/24 192.0.2.0/24 2001:db8::/32 192.0.2.200]" {
		t.Errorf("rules after two refused changes: %s; want them unchanged", cidrs)
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+host.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove the deny rule: %d %s", rec.Code, rec.Body.String())
	}
	if res := check(h, base, "192.0.2.200"); !res.Allowed {
		t.Errorf("check once its deny rule is removed: %+v, want allowed", res)
	}
	for _, tc := range []struct {
		rule, code string
		status     int
	}{
		{"not-a-rule", errs.CodeBadRequest, http.StatusBadRequest},
		{host.ID.String(), errs.CodeNotFound, http.StatusNotFound},
	} {
		if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+tc.rule, nil); rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("remove rule %s: %d %s, want %d %s", tc.rule, rec.Code, rec.Body.String(), tc.status, tc.code)
		}
	}

	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), (&Handler{Service: svc}).Mount)
	otherBase := "/organizations/" + other.String() + "/ip-rules"
	if rec := dbtest.Do(t, asOther, http.MethodGet, base, nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organization listing the rules: %d, want 403", rec.Code)
	}
	if enabled, cidrs := list(asOther, otherBase); enabled || cidrs != "[]" {
		t.Errorf("another organization's own rules: enabled %v, %s; want none of this one's", enabled, cidrs)
	}
	if rec := dbtest.Do(t, asOther, http.MethodDelete, otherBase+"/"+office.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("delete another organization's rule: %d, want 404", rec.Code)
	}
	if res := check(asOther, otherBase, "203.0.113.9"); res.Enabled || !res.Allowed {
		t.Errorf("another organization's check: %+v; want this one's rules not applied", res)
	}

	if code := setEnabled(false); code != http.StatusOK {
		t.Errorf("switch off: %d", code)
	}
	if enabled, cidrs := list(h, base); enabled || cidrs != "[198.51.100.0/24 192.0.2.0/24 2001:db8::/32]" {
		t.Errorf("rules at the end: enabled %v, %s; want off, with the three allow rules", enabled, cidrs)
	}
	for action, want := range map[string]int{"ip_rules.rule_added": 4, "ip_rules.rule_removed": 1, "ip_rules.enforcement_changed": 2} {
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND actor_user_id = $3`,
			organization, action, admin.ID); n != want {
			t.Errorf("%d %s records, want %d", n, action, want)
		}
	}
	// Each rule change names the rule, and what it was.
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'ip_rules.rule_removed'
		AND resource_type = 'ip_rule' AND resource_id = $2 AND metadata->>'cidr' = '192.0.2.200' AND metadata->>'action' = 'deny'`,
		organization, host.ID); n != 1 {
		t.Errorf("%d removal records naming the deny rule, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'ip_rules.rule_added'
		AND resource_id IS NOT NULL AND metadata ? 'cidr'`, organization); n != 4 {
		t.Errorf("%d additions naming their rule, want 4", n)
	}
}

// TestUnknownActionIsRefused checks that a rule whose action is neither allow
// nor deny is refused, not stored as an allow rule.
func TestUnknownActionIsRefused(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: NewService(dbtest.Pool(t))}).Mount)
	for _, action := range []string{"Deny", "block"} {
		rec := dbtest.Do(t, h, http.MethodPost, "/organizations/"+organization.String()+"/ip-rules", map[string]string{"cidr": "203.0.113.0/24", "action": action})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), CodeRiskRuleActionInvalid) {
			t.Errorf("add a rule with action %q: %d %s, want 422 %s", action, rec.Code, rec.Body.String(), CodeRiskRuleActionInvalid)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.ip_rules WHERE organization_id = $1`, organization); n != 0 {
		t.Errorf("%d rules stored after the refusals, want none", n)
	}
}
