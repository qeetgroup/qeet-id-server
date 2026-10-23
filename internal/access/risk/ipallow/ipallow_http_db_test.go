//go:build integration

package ipallow

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRulesAreManagedOverHTTP checks that an organisation's address rules are
// added, listed, checked, removed and switched on and off over HTTP; that a
// change locking the caller out is refused and not kept; that changes are
// audited; and that another organisation can't see or remove them.
func TestRulesAreManagedOverHTTP(t *testing.T) {
	svc := NewService(dbtest.Pool(t))
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	base := "/tenants/" + tenant.String() + "/ip-rules"
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
		t.Errorf("a new organisation's rules: enabled %v, %s; want off and none", enabled, cidrs)
	}
	for _, cidr := range []string{"", "not-an-address", "10.0.0.0/33", "300.1.1.1"} {
		rec := dbtest.Do(t, h, http.MethodPost, base, map[string]string{"cidr": cidr, "action": "deny"})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), errs.CodeRiskCIDRInvalid) {
			t.Errorf("add %q: %d %s, want 422 %s", cidr, rec.Code, rec.Body.String(), errs.CodeRiskCIDRInvalid)
		}
	}
	if r := add(" 198.51.100.0/24 ", ""); r.Action != "allow" || r.CIDR != "198.51.100.0/24" || r.TenantID != tenant {
		t.Errorf("a rule added without an action: %+v; want an allow rule for the trimmed range", r)
	}
	if res := check(h, base, "203.0.113.9"); res.Enabled || !res.Allowed || res.ReasonCode != CodeEnforcementOff {
		t.Errorf("check with the rules off: %+v; want allowed as %s", res, CodeEnforcementOff)
	}
	rec := dbtest.Do(t, h, http.MethodPut, base+"/config", map[string]bool{"enabled": true})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errs.CodeRiskRulesLockOutCaller) {
		t.Errorf("switch on rules that refuse the caller: %d %s, want 409 %s", rec.Code, rec.Body.String(), errs.CodeRiskRulesLockOutCaller)
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
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errs.CodeRiskRulesLockOutCaller) {
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
	otherBase := "/tenants/" + other.String() + "/ip-rules"
	if rec := dbtest.Do(t, asOther, http.MethodGet, base, nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organisation listing the rules: %d, want 403", rec.Code)
	}
	if enabled, cidrs := list(asOther, otherBase); enabled || cidrs != "[]" {
		t.Errorf("another organisation's own rules: enabled %v, %s; want none of this one's", enabled, cidrs)
	}
	if rec := dbtest.Do(t, asOther, http.MethodDelete, otherBase+"/"+office.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("delete another organisation's rule: %d, want 404", rec.Code)
	}
	if res := check(asOther, otherBase, "203.0.113.9"); res.Enabled || !res.Allowed {
		t.Errorf("another organisation's check: %+v; want this one's rules not applied", res)
	}

	if code := setEnabled(false); code != http.StatusOK {
		t.Errorf("switch off: %d", code)
	}
	if enabled, cidrs := list(h, base); enabled || cidrs != "[198.51.100.0/24 192.0.2.0/24 2001:db8::/32]" {
		t.Errorf("rules at the end: enabled %v, %s; want off, with the three allow rules", enabled, cidrs)
	}
	for action, want := range map[string]int{"ip_rules.rule_added": 4, "ip_rules.rule_removed": 1, "ip_rules.enforcement_changed": 2} {
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = $2 AND actor_user_id = $3`,
			tenant, action, admin.ID); n != want {
			t.Errorf("%d %s records, want %d", n, action, want)
		}
	}
}

// TestSignInIsJudgedByEnforcedRules checks that a sign-in is refused only by
// an organisation's enforced rules, and that each refusal is recorded as
// auth.address_refused with the rule responsible, whether it is checked in its
// own transaction or the caller's.
func TestSignInIsJudgedByEnforcedRules(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	tenant := dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	refusals := func(path, cond string, args ...any) int {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'auth.address_refused'
			AND metadata->>'path' = $2 AND `+cond, append([]any{tenant, path}, args...)...)
	}
	inTx := func(fn func(tx pgx.Tx) error) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, pool, fn); err != nil {
			t.Fatal(err)
		}
	}

	if err := svc.CheckSignIn(ctx, uuid.Nil, user.ID, "203.0.113.9", "password"); err != nil {
		t.Errorf("sign-in to no organisation: %v, want allowed", err)
	}
	if err := svc.CheckSignIn(ctx, tenant, user.ID, "203.0.113.9", "password"); err != nil {
		t.Errorf("sign-in to an organisation that never set rules: %v, want allowed", err)
	}
	var deny *Rule
	inTx(func(tx pgx.Tx) (err error) {
		if _, err = svc.AddRule(ctx, tx, tenant, "198.51.100.0/24", "office", "allow"); err != nil {
			return err
		}
		deny, err = svc.AddRule(ctx, tx, tenant, "198.51.100.66", "kiosk", "deny")
		return err
	})
	inTx(func(tx pgx.Tx) error { return svc.SetEnabled(ctx, tx, tenant, false) })
	if err := svc.CheckSignIn(ctx, tenant, user.ID, "203.0.113.9", "password"); err != nil {
		t.Errorf("sign-in with the rules off: %v, want allowed", err)
	}

	inTx(func(tx pgx.Tx) error { return svc.SetEnabled(ctx, tx, tenant, true) })
	if err := svc.CheckSignIn(ctx, tenant, user.ID, "198.51.100.7", "password"); err != nil {
		t.Errorf("sign-in from an allowed address: %v", err)
	}
	if err := svc.CheckSignIn(ctx, tenant, user.ID, "198.51.100.66", "password"); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Errorf("sign-in from a denied address: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if n := refusals("password", `resource_id = $3 AND actor_user_id = $4 AND ip = '198.51.100.66'
		AND metadata->>'reason' = 'deny_rule' AND metadata->>'cidr' = '198.51.100.66'`, deny.ID, user.ID); n != 1 {
		t.Errorf("the denied sign-in was recorded %d times with its rule, want once", n)
	}
	if n := refusals("password", "true"); n != 1 {
		t.Errorf("%d password sign-ins recorded as refused, want only the denied one", n)
	}
	if err := svc.CheckSignIn(ctx, tenant, uuid.Nil, "not an address", "magic_link"); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Errorf("sign-in from an unreadable address: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if n := refusals("magic_link", `ip IS NULL AND actor_user_id IS NULL AND resource_id IS NULL
		AND metadata->>'address' = 'not an address' AND metadata->>'reason' = 'address_unknown'`); n != 1 {
		t.Errorf("the unreadable address was recorded %d times, want once, in the metadata only", n)
	}

	signInTx := func(ip string, commit bool) error {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		checkErr := svc.CheckSignInTx(ctx, tx, tenant, user.ID, ip, "switch")
		if commit {
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}
		return checkErr
	}
	if err := signInTx("198.51.100.7", true); err != nil {
		t.Errorf("sign-in in a transaction from an allowed address: %v", err)
	}
	if err := signInTx("203.0.113.9", false); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Errorf("sign-in in a transaction from outside the allow rules: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if n := refusals("switch", "true"); n != 0 {
		t.Errorf("a refusal in a rolled-back transaction was kept (%d records)", n)
	}
	if err := signInTx("203.0.113.9", true); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Errorf("sign-in in a committed transaction: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if n := refusals("switch", `resource_id IS NULL AND metadata->>'reason' = 'not_in_allow_rules'`); n != 1 {
		t.Errorf("the committed refusal was recorded %d times, want once, naming no rule", n)
	}
}

// TestUnknownActionIsRefused checks that a rule whose action is neither allow
// nor deny is refused, not stored as an allow rule.
func TestUnknownActionIsRefused(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: NewService(dbtest.Pool(t))}).Mount)
	for _, action := range []string{"Deny", "block"} {
		rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+tenant.String()+"/ip-rules", map[string]string{"cidr": "203.0.113.0/24", "action": action})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), errs.CodeRiskRuleActionInvalid) {
			t.Errorf("add a rule with action %q: %d %s, want 422 %s", action, rec.Code, rec.Body.String(), errs.CodeRiskRuleActionInvalid)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.ip_rules WHERE tenant_id = $1`, tenant); n != 0 {
		t.Errorf("%d rules stored after the refusals, want none", n)
	}
}
