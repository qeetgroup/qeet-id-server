//go:build integration

package ipallow

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestCheckNamesItsReason checks that an address check answers a stable
// reason code for every outcome, naming the deny rule that refused it.
func TestCheckNamesItsReason(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	organization := dbtest.Organization(t)
	admin := audit.Actor{Type: "system", IP: "10.1.1.1"}

	if res, err := svc.Check(ctx, organization, "8.8.8.8"); err != nil || res.Enabled || !res.Allowed || res.ReasonCode != CodeEnforcementOff {
		t.Errorf("rules off: %+v, %v; want allowed as %s", res, err, CodeEnforcementOff)
	}
	if _, err := svc.AddRule(ctx, organization, "10.0.0.0/8", "office", "allow", admin); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddRule(ctx, organization, "10.6.0.0/16", "lab", "deny", admin); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetEnabled(ctx, organization, true, admin); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip, code string
		allowed  bool
		params   map[string]any
	}{
		{"10.1.1.1", "ip.allowed", true, nil},
		{"10.6.6.6", "ip.deny_rule", false, map[string]any{"cidr": "10.6.0.0/16"}},
		{"8.8.8.8", "ip.not_in_allow_rules", false, nil},
		{"not an address", "ip.address_unknown", false, nil},
	} {
		res, err := svc.Check(ctx, organization, tc.ip)
		if err != nil || !res.Enabled || res.Allowed != tc.allowed || res.ReasonCode != tc.code || res.Reason == "" ||
			fmt.Sprint(res.ReasonParams) != fmt.Sprint(tc.params) || res.Rules.Allowed != tc.allowed || res.Rules.ReasonCode != tc.code {
			t.Errorf("%s: %+v, %v; want allowed %v as %s %v", tc.ip, res, err, tc.allowed, tc.code, tc.params)
		}
	}

	// With the rules off, the address is let in, and the rules still say what
	// they would decide.
	if err := svc.SetEnabled(ctx, organization, false, admin); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Check(ctx, organization, "10.6.6.6")
	if err != nil || res.Enabled || !res.Allowed || res.ReasonCode != CodeEnforcementOff ||
		res.Rules.Allowed || res.Rules.ReasonCode != "ip.deny_rule" || fmt.Sprint(res.Rules.ReasonParams) != fmt.Sprint(map[string]any{"cidr": "10.6.0.0/16"}) {
		t.Errorf("rules off: %+v, %v; want allowed now, and the deny rule named as what the rules decide", res, err)
	}
}

// TestSignInIsJudgedByEnforcedRules checks that a sign-in is refused only by
// an organization's enforced rules, and that each refusal is recorded as
// auth.address_refused with the rule responsible, whether it is checked in its
// own transaction or the caller's.
func TestSignInIsJudgedByEnforcedRules(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	refusals := func(path, cond string, args ...any) int {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.address_refused'
			AND metadata->>'path' = $2 AND `+cond, append([]any{organization, path}, args...)...)
	}
	admin := audit.Actor{Type: "system", IP: "198.51.100.7"}

	if err := svc.CheckSignIn(ctx, uuid.Nil, user.ID, "203.0.113.9", "password"); err != nil {
		t.Errorf("sign-in to no organization: %v, want allowed", err)
	}
	if err := svc.CheckSignIn(ctx, organization, user.ID, "203.0.113.9", "password"); err != nil {
		t.Errorf("sign-in to an organization that never set rules: %v, want allowed", err)
	}
	if _, err := svc.AddRule(ctx, organization, "198.51.100.0/24", "office", "allow", admin); err != nil {
		t.Fatal(err)
	}
	deny, err := svc.AddRule(ctx, organization, "198.51.100.66", "kiosk", "deny", admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetEnabled(ctx, organization, false, admin); err != nil {
		t.Fatal(err)
	}
	if err := svc.CheckSignIn(ctx, organization, user.ID, "203.0.113.9", "password"); err != nil {
		t.Errorf("sign-in with the rules off: %v, want allowed", err)
	}

	if err := svc.SetEnabled(ctx, organization, true, admin); err != nil {
		t.Fatal(err)
	}
	if err := svc.CheckSignIn(ctx, organization, user.ID, "198.51.100.7", "password"); err != nil {
		t.Errorf("sign-in from an allowed address: %v", err)
	}
	if err := svc.CheckSignIn(ctx, organization, user.ID, "198.51.100.66", "password"); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Errorf("sign-in from a denied address: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if n := refusals("password", `resource_id = $3 AND actor_user_id = $4 AND ip = '198.51.100.66'
		AND metadata->>'reason' = 'deny_rule' AND metadata->>'cidr' = '198.51.100.66'`, deny.ID, user.ID); n != 1 {
		t.Errorf("the denied sign-in was recorded %d times with its rule, want once", n)
	}
	if n := refusals("password", "true"); n != 1 {
		t.Errorf("%d password sign-ins recorded as refused, want only the denied one", n)
	}
	if err := svc.CheckSignIn(ctx, organization, uuid.Nil, "not an address", "magic_link"); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
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
		checkErr := svc.CheckSignInTx(ctx, tx, organization, user.ID, ip, "switch")
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
