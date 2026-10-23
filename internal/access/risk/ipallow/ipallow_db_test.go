//go:build integration

package ipallow

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestCheckNamesItsReason checks that an address check answers a stable
// reason code for every outcome, naming the deny rule that refused it.
func TestCheckNamesItsReason(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	tenant := dbtest.Tenant(t)
	inTx := func(fn func(tx pgx.Tx) error) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := fn(tx); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	if res, err := svc.Check(ctx, tenant, "8.8.8.8"); err != nil || res.Enabled || !res.Allowed || res.ReasonCode != CodeEnforcementOff {
		t.Errorf("rules off: %+v, %v; want allowed as %s", res, err, CodeEnforcementOff)
	}
	inTx(func(tx pgx.Tx) error {
		if _, err := svc.AddRule(ctx, tx, tenant, "10.0.0.0/8", "office", "allow"); err != nil {
			return err
		}
		if _, err := svc.AddRule(ctx, tx, tenant, "10.6.0.0/16", "lab", "deny"); err != nil {
			return err
		}
		return svc.SetEnabled(ctx, tx, tenant, true)
	})
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
		res, err := svc.Check(ctx, tenant, tc.ip)
		if err != nil || !res.Enabled || res.Allowed != tc.allowed || res.ReasonCode != tc.code || res.Reason == "" ||
			fmt.Sprint(res.ReasonParams) != fmt.Sprint(tc.params) {
			t.Errorf("%s: %+v, %v; want allowed %v as %s %v", tc.ip, res, err, tc.allowed, tc.code, tc.params)
		}
	}
}
