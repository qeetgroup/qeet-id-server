//go:build integration

package analytics

import (
	"math"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// recordEvent writes an audit event for tenant as the authentication service
// does.
func recordEvent(t *testing.T, tenant uuid.UUID, action string, metadata map[string]any) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	e := audit.Actor{Type: "anonymous"}.Event(tenant, action, "user", uuid.New(), metadata)
	if err := audit.Record(ctx, tx, e); err != nil {
		t.Fatalf("record %s: %v", action, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestOverviewCountsFailedSignIns checks that the failed sign-ins the
// authentication service records appear in the failed-login KPI and charts, and
// only for their own tenant.
func TestOverviewCountsFailedSignIns(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	for range 2 {
		recordEvent(t, tenant, "auth.sign_in_failed", map[string]any{"method": "password", "reason": "wrong_password"})
	}
	recordEvent(t, other, "auth.sign_in_failed", map[string]any{"method": "password", "reason": "wrong_password"})

	out, err := NewReader(dbtest.Pool(t)).Overview(dbtest.Context(t), tenant)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if got := out.KPIs.FailedLogins24h.Value; got != 2 {
		t.Errorf("failed_logins_24h = %v, want 2", got)
	}
	var hourly int64
	for _, p := range out.FailedLoginsHourly24h {
		hourly += p.Attempts
	}
	if hourly != 2 {
		t.Errorf("failed_logins_hourly_24h adds up to %d, want 2", hourly)
	}
	var daily float64
	for _, p := range out.FailedTrend14d {
		daily += p.Value
	}
	if daily != 2 {
		t.Errorf("failed_trend_14d adds up to %v, want 2", daily)
	}
}

// TestOverviewBucketsSignInsByFirstFactor checks that every recorded sign-in
// method is counted under its first factor, and that sessions opened by
// switching or creating an organisation or accepting an invitation are not.
func TestOverviewBucketsSignInsByFirstFactor(t *testing.T) {
	tenant := dbtest.Tenant(t)
	for _, method := range []string{
		"password", "password_mfa", "password_email_confirmed", "passkey", "social_mfa", "saml",
		"magic_link", "magic_link_mfa", "ldap", "ldap_email_confirmed",
		"tenant_switch", "tenant_create", "invite_accept",
	} {
		recordEvent(t, tenant, "auth.login_succeeded", map[string]any{"method": method})
	}

	out, err := NewReader(dbtest.Pool(t)).Overview(dbtest.Context(t), tenant)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	var got ActivityPoint
	for _, p := range out.LoginActivity14d {
		got.Password += p.Password
		got.Passkey += p.Passkey
		got.Social += p.Social
		got.SAML += p.SAML
		got.OIDC += p.OIDC
		got.MagicLink += p.MagicLink
		got.LDAP += p.LDAP
	}
	if want := (ActivityPoint{Password: 3, Passkey: 1, Social: 1, SAML: 1, MagicLink: 2, LDAP: 2}); got != want {
		t.Errorf("login_activity_14d adds up to %+v, want %+v", got, want)
	}

	shares := map[string]float64{}
	for _, s := range out.LoginMethodsMix {
		shares[s.Method] = s.Value
	}
	want := map[string]float64{"password": 30, "passkey": 10, "social": 10, "saml": 10, "magic_link": 20, "ldap": 20}
	if len(shares) != len(want) {
		t.Errorf("login_methods_mix = %v, want %v", shares, want)
	}
	for method, pct := range want {
		if math.Abs(shares[method]-pct) > 0.001 {
			t.Errorf("login_methods_mix[%q] = %v, want %v", method, shares[method], pct)
		}
	}
}
