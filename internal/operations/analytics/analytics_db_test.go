//go:build integration

package analytics

import (
	"math"
	"testing"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

const testPassword = "Kx7mQ2vLp9Wz"

// TestOverviewCountsPurgedSessionsSignIns checks that sign-ins and active
// people are counted from the sign-in log, so a sign-in still counts once the
// cleanup has deleted its ended session; that hosted sign-ins count; that
// switching to the organization makes a person active in it but is no
// sign-in; and that each organization counts only its own.
func TestOverviewCountsPurgedSessionsSignIns(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	organization, home := dbtest.Organization(t), dbtest.Organization(t)
	account := func(home uuid.UUID, memberOf ...uuid.UUID) dbtest.Account {
		a := dbtest.User(t, home, memberOf...)
		dbtest.SetPassword(t, a.ID, testPassword)
		return a
	}
	signIn := func(a dbtest.Account) *auth.TokenPair {
		res, err := svc.Login(ctx, auth.LoginInput{Email: a.Email, Password: testPassword})
		if err != nil || res.Pair == nil {
			t.Fatalf("sign in: %+v, %v", res, err)
		}
		return res.Pair
	}
	earlier, lapsed, regular, hosted := account(organization, organization), account(organization, organization), account(organization, organization), account(organization, organization)
	guest := account(home, home, organization)

	// Two sign-ins whose sessions ended when they began, 45 and 20 days ago,
	// and have since been purged.
	for a, days := range map[dbtest.Account]int{earlier: 45, lapsed: 20} {
		pair := signIn(a)
		if _, err := pool.Exec(ctx, `UPDATE auth.sessions SET created_at = NOW() - make_interval(days => $2),
			revoked_at = NOW() - make_interval(days => $2) WHERE id = $1`, pair.SessionID, days); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE audit.events SET created_at = NOW() - make_interval(days => $2)
			WHERE action = 'auth.login_succeeded' AND resource_id = $1`, pair.SessionID, days); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := auth.PurgeEndedSessions(ctx, pool, auth.SessionRetention, nil); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = ANY($1)`, []uuid.UUID{earlier.ID, lapsed.ID}); n != 0 {
		t.Fatalf("%d old sessions survived the purge", n)
	}

	signIn(regular)
	signIn(regular)
	if _, err := svc.CreateLoginSession(ctx, hosted.ID, "", "test"); err != nil {
		t.Fatalf("hosted sign-in: %v", err)
	}
	if _, err := svc.SwitchOrganization(ctx, auth.SwitchOrganizationInput{UserID: guest.ID, FromSessionID: signIn(guest).SessionID, OrganizationID: organization}); err != nil {
		t.Fatalf("switch: %v", err)
	}

	out, err := NewReader(pool).Overview(ctx, organization)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	k := out.KPIs
	for _, c := range []struct {
		name      string
		got, want Metric
	}{
		// lapsed, regular, hosted and guest; earlier the 30 days before.
		{"mau", k.MAU, Metric{Value: 4, DeltaPct: 300}},
		{"dau", k.DAU, Metric{Value: 3, DeltaPct: 100}},
		// regular twice and hosted; the switch is no sign-in.
		{"logins_today", k.LoginsToday, Metric{Value: 3, DeltaPct: 100}},
		// lapsed, regular twice and hosted, by three people; earlier once.
		{"avg_sessions_per_user", k.AvgSessionsPerUser, Metric{Value: 4.0 / 3, DeltaPct: 100.0 / 3}},
		{"stickiness_pct", k.StickinessPct, Metric{Value: 75, DeltaPct: 75}},
		// The sessions play no part in these.
		{"total_users", k.TotalUsers, Metric{Value: 4, DeltaPct: 100}},
		{"mfa_adoption_pct", k.MFAAdoptionPct, Metric{}},
	} {
		if math.Abs(c.got.Value-c.want.Value) > 0.001 || math.Abs(c.got.DeltaPct-c.want.DeltaPct) > 0.001 {
			t.Errorf("%s = %+v, want %+v", c.name, c.got, c.want)
		}
	}
	var logins float64
	for _, p := range out.LoginTrend14d {
		logins += p.Value
	}
	if logins != 3 {
		t.Errorf("login_trend_14d adds up to %v, want 3", logins)
	}
	if n := len(out.UserTrend14d); n != 14 || out.UserTrend14d[n-1].Value != 4 {
		t.Errorf("user_trend_14d = %+v, want 14 days ending at 4", out.UserTrend14d)
	}
	var wau int64
	for _, w := range out.WeeklyActivity8w {
		wau += w.WAU
	}
	if n := len(out.WeeklyActivity8w); n != 8 || wau != 5 || out.WeeklyActivity8w[n-1] != (WeeklyActivityPoint{Week: out.WeeklyActivity8w[n-1].Week, WAU: 3, DAU: 3}) {
		t.Errorf("weekly_activity_8w = %+v, want 8 weeks of 5 in all, 3 this week", out.WeeklyActivity8w)
	}

	other, err := NewReader(pool).Overview(ctx, home)
	if err != nil {
		t.Fatalf("overview of the guest's own organisation: %v", err)
	}
	if other.KPIs.MAU.Value != 1 || other.KPIs.LoginsToday.Value != 1 {
		t.Errorf("the guest's own organisation counts mau %v and logins %v, want its one sign-in", other.KPIs.MAU.Value, other.KPIs.LoginsToday.Value)
	}
}

// recordEvent writes an audit event for organization as the authentication service
// does.
func recordEvent(t *testing.T, organization uuid.UUID, action string, metadata map[string]any) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	e := audit.Actor{Type: "anonymous"}.Event(organization, action, "user", uuid.New(), metadata)
	if err := audit.Record(ctx, tx, e); err != nil {
		t.Fatalf("record %s: %v", action, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestOverviewCountsFailedSignIns checks that the failed sign-ins the
// authentication service records appear in the failed-login KPI and charts, and
// only for their own organization.
func TestOverviewCountsFailedSignIns(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	for range 2 {
		recordEvent(t, organization, "auth.sign_in_failed", map[string]any{"method": "password", "reason": "wrong_password"})
	}
	recordEvent(t, other, "auth.sign_in_failed", map[string]any{"method": "password", "reason": "wrong_password"})

	out, err := NewReader(dbtest.Pool(t)).Overview(dbtest.Context(t), organization)
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
// switching or creating an organization or accepting an invitation are not.
func TestOverviewBucketsSignInsByFirstFactor(t *testing.T) {
	organization := dbtest.Organization(t)
	for _, method := range []string{
		"password", "password_mfa", "password_email_confirmed", "passkey", "social_mfa", "saml",
		"magic_link", "magic_link_mfa", "ldap", "ldap_email_confirmed",
		"tenant_switch", "tenant_create", "invite_accept",
	} {
		recordEvent(t, organization, "auth.login_succeeded", map[string]any{"method": method})
	}

	out, err := NewReader(dbtest.Pool(t)).Overview(dbtest.Context(t), organization)
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
