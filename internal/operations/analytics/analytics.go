// Package analytics serves the admin dashboard: one endpoint returns every KPI
// and chart series in a single payload. Series with no data yet come back as
// empty or zero buckets rather than errors.
package analytics

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/analytics/dbgen"
)

// Reader computes an organization's dashboard projections.
type Reader struct {
	q *dbgen.Queries
}

// NewReader returns a Reader over pool.
func NewReader(pool *pgxpool.Pool) *Reader {
	return &Reader{q: dbgen.New(pool)}
}

// Overview is the admin dashboard's payload. Timestamps are RFC3339 UTC.
// WeeklyActivity8w has one bucket per ISO week, oldest first.
type Overview struct {
	GeneratedAt time.Time `json:"generated_at"`

	KPIs struct {
		MAU                Metric `json:"mau"`
		LoginsToday        Metric `json:"logins_today"`
		MFAAdoptionPct     Metric `json:"mfa_adoption_pct"`
		FailedLogins24h    Metric `json:"failed_logins_24h"`
		DAU                Metric `json:"dau"`
		TotalUsers         Metric `json:"total_users"`
		AvgSessionsPerUser Metric `json:"avg_sessions_per_user"`
		StickinessPct      Metric `json:"stickiness_pct"`
	} `json:"kpis"`

	WeeklyActivity8w []WeeklyActivityPoint `json:"weekly_activity_8w"`

	UserTrend14d   []TrendPoint `json:"user_trend_14d"`
	LoginTrend14d  []TrendPoint `json:"login_trend_14d"`
	MFATrend14d    []TrendPoint `json:"mfa_trend_14d"`
	FailedTrend14d []TrendPoint `json:"failed_trend_14d"`

	LoginActivity14d      []ActivityPoint `json:"login_activity_14d"`
	LoginMethodsMix       []MethodSlice   `json:"login_methods_mix"`
	MFAMethodsAdoption    []MethodCount   `json:"mfa_methods_adoption"`
	FailedLoginsHourly24h []HourlyPoint   `json:"failed_logins_hourly_24h"`

	// Range is the sign-ins day by day over the range the request chose,
	// when it chose one.
	Range *SignInRange `json:"range,omitempty"`
}

// Metric is a KPI value and its change from the previous period, in percent;
// MFAAdoptionPct and StickinessPct change in percentage points.
type Metric struct {
	Value    float64 `json:"value"`
	DeltaPct float64 `json:"delta_pct"`
}

// TrendPoint is one day of a trend series.
type TrendPoint struct {
	Date  string  `json:"date"`
	Value float64 `json:"value"`
}

// ActivityPoint is one day of sign-ins by first factor. A method with none is
// 0, so the console's stacked chart has no gaps.
type ActivityPoint struct {
	Date      string `json:"date"`
	Password  int64  `json:"password"`
	Passkey   int64  `json:"passkey"`
	Social    int64  `json:"social"`
	SAML      int64  `json:"saml"`
	OIDC      int64  `json:"oidc"`
	MagicLink int64  `json:"magic_link"`
	LDAP      int64  `json:"ldap"`
}

// MethodSlice is one first factor's share, in percent, of the last 30 days'
// successful sign-ins, counted as for ActivityPoint.
type MethodSlice struct {
	Method string  `json:"method"`
	Value  float64 `json:"value"`
}

// MethodCount is the number of users enrolled in an MFA method.
type MethodCount struct {
	Method string `json:"method"`
	Users  int64  `json:"users"`
}

// HourlyPoint is the failed sign-in attempts of one hour.
type HourlyPoint struct {
	Hour     string `json:"hour"`
	Attempts int64  `json:"attempts"`
}

// WeeklyActivityPoint is one ISO week of activity.
type WeeklyActivityPoint struct {
	Week string `json:"week"` // "Wnn" — ISO week number
	WAU  int64  `json:"wau"`  // distinct people who signed in that week
	DAU  int64  `json:"dau"`  // average DAU within the week
}

// Overview runs every dashboard projection for the organization, one query at a
// time, and returns them in one payload. Any failure fails the whole request,
// so the dashboard shows one error rather than partial charts.
func (r *Reader) Overview(ctx context.Context, organizationID uuid.UUID) (*Overview, error) {
	// Non-nil slices, so empty series encode as [] rather than null.
	out := &Overview{
		GeneratedAt:           time.Now().UTC(),
		WeeklyActivity8w:      []WeeklyActivityPoint{},
		UserTrend14d:          []TrendPoint{},
		LoginTrend14d:         []TrendPoint{},
		MFATrend14d:           []TrendPoint{},
		FailedTrend14d:        []TrendPoint{},
		LoginActivity14d:      []ActivityPoint{},
		LoginMethodsMix:       []MethodSlice{},
		MFAMethodsAdoption:    []MethodCount{},
		FailedLoginsHourly24h: []HourlyPoint{},
	}

	if err := r.kpis(ctx, organizationID, out); err != nil {
		return nil, err
	}
	if err := r.trends14d(ctx, organizationID, out); err != nil {
		return nil, err
	}
	if err := r.loginActivity14d(ctx, organizationID, out); err != nil {
		return nil, err
	}
	if err := r.loginMethodsMix(ctx, organizationID, out); err != nil {
		return nil, err
	}
	if err := r.mfaMethodsAdoption(ctx, organizationID, out); err != nil {
		return nil, err
	}
	if err := r.failedHourly24h(ctx, organizationID, out); err != nil {
		return nil, err
	}
	if err := r.extraKPIs(ctx, organizationID, out); err != nil {
		return nil, err
	}
	if err := r.weeklyActivity8w(ctx, organizationID, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Reader) kpis(ctx context.Context, tid uuid.UUID, out *Overview) error {
	// MAU: distinct people who signed in in the last 30 days, against the 30
	// days before.
	mau, err := r.q.CountMAUWindows(ctx, &tid)
	if err != nil {
		return err
	}
	out.KPIs.MAU = Metric{Value: float64(mau.MauNow), DeltaPct: pctChange(mau.MauNow, mau.MauPrev)}

	// Logins today, against yesterday.
	logins, err := r.q.CountLoginsTodayWindows(ctx, &tid)
	if err != nil {
		return err
	}
	out.KPIs.LoginsToday = Metric{Value: float64(logins.LoginsToday), DeltaPct: pctChange(logins.LoginsToday, logins.LoginsYday)}

	// MFA adoption: % of active users with a confirmed TOTP factor. Its delta is
	// in percentage points, against a week ago.
	mfaPct, err := r.q.MFAAdoptionPct(ctx, &tid)
	if err != nil {
		return err
	}
	mfaPctPrev, err := r.q.MFAAdoptionPctWeekAgo(ctx, &tid)
	if err != nil {
		return err
	}
	out.KPIs.MFAAdoptionPct = Metric{Value: mfaPct, DeltaPct: mfaPct - mfaPctPrev}

	// Failed logins in the last 24h, against the 24h before, from
	// auth.sign_in_failed audit events.
	failed, err := r.q.CountFailedLogins24hWindows(ctx, &tid)
	if err != nil {
		return err
	}
	out.KPIs.FailedLogins24h = Metric{Value: float64(failed.FailedNow), DeltaPct: pctChange(failed.FailedNow, failed.FailedPrev)}
	return nil
}

func (r *Reader) trends14d(ctx context.Context, tid uuid.UUID, out *Overview) error {
	// One bucket per day for the last 14 days, so the chart always has 14
	// points.
	rows, err := r.q.GetTrends14d(ctx, &tid)
	if err != nil {
		return err
	}
	for _, row := range rows {
		out.UserTrend14d = append(out.UserTrend14d, TrendPoint{Date: row.Day, Value: float64(row.UsersCum)})
		out.LoginTrend14d = append(out.LoginTrend14d, TrendPoint{Date: row.Day, Value: float64(row.Logins)})
		out.MFATrend14d = append(out.MFATrend14d, TrendPoint{Date: row.Day, Value: float64(row.MfaNew)})
		out.FailedTrend14d = append(out.FailedTrend14d, TrendPoint{Date: row.Day, Value: float64(row.Fails)})
	}
	return nil
}

func (r *Reader) loginActivity14d(ctx context.Context, tid uuid.UUID, out *Overview) error {
	rows, err := r.q.GetLoginActivity14d(ctx, &tid)
	if err != nil {
		return err
	}
	for _, row := range rows {
		out.LoginActivity14d = append(out.LoginActivity14d, ActivityPoint{
			Date:      row.Day,
			Password:  row.Password,
			Passkey:   row.Passkey,
			Social:    row.Social,
			SAML:      row.Saml,
			OIDC:      row.Oidc,
			MagicLink: row.MagicLink,
			LDAP:      row.Ldap,
		})
	}
	return nil
}

func (r *Reader) loginMethodsMix(ctx context.Context, tid uuid.UUID, out *Overview) error {
	buckets, err := r.q.CountLoginMethods30d(ctx, &tid)
	if err != nil {
		return err
	}
	var total int64
	for _, b := range buckets {
		total += b.N
	}
	if total == 0 {
		return nil
	}
	for _, b := range buckets {
		out.LoginMethodsMix = append(out.LoginMethodsMix, MethodSlice{
			Method: b.Method,
			Value:  100.0 * float64(b.N) / float64(total),
		})
	}
	return nil
}

func (r *Reader) mfaMethodsAdoption(ctx context.Context, tid uuid.UUID, out *Overview) error {
	// Only TOTP and recovery codes are counted, and a method with no users is
	// left out.
	totp, err := r.q.CountMFATotpUsers(ctx, &tid)
	if err != nil {
		return err
	}
	recovery, err := r.q.CountMFARecoveryUsers(ctx, &tid)
	if err != nil {
		return err
	}
	if totp > 0 {
		out.MFAMethodsAdoption = append(out.MFAMethodsAdoption, MethodCount{Method: "TOTP", Users: totp})
	}
	if recovery > 0 {
		out.MFAMethodsAdoption = append(out.MFAMethodsAdoption, MethodCount{Method: "Recovery Codes", Users: recovery})
	}
	return nil
}

func (r *Reader) failedHourly24h(ctx context.Context, tid uuid.UUID, out *Overview) error {
	rows, err := r.q.GetFailedLoginsHourly24h(ctx, &tid)
	if err != nil {
		return err
	}
	for _, row := range rows {
		out.FailedLoginsHourly24h = append(out.FailedLoginsHourly24h, HourlyPoint{
			Hour:     row.Hour,
			Attempts: row.Attempts,
		})
	}
	return nil
}

// extraKPIs fills the analytics page's KPIs that the dashboard overview lacks:
// DAU, total users, average sessions per user over 30 days, and stickiness
// (DAU/MAU).
func (r *Reader) extraKPIs(ctx context.Context, tid uuid.UUID, out *Overview) error {
	// DAU: distinct people who signed in today, against yesterday.
	dau, err := r.q.CountDAUWindows(ctx, &tid)
	if err != nil {
		return err
	}
	dauNow, dauPrev := dau.DauNow, dau.DauPrev
	out.KPIs.DAU = Metric{Value: float64(dauNow), DeltaPct: pctChange(dauNow, dauPrev)}

	// Total users, against 30 days ago.
	users, err := r.q.CountTotalUsersWindows(ctx, &tid)
	if err != nil {
		return err
	}
	out.KPIs.TotalUsers = Metric{Value: float64(users.UsersNow), DeltaPct: pctChange(users.UsersNow, users.UsersPrev)}

	// Average sign-ins per person who signed in, last 30 days against the 30
	// before.
	avg, err := r.q.AvgSignInsPerPersonWindows(ctx, &tid)
	if err != nil {
		return err
	}
	avgNow, avgPrev := avg.AvgNow, avg.AvgPrev
	deltaAvg := 0.0
	if avgPrev > 0 {
		deltaAvg = 100.0 * (avgNow - avgPrev) / avgPrev
	} else if avgNow > 0 {
		deltaAvg = 100
	}
	out.KPIs.AvgSessionsPerUser = Metric{Value: avgNow, DeltaPct: deltaAvg}

	// Stickiness: DAU as a percentage of MAU.
	mauVal := out.KPIs.MAU.Value
	stickNow := 0.0
	if mauVal > 0 {
		stickNow = 100.0 * float64(dauNow) / mauVal
	}
	// Its delta is in percentage points, against the same ratio a week ago.
	stick, err := r.q.CountStickinessPriorWeek(ctx, &tid)
	if err != nil {
		return err
	}
	dauPrevWeek, mauPrevWeek := stick.DauPrevWeek, stick.MauPrevWeek
	stickPrev := 0.0
	if mauPrevWeek > 0 {
		stickPrev = 100.0 * float64(dauPrevWeek) / float64(mauPrevWeek)
	}
	out.KPIs.StickinessPct = Metric{Value: stickNow, DeltaPct: stickNow - stickPrev}
	return nil
}

// weeklyActivity8w fills 8 trailing ISO-week buckets of WAU and average DAU.
// A week with no activity is zero, so the chart keeps its width for a new
// organization.
func (r *Reader) weeklyActivity8w(ctx context.Context, tid uuid.UUID, out *Overview) error {
	rows, err := r.q.GetWeeklyActivity8w(ctx, &tid)
	if err != nil {
		return err
	}
	for _, row := range rows {
		out.WeeklyActivity8w = append(out.WeeklyActivity8w, WeeklyActivityPoint{
			Week: row.Week,
			WAU:  row.Wau,
			DAU:  row.Dau,
		})
	}
	return nil
}

// pctChange returns the percentage change from prev to now. From a prev of 0 it
// is 100, or 0 if now is 0 too.
func pctChange(now, prev int64) float64 {
	if prev == 0 {
		if now == 0 {
			return 0
		}
		return 100
	}
	return 100.0 * float64(now-prev) / float64(prev)
}
