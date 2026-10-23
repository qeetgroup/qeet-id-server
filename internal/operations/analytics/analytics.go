// Package analytics serves the admin dashboard: one endpoint returns every KPI
// and chart series in a single payload. Series with no data yet come back as
// empty or zero buckets rather than errors.
package analytics

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/analytics/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Reader computes a tenant's dashboard projections.
type Reader struct {
	pool *pgxpool.Pool  // queries sqlc cannot type: mixed-type CASE, jsonb ->>, bigint+numeric
	q    *dbgen.Queries // the static aggregations of queries.sql
}

// NewReader returns a Reader over pool.
func NewReader(pool *pgxpool.Pool) *Reader {
	return &Reader{pool: pool, q: dbgen.New(pool)}
}

// pgUUID converts id to the pgtype.UUID that the generated query parameters
// take.
func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
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
	WAU  int64  `json:"wau"`  // distinct users with a session in that week
	DAU  int64  `json:"dau"`  // average DAU within the week
}

// Overview runs every dashboard projection for the tenant, one query at a
// time, and returns them in one payload. Any failure fails the whole request,
// so the dashboard shows one error rather than partial charts.
func (r *Reader) Overview(ctx context.Context, tenantID uuid.UUID) (*Overview, error) {
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

	if err := r.kpis(ctx, tenantID, out); err != nil {
		return nil, err
	}
	if err := r.trends14d(ctx, tenantID, out); err != nil {
		return nil, err
	}
	if err := r.loginActivity14d(ctx, tenantID, out); err != nil {
		return nil, err
	}
	if err := r.loginMethodsMix(ctx, tenantID, out); err != nil {
		return nil, err
	}
	if err := r.mfaMethodsAdoption(ctx, tenantID, out); err != nil {
		return nil, err
	}
	if err := r.failedHourly24h(ctx, tenantID, out); err != nil {
		return nil, err
	}
	if err := r.extraKPIs(ctx, tenantID, out); err != nil {
		return nil, err
	}
	if err := r.weeklyActivity8w(ctx, tenantID, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Reader) kpis(ctx context.Context, tid uuid.UUID, out *Overview) error {
	// MAU: distinct users with a session created in the last 30 days, against
	// the 30 days before.
	mau, err := r.q.CountMAUWindows(ctx, pgUUID(tid))
	if err != nil {
		return err
	}
	out.KPIs.MAU = Metric{Value: float64(mau.MauNow), DeltaPct: pctChange(mau.MauNow, mau.MauPrev)}

	// Logins today, against yesterday.
	logins, err := r.q.CountLoginsTodayWindows(ctx, pgUUID(tid))
	if err != nil {
		return err
	}
	out.KPIs.LoginsToday = Metric{Value: float64(logins.LoginsToday), DeltaPct: pctChange(logins.LoginsToday, logins.LoginsYday)}

	// MFA adoption: % of active users with a confirmed TOTP factor. Its delta is
	// in percentage points, against a week ago.
	var mfaPct, mfaPctPrev float64
	if err := r.pool.QueryRow(ctx, `
		WITH active AS (
			SELECT id FROM "user".users
			WHERE tenant_id = $1 AND status = 'active' AND deleted_at IS NULL
		),
		enrolled AS (
			SELECT user_id FROM auth.mfa_totp WHERE confirmed_at IS NOT NULL
		)
		SELECT
			CASE WHEN COUNT(active.id) = 0 THEN 0
			     ELSE 100.0 * COUNT(*) FILTER (WHERE enrolled.user_id IS NOT NULL) / COUNT(active.id)
			END
		FROM active LEFT JOIN enrolled ON enrolled.user_id = active.id
	`, tid).Scan(&mfaPct); err != nil {
		return err
	}
	if err := r.pool.QueryRow(ctx, `
		WITH active AS (
			SELECT id FROM "user".users
			WHERE tenant_id = $1 AND status = 'active' AND deleted_at IS NULL
			  AND created_at <= NOW() - INTERVAL '7 days'
		),
		enrolled AS (
			SELECT user_id FROM auth.mfa_totp
			WHERE confirmed_at IS NOT NULL AND confirmed_at <= NOW() - INTERVAL '7 days'
		)
		SELECT
			CASE WHEN COUNT(active.id) = 0 THEN 0
			     ELSE 100.0 * COUNT(*) FILTER (WHERE enrolled.user_id IS NOT NULL) / COUNT(active.id)
			END
		FROM active LEFT JOIN enrolled ON enrolled.user_id = active.id
	`, tid).Scan(&mfaPctPrev); err != nil {
		return err
	}
	out.KPIs.MFAAdoptionPct = Metric{Value: mfaPct, DeltaPct: mfaPct - mfaPctPrev}

	// Failed logins in the last 24h, against the 24h before, from
	// auth.sign_in_failed audit events.
	failed, err := r.q.CountFailedLogins24hWindows(ctx, pgUUID(tid))
	if err != nil {
		return err
	}
	out.KPIs.FailedLogins24h = Metric{Value: float64(failed.FailedNow), DeltaPct: pctChange(failed.FailedNow, failed.FailedPrev)}
	return nil
}

func (r *Reader) trends14d(ctx context.Context, tid uuid.UUID, out *Overview) error {
	// One bucket per day for the last 14 days, so the chart always has 14
	// points.
	rows, err := r.pool.Query(ctx, `
		WITH days AS (
			SELECT date_trunc('day', d)::date AS day
			FROM generate_series(
				date_trunc('day', NOW() - INTERVAL '13 days'),
				date_trunc('day', NOW()),
				'1 day'::interval
			) AS d
		),
		users_per_day AS (
			SELECT date_trunc('day', created_at)::date AS day, COUNT(*) AS new_users
			FROM "user".users
			WHERE tenant_id = $1 AND deleted_at IS NULL
			GROUP BY 1
		),
		base AS (
			SELECT COUNT(*) AS total
			FROM "user".users
			WHERE tenant_id = $1 AND deleted_at IS NULL
			  AND created_at < NOW() - INTERVAL '14 days'
		),
		sessions_per_day AS (
			SELECT date_trunc('day', created_at)::date AS day, COUNT(*) AS sess
			FROM auth.sessions
			WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '14 days'
			GROUP BY 1
		),
		failed_per_day AS (
			SELECT date_trunc('day', created_at)::date AS day, COUNT(*) AS fails
			FROM audit.events
			WHERE tenant_id = $1 AND action = 'auth.sign_in_failed'
			  AND created_at >= NOW() - INTERVAL '14 days'
			GROUP BY 1
		),
		mfa_per_day AS (
			SELECT date_trunc('day', confirmed_at)::date AS day, COUNT(*) AS enrolled
			FROM auth.mfa_totp t
			JOIN "user".users u ON u.id = t.user_id
			WHERE u.tenant_id = $1 AND u.deleted_at IS NULL AND t.confirmed_at IS NOT NULL
			GROUP BY 1
		)
		SELECT
			days.day::text,
			COALESCE((SELECT total FROM base), 0)
				+ COALESCE(SUM(users_per_day.new_users)
				           FILTER (WHERE users_per_day.day <= days.day), 0) AS users_cum,
			COALESCE(sessions_per_day.sess, 0) AS logins,
			COALESCE(mfa_per_day.enrolled, 0) AS mfa_new,
			COALESCE(failed_per_day.fails, 0) AS fails
		FROM days
		LEFT JOIN users_per_day ON users_per_day.day = days.day
		LEFT JOIN sessions_per_day ON sessions_per_day.day = days.day
		LEFT JOIN mfa_per_day ON mfa_per_day.day = days.day
		LEFT JOIN failed_per_day ON failed_per_day.day = days.day
		GROUP BY days.day, sessions_per_day.sess, mfa_per_day.enrolled, failed_per_day.fails
		ORDER BY days.day ASC
	`, tid)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			day                             string
			usersCum, logins, mfaNew, fails int64
		)
		if err := rows.Scan(&day, &usersCum, &logins, &mfaNew, &fails); err != nil {
			return err
		}
		out.UserTrend14d = append(out.UserTrend14d, TrendPoint{Date: day, Value: float64(usersCum)})
		out.LoginTrend14d = append(out.LoginTrend14d, TrendPoint{Date: day, Value: float64(logins)})
		out.MFATrend14d = append(out.MFATrend14d, TrendPoint{Date: day, Value: float64(mfaNew)})
		out.FailedTrend14d = append(out.FailedTrend14d, TrendPoint{Date: day, Value: float64(fails)})
	}
	return rows.Err()
}

func (r *Reader) loginActivity14d(ctx context.Context, tid uuid.UUID, out *Overview) error {
	rows, err := r.q.GetLoginActivity14d(ctx, pgUUID(tid))
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
	rows, err := r.pool.Query(ctx, `
		SELECT regexp_replace(COALESCE(metadata->>'method', 'password'), '_(mfa|email_confirmed)$', '') AS method,
		       COUNT(*) AS n
		FROM audit.events
		WHERE tenant_id = $1
		  AND action = 'auth.login_succeeded'
		  AND COALESCE(metadata->>'method', '') NOT IN ('tenant_switch', 'tenant_create', 'invite_accept')
		  AND created_at >= NOW() - INTERVAL '30 days'
		GROUP BY 1
		ORDER BY n DESC
	`, tid)
	if err != nil {
		return err
	}
	defer rows.Close()
	var total int64
	type bucket struct {
		method string
		n      int64
	}
	var buckets []bucket
	for rows.Next() {
		var b bucket
		if err := rows.Scan(&b.method, &b.n); err != nil {
			return err
		}
		buckets = append(buckets, b)
		total += b.n
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if total == 0 {
		return nil
	}
	for _, b := range buckets {
		out.LoginMethodsMix = append(out.LoginMethodsMix, MethodSlice{
			Method: b.method,
			Value:  100.0 * float64(b.n) / float64(total),
		})
	}
	return nil
}

func (r *Reader) mfaMethodsAdoption(ctx context.Context, tid uuid.UUID, out *Overview) error {
	// Only TOTP and recovery codes are counted, and a method with no users is
	// left out.
	totp, err := r.q.CountMFATotpUsers(ctx, pgUUID(tid))
	if err != nil {
		return err
	}
	recovery, err := r.q.CountMFARecoveryUsers(ctx, pgUUID(tid))
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
	rows, err := r.q.GetFailedLoginsHourly24h(ctx, pgUUID(tid))
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
	// DAU: distinct users with a session today, against yesterday.
	dau, err := r.q.CountDAUWindows(ctx, pgUUID(tid))
	if err != nil {
		return err
	}
	dauNow, dauPrev := dau.DauNow, dau.DauPrev
	out.KPIs.DAU = Metric{Value: float64(dauNow), DeltaPct: pctChange(dauNow, dauPrev)}

	// Total users, against 30 days ago.
	users, err := r.q.CountTotalUsersWindows(ctx, pgUUID(tid))
	if err != nil {
		return err
	}
	out.KPIs.TotalUsers = Metric{Value: float64(users.UsersNow), DeltaPct: pctChange(users.UsersNow, users.UsersPrev)}

	// Average sessions per active user, last 30 days against the 30 before.
	var avgNow, avgPrev float64
	if err := r.pool.QueryRow(ctx, `
		SELECT
			COALESCE(
				CASE WHEN COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') = 0 THEN 0
				     ELSE COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days')::float
				          / NULLIF(COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days'), 0)
				END, 0),
			COALESCE(
				CASE WHEN COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '60 days'
				                                            AND created_at <  NOW() - INTERVAL '30 days') = 0 THEN 0
				     ELSE COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '60 days'
				                            AND created_at <  NOW() - INTERVAL '30 days')::float
				          / NULLIF(COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '60 days'
				                                                      AND created_at <  NOW() - INTERVAL '30 days'), 0)
				END, 0)
		FROM auth.sessions
		WHERE tenant_id = $1
	`, tid).Scan(&avgNow, &avgPrev); err != nil {
		return err
	}
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
	stick, err := r.q.CountStickinessPriorWeek(ctx, pgUUID(tid))
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
// tenant.
func (r *Reader) weeklyActivity8w(ctx context.Context, tid uuid.UUID, out *Overview) error {
	rows, err := r.q.GetWeeklyActivity8w(ctx, pgUUID(tid))
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

// Handler serves the dashboard endpoint.
type Handler struct {
	Reader *Reader
}

// Mount registers GET /tenants/{tenantID}/analytics/overview.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/analytics/overview", h.overview)
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAnalyticsTenantInvalid)
		return
	}
	// The caller's tenant must be the path's.
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil || *p.TenantID != tid {
		httpx.WriteError(w, r, errs.ErrAnalyticsTenantMismatch)
		return
	}
	out, err := h.Reader.Overview(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
