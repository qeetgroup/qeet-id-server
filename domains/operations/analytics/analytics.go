// Package analytics powers the admin dashboard's KPI cards and charts.
// It exposes one endpoint — GET /v1/tenants/{tenantID}/analytics/overview —
// that returns everything the dashboard needs in a single payload, so we
// avoid a thundering-herd of small queries on first render.
//
// Every aggregation lives here as its own SQL projection. Where the
// underlying data isn't recorded yet (e.g. failed-login events, SMS-MFA
// adoption, passkey method tagging), the projection returns empty
// buckets and the dashboard renders a "no data yet" sliver — the dial
// lights up automatically as the platform starts recording the data.
package analytics

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

type Reader struct {
	pool *pgxpool.Pool
}

func NewReader(pool *pgxpool.Pool) *Reader {
	return &Reader{pool: pool}
}

// Overview is the response shape consumed by the admin dashboard. All
// timestamps are RFC3339 UTC; the frontend converts to local time.
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

	// 8-week weekly active users + daily active users trend (one bucket
	// per ISO week, oldest first). Powers the analytics page's "Active
	// users" area chart.
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

type Metric struct {
	Value    float64 `json:"value"`
	DeltaPct float64 `json:"delta_pct"`
}

type TrendPoint struct {
	Date  string  `json:"date"`
	Value float64 `json:"value"`
}

// ActivityPoint is a daily bucket grouped by method. Missing methods are
// emitted as 0 so the frontend's stacked-area chart doesn't gap.
type ActivityPoint struct {
	Date     string `json:"date"`
	Password int64  `json:"password"`
	Passkey  int64  `json:"passkey"`
	Social   int64  `json:"social"`
	SAML     int64  `json:"saml"`
	OIDC     int64  `json:"oidc"`
}

type MethodSlice struct {
	Method string  `json:"method"`
	Value  float64 `json:"value"`
}

type MethodCount struct {
	Method string `json:"method"`
	Users  int64  `json:"users"`
}

type HourlyPoint struct {
	Hour     string `json:"hour"`
	Attempts int64  `json:"attempts"`
}

type WeeklyActivityPoint struct {
	Week string `json:"week"` // "Wnn" — ISO week number
	WAU  int64  `json:"wau"`  // distinct users with a session in that week
	DAU  int64  `json:"dau"`  // average DAU within the week
}

// Overview runs all the aggregations needed for the dashboard in
// parallel-ish (one round-trip per projection) and returns one payload.
// Failure of any one projection aborts the request — the dashboard
// shows a single error state rather than partially-populated charts.
func (r *Reader) Overview(ctx context.Context, tenantID uuid.UUID) (*Overview, error) {
	// Initialise every slice non-nil so empty result sets serialise as
	// JSON `[]` rather than `null` — frontends can iterate without
	// guarding every access site.
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
	// MAU = distinct users with a session created in the last 30 days.
	// Delta = % change vs the prior 30-day window.
	var mauNow, mauPrev int64
	if err := r.pool.QueryRow(ctx, `
		SELECT
			COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days'),
			COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '60 days'
			                                   AND created_at <  NOW() - INTERVAL '30 days')
		FROM auth.sessions
		WHERE tenant_id = $1
	`, tid).Scan(&mauNow, &mauPrev); err != nil {
		return err
	}
	out.KPIs.MAU = Metric{Value: float64(mauNow), DeltaPct: pctChange(mauNow, mauPrev)}

	// Logins today + delta vs yesterday.
	var loginsToday, loginsYday int64
	if err := r.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE created_at >= date_trunc('day', NOW())),
			COUNT(*) FILTER (WHERE created_at >= date_trunc('day', NOW() - INTERVAL '1 day')
			                  AND created_at <  date_trunc('day', NOW()))
		FROM auth.sessions
		WHERE tenant_id = $1
	`, tid).Scan(&loginsToday, &loginsYday); err != nil {
		return err
	}
	out.KPIs.LoginsToday = Metric{Value: float64(loginsToday), DeltaPct: pctChange(loginsToday, loginsYday)}

	// MFA adoption = % of (active, non-deleted) tenant users with a
	// confirmed TOTP factor. Delta is pp change vs a week ago (the
	// dashboard treats this metric specially).
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

	// Failed logins in the last 24h. Audit-event source — only lights
	// up once §1.10-style failed-login auditing ships. Until then this
	// stays at 0 and the dashboard reports the same.
	var failedNow, failedPrev int64
	if err := r.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours'),
			COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '48 hours'
			                  AND created_at <  NOW() - INTERVAL '24 hours')
		FROM audit.events
		WHERE tenant_id = $1 AND action = 'auth.login_failed'
	`, tid).Scan(&failedNow, &failedPrev); err != nil {
		return err
	}
	out.KPIs.FailedLogins24h = Metric{Value: float64(failedNow), DeltaPct: pctChange(failedNow, failedPrev)}
	return nil
}

func (r *Reader) trends14d(ctx context.Context, tid uuid.UUID, out *Overview) error {
	// Generate 14 daily buckets starting 13 days ago so the chart
	// always shows exactly 14 points even on days with no activity.
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
			WHERE tenant_id = $1 AND action = 'auth.login_failed'
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
	rows, err := r.pool.Query(ctx, `
		WITH days AS (
			SELECT date_trunc('day', d)::date AS day
			FROM generate_series(
				date_trunc('day', NOW() - INTERVAL '13 days'),
				date_trunc('day', NOW()),
				'1 day'::interval
			) AS d
		),
		grouped AS (
			SELECT date_trunc('day', created_at)::date AS day,
			       COALESCE(metadata->>'method', 'password') AS method,
			       COUNT(*) AS n
			FROM audit.events
			WHERE tenant_id = $1
			  AND action = 'auth.login_succeeded'
			  AND created_at >= NOW() - INTERVAL '14 days'
			GROUP BY 1, 2
		)
		SELECT
			days.day::text,
			COALESCE(SUM(n) FILTER (WHERE method = 'password'),     0)::bigint,
			COALESCE(SUM(n) FILTER (WHERE method = 'passkey'),      0)::bigint,
			COALESCE(SUM(n) FILTER (WHERE method = 'social'),       0)::bigint,
			COALESCE(SUM(n) FILTER (WHERE method = 'saml'),         0)::bigint,
			COALESCE(SUM(n) FILTER (WHERE method = 'oidc'),         0)::bigint
		FROM days LEFT JOIN grouped ON grouped.day = days.day
		GROUP BY days.day
		ORDER BY days.day ASC
	`, tid)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p ActivityPoint
		if err := rows.Scan(&p.Date, &p.Password, &p.Passkey, &p.Social, &p.SAML, &p.OIDC); err != nil {
			return err
		}
		out.LoginActivity14d = append(out.LoginActivity14d, p)
	}
	return rows.Err()
}

func (r *Reader) loginMethodsMix(ctx context.Context, tid uuid.UUID, out *Overview) error {
	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(metadata->>'method', 'password') AS method, COUNT(*) AS n
		FROM audit.events
		WHERE tenant_id = $1
		  AND action = 'auth.login_succeeded'
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
	// Only TOTP + Recovery Codes are first-class today. Other methods
	// (Passkey-MFA, SMS OTP, Email OTP) will appear once their tables
	// exist; until then the dashboard renders just the populated bars.
	var totp, recovery int64
	if err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM auth.mfa_totp t
		JOIN "user".users u ON u.id = t.user_id
		WHERE u.tenant_id = $1 AND u.deleted_at IS NULL AND t.confirmed_at IS NOT NULL
	`, tid).Scan(&totp); err != nil {
		return err
	}
	if err := r.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT c.user_id)
		FROM auth.mfa_recovery_codes c
		JOIN "user".users u ON u.id = c.user_id
		WHERE u.tenant_id = $1 AND u.deleted_at IS NULL AND c.used_at IS NULL
	`, tid).Scan(&recovery); err != nil {
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
	rows, err := r.pool.Query(ctx, `
		WITH hours AS (
			SELECT date_trunc('hour', h) AS hour
			FROM generate_series(
				date_trunc('hour', NOW() - INTERVAL '23 hours'),
				date_trunc('hour', NOW()),
				'1 hour'::interval
			) AS h
		),
		grouped AS (
			SELECT date_trunc('hour', created_at) AS hour, COUNT(*) AS n
			FROM audit.events
			WHERE tenant_id = $1
			  AND action = 'auth.login_failed'
			  AND created_at >= NOW() - INTERVAL '24 hours'
			GROUP BY 1
		)
		SELECT to_char(hours.hour, 'HH24:MI'), COALESCE(grouped.n, 0)
		FROM hours LEFT JOIN grouped ON grouped.hour = hours.hour
		ORDER BY hours.hour ASC
	`, tid)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p HourlyPoint
		if err := rows.Scan(&p.Hour, &p.Attempts); err != nil {
			return err
		}
		out.FailedLoginsHourly24h = append(out.FailedLoginsHourly24h, p)
	}
	return rows.Err()
}

// extraKPIs populates the analytics-page-specific KPIs that aren't on
// the dashboard overview: DAU, total users, average sessions/user (last
// 30 days), and stickiness (DAU/MAU). Each one runs as its own SQL so
// a slow query in one stat doesn't block the rest of the dashboard.
func (r *Reader) extraKPIs(ctx context.Context, tid uuid.UUID, out *Overview) error {
	// DAU = distinct users with a session today vs yesterday.
	var dauNow, dauPrev int64
	if err := r.pool.QueryRow(ctx, `
		SELECT
			COUNT(DISTINCT user_id) FILTER (WHERE created_at >= date_trunc('day', NOW())),
			COUNT(DISTINCT user_id) FILTER (WHERE created_at >= date_trunc('day', NOW() - INTERVAL '1 day')
			                                AND created_at <  date_trunc('day', NOW()))
		FROM auth.sessions
		WHERE tenant_id = $1
	`, tid).Scan(&dauNow, &dauPrev); err != nil {
		return err
	}
	out.KPIs.DAU = Metric{Value: float64(dauNow), DeltaPct: pctChange(dauNow, dauPrev)}

	// Total users in tenant + delta vs 30 days ago.
	var usersNow, usersPrev int64
	if err := r.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE deleted_at IS NULL),
			COUNT(*) FILTER (WHERE deleted_at IS NULL AND created_at <= NOW() - INTERVAL '30 days')
		FROM "user".users
		WHERE tenant_id = $1
	`, tid).Scan(&usersNow, &usersPrev); err != nil {
		return err
	}
	out.KPIs.TotalUsers = Metric{Value: float64(usersNow), DeltaPct: pctChange(usersNow, usersPrev)}

	// Avg sessions per active user, last 30d vs prior 30d.
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

	// Stickiness = DAU / MAU expressed as a percentage. Industry-
	// standard product-engagement signal.
	mauVal := out.KPIs.MAU.Value
	stickNow := 0.0
	if mauVal > 0 {
		stickNow = 100.0 * float64(dauNow) / mauVal
	}
	// For the delta, compare to the same ratio a week ago.
	var dauPrevWeek, mauPrevWeek int64
	if err := r.pool.QueryRow(ctx, `
		SELECT
			COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '8 days'
			                                  AND created_at <  NOW() - INTERVAL '7 days'),
			COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '37 days'
			                                  AND created_at <  NOW() - INTERVAL '7 days')
		FROM auth.sessions
		WHERE tenant_id = $1
	`, tid).Scan(&dauPrevWeek, &mauPrevWeek); err != nil {
		return err
	}
	stickPrev := 0.0
	if mauPrevWeek > 0 {
		stickPrev = 100.0 * float64(dauPrevWeek) / float64(mauPrevWeek)
	}
	out.KPIs.StickinessPct = Metric{Value: stickNow, DeltaPct: stickNow - stickPrev}
	return nil
}

// weeklyActivity8w returns 8 trailing ISO-week buckets of (WAU, avg DAU
// in week). Buckets are always 8 wide — missing weeks return zero —
// so the chart doesn't compress on a brand-new tenant.
func (r *Reader) weeklyActivity8w(ctx context.Context, tid uuid.UUID, out *Overview) error {
	rows, err := r.pool.Query(ctx, `
		WITH weeks AS (
			SELECT date_trunc('week', d) AS week_start
			FROM generate_series(
				date_trunc('week', NOW() - INTERVAL '7 weeks'),
				date_trunc('week', NOW()),
				'1 week'::interval
			) AS d
		),
		w AS (
			SELECT
				date_trunc('week', created_at) AS week_start,
				COUNT(DISTINCT user_id) AS wau
			FROM auth.sessions
			WHERE tenant_id = $1 AND created_at >= date_trunc('week', NOW() - INTERVAL '7 weeks')
			GROUP BY 1
		),
		d AS (
			SELECT
				lat.dw AS week_start,
				AVG(daily_users)::bigint AS dau_avg
			FROM (
				SELECT
					date_trunc('day', created_at) AS day,
					COUNT(DISTINCT user_id) AS daily_users
				FROM auth.sessions
				WHERE tenant_id = $1 AND created_at >= date_trunc('week', NOW() - INTERVAL '7 weeks')
				GROUP BY 1
			) daily, LATERAL (SELECT date_trunc('week', daily.day) AS dw) lat
			GROUP BY 1
		)
		SELECT
			to_char(weeks.week_start, '"W"IW') AS week,
			COALESCE(w.wau, 0),
			COALESCE(d.dau_avg, 0)
		FROM weeks
		LEFT JOIN w ON w.week_start = weeks.week_start
		LEFT JOIN d ON d.week_start = weeks.week_start
		ORDER BY weeks.week_start ASC
	`, tid)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p WeeklyActivityPoint
		if err := rows.Scan(&p.Week, &p.WAU, &p.DAU); err != nil {
			return err
		}
		out.WeeklyActivity8w = append(out.WeeklyActivity8w, p)
	}
	return rows.Err()
}

func pctChange(now, prev int64) float64 {
	if prev == 0 {
		if now == 0 {
			return 0
		}
		return 100
	}
	return 100.0 * float64(now-prev) / float64(prev)
}

type Handler struct {
	Reader *Reader
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/analytics/overview", h.overview)
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	// Cross-tenant guard: the JWT's tenant must match the path param.
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil || *p.TenantID != tid {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("cross-tenant access denied"))
		return
	}
	out, err := h.Reader.Overview(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
