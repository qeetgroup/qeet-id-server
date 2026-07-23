-- Queries for the analytics domain (admin dashboard KPIs + chart projections).
--
-- These are the static aggregations whose result types sqlc can infer cleanly.
-- A handful of projections stay hand-written in analytics.go because sqlc cannot
-- infer their return types without changing behaviour:
--   - kpis() MFA-adoption + MFA-adoption-prior: the mixed-type CASE
--     (integer 0 vs numeric ratio) resolves to numeric, which sqlc emits as
--     interface{} rather than float64.
--   - extraKPIs() avg-sessions-per-user: COALESCE(CASE ... ::float, 0) also
--     resolves to interface{} under sqlc.
--   - trends14d(): users_cum = COALESCE(bigint) + COALESCE(SUM(...) numeric) is
--     mis-inferred as int32 while the code scans int64 (narrowing/overflow risk).
--   - loginMethodsMix(): COALESCE(metadata->>'method', ...) (jsonb ->>) is
--     emitted as interface{} rather than string.

-- name: CountMAUWindows :one
SELECT
    COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') AS mau_now,
    COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '60 days'
                                       AND created_at <  NOW() - INTERVAL '30 days') AS mau_prev
FROM auth.sessions
WHERE tenant_id = @tid;

-- name: CountLoginsTodayWindows :one
SELECT
    COUNT(*) FILTER (WHERE created_at >= date_trunc('day', NOW())) AS logins_today,
    COUNT(*) FILTER (WHERE created_at >= date_trunc('day', NOW() - INTERVAL '1 day')
                      AND created_at <  date_trunc('day', NOW())) AS logins_yday
FROM auth.sessions
WHERE tenant_id = @tid;

-- name: CountFailedLogins24hWindows :one
SELECT
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours') AS failed_now,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '48 hours'
                      AND created_at <  NOW() - INTERVAL '24 hours') AS failed_prev
FROM audit.events
WHERE tenant_id = @tid AND action = 'auth.login_failed';

-- name: GetLoginActivity14d :many
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
    WHERE tenant_id = @tid
      AND action = 'auth.login_succeeded'
      AND created_at >= NOW() - INTERVAL '14 days'
    GROUP BY 1, 2
)
SELECT
    days.day::text AS day,
    COALESCE(SUM(n) FILTER (WHERE method = 'password'),     0)::bigint AS password,
    COALESCE(SUM(n) FILTER (WHERE method = 'passkey'),      0)::bigint AS passkey,
    COALESCE(SUM(n) FILTER (WHERE method = 'social'),       0)::bigint AS social,
    COALESCE(SUM(n) FILTER (WHERE method = 'saml'),         0)::bigint AS saml,
    COALESCE(SUM(n) FILTER (WHERE method = 'oidc'),         0)::bigint AS oidc
FROM days LEFT JOIN grouped ON grouped.day = days.day
GROUP BY days.day
ORDER BY days.day ASC;

-- name: CountMFATotpUsers :one
SELECT COUNT(*)
FROM auth.mfa_totp t
JOIN "user".users u ON u.id = t.user_id
WHERE u.tenant_id = @tid AND u.deleted_at IS NULL AND t.confirmed_at IS NOT NULL;

-- name: CountMFARecoveryUsers :one
SELECT COUNT(DISTINCT c.user_id)
FROM auth.mfa_recovery_codes c
JOIN "user".users u ON u.id = c.user_id
WHERE u.tenant_id = @tid AND u.deleted_at IS NULL AND c.used_at IS NULL;

-- name: GetFailedLoginsHourly24h :many
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
    WHERE tenant_id = @tid
      AND action = 'auth.login_failed'
      AND created_at >= NOW() - INTERVAL '24 hours'
    GROUP BY 1
)
SELECT to_char(hours.hour, 'HH24:MI') AS hour, COALESCE(grouped.n, 0) AS attempts
FROM hours LEFT JOIN grouped ON grouped.hour = hours.hour
ORDER BY hours.hour ASC;

-- name: CountDAUWindows :one
SELECT
    COUNT(DISTINCT user_id) FILTER (WHERE created_at >= date_trunc('day', NOW())) AS dau_now,
    COUNT(DISTINCT user_id) FILTER (WHERE created_at >= date_trunc('day', NOW() - INTERVAL '1 day')
                                    AND created_at <  date_trunc('day', NOW())) AS dau_prev
FROM auth.sessions
WHERE tenant_id = @tid;

-- name: CountTotalUsersWindows :one
SELECT
    COUNT(*) FILTER (WHERE deleted_at IS NULL) AS users_now,
    COUNT(*) FILTER (WHERE deleted_at IS NULL AND created_at <= NOW() - INTERVAL '30 days') AS users_prev
FROM "user".users
WHERE tenant_id = @tid;

-- name: CountStickinessPriorWeek :one
SELECT
    COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '8 days'
                                      AND created_at <  NOW() - INTERVAL '7 days') AS dau_prev_week,
    COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '37 days'
                                      AND created_at <  NOW() - INTERVAL '7 days') AS mau_prev_week
FROM auth.sessions
WHERE tenant_id = @tid;

-- name: GetWeeklyActivity8w :many
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
    WHERE sessions.tenant_id = @tid AND created_at >= date_trunc('week', NOW() - INTERVAL '7 weeks')
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
        WHERE tenant_id = @tid AND created_at >= date_trunc('week', NOW() - INTERVAL '7 weeks')
        GROUP BY 1
    ) daily, LATERAL (SELECT date_trunc('week', daily.day) AS dw) lat
    GROUP BY 1
)
SELECT
    to_char(weeks.week_start, '"W"IW') AS week,
    COALESCE(w.wau, 0) AS wau,
    COALESCE(d.dau_avg, 0) AS dau
FROM weeks
LEFT JOIN w ON w.week_start = weeks.week_start
LEFT JOIN d ON d.week_start = weeks.week_start
ORDER BY weeks.week_start ASC;
