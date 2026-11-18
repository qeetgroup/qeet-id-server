-- Queries for the analytics domain (admin dashboard KPIs + chart projections).
-- Where Postgres would answer numeric or an untyped expression, the result is
-- cast (::float8, ::bigint, ::text) so sqlc types it as the Go code reads it.
--
-- Sign-ins and active users come from the sign-in log, the auth.login_succeeded
-- audit events, not from auth.sessions: ended sessions are purged after a
-- week, and the log is kept. Counts of people take every such event in the
-- organization, switching to it, creating it and accepting an invitation to it
-- included; counts of sign-ins leave those three out, as they record no factor
-- of their own.

-- name: CountMAUWindows :one
-- People who signed in to the organization in the last 30 days, and in the 30
-- before.
SELECT
    COUNT(DISTINCT actor_user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') AS mau_now,
    COUNT(DISTINCT actor_user_id) FILTER (WHERE created_at <  NOW() - INTERVAL '30 days') AS mau_prev
FROM audit.events
WHERE organization_id = @tid
  AND action = 'auth.login_succeeded'
  AND created_at >= NOW() - INTERVAL '60 days';

-- name: CountLoginsTodayWindows :one
-- Sign-ins to the organization today, and yesterday.
SELECT
    COUNT(*) FILTER (WHERE created_at >= date_trunc('day', NOW())) AS logins_today,
    COUNT(*) FILTER (WHERE created_at <  date_trunc('day', NOW())) AS logins_yday
FROM audit.events
WHERE organization_id = @tid
  AND action = 'auth.login_succeeded'
  AND COALESCE(metadata->>'method', '') NOT IN ('organization_switch', 'organization_create', 'invite_accept')
  AND created_at >= date_trunc('day', NOW() - INTERVAL '1 day');

-- name: CountFailedLogins24hWindows :one
SELECT
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours') AS failed_now,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '48 hours'
                      AND created_at <  NOW() - INTERVAL '24 hours') AS failed_prev
FROM audit.events
WHERE organization_id = @tid AND action = 'auth.sign_in_failed';

-- name: GetLoginActivity14d :many
-- Sign-ins per day by first factor. The method's _mfa or _email_confirmed
-- suffix (a second step) is dropped, and sessions opened by switching or
-- creating an organization or accepting an invitation are not counted: they
-- record no factor of their own.
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
           regexp_replace(COALESCE(metadata->>'method', 'password'), '_(mfa|email_confirmed)$', '') AS method,
           COUNT(*) AS n
    FROM audit.events
    WHERE organization_id = @tid
      AND action = 'auth.login_succeeded'
      AND COALESCE(metadata->>'method', '') NOT IN ('organization_switch', 'organization_create', 'invite_accept')
      AND created_at >= NOW() - INTERVAL '14 days'
    GROUP BY 1, 2
)
SELECT
    days.day::text AS day,
    COALESCE(SUM(n) FILTER (WHERE method = 'password'),     0)::bigint AS password,
    COALESCE(SUM(n) FILTER (WHERE method = 'passkey'),      0)::bigint AS passkey,
    COALESCE(SUM(n) FILTER (WHERE method = 'social'),       0)::bigint AS social,
    COALESCE(SUM(n) FILTER (WHERE method = 'saml'),         0)::bigint AS saml,
    COALESCE(SUM(n) FILTER (WHERE method = 'oidc'),         0)::bigint AS oidc,
    COALESCE(SUM(n) FILTER (WHERE method = 'magic_link'),   0)::bigint AS magic_link,
    COALESCE(SUM(n) FILTER (WHERE method = 'ldap'),         0)::bigint AS ldap
FROM days LEFT JOIN grouped ON grouped.day = days.day
GROUP BY days.day
ORDER BY days.day ASC;

-- name: CountMFATotpUsers :one
SELECT COUNT(*)
FROM auth.mfa_totp t
JOIN account.users u ON u.id = t.user_id
WHERE u.organization_id = @tid AND u.deleted_at IS NULL AND t.confirmed_at IS NOT NULL;

-- name: CountMFARecoveryUsers :one
SELECT COUNT(DISTINCT c.user_id)
FROM auth.mfa_recovery_codes c
JOIN account.users u ON u.id = c.user_id
WHERE u.organization_id = @tid AND u.deleted_at IS NULL AND c.used_at IS NULL;

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
    WHERE organization_id = @tid
      AND action = 'auth.sign_in_failed'
      AND created_at >= NOW() - INTERVAL '24 hours'
    GROUP BY 1
)
SELECT to_char(hours.hour, 'HH24:MI') AS hour, COALESCE(grouped.n, 0) AS attempts
FROM hours LEFT JOIN grouped ON grouped.hour = hours.hour
ORDER BY hours.hour ASC;

-- name: CountDAUWindows :one
-- People who signed in to the organization today, and yesterday.
SELECT
    COUNT(DISTINCT actor_user_id) FILTER (WHERE created_at >= date_trunc('day', NOW())) AS dau_now,
    COUNT(DISTINCT actor_user_id) FILTER (WHERE created_at <  date_trunc('day', NOW())) AS dau_prev
FROM audit.events
WHERE organization_id = @tid
  AND action = 'auth.login_succeeded'
  AND created_at >= date_trunc('day', NOW() - INTERVAL '1 day');

-- name: CountTotalUsersWindows :one
SELECT
    COUNT(*) FILTER (WHERE deleted_at IS NULL) AS users_now,
    COUNT(*) FILTER (WHERE deleted_at IS NULL AND created_at <= NOW() - INTERVAL '30 days') AS users_prev
FROM account.users
WHERE organization_id = @tid;

-- name: CountStickinessPriorWeek :one
-- DAU and MAU as they stood a week ago.
SELECT
    COUNT(DISTINCT actor_user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '8 days') AS dau_prev_week,
    COUNT(DISTINCT actor_user_id) AS mau_prev_week
FROM audit.events
WHERE organization_id = @tid
  AND action = 'auth.login_succeeded'
  AND created_at >= NOW() - INTERVAL '37 days'
  AND created_at <  NOW() - INTERVAL '7 days';

-- name: GetWeeklyActivity8w :many
-- People who signed in to the organization per ISO week, and their daily
-- average, for the last 8 weeks.
WITH weeks AS (
    SELECT date_trunc('week', d) AS week_start
    FROM generate_series(
        date_trunc('week', NOW() - INTERVAL '7 weeks'),
        date_trunc('week', NOW()),
        '1 week'::interval
    ) AS d
),
sign_ins AS (
    SELECT created_at, actor_user_id AS user_id
    FROM audit.events
    WHERE organization_id = @tid
      AND action = 'auth.login_succeeded'
      AND created_at >= date_trunc('week', NOW() - INTERVAL '7 weeks')
),
w AS (
    SELECT
        date_trunc('week', created_at) AS week_start,
        COUNT(DISTINCT user_id) AS wau
    FROM sign_ins
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
        FROM sign_ins
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

-- name: MFAAdoptionPct :one
-- The share of the organization's active people with a confirmed TOTP factor,
-- as a percentage.
WITH active AS (
    SELECT id FROM account.users
    WHERE organization_id = @tid AND status = 'active' AND deleted_at IS NULL
),
enrolled AS (
    SELECT user_id FROM auth.mfa_totp WHERE confirmed_at IS NOT NULL
)
SELECT (CASE WHEN COUNT(active.id) = 0 THEN 0
             ELSE 100.0 * COUNT(*) FILTER (WHERE enrolled.user_id IS NOT NULL) / COUNT(active.id)
        END)::float8 AS pct
FROM active LEFT JOIN enrolled ON enrolled.user_id = active.id;

-- name: MFAAdoptionPctWeekAgo :one
-- MFAAdoptionPct as it stood a week ago.
WITH active AS (
    SELECT id FROM account.users
    WHERE organization_id = @tid AND status = 'active' AND deleted_at IS NULL
      AND created_at <= NOW() - INTERVAL '7 days'
),
enrolled AS (
    SELECT user_id FROM auth.mfa_totp
    WHERE confirmed_at IS NOT NULL AND confirmed_at <= NOW() - INTERVAL '7 days'
)
SELECT (CASE WHEN COUNT(active.id) = 0 THEN 0
             ELSE 100.0 * COUNT(*) FILTER (WHERE enrolled.user_id IS NOT NULL) / COUNT(active.id)
        END)::float8 AS pct
FROM active LEFT JOIN enrolled ON enrolled.user_id = active.id;

-- name: GetTrends14d :many
-- One bucket per day for the last 14 days, so the chart always has 14 points:
-- people in total, sign-ins, new TOTP enrolments and failed sign-ins.
WITH days AS (
    SELECT date_trunc('day', d)::date AS day
    FROM generate_series(
        date_trunc('day', NOW() - INTERVAL '13 days'),
        date_trunc('day', NOW()),
        '1 day'::interval
    ) AS d
),
users_per_day AS (
    SELECT date_trunc('day', nu.created_at)::date AS day, COUNT(*) AS new_users
    FROM account.users nu
    WHERE nu.organization_id = @tid AND nu.deleted_at IS NULL
    GROUP BY 1
),
base AS (
    SELECT COUNT(*) AS total
    FROM account.users bu
    WHERE bu.organization_id = @tid AND bu.deleted_at IS NULL
      AND bu.created_at < NOW() - INTERVAL '14 days'
),
sign_ins_per_day AS (
    SELECT date_trunc('day', se.created_at)::date AS day, COUNT(*) AS sign_ins
    FROM audit.events se
    WHERE se.organization_id = @tid AND se.action = 'auth.login_succeeded'
      AND COALESCE(se.metadata->>'method', '') NOT IN ('organization_switch', 'organization_create', 'invite_accept')
      AND se.created_at >= NOW() - INTERVAL '14 days'
    GROUP BY 1
),
failed_per_day AS (
    SELECT date_trunc('day', fe.created_at)::date AS day, COUNT(*) AS fails
    FROM audit.events fe
    WHERE fe.organization_id = @tid AND fe.action = 'auth.sign_in_failed'
      AND fe.created_at >= NOW() - INTERVAL '14 days'
    GROUP BY 1
),
mfa_per_day AS (
    SELECT date_trunc('day', confirmed_at)::date AS day, COUNT(*) AS enrolled
    FROM auth.mfa_totp t
    JOIN account.users u ON u.id = t.user_id
    WHERE u.organization_id = @tid AND u.deleted_at IS NULL AND t.confirmed_at IS NOT NULL
    GROUP BY 1
)
SELECT
    days.day::text AS day,
    (COALESCE((SELECT total FROM base), 0)
        + COALESCE(SUM(users_per_day.new_users)
                   FILTER (WHERE users_per_day.day <= days.day), 0))::bigint AS users_cum,
    COALESCE(sign_ins_per_day.sign_ins, 0)::bigint AS logins,
    COALESCE(mfa_per_day.enrolled, 0)::bigint AS mfa_new,
    COALESCE(failed_per_day.fails, 0)::bigint AS fails
FROM days
LEFT JOIN users_per_day ON users_per_day.day = days.day
LEFT JOIN sign_ins_per_day ON sign_ins_per_day.day = days.day
LEFT JOIN mfa_per_day ON mfa_per_day.day = days.day
LEFT JOIN failed_per_day ON failed_per_day.day = days.day
GROUP BY days.day, sign_ins_per_day.sign_ins, mfa_per_day.enrolled, failed_per_day.fails
ORDER BY days.day ASC;

-- name: CountLoginMethods30d :many
-- Sign-ins of the last 30 days by first factor, most used first.
SELECT regexp_replace(COALESCE(metadata->>'method', 'password'), '_(mfa|email_confirmed)$', '')::text AS method,
       COUNT(*) AS n
FROM audit.events
WHERE organization_id = @tid
  AND action = 'auth.login_succeeded'
  AND COALESCE(metadata->>'method', '') NOT IN ('organization_switch', 'organization_create', 'invite_accept')
  AND created_at >= NOW() - INTERVAL '30 days'
GROUP BY 1
ORDER BY n DESC;

-- name: AvgSignInsPerPersonWindows :one
-- Sign-ins per person who signed in, in the last 30 days and the 30 before.
SELECT
    COALESCE(
        CASE WHEN COUNT(DISTINCT actor_user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') = 0 THEN 0
             ELSE COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days')::float
                  / NULLIF(COUNT(DISTINCT actor_user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days'), 0)
        END, 0)::float8 AS avg_now,
    COALESCE(
        CASE WHEN COUNT(DISTINCT actor_user_id) FILTER (WHERE created_at < NOW() - INTERVAL '30 days') = 0 THEN 0
             ELSE COUNT(*) FILTER (WHERE created_at < NOW() - INTERVAL '30 days')::float
                  / NULLIF(COUNT(DISTINCT actor_user_id) FILTER (WHERE created_at < NOW() - INTERVAL '30 days'), 0)
        END, 0)::float8 AS avg_prev
FROM audit.events
WHERE organization_id = @tid AND action = 'auth.login_succeeded'
  AND COALESCE(metadata->>'method', '') NOT IN ('organization_switch', 'organization_create', 'invite_accept')
  AND created_at >= NOW() - INTERVAL '60 days';

-- name: CountSignInsByDay :many
-- The organization's sign-ins, people signing in and failed sign-ins by UTC day
-- from the day of @from_at to the day of @to_at, of @method when not ''.
SELECT to_char(d, 'YYYY-MM-DD')::text AS day,
       count(e.id) FILTER (WHERE e.action = 'auth.login_succeeded') AS sign_ins,
       count(DISTINCT e.actor_user_id) FILTER (WHERE e.action = 'auth.login_succeeded') AS people,
       count(e.id) FILTER (WHERE e.action = 'auth.sign_in_failed') AS failed
FROM generate_series(date_trunc('day', timezone('UTC', @from_at::timestamptz)),
                     date_trunc('day', timezone('UTC', @to_at::timestamptz)), INTERVAL '1 day') AS d
LEFT JOIN audit.events e
  ON e.organization_id = @tid
 AND e.created_at >= timezone('UTC', d) AND e.created_at < timezone('UTC', d + INTERVAL '1 day')
 AND e.created_at >= @from_at::timestamptz AND e.created_at <= @to_at::timestamptz
 AND e.action IN ('auth.login_succeeded', 'auth.sign_in_failed')
 AND COALESCE(e.metadata->>'method', '') NOT IN ('organization_switch', 'organization_create', 'invite_accept')
 AND (@method::text = '' OR e.metadata->>'method' = @method::text)
GROUP BY d ORDER BY d;
