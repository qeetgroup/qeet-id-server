-- Queries for the threat-detection/bot domain, compiled by sqlc into ./dbgen.

-- name: GetUserOrganizationByEmail :one
SELECT id, organization_id FROM account.users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL AND organization_id IS NOT NULL
LIMIT 1;

-- name: InsertBotEvent :exec
-- An empty @ip is recorded as NULL.
INSERT INTO auth.bot_events (organization_id, ip, user_agent, score, verdict, user_id)
VALUES (@organization_id, NULLIF(@ip::text, '')::inet, @user_agent, @score, @verdict, @user_id);

-- name: CountBotEvents :one
-- The organization's detections, of @verdict unless it is empty.
SELECT count(*) FROM auth.bot_events
WHERE organization_id = @organization_id AND (@verdict::text = '' OR verdict = @verdict::text);

-- name: ListBotEvents :many
-- A page of CountBotEvents' detections, newest first, before the cursor
-- (before_ts, before_id) when it is set; ip is '' when none was recorded. The
-- outcome is how the account's first sign-in from the same address within
-- @outcome_window of the detection ended.
SELECT b.id, COALESCE(host(b.ip), '')::text AS ip, b.user_agent, b.score, b.verdict, b.created_at, b.user_id,
       u.email AS user_email,
       COALESCE((
           SELECT CASE e.action WHEN 'auth.login_succeeded' THEN 'signed_in' ELSE 'failed' END
           FROM audit.events e
           WHERE e.organization_id = b.organization_id AND e.actor_user_id = b.user_id
             AND e.action IN ('auth.login_succeeded', 'auth.sign_in_failed')
             AND e.ip IS NOT DISTINCT FROM b.ip
             AND e.created_at >= b.created_at AND e.created_at < b.created_at + (@outcome_window::text)::interval
           ORDER BY e.created_at LIMIT 1), 'unknown')::text AS outcome
FROM auth.bot_events b
LEFT JOIN account.users u ON u.id = b.user_id
WHERE b.organization_id = @organization_id AND (@verdict::text = '' OR b.verdict = @verdict::text)
  AND (sqlc.narg('before_ts')::timestamptz IS NULL
       OR (b.created_at, b.id) < (sqlc.narg('before_ts')::timestamptz, sqlc.narg('before_id')::uuid))
ORDER BY b.created_at DESC, b.id DESC
LIMIT @lim;

-- name: GetBotEventStats :one
SELECT
    COUNT(*) FILTER (WHERE verdict = 'blocked'   AND created_at >= NOW() - INTERVAL '24 hours') AS blocked_24h,
    COUNT(*) FILTER (WHERE verdict = 'challenged' AND created_at >= NOW() - INTERVAL '24 hours') AS challenged_24h
FROM auth.bot_events WHERE organization_id = $1;

-- name: GetBotSettings :one
SELECT ua_check, honeypot, captcha, signature, score_threshold
FROM auth.bot_settings WHERE organization_id = $1;

-- LockBotSettings is GetBotSettings holding the row until the update that
-- replaces it commits.
-- name: LockBotSettings :one
SELECT ua_check, honeypot, captcha, signature, score_threshold
FROM auth.bot_settings WHERE organization_id = $1
FOR UPDATE;

-- name: UpsertBotSettings :exec
INSERT INTO auth.bot_settings (organization_id, ua_check, honeypot, captcha, signature, score_threshold, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, NOW())
ON CONFLICT (organization_id) DO UPDATE SET
    ua_check        = EXCLUDED.ua_check,
    honeypot        = EXCLUDED.honeypot,
    captcha         = EXCLUDED.captcha,
    signature       = EXCLUDED.signature,
    score_threshold = EXCLUDED.score_threshold,
    updated_at      = NOW();
