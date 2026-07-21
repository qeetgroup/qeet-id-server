-- Queries for the threat-detection/bot domain.
-- Static queries are compiled by sqlc into ./dbgen.
-- InsertBotEvent is intentionally hand-written in bot.go because it uses
-- NULLIF($2,'')::inet — the inet cast makes sqlc parameter-type inference
-- ambiguous; correctness takes priority over coverage.

-- name: GetUserTenantByEmail :one
SELECT tenant_id FROM "user".users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL AND tenant_id IS NOT NULL
LIMIT 1;

-- ListBotEvents is intentionally hand-written in bot.go because COALESCE(host(ip),'')
-- causes sqlc to generate interface{} for the column type, making type-safe scanning
-- impossible without runtime assertions.

-- name: GetBotEventStats :one
SELECT
    COUNT(*) FILTER (WHERE verdict = 'blocked'   AND created_at >= NOW() - INTERVAL '24 hours') AS blocked_24h,
    COUNT(*) FILTER (WHERE verdict = 'challenged' AND created_at >= NOW() - INTERVAL '24 hours') AS challenged_24h
FROM auth.bot_events WHERE tenant_id = $1;

-- name: GetBotSettings :one
SELECT ua_check, honeypot, captcha, signature, score_threshold
FROM auth.bot_settings WHERE tenant_id = $1;

-- name: UpsertBotSettings :exec
INSERT INTO auth.bot_settings (tenant_id, ua_check, honeypot, captcha, signature, score_threshold, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
    ua_check        = EXCLUDED.ua_check,
    honeypot        = EXCLUDED.honeypot,
    captcha         = EXCLUDED.captcha,
    signature       = EXCLUDED.signature,
    score_threshold = EXCLUDED.score_threshold,
    updated_at      = NOW();
