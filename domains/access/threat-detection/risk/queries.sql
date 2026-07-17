-- Queries for the threat-detection/risk domain.
-- All queries are static and compiled by sqlc into ./dbgen.

-- name: GetRiskSettings :one
SELECT medium_threshold, high_threshold, force_mfa_at_level,
       impossible_travel_enabled, min_travel_hours, device_reputation_enabled
FROM auth.risk_settings WHERE tenant_id = $1;

-- name: UpsertRiskSettings :exec
INSERT INTO auth.risk_settings (
    tenant_id, medium_threshold, high_threshold, force_mfa_at_level,
    impossible_travel_enabled, min_travel_hours, device_reputation_enabled, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
    medium_threshold           = EXCLUDED.medium_threshold,
    high_threshold             = EXCLUDED.high_threshold,
    force_mfa_at_level         = EXCLUDED.force_mfa_at_level,
    impossible_travel_enabled  = EXCLUDED.impossible_travel_enabled,
    min_travel_hours           = EXCLUDED.min_travel_hours,
    device_reputation_enabled  = EXCLUDED.device_reputation_enabled,
    updated_at                 = NOW();

-- name: GetLastCountry :one
SELECT country, seen_at FROM auth.login_context_history
WHERE tenant_id = $1 AND user_id = $2 AND country IS NOT NULL AND country <> ''
ORDER BY seen_at DESC LIMIT 1;

-- name: DeviceSeenBefore :one
SELECT EXISTS(
    SELECT 1 FROM auth.login_context_history
    WHERE tenant_id = $1 AND user_id = $2 AND device_key = $3
) AS exists;

-- name: InsertLoginContext :exec
INSERT INTO auth.login_context_history (tenant_id, user_id, device_key, country)
VALUES ($1, $2, $3, $4);
