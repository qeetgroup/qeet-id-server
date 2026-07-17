-- Queries for the ratelimits domain.
-- Static queries against platform.rate_limit_overrides live here and are
-- compiled by sqlc into ./dbgen.
-- SetOverride / DeleteOverride are owned by platform/cache/ratelimit (the
-- TenantLimiter) and remain hand-written there; this package only reads.

-- name: GetRateLimitOverrides :many
SELECT limit_key, rate, capacity
FROM platform.rate_limit_overrides
WHERE tenant_id = @tenant_id;
