-- Queries for the ratelimits domain: an organization's overrides in
-- platform.rate_limit_overrides. The limiters in platform/cache/ratelimit
-- read them back into memory.

-- name: GetRateLimitOverrides :many
SELECT limit_key, rate, capacity
FROM platform.rate_limit_overrides
WHERE organization_id = @organization_id;

-- name: UpsertRateLimitOverride :exec
INSERT INTO platform.rate_limit_overrides (organization_id, limit_key, rate, capacity, updated_at)
VALUES (@organization_id, @limit_key, @rate, @capacity, NOW())
ON CONFLICT (organization_id, limit_key) DO UPDATE SET
    rate = EXCLUDED.rate, capacity = EXCLUDED.capacity, updated_at = NOW();

-- name: DeleteRateLimitOverrides :exec
DELETE FROM platform.rate_limit_overrides WHERE organization_id = @organization_id;
