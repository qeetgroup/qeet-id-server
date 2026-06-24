# Rate Limiting

## Overview

Rate limiting is implemented in `platform/cache/ratelimit` using a **token-bucket algorithm**. Limits are applied per key type with different parameters for different principal types and endpoints.

The limiter can use either:
- **In-process store (`memStore`)** — per-replica, no shared state (default, always available)
- **Redis-backed store** — shared across replicas; enables globally consistent limits

Configure Redis via the `REDIS_URL` environment variable. If unset, the in-process store is used.

**Fail-open behavior:** If the Redis store returns an error, the request is allowed (see [ADR-0007](../adr/0007-rate-limit-fail-open.md)).

## Limit tiers

### Public endpoints (per-IP)

Applied to login, signup, recovery, and passkey endpoints.

| Parameter | Value |
|---|---|
| Rate | 5 requests/second |
| Burst | 20 requests |
| Key | Client IP (`X-Forwarded-For` first, then `RemoteAddr`) |

This limits brute-force attacks: an attacker can make at most 20 rapid requests before hitting the limit, then 5/second sustained.

### Authenticated endpoints (per-tenant)

Applied to all authenticated `/v1` routes.

| Parameter | Value |
|---|---|
| Rate | 100 requests/second |
| Burst | 500 requests |
| Key | Tenant ID from JWT claims |

### Per-user

Applied within authenticated routes for user-principal tokens.

| Parameter | Value |
|---|---|
| Rate | 30 requests/second |
| Burst | 100 requests |
| Key | User ID from JWT claims |

### Per-API-key

Applied to API-key-authenticated requests.

| Parameter | Value |
|---|---|
| Rate | 50 requests/second |
| Burst | 200 requests |
| Key | API key ID (not the secret; the ID is extracted during key authentication) |

## Response on rate limit exceeded

```
HTTP/1.1 429 Too Many Requests
Retry-After: 3
Content-Type: application/json

{
  "error": {
    "code":    "too_many_requests",
    "message": "rate limit exceeded",
    "request_id": "req_..."
  }
}
```

`Retry-After` is the number of seconds until the next token refills. Clients should respect this and back off accordingly.

## Token-bucket mechanics

The token bucket refills at the configured rate continuously:

```
Available tokens = min(capacity, prev_tokens + (elapsed_seconds × rate))
```

If the bucket has ≥ 1 token, the request is allowed and 1 token is consumed. If empty, `429` is returned. The burst capacity allows short spikes above the sustained rate.

## Monitoring

Rate limit hits are observable via:
- Server access log: `"status":429` lines
- Prometheus metric: `http_requests_total{status="429"}` — breakable by path
- Alert rule in `git history: deploy/base/observability/prometheus/alerts.yml`: fires when 429 rate exceeds threshold over 5 minutes

## Redis considerations

When Redis is used, rate limit state is shared across all API replicas. Without Redis, each replica has its own independent bucket — a client hitting multiple replicas can exceed the intended rate limit by a factor of the replica count.

For most deployments (1–3 replicas), the in-process limiter is sufficient. Redis is recommended for deployments with > 5 replicas or when precise global rate limiting is required.
