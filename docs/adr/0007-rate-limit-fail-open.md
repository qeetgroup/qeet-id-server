# ADR-0007: Rate Limiter Fails Open on Store Error

**Status:** Accepted  
**Date:** 2025-Q1  
**Deciders:** Qeet ID core team

---

## Context

Qeet ID uses a token-bucket rate limiter (`platform/cache/ratelimit`) that optionally uses Redis as the shared state store. The choice of Redis makes the rate limiter a dependency that can fail.

Two failure modes were considered:

1. **Fail closed** — if Redis is unavailable, deny all requests (treat as rate-limited)
2. **Fail open** — if Redis is unavailable, allow all requests (degrade gracefully)

## Decision

The rate limiter **fails open** on store errors:

```go
// platform/cache/ratelimit/limiter.go
func (l *Limiter) Allow(key string) bool {
    ok, err := l.store.Allow(key, l.rate, l.capacity)
    if err != nil {
        // Redis unavailable — log, alert, and allow
        l.logger.Error("rate limit store error", "err", err)
        return true
    }
    return ok
}
```

Store errors are logged at ERROR level. An alert rule (`git history: deploy/base/observability/prometheus/alerts.yml`) fires if rate-limit store errors exceed a threshold.

## Consequences

**Positive:**
- A Redis outage (maintenance, network partition, OOM kill) **never causes a site-wide lockout**
- Availability is preserved; the degraded mode is "rate limiting is not enforced" rather than "the site is down"
- SMTP failover, Kubernetes node failure, Redis eviction — none of these bring down auth flows

**Negative / watch-outs:**
- During a Redis outage, attackers can send unlimited requests to login endpoints. The in-process fallback limiter (`memStore`) continues to enforce limits per-process; with multiple API replicas, per-IP limits degrade from global to per-replica
- An extended Redis outage with a distributed brute-force attack is the worst-case scenario. Mitigation: cloud-level IP blocking via CDN/WAF for sustained attacks
- The `memStore` fallback is per-process and not coordinated across replicas — by design, this is acceptable as a soft degradation

**Alternative considered:** Fail closed with circuit-breaker (allow traffic to a queue until Redis recovers). Rejected as over-engineering for pre-1.0; revisit if abuse patterns emerge.
