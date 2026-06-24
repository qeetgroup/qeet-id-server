# Monitoring Runbook

## Overview

Qeet ID uses Prometheus + Grafana for metrics, OTel for distributed tracing, and structured JSON logs for observability. Observability config (Prometheus scrape rules, Grafana dashboard, OTel collector) is not bundled with the current simple deploy — set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable tracing; metrics are always available at `/metrics`.

## Prometheus metrics

Exposed at `GET /metrics` (Prometheus scrape format).

### Key metrics

| Metric | Type | Description |
|---|---|---|
| `http_request_duration_seconds` | Histogram | Per-route request latency (labels: `method`, `path`, `status`) |
| `http_requests_in_flight` | Gauge | Current concurrent requests |
| `http_requests_total` | Counter | Total requests (labels: `method`, `path`, `status`) |
| `build_info` | Gauge | Version metadata (labels: `version`, `commit`, `go_version`) |

### Prometheus scrape config (EC2 + Docker Compose)

Add a scrape job pointing at the host:
```yaml
scrape_configs:
  - job_name: qeet-id
    static_configs:
      - targets: ['<EC2-PRIVATE-IP>:4001']
```

> Grafana dashboards and Prometheus alert rules are in git history (`deploy/base/observability/`) — restore when you add a monitoring stack.

## Alert rules (recommended thresholds)

| Alert | Condition | Severity |
|---|---|---|
| `QeetIDHighErrorRate` | 5xx rate > 5% over 5 min | critical |
| `QeetIDHighLatency` | P95 latency > 2s over 5 min | warning |
| `QeetIDInstanceDown` | No scrape for 2 min | critical |
| `QeetIDHighRateLimitRate` | 429 rate > 50/min over 5 min | warning |
| `QeetIDRateLimitStoreError` | Rate limit store errors > 0 | warning |
| `QeetIDReadinessFailure` | `/readyz` returns non-200 | critical |

## Distributed tracing (OTel)

Tracing is enabled when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. When unset, tracing is a no-op with zero overhead.

To enable tracing, set in `.env`:
```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://your-otel-collector:4318
```

Traces are propagated via W3C Trace Context headers (`traceparent`, `tracestate`).

## Structured logs

All logs are JSON-structured via `platform/observability/logging` (wraps `slog`). Format:
```json
{
  "level": "INFO",
  "msg": "request",
  "request_id": "req_01J...",
  "method": "POST",
  "path": "/v1/auth/login",
  "status": 200,
  "latency_ms": 45,
  "tenant_id": "01J...",
  "user_id": "01J..."
}
```

PII fields (email, display_name, passwords) are never logged — the redacting slog handler filters them.

### Searching logs

```bash
docker compose -f deploy/prod/docker-compose.yml logs app --follow --tail=100
docker compose -f deploy/prod/docker-compose.yml logs app | jq 'select(.status >= 500)'
docker compose -f deploy/prod/docker-compose.yml logs app | jq 'select(.request_id == "req_01J...")'
```

## Health probes

| Probe | Endpoint | Returns |
|---|---|---|
| Liveness | `GET /healthz` | `{ "status": "ok", "version": "...", "commit": "...", "uptime": "..." }` |
| Readiness | `GET /readyz` | `{ "status": "ok" }` or `503 { "status": "unavailable", "reason": "db" }` |

`/readyz` pings the PostgreSQL connection pool on every call. A 503 from `/readyz` means the database is unreachable — investigate DB connectivity first.

`/healthz` never returns a non-200 (unless the process is dead) — it's a liveness signal only.

## Signals to watch

### Normal operation baseline (approximate)
- Latency P95: < 200ms for most endpoints; < 500ms for federation protocol endpoints
- Error rate (5xx): < 0.1%
- Rate limit hits: occasional spikes are normal; sustained > 50/min warrants investigation

### Warning signs
- Sustained P95 latency > 1s → check DB query times; check for N+1 query patterns
- 5xx rate > 1% → check error logs for `unhandled error` (unexpected panics or DB errors)
- 429 rate spike → could be a scraper/bot; review IP patterns in audit log
- `/readyz` intermittently returning 503 → DB connection pool exhausted or DB overloaded
- `build_info` metric disappears → pod restart or crash loop

## Log-based alerting

For log-based alerts (Loki/Datadog/Splunk), query for:
- `level=ERROR` — any unhandled errors
- `status>=500` — server errors (should correlate with Prometheus `5xx` metric)
- `msg="rate limit store error"` — Redis connectivity issues
- `msg="audit record failed"` — audit write failures (high severity)
