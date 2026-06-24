# Monitoring Runbook

## Overview

Qeet ID uses Prometheus + Grafana for metrics, OTel for distributed tracing, and structured JSON logs for observability. All observability configuration is in [`deploy/base/observability/`](../../deploy/base/observability/).

## Prometheus metrics

Exposed at `GET /metrics` (Prometheus scrape format).

### Key metrics

| Metric | Type | Description |
|---|---|---|
| `http_request_duration_seconds` | Histogram | Per-route request latency (labels: `method`, `path`, `status`) |
| `http_requests_in_flight` | Gauge | Current concurrent requests |
| `http_requests_total` | Counter | Total requests (labels: `method`, `path`, `status`) |
| `build_info` | Gauge | Version metadata (labels: `version`, `commit`, `go_version`) |

### Kubernetes scraping

The Helm chart includes a `ServiceMonitor` (`deploy/base/helm/qeet-id/templates/servicemonitor.yaml`) for automatic Prometheus Operator discovery. Ensure Prometheus Operator is installed in the cluster.

Manual scrape config (without Operator):
```yaml
# deploy/base/observability/prometheus/prometheus.yml
scrape_configs:
  - job_name: qeet-id
    static_configs:
      - targets: ['qeet-id-service:4001']
```

## Grafana dashboard

Dashboard: [`deploy/base/observability/grafana/dashboards/qeet-id.json`](../../deploy/base/observability/grafana/dashboards/qeet-id.json)

Import via Grafana UI: Dashboards → Import → Upload JSON file.

**Key panels:**
- Request rate (req/s by status code)
- P50/P95/P99 latency by endpoint
- Error rate (4xx and 5xx)
- In-flight requests
- Rate limit hits (429s)

## Alert rules

Defined in [`deploy/base/observability/prometheus/alerts.yml`](../../deploy/base/observability/prometheus/alerts.yml).

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

OTel Collector config: [`deploy/base/observability/otel-collector-config.yaml`](../../deploy/base/observability/otel-collector-config.yaml)

To enable in Kubernetes:
```yaml
# In environments/prod/values.yaml
env:
  OTEL_EXPORTER_OTLP_ENDPOINT: "http://otel-collector:4317"
  OTEL_SERVICE_NAME: "qeet-id"
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

Kubernetes:
```bash
kubectl logs -n qeet-id deploy/qeet-id --tail=100 --follow | jq 'select(.status >= 500)'
kubectl logs -n qeet-id deploy/qeet-id | jq 'select(.request_id == "req_01J...")'
```

Docker Compose:
```bash
docker compose -f deploy/environments/prod/compose/docker-compose.prod.yml logs api --follow --tail=100
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
