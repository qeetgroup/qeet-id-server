# Observability bundle

qeet-id exposes Prometheus metrics at `/metrics`, Kubernetes-shaped probes at
`/healthz` + `/readyz`, and OTLP traces (when `OTEL_EXPORTER_OTLP_ENDPOINT` is
set). This directory holds the operator-facing config to consume them.

| File | Purpose |
| --- | --- |
| `prometheus/prometheus.yml` | Standalone scrape config (Compose/dev). In k8s use the chart's `serviceMonitor.enabled`. |
| `prometheus/alerts.yml` | Alert rules (availability, error rate, latency, runtime). Also pasteable into a `PrometheusRule` CR. |
| `grafana/dashboards/qeet-id.json` | Importable Grafana dashboard (request rate, 5xx rate, p50/p95/p99 latency, top routes, runtime, build_info). |
| `otel-collector-config.yaml` | OTel Collector pipeline that receives app traces and forwards to a backend (Tempo by default). |

## Metrics emitted (see `platform/observability/metrics`)
- `http_requests_total{method,route,status}` — counter (route = chi pattern, bounded cardinality).
- `http_request_duration_seconds_{bucket,sum,count}{method,route}` — latency histogram.
- `build_info{version,commit,goversion}` — constant `1`, for pivoting dashboards/alerts by deployed version.
- Standard `go_*` / `process_*` runtime series.

## Wiring
- **Kubernetes:** set `serviceMonitor.enabled=true` (prod values already do). Load `alerts.yml`
  as a `PrometheusRule`. Import the dashboard, or provision it via a Grafana sidecar ConfigMap.
- **Compose:** add a `prometheus` service mounting `prometheus/` and an `otel-collector` mounting
  `otel-collector-config.yaml`, then point `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318`
  in `.env.prod`. Keep `/metrics` off the public edge — the Caddyfile already 404s it.

## SLO starting points
- Availability: 99.9% (error-budget burn from `QeetIdHighErrorRate`).
- Latency: p99 < 1s (`QeetIdHighLatencyP99`). Tune per endpoint class once baselined.
- Set `OTEL_TRACES_SAMPLER_RATIO` to ~0.1 in prod to bound trace volume.
