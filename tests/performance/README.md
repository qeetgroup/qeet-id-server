# tests/performance/

Load and performance tests using [k6](https://k6.io). These tests measure throughput, latency, and error rates under realistic load.

## Prerequisites

```bash
# macOS
brew install k6

# Docker
docker pull grafana/k6
```

The backend must be running before executing tests:
```bash
make db-up migrate-up
make dev-backend
```

## Run

```bash
# Auth flow — constant load
k6 run tests/performance/auth.js

# User management — ramping
k6 run tests/performance/users.js

# With output to Grafana/InfluxDB
k6 run --out influxdb=http://localhost:8086/k6 tests/performance/auth.js

# With environment override
k6 run -e BASE_URL=https://staging.id.qeet.in tests/performance/auth.js
```

## Scenarios

| Script | What it tests | Target |
|---|---|---|
| `auth.js` | Login + token refresh flow | p95 < 300ms at 50 VUs |
| `users.js` | User CRUD via API key | p95 < 200ms at 20 VUs |
| `webhooks.js` | Webhook delivery latency (outbox) | Delivery < 1s at 10 VUs |
| `audit.js` | Audit log query under write load | p95 < 500ms at 10 VUs |
| `soak.js` | 60-minute soak test (auth + CRUD mix) | Sustained 20 VUs, < 0.1% error |

## Thresholds

All scripts fail the run if:
- `http_req_failed` > 1%
- p95 response time exceeds the per-scenario target
- Error rate during ramp-down > 0.5%
