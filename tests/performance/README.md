# tests/performance/

Load and performance tests using [k6](https://k6.io). These tests measure throughput, latency, and error rates under realistic load.

## Prerequisites

```bash
# macOS
brew install k6

# Docker
docker pull grafana/k6
```

The backend must be running against seeded data before executing tests:
```bash
make db-up migrate-up seed
make dev
```

`auth.js`, `soak.js`, and `authz.js` log in as specific `make seed` fixtures
(`cmd/seed/main.go` — `@qeet.in` accounts, password `Password123!`); `users.js`
needs an API key instead (`k6 run -e API_KEY=sk_... tests/performance/users.js`).

## Run

```bash
# Auth flow — constant load
k6 run tests/performance/auth.js

# User management — ramping
k6 run -e API_KEY=sk_... tests/performance/users.js

# RBAC + ReBAC /check — ramping
k6 run tests/performance/authz.js

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
| `authz.js` | RBAC `/check` + ReBAC recursive group-membership `/check` | p95 < 200ms at 30 VUs |
| `soak.js` | 60-minute soak test (auth + CRUD mix) | Sustained 20 VUs, < 0.1% error |

`webhooks.js` (delivery latency) and `audit.js` (query-under-write-load) are
planned but not yet implemented — remove this line once they land.

## Thresholds

All scripts fail the run if:
- `http_req_failed` > 1%
- p95 response time exceeds the per-scenario target
- Error rate during ramp-down > 0.5%

These thresholds are **local dev-machine sanity targets**, not measured
production SLAs — nothing here runs in CI (no job wires k6 into
`.github/workflows/ci.yml`, and there's no docker-compose that brings up the
app server alongside Postgres for one). They exist to catch obvious
regressions when run by hand, not to back an external performance claim.
Qeet ID has **no published p95/p99 numbers** for its authorization or
token-issuance hot paths — tracked honestly as unpublished (Gap 11 in the
`qeet-files` repo's `qeet-id/research/GAP-ANALYSIS.md`), pending representative
post-GA traffic (a premature number risks being unimpressive or quickly
stale). Extending coverage here is a prerequisite for that, not a substitute.
