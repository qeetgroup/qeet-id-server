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

# OIDC discovery + JWKS latency — constant load
k6 run tests/performance/discovery.js

# Convenience: run the suite via the k6 Docker image (no host install)
make bench   # discovery (SLO gate) + authz (informational)

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
| `discovery.js` | OIDC discovery + JWKS (public, unthrottled) | p95 < 20ms (per-endpoint) |
| `soak.js` | 60-minute soak test (auth + CRUD mix) | Sustained 20 VUs, < 0.1% error |

`webhooks.js` (delivery latency) and `audit.js` (query-under-write-load) are
planned but not yet implemented — remove this line once they land.

## Thresholds

All scripts fail the run if:
- `http_req_failed` > 1%
- p95 response time exceeds the per-scenario target
- Error rate during ramp-down > 0.5%

## CI

[`.github/workflows/perf.yml`](../../.github/workflows/perf.yml) runs nightly
(and on demand) — it spins up Postgres, boots the server, seeds, and runs the
benchmarks. `discovery.js` is a **hard SLO gate** (p95 < 20ms); `authz.js` runs
**informational** because a single seeded user also exercises the per-user rate
limiter (so its `http_req_failed` isn't a clean per-run gate). Perf is
deliberately *not* on the per-PR path — the runs are slow and rate-limit-sensitive.

## Measured (local dev machine, 2026-07-17)

First real numbers, both well inside their SLOs (dev-machine, not a production SLA):

| Path | Result | SLO |
|---|---|---|
| OIDC discovery / JWKS | **p95 ≈ 3.2ms**, 0% errors, ~9,300 req/s | < 20ms |
| RBAC + recursive ReBAC `/check` | **p95 ≈ 11.9ms**, median 6.5ms, 0% errors | < 30ms |

These are dev-machine sanity numbers, not a production SLA — representative
post-GA traffic is still needed for an external performance claim (Gap 11 in the
`qeet-files` repo's `qeet-id/research/GAP-ANALYSIS.md`). Token-issuance and
API-read hot paths are not yet benchmarked.
