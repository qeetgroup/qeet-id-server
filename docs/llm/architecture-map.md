# Architecture Map — qeet-id-server

**Level:** L2 — repository · **Last verified:** 2026-08-28
**Verification scope:** every path below was confirmed to exist on disk. Line numbers were read from
the file at that revision and may drift — the file is authoritative, the line number is a hint.

A navigation index. "Where is X?" answered in one hop. For *how* things work, read
[context.md](context.md).

---

## Start here

| | |
|---|---|
| Repository identity | [`qeet-repo.yml`](../../qeet-repo.yml) |
| Agent instructions | [`AGENTS.md`](../../AGENTS.md) |
| Product architecture (L1) | `qeetgroup/qeet-id-context` |
| Organization standards (L0) | `qeetgroup/qeet-context` |
| Shipped-vs-planned status | [`ROADMAP.md`](../../ROADMAP.md) — see the staleness note in [context.md](context.md#known-technical-debt) |

## Entrypoints

| Binary | Path |
|---|---|
| API server | `cmd/api/main.go` → `bootstrap.Run()` |
| Background workers | `cmd/worker/main.go` |
| Scheduled maintenance | `cmd/scheduler/main.go` |
| Migration runner | `cmd/migrate/main.go` |
| Demo data (dev only) | `cmd/seed/main.go` |

## Composition root — where everything is wired

| | |
|---|---|
| Application lifecycle | `internal/bootstrap/app.go` |
| Dependency construction | `internal/bootstrap/dependencies.go` |
| **Router + middleware** | `internal/bootstrap/router.go` |
| Route → permission map | `internal/bootstrap/permissions.go` |
| HTTP server | `internal/bootstrap/server.go` |
| Startup/shutdown | `internal/bootstrap/lifecycle.go` |

**All new wiring goes in `internal/bootstrap`.** Nowhere else.

## HTTP

| Concern | Path |
|---|---|
| Router construction | `internal/bootstrap/router.go` — `NewRouter()` |
| Global middleware chain | `internal/bootstrap/router.go` (RequestID, RealIP, Recoverer, InFlight, SecurityHeaders, AccessLog, tracing, metrics, CORS, CSRF) |
| Health / readiness | `internal/bootstrap/router.go` → `/healthz`, `/readyz` |
| Metrics | `internal/bootstrap/router.go` → `/metrics` |
| Request helpers, principal, guards | `internal/platform/http/httpx/` |
| Error taxonomy | `internal/platform/http/errs/` |
| Status-code mapping | `internal/platform/http/codes/` |
| Cursor pagination | `internal/platform/http/paging/` |

## Security — read these carefully before editing

| Concern | Path |
|---|---|
| **Auth middleware, principal, `EnforceTenantScope`, `RequireTenant`** | `internal/platform/http/httpx/auth.go` |
| **CSRF double-submit** | `internal/platform/http/httpx/csrf.go` |
| Security headers | `internal/platform/http/httpx/` |
| **JWT issue/verify, ES256, `kid`, rotation** | `internal/platform/crypto/tokens/jwt.go` |
| **Password hashing (Argon2id)** | `internal/platform/crypto/encryption/hasher.go` |
| Encryption, secrets vault crypto | `internal/platform/crypto/encryption/` |
| TOTP | `internal/platform/crypto/encryption/totp/` |
| Breached-password check | `internal/platform/crypto/hibp/` |
| **Boot-time production gate** | `internal/platform/config/config.go` — `Config.Validate()` |

## Authentication

| Flow | Path |
|---|---|
| Password login, sessions, refresh | `internal/access/authentication/service.go` |
| Hosted SSO login session (`qe_ls`) | `internal/access/authentication/loginsession.go` |
| Trusted device (`qe_td`) | `internal/access/authentication/trusteddevice.go` |
| Account lockout | `internal/access/authentication/lockout.go` |
| Passkeys / WebAuthn | `internal/access/passkeys/` |
| MFA — TOTP, OTP, recovery codes | `internal/access/mfa/mfa.go` |
| MFA — push approval | `internal/access/mfa/push.go` |
| Magic link, password reset | `internal/access/recovery/` |
| Adaptive risk, login history | `internal/access/threat/risk/` |
| Bot detection | `internal/access/threat/bot/` |
| IP allow/deny | `internal/access/risk/ipallow/` |

## Authorization

| Model | Path |
|---|---|
| RBAC + route enforcement | `internal/access/authorization/rbac/` (`enforce.go`) |
| ABAC | `internal/access/authorization/abac/` |
| ReBAC (Zanzibar-style) | `internal/access/authorization/rebac/` |
| AuthZEN PDP/PEP | `internal/access/authorization/authzen/` |
| Tenant security policy | `internal/access/authorization/policy/` |
| Password rules, login methods | `internal/access/authorization/authpolicy/` |
| **Route → permission map** | `internal/bootstrap/permissions.go` |

## Identity

| Concern | Path |
|---|---|
| Tenants | `internal/identity/tenant/` |
| Per-tenant branding | `internal/identity/tenant/branding/` |
| Users, bulk import, IdP migration | `internal/identity/users/` |
| Groups | `internal/identity/groups/` |
| Invitations | `internal/identity/invitations/` |
| Email/phone verification | `internal/identity/verification/` |
| DNS domain verification | `internal/identity/domainverify/` |

## Federation

| Protocol | Path |
|---|---|
| OIDC/OAuth provider, discovery, JWKS | `internal/federation/oidc/oidc.go` |
| Device grant | `internal/federation/oidc/device.go` |
| CIBA | `internal/federation/oidc/ciba.go` |
| OAuth client administration | `internal/federation/oidc/clients_admin.go` |
| SAML — SP | `internal/federation/saml/saml.go` |
| SAML — IdP | `internal/federation/saml/idp.go` |
| SCIM 2.0 | `internal/federation/scim/` |
| LDAP / AD | `internal/federation/ldap/` |
| Social login | `internal/federation/social/` |
| Self-serve admin portal | `internal/federation/adminportal/` |

## Developer & machine identity

| Concern | Path |
|---|---|
| API keys (`qk_`) | `internal/developer/api-keys/` |
| Service principals, `client_credentials` | `internal/developer/principal/` |
| **AI agents, lifecycle, kill switch** | `internal/developer/agents/` |
| Auth hooks | `internal/developer/auth-hooks/` |
| Webhooks + DLQ | `internal/developer/webhooks/` |
| Secrets vault, KMS provider | `internal/developer/credentials/secrets/` |
| Third-party token vault | `internal/developer/credentials/tokenvault/` |
| Verifiable credentials | `internal/developer/credentials/vc/` |

## Operations

| Concern | Path |
|---|---|
| Hash-chained audit log, `/verify` | `internal/operations/audit/` |
| Anomaly detection | `internal/operations/audit/anomaly/` |
| Billing, payments, tax | `internal/operations/billing/` |
| GDPR erasure, export | `internal/operations/gdpr/` |
| Retention auto-purge | `internal/operations/retention/` |
| SIEM streaming | `internal/operations/siem/` |
| Analytics | `internal/operations/analytics/` |
| Live activity feed (SSE) | `internal/operations/activity/` |
| In-app notifications | `internal/operations/notifications/` |
| Plan entitlements | `internal/operations/entitlements/` |
| Per-tenant rate-limit overrides | `internal/operations/ratelimits/` |
| AI assistant | `internal/operations/qeetai/` |

## Data

| Concern | Path |
|---|---|
| Postgres pool | `internal/platform/database/postgres/` |
| pgx error mapping | `internal/platform/database/postgres/pgxerr/` |
| **Migrations (0001–0096)** | `internal/platform/database/migrations/` |
| Migration runner (`//go:embed`) | `internal/platform/database/migrations/runner.go` |
| Per-domain queries | `internal/<context>/<domain>/queries.sql` (48) |
| sqlc config | `internal/<context>/<domain>/sqlc.yaml` (48) |
| Generated accessors | `internal/<context>/<domain>/dbgen/` (47) — **never hand-edit** |

## Events & background work

| Concern | Path |
|---|---|
| Transactional outbox | `internal/platform/events/outbox/outbox.go` |
| NATS publishing | `internal/platform/events/outbox/nats.go` |
| Worker pool | `internal/platform/jobs/worker.go` |
| Standalone worker | `cmd/worker/main.go` — webhooks, anomaly, gdpr, retention, siem, outbox |
| Scheduler | `cmd/scheduler/main.go` — audit maintenance, advisory-lock coordinated |

## Configuration & observability

| Concern | Path |
|---|---|
| **All 81 env vars, defaults, `Validate()`** | `internal/platform/config/config.go` |
| Variable reference | `.env.example` — placeholders only |
| Structured logging | `internal/platform/observability/logging/` |
| Prometheus metrics | `internal/platform/observability/metrics/` |
| OpenTelemetry tracing | `internal/platform/observability/tracing/` |
| Health probes | `internal/platform/observability/health/` |
| Build info | `internal/platform/observability/buildinfo/` |
| Rate limiting | `internal/platform/cache/ratelimit/` |
| Email templates / notifier | `internal/platform/messaging/` |

## Contracts

| | |
|---|---|
| **OpenAPI 3.1 — 5 documents** | `api/openapi/{auth,management,federation,developer,operations}.yaml` |
| Spec conventions | `api/openapi/README.md` |
| Postman collection | `api/postman/` |
| AI tool catalogue | `api/qeetai/tools.manifest.json` |

## Tests

| Kind | Path |
|---|---|
| **Architecture fitness (R1/R2)** | `tests/architecture/arch_test.go` |
| Integration (Testcontainers) | `tests/integration/` — 18 files, `-tags integration` |
| **OpenAPI route coverage gate** | `tests/integration/coverage_test.go` |
| Security regression | `tests/security/{auth_bypass,csrf,headers}_test.go` |
| Semgrep rule — no raw SQL fmt | `tests/security/semgrep/no-raw-sql-fmt.yaml` |
| k6 performance | `tests/performance/` |
| Shared harness | `tests/fixtures/` |

## Build, CI, deploy

| | |
|---|---|
| Commands | `Makefile` |
| Linter config | `.golangci.yml` |
| Container | `Dockerfile` |
| Local dependencies | `docker-compose.yml` — postgres :5001, nats :4222, mailpit :8025 |
| CI | `.github/workflows/ci.yml` — test · lint · integration · vuln |
| CodeQL | `.github/workflows/codeql.yml` |
| Deploy (on `main`) | `.github/workflows/deploy.yml` |
| Tooling | `tools/` — openapi-split, migration-tools, qa, scripts |

**Deployment manifests are not in this repository** — Terraform and the rollout live in
`qeetgroup/qeet-id-deploy`.
