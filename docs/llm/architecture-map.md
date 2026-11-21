# Architecture Map — qeet-id-server

**Level:** L2 — repository · **Last verified:** 2026-11-15
**Verification scope:** every path and named entry point below was checked against the repository at
`c2454fec`. The file is authoritative; this page is a navigation aid.

A navigation index. "Where is X?" answered in one hop. For _how_ things work, read
[context.md](context.md).

---

## Start here

|                             |                                        |
| --------------------------- | -------------------------------------- |
| Repository identity         | [`qeet-repo.yml`](../../qeet-repo.yml) |
| Agent instructions          | [`AGENTS.md`](../../AGENTS.md)         |
| Product architecture (L1)   | `qeetgroup/qeet-id-context`            |
| Organization standards (L0) | `qeetgroup/qeet-context`               |

## Entrypoints

| Binary                                           | Path                                                                                                                                                      |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| API server                                       | `cmd/api/main.go` → `bootstrap.Run()`                                                                                                                     |
| Scheduled maintenance                            | `internal/bootstrap/maintenance.go` (`MaintenanceJobs`; each job in its context's `wire_<context>.go`) · `internal/platform/worker/scheduled.go` (runner) |
| Demo data (a workstation and the kit's DEV only) | `cmd/seed/` — `main.go` runs the steps in `internal/` (census, accounts, connections, integrations, security)                                             |

## Composition root — where everything is wired

|                         |                                                                                                                                                                     |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Application lifecycle   | `internal/bootstrap/app.go`                                                                                                                                         |
| Dependency construction | `internal/bootstrap/dependencies.go` and one `wire_<context>.go` per bounded context (building blocks in `keys.go`, `mail.go`, `infra.go`, `sso.go`, `adapters.go`) |
| **Router + middleware** | `internal/bootstrap/router.go`                                                                                                                                      |
| Route → permission map  | `internal/bootstrap/permissions.go`, joined from each context's table in `wire_<context>.go`                                                                        |
| HTTP server             | `internal/bootstrap/server.go`                                                                                                                                      |
| Startup/shutdown        | `internal/bootstrap/lifecycle.go`                                                                                                                                   |

**All new wiring goes in `internal/bootstrap`.** Nowhere else.

## HTTP

| Concern                                               | Path                                                                                                                              |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Router construction                                   | `internal/bootstrap/router.go` — `NewRouter()`                                                                                    |
| Global middleware chain                               | `internal/bootstrap/router.go` (RequestID, RealIP, Recoverer, InFlight, SecurityHeaders, AccessLog, tracing, metrics, CORS, CSRF) |
| Health / readiness                                    | `internal/bootstrap/router.go` → `/healthz`, `/readyz`                                                                            |
| Metrics                                               | `internal/bootstrap/router.go` → `/metrics`                                                                                       |
| Request helpers, principal, guards                    | `internal/platform/http/httpx/`                                                                                                   |
| Error taxonomy                                        | `internal/platform/http/errs/`                                                                                                    |
| Cursor pagination                                     | `internal/platform/http/paging/`                                                                                                  |
| Server-Sent Events writer (activity stream, Qeet AI)  | `internal/platform/http/sse/`                                                                                                     |
| Small string helpers (nullable pointers, comma lists) | `internal/platform/strutil/`                                                                                                      |

## Security — read these carefully before editing

| Concern                                                                           | Path                                                                    |
| --------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **Auth middleware, principal, `EnforceOrganizationScope`, `RequireOrganization`** | `internal/platform/http/httpx/auth.go`                                  |
| **CSRF double-submit**                                                            | `internal/platform/http/httpx/csrf.go`                                  |
| Security headers                                                                  | `internal/platform/http/httpx/`                                         |
| **JWT issue/verify, ES256 or RS256, `kid`, rotation**                             | `internal/platform/crypto/tokens/` — `issue.go`, `verify.go`, `keys.go` |
| **Password hashing (Argon2id)**                                                   | `internal/platform/crypto/password/hasher.go`                           |
| Encryption, secrets vault crypto                                                  | `internal/platform/crypto/envelope/`                                    |
| TOTP                                                                              | `internal/platform/crypto/totp/`                                        |
| Breached-password check                                                           | `internal/platform/crypto/hibp/`                                        |
| One-time codes and tokens, and the hash they are stored as                        | `internal/platform/crypto/codes/`                                       |
| **Boot-time production gate**                                                     | `internal/platform/config/validate.go` — `Config.Validate()`            |

## Authentication

| Flow                                                | Path                                                                                       |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Password login, sessions, refresh                   | `internal/access/authentication/` — `password.go`, `issue.go`, `refresh.go`, `sessions.go` |
| Hosted SSO login session (`qe_ls`)                  | `internal/access/authentication/loginsession.go`                                           |
| Trusted device (`qe_td`)                            | `internal/access/authentication/trusteddevice.go`                                          |
| Account lockout                                     | `internal/access/authentication/lockout.go`                                                |
| Passkeys / WebAuthn                                 | `internal/access/passkey/`                                                                 |
| MFA — TOTP, OTP, recovery codes                     | `internal/access/mfa/` — `totp.go`, `otp.go`, `stepup.go`                                  |
| MFA — push approval                                 | `internal/access/mfa/push.go`, `pushdevices.go`, `pushchallenge.go`, `pushadmin.go`        |
| MFA — push delivery (APNs for iOS, FCM for Android) | `internal/access/mfa/pushnative.go`                                                        |
| Magic link, password reset                          | `internal/access/recovery/`                                                                |
| Adaptive risk, login history                        | `internal/access/threat/risk/`                                                             |
| Bot detection                                       | `internal/access/threat/bot/`                                                              |
| IP allow/deny                                       | `internal/access/ipallow/`                                                                 |

## Authorization

| Model                                                                | Path                                                      |
| -------------------------------------------------------------------- | --------------------------------------------------------- |
| RBAC + route enforcement                                             | `internal/access/authorization/rbac/` (`enforce.go`)      |
| Access requests (ask for a role; approve, deny, time-limited grants) | `internal/access/authorization/accessrequest/`            |
| ABAC                                                                 | `internal/access/authorization/abac/`                     |
| ReBAC (Zanzibar-style)                                               | `internal/access/authorization/rebac/`                    |
| AuthZEN PDP/PEP                                                      | `internal/access/authorization/authzen/`                  |
| Access decision log                                                  | `internal/access/authorization/decisionlog/`              |
| Organization security policy                                         | `internal/access/authpolicy/securitypolicy.go`            |
| Password rules, login methods                                        | `internal/access/authpolicy/`                             |
| **Route → permission map**                                           | `internal/bootstrap/permissions.go` + `wire_<context>.go` |

## Identity

| Concern                           | Path                                       |
| --------------------------------- | ------------------------------------------ |
| Organizations                     | `internal/identity/organization/`          |
| Per-organization branding         | `internal/identity/organization/branding/` |
| Users, bulk import, IdP migration | `internal/identity/user/`                  |
| Groups                            | `internal/identity/group/`                 |
| Invitations                       | `internal/identity/invite/`                |
| Email/phone verification          | `internal/identity/verification/`          |
| DNS domain verification           | `internal/identity/domainverify/`          |

## Federation

| Protocol                                              | Path                                                                                                                                   |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| OIDC/OAuth provider, discovery, JWKS                  | `internal/federation/oidc/` — `authorization_code.go`, `refresh.go`, `token_exchange.go`, `authorize.go`, `discovery.go`, `clients.go` |
| The token endpoint (every grant) and its error writer | `internal/federation/oidc/http_token.go`                                                                                               |
| Device and CIBA polling (one step)                    | `internal/federation/oidc/poll.go`                                                                                                     |
| Device grant                                          | `internal/federation/oidc/device.go`                                                                                                   |
| CIBA                                                  | `internal/federation/oidc/ciba.go`                                                                                                     |
| OAuth client administration                           | `internal/federation/oidc/clients_admin.go`                                                                                            |
| SAML — SP                                             | `internal/federation/saml/saml.go`, `signin.go`, `acs.go`                                                                              |
| SAML — IdP                                            | `internal/federation/saml/idp.go`, `idp_sso.go`                                                                                        |
| SCIM 2.0                                              | `internal/federation/scim/`                                                                                                            |
| LDAP / AD                                             | `internal/federation/ldap/`                                                                                                            |
| Social login                                          | `internal/federation/social/`                                                                                                          |
| Federated account provisioning (link, adopt, JIT)     | `internal/federation/provision/` · checks in `internal/federation/identitylink/`                                                       |
| OpenID Connect relying party (SSO + social)           | `internal/federation/oidcrp/`                                                                                                          |
| Federated sign-in codes and OAuth states              | `internal/federation/logincode/` · `internal/federation/oauthstate/`                                                                   |
| Self-serve admin portal                               | `internal/federation/adminportal/`                                                                                                     |

## Developer & machine identity

| Concern                                                         | Path                                         |
| --------------------------------------------------------------- | -------------------------------------------- |
| API keys (`qk_`)                                                | `internal/developer/apikey/`                 |
| Service principals, `client_credentials`                        | `internal/developer/principal/`              |
| Rotating a key or machine secret: request, scope check, overlap | `internal/developer/rotation/`               |
| **AI agents, lifecycle, kill switch**                           | `internal/developer/agent/`                  |
| Auth hooks                                                      | `internal/developer/authhook/`               |
| Webhooks + DLQ                                                  | `internal/developer/webhook/`                |
| Secrets vault, KMS provider                                     | `internal/developer/credentials/secret/`     |
| Third-party token vault                                         | `internal/developer/credentials/tokenvault/` |
| Verifiable credentials                                          | `internal/developer/credentials/vc/`         |

## Operations

| Concern                                                                                      | Path                                  |
| -------------------------------------------------------------------------------------------- | ------------------------------------- |
| Hash-chained audit log, `/verify`                                                            | `internal/operations/audit/`          |
| Anomaly detection                                                                            | `internal/operations/audit/anomaly/`  |
| Critical events (anomalies + critical audit actions, for on-call)                            | `internal/operations/audit/critical/` |
| Billing, payments, tax                                                                       | `internal/operations/billing/`        |
| GDPR erasure, export                                                                         | `internal/operations/gdpr/`           |
| Retention auto-purge                                                                         | `internal/operations/retention/`      |
| SIEM streaming                                                                               | `internal/operations/siem/`           |
| Analytics                                                                                    | `internal/operations/analytics/`      |
| Dashboard overview (set-up state and counts, per permission)                                 | `internal/operations/overview/`       |
| Service health and incidents                                                                 | `internal/operations/servicehealth/`  |
| Live activity feed (SSE)                                                                     | `internal/operations/activity/`       |
| In-app notifications                                                                         | `internal/operations/notification/`   |
| Plan entitlements, and the `PlanGate` / `PlanLimiter` / `SeatGuard` interfaces packages take | `internal/operations/entitlements/`   |
| Per-organization rate-limit overrides                                                        | `internal/operations/ratelimits/`     |
| AI assistant                                                                                 | `internal/operations/qeetai/`         |

## Data

| Concern                                         | Path                                                                                                            |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Postgres pool                                   | `internal/platform/database/postgres/`                                                                          |
| pgx error mapping                               | `internal/platform/database/postgres/`                                                                          |
| **Migrations (0001–0012, the schema baseline)** | `internal/platform/database/migrations/`                                                                        |
| Migration runner (`//go:embed`)                 | `internal/platform/database/migrations/runner.go`                                                               |
| Per-domain queries                              | `internal/<context>/<domain>/queries.sql` (60)                                                                  |
| sqlc config                                     | `sqlc.yaml` at the root: one entry per package, shared overrides (NULL-able uuid/timestamptz/date are pointers) |
| Generated accessors                             | `internal/<context>/<domain>/dbgen/` (60) — **never hand-edit**                                                 |

## Events & background work

| Concern              | Path                                                                                           |
| -------------------- | ---------------------------------------------------------------------------------------------- |
| Transactional outbox | `internal/platform/events/outbox/outbox.go`                                                    |
| NATS publishing      | `internal/platform/events/outbox/nats.go`                                                      |
| Worker pool          | `internal/platform/worker/worker.go`                                                           |
| Continuous workers   | the API runs them: the `workers` list in `internal/bootstrap/dependencies.go`                  |
| Scheduler            | `cmd/scheduler/main.go` — runs `bootstrap.MaintenanceJobs` standalone; the API embeds the same |

## Configuration & observability

| Concern                                               | Path                                                                                                |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **All 111 env vars, defaults, `Validate()`**          | `internal/platform/config/config.go` · `validate.go`                                                |
| Variable reference                                    | `.env.example` — placeholders only                                                                  |
| Structured logging                                    | `internal/platform/observability/logging/`                                                          |
| Prometheus metrics                                    | `internal/platform/observability/metrics/`                                                          |
| OpenTelemetry tracing                                 | `internal/platform/observability/tracing/`                                                          |
| Health probes                                         | `internal/platform/observability/health/`                                                           |
| Build info                                            | `internal/platform/observability/buildinfo/`                                                        |
| Rate limiting                                         | `internal/platform/cache/ratelimit/`                                                                |
| Email templates / notifier                            | `internal/platform/messaging/`                                                                      |
| Email delivery records, suppression list, SES webhook | `internal/platform/messaging/delivery/` (organization API: `internal/operations/email/delivery.go`) |

## Contracts

|                                                      |                                                                                                          |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| **OpenAPI 3.1 — 5 documents** (generated, committed) | `api/openapi/{access,identity,federation,developer,operations}.yaml`                                     |
| OpenAPI sources — edit these, then `make openapi`    | `api/openapi/src/<document>/` (`openapi.yaml`, `paths/<tag>/`, `components/`), `api/openapi/src/shared/` |
| Spec conventions                                     | `api/openapi/README.md`                                                                                  |
| AI tool catalogue                                    | `internal/operations/qeetai/tools.manifest.json`                                                         |

## Tests

| Kind                                            | Path                                                                      |
| ----------------------------------------------- | ------------------------------------------------------------------------- |
| Unit                                            | `_test.go` beside the source                                              |
| **OpenAPI route coverage gate**                 | `internal/bootstrap/openapi_coverage_test.go`                             |
| OpenAPI validity and cross-document consistency | `internal/bootstrap/openapi_valid_test.go`, `openapi_consistency_test.go` |

## Build, CI, deploy

|                                                |                                                                                                                                                |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Commands                                       | `Makefile`                                                                                                                                     |
| Linter config                                  | `.golangci.yml`                                                                                                                                |
| Container                                      | `Dockerfile`                                                                                                                                   |
| Local dependencies                             | `docker-compose.yml` — postgres :5001, nats :4222, mailpit :8025                                                                               |
| Hosted Verify                                  | `.github/workflows/ci.yml` — build · vet · lint · vulnerability scan · API contract checks · secret scan; no other Go tests or sqlc/gosec gate |
| Candidate image (on `release/**`, `hotfix/**`) | `.github/workflows/candidate.yml`                                                                                                              |
| Deploy (merged release or hotfix into `main`)  | `.github/workflows/deploy.yml`                                                                                                                 |
| Release version from a branch name             | `scripts/release/version.sh`                                                                                                                   |

**Deployment manifests are not in this repository** — Terraform and the rollout live in
`qeetgroup/qeet-id-deploy`.
