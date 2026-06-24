<div align="center">

# Qeet ID

### Passkeys-first identity platform — the open-source Auth0 / Okta alternative

*Developer-first · Enterprise-ready · Self-hostable · India-native*

<br>

[![CI](https://github.com/qeetgroup/qeet-id/actions/workflows/ci.yml/badge.svg)](./.github/workflows/ci.yml)
[![Go 1.25](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](./go.mod)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1-6BA539?logo=openapiinitiative&logoColor=white)](./api/openapi/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Security: gitleaks](https://img.shields.io/badge/Security-gitleaks-red)](./github/workflows/ci.yml)
[![Arch tests](https://img.shields.io/badge/Architecture-fitness%20tests-blueviolet)](./.github/workflows/ci.yml)

<br>

**[Quickstart](#quickstart)** · **[Architecture](#architecture-at-a-glance)** · **[Features](#feature-status)** · **[SDKs](#sdks)** · **[Deploy](#deployment)** · **[Docs](#documentation)**

</div>

---

<div align="center">

| &nbsp;&nbsp;&nbsp;🏗 Single deployable&nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp;🔌 ~190 API routes&nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp;🖥 3 React frontends&nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp;📦 5 first-party SDKs&nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp;🗄 62 migrations&nbsp;&nbsp;&nbsp; |
|:---:|:---:|:---:|:---:|:---:|
| Go modular monolith | 5 OpenAPI 3.1 specs | Admin · Login · Website | TS · React · Next.js · Go · Python | 6 PostgreSQL schemas |

</div>

---

Qeet ID is a **complete identity stack** in a single Go binary — authentication, enterprise SSO & SCIM, fine-grained authorization, machine & AI-agent identity, billing, audit, and compliance. Three React frontends (admin console, hosted login, marketing site) and five first-party SDKs ship alongside the API. UI primitives come from the shared [`@qeetrix/*`](../qeetrix/) design system; end-user docs live at [docs.qeet.in](https://docs.qeet.in).

> **Status: pre-1.0 · feature-complete for the July 2026 GA.** Every capability listed below has working Go code — no stubbed endpoints, no mock handlers. Remaining work is external-ops hardening (KMS BYOK, conformance, deliverability, penetration test) and UX polish (i18n/a11y for ~70 older admin screens, CIBA grant, prebuilt SDK components).

---

## Why Qeet ID?

<div align="center">

| Capability | **Qeet ID** | Auth0 | Okta | Clerk | Supabase Auth | better-auth |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| Open source (MIT) | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Fully self-hostable | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Backend language | Go | Managed | Managed | Node.js | Managed | Node.js/TS |
| Passkeys / WebAuthn | ✅ Native | 🟡 Add-on | 🟡 Add-on | ✅ | ✅ | ✅ |
| SAML 2.0 SP **and** IdP | ✅ Both | ✅ SP only | ✅ | 🟡 Enterprise | ❌ | ❌ |
| SCIM 2.0 provisioning | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| LDAP / Active Directory | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| OIDC provider (issue tokens) | ✅ | ✅ | ✅ | ❌ | 🟡 Plugin | 🟡 Plugin |
| ReBAC (Zanzibar-style) | ✅ Built-in | ❌ | ✅ (OPA) | ❌ | ❌ | ❌ |
| AI-agent identity (MCP) | ✅ Full stack | ❌ | ❌ | ❌ | ❌ | ❌ |
| Verifiable Credentials (W3C VC) | ✅ JWT-VC | ❌ | ❌ | ❌ | ❌ | ❌ |
| India payments (Razorpay) | ✅ Built-in | ❌ | ❌ | ❌ | ❌ | ❌ |
| Hash-chained audit log | ✅ `/verify` | ❌ | ❌ | ❌ | ❌ | ❌ |
| Refresh-token theft detection | ✅ | 🟡 | ✅ | ✅ | ❌ | ❌ |
| Breach-password detection (HIBP) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| SIEM streaming (Splunk / Datadog) | ✅ Built-in | 🟡 Export | ✅ | ❌ | ❌ | ❌ |
| Multi-currency billing | ✅ ISO-4217 | ❌ | ❌ | ❌ | ❌ | ❌ |
| Prebuilt UI components | ⏳ Planned | ✅ | ✅ | ✅ Best-in-class | ❌ | ❌ |
| GDPR erasure + data export | ✅ | ✅ | ✅ | 🟡 | 🟡 | ❌ |
| Production config boot-gate | ✅ | n/a | n/a | n/a | ❌ | ❌ |

</div>

---

## Architecture at a glance

A **single deployable** Go module with five bounded contexts and shared infrastructure under `platform/`. Boundaries are enforced by build-time fitness tests — not convention.

```
            ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
 End users  │  Hosted Login │  │ Admin Console │  │  Website      │
 Admins     │  Next.js      │  │ Vite+TanStack │  │  Next.js      │    Browsers
 Developers │  :3004        │  │  :3002        │  │  :3001        │    SDKs · AI agents
            └───────┬───────┘  └───────┬───────┘  └───────┬───────┘    service accounts
                    └──────────────────┼──────────────────┘
                                       ▼
          ┌────────────────────────────────────────────────────────────────┐
          │  Go API  (chi v5)  ·  cmd/server  ·  :4001                     │
          │  RequestID → RealIP → Recoverer → SecurityHeaders              │
          │  → AccessLog → Tracing → Metrics → CSRF → CORS → authz         │
          │                                                                 │
          │  ┌────────────┐ ┌────────────┐ ┌────────────┐                  │
          │  │  identity  │ │   access   │ │ federation │                  │
          │  │ users·orgs │ │ auth·mfa·  │ │ oidc·saml· │                  │
          │  │ groups·inv │ │ rbac·rebac │ │ scim·ldap  │                  │
          │  └────────────┘ └────────────┘ └────────────┘                  │
          │  ┌────────────┐ ┌────────────────────────────┐                 │
          │  │ developer  │ │         operations         │                 │
          │  │ api-keys·  │ │ audit·billing·compliance·  │                 │
          │  │ agents·vc  │ │ siem·analytics·retention   │                 │
          │  └────────────┘ └────────────────────────────┘                 │
          │                                                                 │
          │  platform/  api · database · security · cache · events         │
          │             observability · messaging · config                  │
          └──────────────────┬────────────────────┬──────────────────────-─┘
                             ▼                    ▼
                 PostgreSQL 16 (pgx v5)      Egress services
                 6 schemas · 30+ tables      SMTP · HIBP · Webhooks
                 multi-tenant by tenant_id   SIEM stream · Payments
                 optional Redis rate-limit   (transactional outbox)
```

### Engineering invariants

| Invariant | How it's enforced |
|:---|:---|
| **Modular-monolith boundaries** — `platform/*` never imports `domains/*`; `domains/*` never imports `cmd` or the router | `tests/architecture/arch_test.go` rules **R1** and **R2** — break a boundary and CI fails |
| **100% API documentation** | `chi.Walk` coverage test compares every mounted route against the 5 OpenAPI specs — undocumented route = CI failure |
| **Multi-tenant isolation** | Every mutable table carries `tenant_id`; 6 PostgreSQL schemas; no cross-schema JOINs — service calls only |
| **Tamper-evident audit** | SHA-256 hash-chained, append-only log; `GET /audit/verify` walks the chain and reports the first broken link |
| **Reliable eventing** | Transactional outbox: business row + audit row + event row commit in a single `pgx.Tx` |
| **No insecure prod boot** | `config.Validate()` refuses to start outside `SERVICE_ENV=dev` with weak/default keys |
| **Asymmetric JWT tokens** | ES256 / ECDSA P-256, JWKS-published, `kid` = RFC 7638 thumbprint, rotation grace window for live key roll |

Deep dives: [`docs/architecture/`](./docs/architecture/) · Decision records: [`docs/adr/`](./docs/adr/)

---

## Feature status

<details open>
<summary><b>🟢 Authentication &amp; sessions</b></summary>

| Feature | Status | Notes |
|:---|:---:|:---|
| Email + password (Argon2id, OWASP params) | ✅ | Per-account lockout, secure enumeration-safe flows |
| Passkeys / WebAuthn (registration + auth) | ✅ | FIDO2, resident credentials, cross-device |
| Magic links | ✅ | Time-limited, single-use |
| Email OTP / SMS OTP | ✅ | SMTP + Twilio wired |
| TOTP (RFC 6238) + recovery codes | ✅ | QR-code enrollment, 8 recovery codes |
| MFA step-up | ✅ | Per-operation elevation, WebAuthn as 2nd factor |
| Session management | ✅ | Refresh rotation + theft detection + silent revocation |
| Breach-password detection | ✅ | HIBP k-anonymity; env-gated (off in dev/CI) |
| Password & passwordless policy | ✅ | Per-tenant config |
| Password reset | ✅ | Enumeration-safe, time-limited tokens |

</details>

<details>
<summary><b>🟢 Enterprise SSO &amp; provisioning</b></summary>

| Feature | Status | Notes |
|:---|:---:|:---|
| OIDC / OAuth 2.0 provider | ✅ | Discovery, JWKS, Auth Code + PKCE, `/userinfo`, refresh, revoke, introspect, logout |
| Device Authorization Grant (RFC 8628) | ✅ | TV / CLI headless flows |
| Token Exchange (RFC 8693) | ✅ | Downscope + act-delegation + `act` claim |
| SAML 2.0 SP mode | ✅ | Consume external IdPs (Entra ID, Google, Okta) |
| SAML 2.0 IdP mode | ✅ | Issue assertions — Qeet ID as the SSO source |
| SCIM 2.0 (Users + Groups + PatchOp) | ✅ | Bi-directional provisioning |
| LDAP / Active Directory | ✅ | Bind-login, connection CRUD + test-bind |
| Social login (generic OIDC per tenant) | ✅ | Google, GitHub, Microsoft, Apple, custom |
| Account linking | ✅ | Multiple providers per user |
| SSO test-connection | ✅ | Validate config before enabling |

</details>

<details>
<summary><b>🟢 Authorization</b></summary>

| Feature | Status | Notes |
|:---|:---:|:---|
| RBAC | ✅ | Roles, permissions, user_roles, role_permissions |
| ABAC policies | ✅ | Attribute-based policy engine with explainable results |
| **ReBAC (Zanzibar-style)** | ✅ | `relation_tuples`, recursive userset `/check` with cycle guard |
| Single `/check` call | ✅ | Returns grant-path trace for auditability |
| IP allow / deny (CIDR) | ✅ | Per-tenant, per-IP CIDR rules |
| Auth Hooks / Actions | ✅ | Post-login gate — allow/deny + custom claims |

</details>

<details>
<summary><b>🟢 Developer &amp; AI-agent platform</b></summary>

| Feature | Status | Notes |
|:---|:---:|:---|
| Scoped API keys | ✅ | `qk_` prefix, expirable, hashed, audited |
| Service accounts (`client_credentials`) | ✅ | Machine-to-machine M2M grant |
| Secrets vault (AES-256-GCM) | ✅ | Per-tenant, scoped `vault:<name>` reads, audited |
| Webhooks (HMAC-SHA256) | ✅ | Signed, exponential backoff retry, DLQ |
| Auth Hooks | ✅ | Post-login allow/deny gate (Developer → Auth Hooks) |
| **AI-agent identity** | ✅ | Ephemeral scoped revocable tokens, `actor_type=agent` |
| **MCP introspection** | ✅ | `actor_type`, `agent_id`, `act` on `/oauth/introspect` |
| **Token delegation (RFC 8693)** | ✅ | `act` claim, `IssueAccessActor` |
| **Verifiable Credentials (W3C JWT-VC)** | ✅ | Issue / verify / revoke, public `/v1/credentials/verify` |
| Analytics | ✅ | MAU/DAU, login methods, MFA adoption, failed attempts |
| SIEM streaming | ✅ | Outbox → Splunk / Datadog via log sinks |

</details>

<details>
<summary><b>🟢 Identity &amp; workspace management</b></summary>

| Feature | Status | Notes |
|:---|:---:|:---|
| Multi-tenant organisations | ✅ | Isolated schemas, per-tenant branding, custom domains |
| User management | ✅ | CRUD, bulk import, sessions, recycle bin |
| Groups | ✅ | Nested membership, SCIM sync |
| Invitations | ✅ | Email-gated, expirable, role-pre-assign |
| Domain verification | ✅ | DNS TXT record check, org lockdown |
| Per-tenant email templates | ✅ | Transactional, i18n scaffold |
| Org switcher / branding preview | ✅ | Live in admin console |

</details>

<details>
<summary><b>🟢 Compliance &amp; billing</b></summary>

| Feature | Status | Notes |
|:---|:---:|:---|
| Hash-chained audit log | ✅ | SHA-256 chain, append-only, `/verify` integrity walk |
| GDPR erasure + grace-period purge | ✅ | Right-to-erasure, configurable retention |
| Data export | ✅ | Per-user export bundle |
| Data retention auto-purge | ✅ | Background worker, tenant-configured period |
| SOC 2 / ISO 27001 / GDPR evidence | ✅ | Admin → Compliance dashboard |
| Multi-currency billing (ISO-4217) | ✅ | Any currency code |
| Card payments — Stripe (international) | ✅ | One-time-per-period checkout, webhook-verified |
| Card payments — Razorpay (India) | ✅ | INR flows, webhook-verified (env-gated) |

</details>

<details>
<summary><b>🟡 Pending (code done; external work remains)</b></summary>

| Item | Status | What's left |
|:---|:---:|:---|
| AWS KMS BYOK | 🟡 | `KeyProvider` interface ready — needs a real KMS key |
| OpenID conformance | 🟡 | Run the official test suite against a deployed instance |
| Email deliverability | 🟡 | SMTP wired — production needs SPF/DKIM/DMARC + bounce handling |
| RDS PITR / backups | 🟡 | Documented in runbook — enable in AWS console |
| i18n remaining screens | 🟡 | Scaffold + new screens + login done; ~70 older admin screens pending |
| WCAG 2.2 AA remaining | 🟡 | New screens + lint gate done; expanding to ~70 older screens |
| External penetration test | 🟡 | Scheduled before GA |
| Billing go-live | 🟡 | Internal model done — Stripe/Razorpay env keys needed |

</details>

<details>
<summary><b>⏳ Planned (not yet built)</b></summary>

| Item | Notes |
|:---|:---|
| CIBA grant (RFC 9449) | Client-Initiated Backchannel Auth for push-based flows |
| `<SignIn/>` / `<OrgSwitcher/>` SDK components | `<UserButton/>` already ships in `@qeetid/react` |
| Non-English locale catalogs | Scaffold and key flows done; catalogs TBD |
| Adaptive / risk-based MFA | Threat-scoring exists; adaptive rule engine pending |
| Managed-cloud infrastructure | Multi-region nodes, auto-scaling, managed offering |
| Kafka / NATS event streaming | Outbox exists; full streaming adapters planned |
| gRPC service definitions | REST-first today; `platform/api/grpc` planned |
| Quantum-ready signing | Hybrid PQC (ML-DSA) as NIST codepoints stabilise |

All planned packages and surfaces are tracked in [ROADMAP.md](./ROADMAP.md).

</details>

---

## Quickstart

### Prerequisites

| Tool | Version | Purpose |
|:---|:---|:---|
| Go | ≥ 1.25 | Backend binary |
| Node.js | ≥ 20.9 | Frontend build (`nvm use v22.20.0`) |
| pnpm | ≥ 9.15.4 | JS workspace |
| Docker + Compose | any | PostgreSQL (via `make db-up`) |
| golang-migrate CLI | any | Standalone migration runs |

### 1 · Install

```bash
make install              # go mod tidy + pnpm install
```

### 2 · Configure & start the database

```bash
cp .env.example .env      # review DB_URL, JWT_SECRET, etc.
make db-up                # Postgres on :5001  (deploy/environments/dev/docker-compose.yml)
make migrate-up           # apply all 62 migrations
make seed-reset           # (optional) demo workspaces + users + audit history
```

`make seed-reset` creates two demo workspaces pre-loaded with users, roles, groups, API keys, webhooks, SSO providers, and audit history. Sign in with **`owner@acme.test`** / **`Password123!`** — see [docs/onboarding/quickstart.md](./docs/onboarding/quickstart.md) for the full account list.

### 3 · Run

```bash
make dev                  # backend + all 3 frontend apps in parallel
```

| Make target | App | URL |
|:---|:---|:---|
| `make dev-backend` | Go API | http://localhost:4001 |
| `make dev-admin` | Admin console (Vite + TanStack) | http://localhost:3002 |
| `make dev-login` | Hosted login (Next.js) | http://localhost:3004 |
| `make dev-web` | Marketing site (Next.js) | http://localhost:3001 |

```bash
curl http://localhost:4001/healthz   # → {"status":"ok"}
make help                            # full target list
```

---

## SDKs

Five first-party SDKs authenticate via `Authorization: ApiKey` + ES256/JWKS verification. Pick your platform:

<details open>
<summary><b>TypeScript / React / Next.js</b></summary>

```bash
# Core SDK
npm install @qeetid/sdk

# React hooks + <UserButton/>
npm install @qeetid/react

# Next.js (HttpOnly sealed-cookie sessions + silent refresh)
npm install @qeetid/nextjs
```

```ts
// Verify a JWT from your own backend
import { QeetIDClient } from '@qeetid/sdk';

const client = new QeetIDClient({ baseUrl: 'https://id.qeet.in' });
const user = await client.auth.verifyToken(accessToken);
```

```tsx
// React — protect a route with a single hook
import { useSession, UserButton } from '@qeetid/react';

export function Navbar() {
  const { user } = useSession();
  return <UserButton />;   // sign-in / sign-out / profile, zero config
}
```

</details>

<details>
<summary><b>Go SDK</b></summary>

```bash
go get github.com/qeetgroup/qeet-id/sdk/go
```

```go
import qeetid "github.com/qeetgroup/qeet-id/sdk/go"

client := qeetid.New(qeetid.Config{BaseURL: "https://id.qeet.in"})
user, err := client.Auth.VerifyToken(ctx, token)
```

</details>

<details>
<summary><b>Python SDK</b></summary>

```bash
pip install qeetid
```

```python
from qeetid import QeetIDClient

client = QeetIDClient(base_url="https://id.qeet.in")
user = client.auth.verify_token(access_token)
```

</details>

<details>
<summary><b>Machine identities &amp; AI agents</b></summary>

```bash
# M2M — client_credentials grant
curl -X POST https://id.qeet.in/oauth/token \
  -d "grant_type=client_credentials&client_id=...&client_secret=...&scope=api:read"

# AI agent — request an ephemeral scoped token
curl -X POST https://id.qeet.in/v1/agents/token \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -d '{"agent_id":"agent_01","scopes":["data:read"],"ttl":"15m"}'

# MCP introspection — get actor_type / agent_id / act claim
curl -X POST https://id.qeet.in/oauth/introspect \
  -H "Authorization: Bearer $TOKEN"
# → { "actor_type": "agent", "agent_id": "agent_01", "act": { "sub": "..." } }
```

</details>

---

## Deployment

The backend ships as a **distroless nonroot** container; migrations ship as a **separate one-shot image** that runs before the app on every deploy.

```bash
# Build both images (context = repo root)
docker build -f deploy/base/docker/Dockerfile          -t qeet-id:dev .
docker build -f deploy/base/docker/Dockerfile.migrate  -t qeet-id-migrate:dev .

# Or use the helper
./deploy/base/docker/build.sh dev
```

| Path | Directory | Best for |
|:---|:---|:---|
| **Local dev** — Postgres only | [deploy/environments/dev/](./deploy/environments/dev/) | `make db-up` |
| **Test** — isolated test DB (:5002) | [deploy/environments/test/](./deploy/environments/test/) | CI / testcontainers |
| **Single host (prod-shaped)** | [deploy/environments/prod/compose/](./deploy/environments/prod/compose/) | VPS · bare-metal · Caddy TLS + Redis |
| **Kubernetes + kustomize** | [deploy/base/kubernetes/base/](./deploy/base/kubernetes/base/) + overlays | GitOps, low overhead |
| **Kubernetes + Helm** | [deploy/base/helm/qeet-id/](./deploy/base/helm/qeet-id/) + per-env `values.yaml` | Full Deployment/Service/Ingress/HPA/PDB + migration Job + ExternalSecrets |
| **AWS infrastructure** | [deploy/base/terraform/](./deploy/base/terraform/) + per-env `terraform.tfvars` | RDS · ECR · KMS CMK · Secrets Manager |
| **Observability stack** | [deploy/base/observability/](./deploy/base/observability/) | Prometheus · Grafana · OTel Collector |

Release images are cosign-signed with SBOM + provenance attestations:
`ghcr.io/qeetgroup/qeet-id` and `ghcr.io/qeetgroup/qeet-id-migrate`

Start with [deploy/runbooks/operations.md](./deploy/runbooks/operations.md).

---

## Testing & quality gates

Every push and PR runs the full gate in [CI](./.github/workflows/ci.yml); all gates are reproducible locally.

| Gate | Local command | What it enforces |
|:---|:---|:---|
| Unit tests + data-race detector | `make test-backend` | Correctness, no concurrent map writes |
| **Architecture fitness (R1/R2)** | _(part of go test)_ | Dependency-direction rules between bounded contexts |
| **OpenAPI 100% coverage** | _(part of go test)_ | Every mounted chi route exists in `api/openapi/` |
| **Coverage floor** | `make cover` | Unit coverage can't regress below the floor |
| Go lint | `make lint-go` | `golangci-lint` ([.golangci.yml](./.golangci.yml)) + `go vet` |
| Vulnerability scan | `govulncheck ./...` (CI) | Known CVEs in Go module graph |
| Secret scan | `gitleaks` (CI) | No committed credentials |
| OpenAPI spec lint | `spectral` (CI) | Spec hygiene across all 5 specs |
| Integration tests | `make test-integration` | Real Postgres via testcontainers (needs Docker) |
| API contract tests | `make test-api [FOLDER=Auth]` | Postman / Newman against a live backend |
| Frontend | `make test` · `make typecheck` · `make lint` | Turbo tests · `tsc --noEmit` · ESLint |

```bash
make test                # backend (go test ./...) + frontend (Turbo)
make cover               # unit coverage + enforce the regression floor
make cover-html          # open the HTML coverage report
make lint                # Go (golangci-lint) + frontend ESLint
make test-integration    # real Postgres, needs Docker
```

---

## Tech stack

<details open>
<summary><b>Backend</b></summary>

| Layer | Technology | Notes |
|:---|:---|:---|
| Language | Go 1.25 | Single module at repo root |
| Router | chi v5 | Composable middleware, clean `r.Route` nesting |
| Database driver | pgx v5 | Direct PostgreSQL; no ORM — hand-written SQL ([ADR-0003](./docs/adr/0003-postgresql-hand-written-sql.md)) |
| JWT signing | golang-jwt/jwt v5 | ES256, ECDSA P-256, JWKS, `kid` = RFC 7638 thumbprint, rotation grace window |
| Password hashing | golang.org/x/crypto | Argon2id, OWASP-recommended params |
| OTP / TOTP | in-house | RFC 6238, RFC 4226; HMAC-SHA1 |
| Secrets vault | AES-256-GCM | KeyProvider abstraction; AWS KMS for BYOK |
| Events | transactional outbox + DLQ | Business + audit + event in one `pgx.Tx` |
| Rate limiting | Redis (optional) | In-process shard-local fallback when `REDIS_URL` unset |
| Payments | Stripe + Razorpay | INR → Razorpay / else → Stripe; webhook signature-verified |
| Observability | Prometheus + OTel | `/metrics`, `/readyz`, `/healthz`, OTLP/HTTP tracing |

</details>

<details>
<summary><b>Frontend</b></summary>

| App | Framework | Key deps |
|:---|:---|:---|
| Admin console (`@qeetid/admin`) | Vite + React 19 | TanStack Router / Query / Form / Table, `@qeetrix/*` |
| Hosted login (`@qeetid/login`) | Next.js 16 + React 19 | i18next, `@qeetrix/*`, WCAG 2.2 AA |
| Website (`@qeetid/web`) | Next.js 16 + React 19 | MDX, `@qeetrix/*` |
| Design system | `@qeetrix/*` | Tailwind v4 + Base UI, Cal Sans + Geist Mono, brand orange `#F26D0E` |
| Workspace | pnpm 9.15.4 + Turborepo | Hoisted to repo root — no `backend/`/`frontend/` wrappers |

</details>

<details>
<summary><b>Database</b></summary>

| Schema | Owner context | Key tables |
|:---|:---|:---|
| `tenant` | identity/organizations | `tenants`, `tenant_branding`, `tenant_domains` |
| `user` | identity/users | `users`, `groups`, `group_members`, `invitations` |
| `auth` | access, federation | `credentials`, `passkey_credentials`, `webauthn_sessions`, `mfa_secrets`, `sessions`, `oidc_clients`, `saml_connections`, `api_keys`, `service_principals` |
| `rbac` | access/authorization | `roles`, `permissions`, `user_roles`, `role_permissions`, `relation_tuples` |
| `audit` | operations/audit | `audit_events` (SHA-256 hash-chained), `log_sinks` |
| `platform` | operations, developer | `outbox`, `outbox_dlq`, `notifications`, `billing_*`, `agents`, `vc_credentials`, `secrets` |

62 migration pairs (0001–0062) in [`platform/database/migrations/`](./platform/database/migrations/). Never edit an applied migration — always add a new pair.

</details>

---

## Repository layout

```
qeet-id/
├── cmd/                    Go entrypoints: server · worker · scheduler · migrate · seed
├── domains/                business logic by bounded context
│   ├── identity/           users · organizations (+branding) · groups · invitations · verification · domains
│   ├── access/             authentication · authorization/{rbac,rebac,policy,authpolicy} · mfa · passkeys
│   │                       recovery · risk/ipallow · threat-detection/{threat,bot}
│   ├── federation/         oidc · saml · scim · ldap · social
│   ├── developer/          api-keys · service-accounts · credentials/{secrets,vc} · auth-hooks · webhooks · agents
│   └── operations/         audit · analytics · notifications · email-templates · retention · compliance · billing · siem
├── platform/               shared infra by concern
│   ├── api/                rest (chi router · httpx · errs · paging) · openapi
│   ├── database/           postgres (pool · dbutil · pgxerr) · migrations (62 SQL pairs)
│   ├── security/           tokens (ES256/JWKS) · encryption · hibp
│   ├── observability/      logging · metrics · tracing · health · buildinfo
│   ├── events/             outbox (+ DLQ)
│   └── cache/ config/ messaging/
├── apps/                   console (admin · Vite) · website (Next.js) · login (Next.js)
├── packages/               shared JS config (qeetid-tsconfig · qeetid-eslint)
├── sdk/                    js/{sdk,nextjs,react} · go · python
├── api/                    openapi/ (5 bounded-context specs) · postman/ (Newman runner)
├── tests/                  architecture · integration · e2e · performance · security · fixtures
├── deploy/                 base/{docker,helm,kubernetes,terraform,observability}
│                           + environments/{dev,test,stage,prod} + runbooks
├── tools/                  codegen · migration-tools · openapi-split · benchmarks · scripts
├── docs/                   architecture (7) · adr (15) · api · security · compliance · onboarding
├── Makefile                root targets — Go module + pnpm/Turbo workspace
└── ROADMAP.md              planned packages & surfaces (not empty stubs)
```

---

## Documentation

| Topic | Location |
|:---|:---|
| Architecture deep-dives (7 docs) | [docs/architecture/](./docs/architecture/) |
| Architecture Decision Records (15) | [docs/adr/](./docs/adr/) |
| Security model & cryptography | [docs/security/](./docs/security/) |
| Compliance (GDPR, data isolation, VC) | [docs/compliance/](./docs/compliance/) |
| Quickstart & onboarding guide | [docs/onboarding/quickstart.md](./docs/onboarding/quickstart.md) |
| Adding a new domain — contributor walkthrough | [docs/onboarding/adding-a-domain.md](./docs/onboarding/adding-a-domain.md) |
| Conventions & dev workflow | [docs/onboarding/development-workflow.md](./docs/onboarding/development-workflow.md) |
| Operational runbooks | [deploy/runbooks/](./deploy/runbooks/) — operations · secrets · scaling · DR |
| API spec (OpenAPI 3.1, 5 specs) | [api/openapi/](./api/openapi/) · merge: `go run ./tools/openapi-split merge` |
| Postman collection (Newman) | [api/postman/](./api/postman/) |
| Runnable example integrations | [examples/](./examples/) — Next.js server flow · React SPA PKCE |
| End-user product docs | [docs.qeet.in](https://docs.qeet.in) (standalone `qeet-docs` site) |
| For AI assistants | [CLAUDE.md](./CLAUDE.md) — layout map, commands, gotchas |
| Planned work | [ROADMAP.md](./ROADMAP.md) |

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Bug reports and feature requests use the templates in [.github/ISSUE_TEMPLATE/](./.github/ISSUE_TEMPLATE/). New backend code must follow the conventions in [docs/onboarding/development-workflow.md](./docs/onboarding/development-workflow.md) and the bounded-context patterns in [docs/architecture/](./docs/architecture/).

## Security

Found a vulnerability? **Do not open a public issue.** Follow the coordinated-disclosure process in [SECURITY.md](./SECURITY.md). Live secrets and `*.pem` keys must never be committed — CI runs `gitleaks` on every push.

## License

[MIT](./LICENSE) © Qeet Group.
