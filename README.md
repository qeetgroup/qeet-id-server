<div align="center">

# 🔐 Qeet ID

### Passkeys-first Identity & Access Platform

**Sign-in, access control, federation and machine identity for modern applications and enterprises, behind one API.**

Passkeys first, standards throughout (OpenID Connect, SAML, SCIM, WebAuthn), PostgreSQL as the source of truth.

[![CI](https://github.com/qeetgroup/qeet-id-server/actions/workflows/ci.yml/badge.svg)](https://github.com/qeetgroup/qeet-id-server/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1-6BA539?logo=openapiinitiative&logoColor=white)](./api/openapi/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](./Dockerfile)
[![Organization isolation](https://img.shields.io/badge/organization%20isolation-row--level%20security-7C3AED?logo=postgresql&logoColor=white)](./docs/llm/boundaries.md)

**[Website](https://id.qeet.in) &middot; [Documentation](https://docs.qeet.in) &middot; [API](./api/openapi/)**

</div>

---

## 🧭 What is Qeet ID?

Qeet ID is an Identity and Access Management platform that combines authentication, authorization, enterprise federation, user lifecycle management, and machine identity behind one API. It gives product teams standards-based identity, with users, credentials and policy in one place, instead of stitching sign-in, authorization and federation together from separate services.

The backend is a Go modular monolith backed by PostgreSQL. Five bounded contexts share a small platform layer, while a composition root wires HTTP routes, policy enforcement, persistence, event delivery, and background work. The API process runs as a single binary and runs its continuous workers itself; a scheduler entrypoint can run the maintenance jobs on their own.

## ✨ Key Features

| Area | Implemented capabilities |
| :--- | :--- |
| **Authentication** | WebAuthn/passkeys, passwords, email verification, magic links, MFA, session management |
| **Authorization** | RBAC, ABAC, ReBAC, organization policies, explainable permission checks, AuthZEN evaluation API |
| **Identity** | Organizations, users, groups, invitations, imports, branding, email templates, DNS domain verification |
| **Federation** | OAuth 2.0/OpenID Connect, SAML 2.0, SCIM 2.0, LDAP/Active Directory, social login |
| **Developer & machine identity** | API keys, service principals, agent identities, verifiable credentials, secrets and token vaults, auth hooks, signed webhooks |
| **Operations** | Tamper-evident audit logs, analytics, GDPR workflows, retention jobs, SIEM sinks, notifications, rate limits, billing and entitlements |
| **AI** | Admin-console copilot backed by Anthropic or any OpenAI-compatible provider, plus a tool manifest for agent integrations |

Some capabilities are entitlement-gated, and external services such as social providers, SMS, email, Redis, NATS, KMS, AI providers, and payment processors require their own configuration.

### 🌐 Supported Standards

`WebAuthn` &middot; `OAuth 2.0` &middot; `OpenID Connect` &middot; `SAML 2.0` &middot; `SCIM 2.0` &middot; `AuthZEN` &middot; `JWT` &middot; `JWKS`

## 🏗️ Architecture

Qeet ID keeps domain boundaries explicit while retaining transactional consistency and a small operational footprint.

```mermaid
flowchart TB
    Clients["Applications / SDKs / CLI"]
    API["API"]

    subgraph Domains["Bounded contexts"]
        Access["access"]
        Identity["identity"]
        Federation["federation"]
        Developer["developer"]
        Operations["operations"]
    end

    Platform["platform · config · crypto · events · observability"]
    Workers["Continuous workers<br/>inside the API"]
    Scheduler["Maintenance scheduler<br/>cmd/scheduler"]
    Postgres[(PostgreSQL)]
    NATS["NATS · optional event fan-out"]
    Redis["Redis · optional shared rate limits"]

    Clients --> API
    API --> Access
    API --> Identity
    API --> Federation
    API --> Developer
    API --> Operations
    Access --> Platform
    Identity --> Platform
    Federation --> Platform
    Developer --> Platform
    Operations --> Platform
    Platform --> Postgres
    API --> Workers --> Postgres
    Scheduler --> Postgres
    Workers -. publish .-> NATS
    API -. distributed limits .-> Redis
```

### Architecture Principles

- **Modular monolith** with explicit boundaries across five domain contexts.
- **PostgreSQL as the source of truth** with organization-scoped persistence.
- **Single API artifact** with embedded workers and a separate scheduler entrypoint.
- **Transactional outbox** for durable events, with optional NATS fan-out.

### Repository layout

```text
cmd/          api · scheduler · seed   (three entrypoints)
internal/
  bootstrap/  composition root — every dependency, route and worker is wired here
  access/     authentication · authorization · mfa · passkeys · recovery · risk · threat
  identity/   organization · users · groups · invitations · verification · domainverify
  federation/ oidc · saml · scim · ldap · social · adminportal
  developer/  api-keys · principal · agents · webhooks · auth-hooks · credentials
  operations/ audit · billing · analytics · gdpr · retention · siem · notifications · qeetai · …
  platform/   config · crypto · database · http · events · jobs · messaging · observability · ai · cache
api/          openapi (five specs) · qeetai (AI tool manifest)
tests/        architecture · integration · performance · security · fixtures
docs/llm/     architecture documentation for coding agents
```

Two boundary rules, enforced by lint (`depguard`):
`internal/platform/*` must not import a bounded context, `cmd/*` or `internal/bootstrap`; and a
bounded context must not import `cmd/*` or `internal/bootstrap`.

## 🧰 Technology Stack

| Layer | Technology |
| :--- | :--- |
| Language | Go 1.27 |
| HTTP | chi v5, REST, OpenAPI 3.1 |
| Database | PostgreSQL 16, pgx v5, SQL/sqlc |
| Authentication | WebAuthn/FIDO2, OAuth 2.0, OpenID Connect, SAML 2.0, SCIM 2.0 |
| Tokens & cryptography | ES256 or RS256 JWT, JWKS, Argon2id, AES-GCM, HMAC-SHA256 |
| Events | PostgreSQL transactional outbox, optional NATS |
| Rate limiting | In-process token buckets, optional Redis |
| Observability | Prometheus metrics, OpenTelemetry tracing, structured logs |
| Testing | Go test, Testcontainers, gosec, govulncheck |
| Container | Multi-stage Docker build, distroless non-root runtime |

## 🚀 Quick start

**You need:** Go 1.27 or newer (it fetches the pinned toolchain, go1.27.4, itself) &middot; Docker (with Compose) &middot; `make` &middot; `openssl`

```bash
git clone https://github.com/qeetgroup/qeet-id-server.git
cd qeet-id-server
make install

cp .env.example .env
# Edit DB_URL in .env to use the local Compose password:
# postgres://postgres:password@localhost:5001/qeet_id?sslmode=disable

make db-up    # postgres :5001 · nats :4222 · mailpit :8025
make dev      # generates .secrets/, applies migrations, serves http://localhost:4001
```

`make dev` runs in the foreground. Open a second shell and check it came up:

```bash
curl localhost:4001/healthz
curl localhost:4001/readyz
make seed     # demo organizations, users, API keys, OIDC clients
```

That is the whole setup. Everything else on this page is reference.

### What just happened

- **`make install`** is `go mod download`. Nothing more.
- **`.env`** carries your local configuration. The `<password>` placeholder must become `password`
  to match the Postgres container in [docker-compose.yml](./docker-compose.yml); edit `DB_URL` as
  shown in the quick-start comment above. Every other development default works as shipped.
- **`make db-up`** starts PostgreSQL 16 on `:5001`, NATS on `:4222` and Mailpit on `:8025`. The
  application itself runs on your host, not in Compose.
- **`make dev`** first runs `make dev-secrets`, generating a persistent ES256 JWT signing key and a
  SAML IdP key/certificate pair into `.secrets/` (gitignored, idempotent — it skips whatever already
  exists). It then starts the API, which **applies database migrations on startup**. There is no
  separate migrate step to remember.
- **`make seed`** loads fictional, production-shaped demo data into an empty database in about a
  minute, so every console and hosted-login screen has something to show:
  - Ten organizations: Qeet Group, whose own products (Qeet Pay, Qeet People, Qeet Notify, Qeet Logs,
    Qeet AI and the Qeet Circle staff console) are its applications, and customers on every plan
    and stage (Enterprise on Okta or Microsoft Entra with SCIM, a Pro trial, an unpaid Starter, a
    cancelled one, a brand-new Free one).
  - About 300 people with roles, teams and managers, and the organizations' SSO (SAML and OpenID
    Connect, with group mappings and break-glass members), SCIM, LDAP, social sign-in (Google,
    Microsoft, GitHub, Apple, Discord, Facebook and X), applications, API keys, webhooks, agents,
    policies, access requests and compliance owners and audits.
  - Sign-ins, sessions, lockouts and the audit trail they leave, all written just now through the
    server's own services: the seed runs no SQL and dates nothing back.

  It needs `SECRETS_KEY` set, so the API can read what it encrypts. **It prints what you need to
  test, so read its output**: test accounts for each role, TOTP secrets, hosted sign-in URLs for each
  organization's app, API keys and invitation links. `make seed-reset` recreates the database first.
  The kit's DEV runs the same seed with `bash macos/dev/seed.sh`. To add a feature to it, see
  [docs/llm/workflows.md](docs/llm/workflows.md#add-a-feature-to-the-demo-data).

### Useful endpoints

| URL | What |
| :--- | :--- |
| `http://localhost:4001/healthz` &middot; `/readyz` | Liveness and readiness |
| `http://localhost:4001/metrics` | Prometheus scrape endpoint |
| `http://localhost:4001/.well-known/openid-configuration` | OIDC discovery |
| `http://localhost:4001/.well-known/jwks.json` | Public signing keys |
| `http://localhost:8025` | Mailpit — read every message the app sends |

Mailpit only catches mail once you point the app at it. `.env.example` ships `SMTP_HOST` blank,
which makes the app **log** emails instead of sending them. To capture them in Mailpit, set
`SMTP_HOST=localhost` and `SMTP_PORT=1025` in `.env` and restart.

### If something goes wrong

| Symptom | Cause |
| :--- | :--- |
| Connection refused or password auth failure at startup | `<password>` is still literal in `.env` |
| Your `.env` edits appear to be ignored | You ran `go run ./cmd/api` directly. **Only the `Makefile` loads `.env`** — nothing in the Go code does, so a direct `go run` silently uses built-in defaults. Use `make dev` |
| `address already in use` on `:4001` | `make kill` frees the port |
| A passkey ceremony fails with `passkey.attestation_invalid` | The browser origin is missing from `WEBAUTHN_RP_ORIGINS`. CORS being correct is not enough |
| You want a clean slate | `make seed-reset` (drops the volume, then seeds), or `make db-reset`, then `make dev` |
| `database schema … isn't recorded as built from the migration files this build carries` at startup | The database was migrated by an earlier build, from an earlier copy of the migrations, or by the `migrate` CLI. `make db-reset`, then `make dev`. For a migration of your own that isn't merged yet: `make migrate-down`, then `make dev` |

## 🛠️ Development

Every target in the [Makefile](./Makefile) — there are no others.

| Command | Purpose |
| :--- | :--- |
| `make install` | `go mod download` |
| `make dev` | Run the API on `:4001` with persistent keys from `.secrets/` |
| `make dev-secrets` | Generate the local JWT and SAML key material only |
| `make build` | Compile the API to `bin/qeet-id` |
| `make test` | Run the unit tests |
| `make test-db` | Run the database tests against PostgreSQL; Docker required |
| `make lint` | Run `go vet` and `golangci-lint` as CI does |
| `make sqlc` / `sqlc-check` | Regenerate `dbgen/` from `queries.sql`, or check it is up to date |
| `make openapi` / `openapi-check` | Build the five API documents from `api/openapi/src/`, or check they are up to date; Bun required |
| `make db-up` / `db-down` | Start or stop PostgreSQL, NATS and Mailpit |
| `make db-reset` | Recreate the local database volume |
| `make migrate-down` | Roll one migration back, to try its down file; needs the `migrate` CLI. The server applies migrations at start |
| `make seed` / `seed-reset` | Load development demo data into an empty database, or recreate the database and load it |
| `make kill` | Free a stuck `:4001` |

Run a single test with `go test ./internal/access/authentication/... -run TestName`.

Before opening a pull request:

```bash
go build ./... && go test -race ./... && make lint
```

Before a push, `make ci` runs the unit and database tests, checks generated SQL, and runs
`govulncheck` and `gosec`. The hosted Verify workflow runs build, vet, lint, vulnerability and secret
scans, and the API contract checks (`make openapi-check` and the OpenAPI tests); it does not run the
other Go test suites or sqlc/gosec gates.

## 📚 API & Documentation

- [api/openapi/](./api/openapi/) holds five self-contained, bounded-context OpenAPI 3.1 documents —
  `auth.yaml` (access), `management.yaml` (identity), `federation.yaml`, `developer.yaml` and
  `operations.yaml`. There is no monolithic `openapi.yaml`. They are generated from the sources in
  `api/openapi/src/` (one file per path) by `make openapi`; edit the sources, not the documents.
- **A route added without a matching specification entry fails the local test gate** —
  `internal/bootstrap/openapi_coverage_test.go` asserts every mounted route is documented. Update the
  spec in the same change as the route and run `make ci` before pushing.
- [Documentation](https://docs.qeet.in) covers product concepts and integration guidance.

## 🧠 Working in this repository

| File | For |
| :--- | :--- |
| [AGENTS.md](./AGENTS.md) | The rules, the commands, and what CI enforces — start here |
| [docs/llm/architecture-map.md](./docs/llm/architecture-map.md) | "Where is X?" answered in one hop |
| [docs/llm/context.md](./docs/llm/context.md) | How the backend actually works |
| [qeet-repo.yml](./qeet-repo.yml) | Machine-readable repository identity |

Three things reliably surprise newcomers:

1. **Organization scope comes from the authenticated principal**, via `httpx.RequireOrganization(r)` — never
   from a path, body, query or header. Row-level security backs it up on organization-owned tables
   in organization-administration requests only; elsewhere a missing `WHERE organization_id = $1` is a cross-organization data
   exposure rather than an error the database catches.
2. **Migrations are immutable once applied.** Add a new `.up.sql`/`.down.sql` pair; never edit an
   existing one.
3. **Two behaviours look like bugs and are deliberate**, each with an ADR: the rate limiter fails
   *open* when its store errors, and auth hooks default to *fail-open*.

## 📦 Deployment

The included [Dockerfile](./Dockerfile) builds the API as a distroless, non-root image.
[Docker Compose](./docker-compose.yml) is intentionally a local dependency stack; it does not
package the application.

Releases are monthly and named after the month they ship: `release/2027.1.0` is cut from
`develop`, testers run its [candidate image](./.github/workflows/candidate.yml), and merging it into
`main` releases `v2027.1.0`; urgent fixes are `hotfix/2027.1.1`. The
[deployment workflow](./.github/workflows/deploy.yml) copies that tested image to AWS ECR without
rebuilding it, rolls the configured host through AWS Systems Manager, then tags and releases the
version only after the roll succeeds. Production configuration must provide
durable signing keys, explicit origins, TLS termination, and external secrets. Helm, Kubernetes, and
Terraform assets are not shipped in this repository.

## 🛡️ Security

Qeet ID validates production configuration at startup and refuses development-only CSRF,
trusted-header, origin, URL, sandbox-payment, or ephemeral-key settings outside the development
environment.

- Passwords and MFA recovery codes use Argon2id; random machine secrets (API keys, service-principal, agent and OAuth client secrets) are stored as their SHA-256.
- Passkeys use `go-webauthn`; access and ID tokens are signed ES256 (an EC P-256 key) or RS256 (an RSA key), with `kid`-based JWKS verification and retired-key support.
- The secrets vault uses AES-GCM with a static key or AWS KMS-backed data-key provider. Every stored value names the data key that sealed it, so the key can be rotated: previous keys stay readable (`SECRETS_PREVIOUS_KEYS`) while a background job moves stored values to the current one (steps on `SecretsKey` in `internal/platform/config/config.go`).
- Organization routes are checked against the authenticated principal and persistence queries carry organization scope.
- Audit events are transactionally recorded in per-organization SHA-256 hash chains; webhooks use HMAC-SHA256 signatures.
- CSRF/origin checks, security headers, login lockout, and per-IP/principal/organization rate limits provide request-layer defenses.

Report vulnerabilities privately according to [SECURITY.md](./SECURITY.md). Please do not open a public issue for a suspected vulnerability.

## 🤝 Contributing

Pull requests target `develop`. Behavior changes need tests, API changes must update
[api/openapi](./api/openapi/), and schema changes must add immutable `.up.sql` and `.down.sql`
migrations. [AGENTS.md](./AGENTS.md) is the source of truth for repository rules and what CI
enforces.

---

<div align="center">

**🔐 Passkeys-first identity and access.**

[Qeet ID](https://id.qeet.in) &middot; Standards First &middot; Developer First

</div>
