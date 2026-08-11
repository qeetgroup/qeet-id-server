<div align="center">

# 🔐 Qeet ID

### Passkeys-first Identity & Access Platform

**A self-hostable Auth0 / Okta alternative for modern applications and enterprises.**

Own the identity layer, keep PostgreSQL as the source of truth, and deploy one Go API artifact.

[![CI](https://github.com/qeetgroup/qeet-id-server/actions/workflows/ci.yml/badge.svg)](https://github.com/qeetgroup/qeet-id-server/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1-6BA539?logo=openapiinitiative&logoColor=white)](./api/openapi/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](./Dockerfile)
[![License](https://img.shields.io/badge/License-MIT-F6C344.svg)](./LICENSE)

**[Website](https://id.qeet.in) &middot; [Documentation](https://docs.qeet.in) &middot; [API](./api/openapi/) &middot; [GitHub](https://github.com/qeetgroup/qeet-id-server) &middot; [Contributing](./CONTRIBUTING.md)**

</div>

---

## 🧭 What is Qeet ID?

Qeet ID is an open-source Identity and Access Management platform that combines authentication, authorization, enterprise federation, user lifecycle management, and machine identity behind one API. It is built for teams that need standards-based identity without handing control of users, credentials, and policy to a hosted identity vendor.

The backend is a Go modular monolith backed by PostgreSQL. Five bounded contexts share a small platform layer, while a composition root wires HTTP routes, policy enforcement, persistence, event delivery, and background work. The default API process runs as a single binary and embeds its continuous workers; dedicated worker and scheduler entrypoints are available when those workloads need to scale independently.

> [!IMPORTANT]
> Qeet ID is currently **pre-1.0**. Review the [changelog](./CHANGELOG.md) and [security policy](./SECURITY.md) before operating it in production.

## ✨ Key Features

| Area | Implemented capabilities |
| :--- | :--- |
| **Authentication** | WebAuthn/passkeys, passwords, email verification, magic links, MFA, session management |
| **Authorization** | RBAC, ABAC, ReBAC, tenant policies, explainable permission checks, AuthZEN evaluation API |
| **Identity** | Multi-tenant organizations, users, groups, invitations, imports, branding, email templates, DNS domain verification |
| **Federation** | OAuth 2.0/OpenID Connect, SAML 2.0, SCIM 2.0, LDAP/Active Directory, social login |
| **Developer & machine identity** | API keys, service principals, agent identities, verifiable credentials, secrets and token vaults, auth hooks, signed webhooks |
| **Operations** | Tamper-evident audit logs, analytics, GDPR workflows, retention jobs, SIEM sinks, notifications, rate limits, billing and entitlements |

Some capabilities are entitlement-gated, and external services such as social providers, SMS, email, Redis, NATS, KMS, and payment processors require their own configuration.

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
    Workers["Continuous workers<br/>embedded or cmd/worker"]
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
- **PostgreSQL as the source of truth** with tenant-scoped persistence.
- **Single API artifact** with embedded workers and separate worker/scheduler entrypoints.
- **Transactional outbox** for durable events, with optional NATS fan-out.

## 🧰 Technology Stack

| Layer | Technology |
| :--- | :--- |
| Language | Go 1.25 |
| HTTP | chi v5, REST, OpenAPI 3.1 |
| Database | PostgreSQL 16, pgx v5, SQL/sqlc |
| Authentication | WebAuthn/FIDO2, OAuth 2.0, OpenID Connect, SAML 2.0, SCIM 2.0 |
| Tokens & cryptography | ES256 JWT, JWKS, Argon2id, AES-GCM, HMAC-SHA256 |
| Events | PostgreSQL transactional outbox, optional NATS |
| Rate limiting | In-process token buckets, optional Redis |
| Observability | Prometheus metrics, OpenTelemetry tracing, structured logs |
| Testing | Go test, Testcontainers, k6, CodeQL, govulncheck |
| Container | Multi-stage Docker build, distroless non-root runtime |

## 🚀 Quick Start

### Requirements

- Go 1.25 or newer
- Docker with Docker Compose
- Make and OpenSSL

### Clone and configure

```bash
git clone https://github.com/qeetgroup/qeet-id-server.git
cd qeet-id-server
make install
cp .env.example .env
```

Replace the `<password>` placeholder in `.env` with the local Docker Compose password:

```dotenv
DB_URL=postgres://postgres:password@localhost:5001/qeet_id?sslmode=disable
```

The remaining development defaults are ready for local use. Social login, SMS, external email, Redis, KMS, and payment integrations stay disabled or use development behavior until configured.

### Start the database and API

```bash
make db-up
make dev
```

`make db-up` starts PostgreSQL, NATS, and Mailpit. `make dev` generates persistent local JWT/SAML signing material under `.secrets/`, applies pending database migrations, and starts the API on `http://localhost:4001`.

### Check health

```bash
curl http://localhost:4001/healthz
curl http://localhost:4001/readyz
```

Prometheus metrics are available at `http://localhost:4001/metrics`. Mailpit runs at `http://localhost:8025`; to capture email instead of logging it, set `SMTP_HOST=localhost` and `SMTP_PORT=1025` in `.env`.

### Load demo data (optional)

After the API has completed its first startup, run in another shell:

```bash
make seed
```

The seed is idempotent and creates fictional development data.

> The API applies migrations automatically. Manual `make migrate-up` and `make migrate-down` targets are also available when the `migrate` CLI is installed.

## 🛠️ Development

| Command | Purpose |
| :--- | :--- |
| `make build` | Compile the API to `bin/qeet-id` |
| `make test` | Run unit and architecture fitness tests |
| `make test-integration` | Run integration flows against Testcontainers PostgreSQL; Docker required |
| `make lint` | Run `go vet ./...` locally |
| `make bench` | Run k6 discovery and authorization performance checks against a running, seeded API |
| `make db-reset` | Recreate the local database volume |
| `make seed-reset` | Destructively reset and reseed development data |

CI adds race detection, diff-scoped golangci-lint, integration tests, `govulncheck`, and CodeQL analysis.

## 📚 API & Documentation

- [OpenAPI contracts](./api/openapi/) are split into access, identity, federation, developer, and operations specifications.
- [Postman collection and environment](./api/postman/) provide an importable API workspace.
- [Documentation](https://docs.qeet.in) covers product concepts and integration guidance.
- OIDC metadata is served from `/.well-known/openid-configuration`; public signing keys are served from `/.well-known/jwks.json`.

## 📦 Deployment

The included [Dockerfile](./Dockerfile) builds the API as a distroless, non-root image. [Docker Compose](./docker-compose.yml) is intentionally a local dependency stack; it does not package the application.

The repository's [deployment workflow](./.github/workflows/deploy.yml) builds and publishes the image to AWS ECR, then rolls the configured host through AWS Systems Manager. Production configuration must provide durable signing keys, explicit origins, TLS termination, and external secrets. Helm, Kubernetes, and Terraform assets are not shipped in this repository.

## 🛡️ Security

Qeet ID validates production configuration at startup and refuses development-only CSRF, trusted-header, origin, URL, or ephemeral-key settings outside the development environment.

- Passwords and credential secrets use Argon2id, with transparent verification and upgrade of legacy bcrypt hashes.
- Passkeys use `go-webauthn`; access and ID tokens use ES256 with `kid`-based JWKS verification and retired-key support.
- The secrets vault uses AES-GCM with a static key or AWS KMS-backed data-key provider.
- Tenant routes are checked against the authenticated principal and persistence queries carry tenant scope.
- Audit events are transactionally recorded in per-tenant SHA-256 hash chains; webhooks use HMAC-SHA256 signatures.
- CSRF/origin checks, security headers, login lockout, and per-IP/principal/tenant rate limits provide request-layer defenses.

Report vulnerabilities privately according to [SECURITY.md](./SECURITY.md). Please do not open a public issue for a suspected vulnerability.

## 🤝 Contributing

Contributions are welcome. Before opening a pull request against `develop`:

```bash
make test
make lint
```

Behavior changes need tests. API changes must update [api/openapi](./api/openapi/), and schema changes must add immutable `.up.sql` and `.down.sql` migrations. See [CONTRIBUTING.md](./CONTRIBUTING.md) and the [Code of Conduct](./CODE_OF_CONDUCT.md) for the complete workflow.

## 📄 License

Qeet ID is available under the [MIT License](./LICENSE).

---

<div align="center">

**🔐 Identity infrastructure you control.**

[Qeet ID](https://id.qeet.in) &middot; Open Source &middot; Self-Hostable &middot; Developer First

</div>
