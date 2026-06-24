# Roadmap — planned structure

This file tracks **planned** packages and surfaces that do not exist yet. They
were previously empty placeholder directories; we removed them so the tree only
contains real code, and record the intent here instead. Create the directory the
day code lands in it.

## Platform (infrastructure)

| Planned package | Purpose | Notes |
|---|---|---|
| `platform/api/grpc` | gRPC server setup, interceptors | Pairs with `api/protobuf/`. REST-first today. |
| `platform/api/openapi` | OpenAPI loading/validation helpers | Specs live in `api/openapi/`; coverage guard in `platform/api/rest`. |
| `platform/cache/memory` | In-process LRU/TTL cache | e.g. WebAuthn challenge sessions, TOTP replay window. |
| `platform/database/repositories` | Shared repository base types/helpers | Generic paginator, `Transactor`, bulk insert. |
| `platform/events/publisher` | Unified `Publisher` interface | Over outbox/Kafka/NATS. Outbox exists at `platform/events/outbox`. |
| `platform/events/subscriber` | In-process/durable event consumers | Fan-out bus. |
| `platform/events/schemas` | Canonical event schema definitions | Shared producer/consumer types. |
| `platform/messaging/kafka` | Kafka producer/consumer wrappers | For cross-service streaming. |
| `platform/messaging/nats` | NATS JetStream wrappers | Lightweight alternative to Kafka. |
| `platform/messaging/queues` | Generic async job queue | DB-backed (outbox) or in-process. |
| `platform/observability/alerts` | Prometheus alert-rule generation | Runtime rules live in `deploy/base/observability/`. |
| `platform/observability/dashboards` | Grafana dashboard generation | Runtime dashboards in `deploy/base/observability/`. |
| `platform/scheduler` | Cron-style maintenance scheduler | Session cleanup, retention purge, outbox sweep. |
| `platform/security/kms` | AWS KMS / envelope-encryption client | Used when `SECRETS_PROVIDER=aws-kms`. |
| `platform/security/secrets` | Promoted per-tenant vault client | Real impl today: `domains/developer/credentials/secrets`. |
| `platform/security/signing` | Unified `Signer`/`Verifier` | Webhook HMAC, SAML XML-Dsig, JWT today live in their packages. |
| `platform/storage` | Object/blob storage client | S3-compatible: avatars, audit exports. |
| `platform/tenancy` | Tenancy primitives + ctx propagation | Today enforced via raw `tenant_id` per query. |
| `platform/testing` | Lightweight unit-test helpers | Integration helpers live in `tests/fixtures/`. |

## Domains (business contexts)

| Planned domain | Context | Purpose |
|---|---|---|
| `access/sessions` | access | First-class session entity (today folded into auth). |
| `access/passwords` | access | Password lifecycle/history as its own concern. |
| `access/devices` | access | Device registry. |
| `access/trusted-devices` | access | Remembered/trusted device management. |
| `access/lockout` | access | Lockout as a dedicated package (today in auth + migration 0041). |
| `identity/memberships` | identity | Membership entity distinct from RBAC user_roles. |
| `identity/profiles` | identity | Extended user profile data. |
| `federation/oauth2` | federation | Generic OAuth2 (beyond OIDC/social). |
| `federation/provisioning` | federation | Provisioning beyond SCIM. |
| `developer/bots` | developer | Bot identities distinct from agents. |
| `developer/integrations` | developer | Third-party integration registry. |
| `operations/subscriptions` | operations | Subscriptions split from billing. |
| `operations/invoices` | operations | Invoices split from billing. |
| `operations/exports` | operations | Data-export jobs (GDPR/analytics). |
| `operations/log-streaming` | operations | Real-time log streaming (SIEM is `operations/siem`). |

## API surfaces

| Planned | Purpose |
|---|---|
| `api/protobuf/` | gRPC `.proto` service definitions (REST-first today). |
| `api/contracts/` | Consumer-driven contract tests (Pact-style) for SDKs/frontends. |
