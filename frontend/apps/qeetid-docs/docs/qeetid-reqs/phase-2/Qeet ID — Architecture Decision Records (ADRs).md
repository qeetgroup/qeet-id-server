# Qeet ID — Architecture Decision Records (ADRs)

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Architecture Decision Records (ADRs) |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Solution Architect (running log) |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document is the running log of Architecture Decision Records (ADRs) for Qeet ID. An ADR captures a single architecturally significant decision: the context, the choice, the rationale, the alternatives considered, and the consequences accepted.

The ADR practice is mandated by NFR AR-07. Every non-trivial architectural decision lives here. Decisions that follow earlier-stated principles (HLSA §3) without deviation do not require an ADR; decisions that introduce or deviate from a principle do.

Each ADR has a stable ID (`ADR-NNN`). Once an ADR is **Accepted**, its content is immutable except via a Superseding ADR. An ADR may be in one of the following states:

| Status | Meaning |
| --- | --- |
| Proposed | Open; awaiting review and sign-off |
| Accepted | Decision is in effect |
| Superseded | Replaced by a later ADR — pointer to the superseder included |
| Deprecated | No longer applicable; not yet replaced; retained for history |

The audience is everyone — every engineer, every architect, every operator, every auditor. ADRs are public-internal: shareable with auditors during SOC 2, with new joiners during onboarding, with any team wanting to understand "why is this the way it is."

This document depends on every other Phase 2 architecture document for the context of each decision.

---

### 3. ADR Template

```
ADR-XXX: [Decision Title]

Status:        Proposed | Accepted | Superseded by ADR-YYY | Deprecated
Date:          YYYY-MM-DD
Deciders:      [Names / Roles]
Tags:          [comma-separated taxonomy]

Context
-------
[Why this decision needs to be made — the constraints, the forcing function, the
relevant Phase 1 baseline references.]

Decision
--------
[What was decided in clear, declarative language.]

Consequences
------------
Positive:
- [...]
Negative / accepted trade-offs:
- [...]

Alternatives Considered
-----------------------
[Each rejected option, with reason for rejection.]

References
----------
- [Phase 1 baseline document or section]
- [Phase 2 architecture document or section]
- [External standard / RFC if applicable]
```

---

### 4. Seed ADRs

These 20 ADRs cover the architecturally significant decisions Phase 2 has made (or proposed). Subsequent ADRs (ADR-021 onward) are added by the team during Phase 2 and beyond as decisions surface.

---

## ADR-001: Microservices over Monolith

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** CTO, Solution Architect, Backend Lead
**Tags:** architecture, services, mvp

### Context

Phase 1 stakeholder findings recorded the CTO's mandate: "Microservices architecture from Day 1. Monolith is not on the table." The platform's scale targets — 10M MAUs at 24 months across 6 SDKs and a heterogeneous customer mix from solo developers to Fortune-500 enterprises — and the need for independent team ownership, independent SLO posture per service, and independent deployment cadence make the microservices choice load-bearing.

A monolith would be faster to ship initially but creates a coordination bottleneck on every change and forces uniform scaling and uniform SLO commitments across very different workloads (the high-RPS `/token` endpoint and the seldom-called billing endpoint cannot share infrastructure economics gracefully).

### Decision

The Qeet ID platform is built as a set of independently deployable microservices on Kubernetes. The service catalog is enumerated in [Microservices Decomposition](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md). Service boundaries follow bounded contexts; each service owns its data.

### Consequences

**Positive:**
- Independent scaling and SLO posture per service.
- Independent team ownership and on-call rotation.
- Reduced blast radius of any single service failure.
- Independent release cadence.
- Aligned with prevailing enterprise-grade auth platform architectures.

**Negative / accepted trade-offs:**
- Operational complexity is significant — Kubernetes, service mesh, mTLS, distributed tracing all required.
- Cross-service refactors are more expensive than monolithic refactors.
- Network is a failure mode; observability becomes mandatory.
- Higher initial engineering investment to ship MVP than a monolith.

### Alternatives Considered

- **Modular monolith** — rejected: would not scale per-service; would force shared on-call.
- **Macroservices (4–5 large services)** — rejected as a half-measure; if microservices are right, commit; if monolith is right, commit; the in-between has the disadvantages of both.

### References

- [HLSA §3.1 AG-01](Qeet ID%20%E2%80%94%20High-Level%20System%20Architecture.md)
- [Microservices Decomposition §3](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)
- Phase 1 Stakeholder Findings: CTO statement

---

## ADR-002: Kubernetes as Orchestration Platform

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** CTO, DevOps Lead, Solution Architect
**Tags:** infrastructure, orchestration

### Context

Given ADR-001, container orchestration is required. Stakeholder findings record team familiarity with Kubernetes, and the broader open-source ecosystem (Istio, Prometheus, OpenTelemetry, cert-manager, Argo CD) presumes Kubernetes.

### Decision

The Qeet ID platform runs on Kubernetes, specifically Amazon EKS (Elastic Kubernetes Service) at MVP. Workloads are containerised; CI/CD targets Helm charts deployed via GitOps.

### Consequences

**Positive:**
- Cloud-portable workload model — Kubernetes runs on AWS, GCP, Azure, on-premise.
- Mature ecosystem for observability, security, networking.
- Standard skills and tooling — easier hiring.

**Negative / accepted trade-offs:**
- Kubernetes itself is operationally complex; managed EKS reduces but does not eliminate the burden.
- Network policy management requires discipline.
- Cost of EKS control plane + node groups + load balancers is non-trivial.

### Alternatives Considered

- **AWS ECS / Fargate** — rejected: AWS-specific; less portable; less mature ecosystem.
- **Nomad** — rejected: smaller ecosystem; team unfamiliar.
- **Plain EC2 + systemd** — rejected: would force re-implementation of orchestration primitives.

### References

- [HLSA §7](Qeet ID%20%E2%80%94%20High-Level%20System%20Architecture.md)
- [Infrastructure & Deployment §6](Qeet ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md)

---

## ADR-003: AWS as Primary Cloud Provider

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** CTO, CFO, Solution Architect, Security Architect
**Tags:** infrastructure, cloud, compliance

### Context

Phase 1 left the cloud decision pending Phase 2 (Charter §11; Compliance CG-06). AWS has the broadest enterprise compliance posture (FedRAMP, GovCloud for v3.0 roadmap, sovereign regions), the deepest set of managed services Qeet ID needs (Aurora, EKS, MSK, ElastiCache, KMS, S3, Shield Advanced), the strongest in-team expertise, and the strongest partner ecosystem.

### Decision

AWS is the primary cloud provider at MVP. Production deployment targets us-east-1 and eu-west-1 at launch. The architecture remains cloud-portable (NFR PO-01/PO-02) — auth-critical components are designed against open-source equivalents (PostgreSQL, Redis, Kafka, Kubernetes) so a future migration to GCP or Azure is economically tractable.

### Consequences

**Positive:**
- Mature managed services accelerate MVP.
- Compliance certification posture is broadest in industry.
- Team expertise reduces ramp cost.

**Negative / accepted trade-offs:**
- Some AWS-specific services (Shield Advanced, KMS, MSK) accrue lock-in — recorded in the Cloud Lock-In Register and reviewed annually (NFR PO-07).
- Multi-cloud is *readiness*, not active deployment; validation effort required to keep the promise honest.

### Alternatives Considered

- **GCP** — rejected at MVP: smaller team familiarity; weaker enterprise compliance footprint at the time of decision; deferred to v2.0 secondary.
- **Azure** — rejected: smaller team familiarity; not a strategic fit at MVP.
- **Multi-cloud active-active at MVP** — rejected: complexity not warranted at MVP scale; on roadmap for v2.0.

### References

- [HLSA §8](Qeet ID%20%E2%80%94%20High-Level%20System%20Architecture.md)
- [Infrastructure & Deployment §3](Qeet ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md)
- Compliance CG-06

---

## ADR-004: PostgreSQL as Primary Database

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Database Architect, Backend Lead, Solution Architect
**Tags:** data, database

### Context

The platform requires ACID transactional consistency for authentication state, multi-tenancy enforcement via row-level security, mature ecosystem (libraries, tooling, operators in the team), portability across clouds, and the ability to scale via read replicas and tenant-sharding.

### Decision

PostgreSQL — specifically Aurora PostgreSQL 16.x at MVP — is the primary OLTP database for all Qeet ID state.

### Consequences

**Positive:**
- ACID guarantees on the auth path (NFR TO-01).
- Mature RLS for tenant isolation (Multi-Tenancy §5.2).
- Strong indexing (incl. partial, expression, BRIN where useful).
- Portable across AWS / GCP / Azure managed offerings.
- Team expertise.

**Negative / accepted trade-offs:**
- Tenant-sharding logic is application-managed (Aurora Limitless or Citus would be alternatives; deferred).
- Connection-pool management requires careful operations (PgBouncer-equivalent).

### Alternatives Considered

- **MySQL** — rejected: weaker RLS story; team prefers PostgreSQL.
- **CockroachDB / YugabyteDB** — rejected at MVP: global-distribution features not required at MVP scale; would add operational complexity.
- **DynamoDB / NoSQL** — rejected: transactional semantics for cross-table auth flows would be unergonomic.

### References

- [HLSA §7](Qeet ID%20%E2%80%94%20High-Level%20System%20Architecture.md)
- [Database Design & Data Model](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)

---

## ADR-005: Redis for Caching & Session Store

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Backend Lead, Database Architect, Solution Architect
**Tags:** data, cache

### Context

Hot reads (session lookup, rate-limit counters, permission caches, JWKS cache) need sub-ms latency. PostgreSQL is the source of truth for everything except true ephemeral state, but it is not optimal for the highest-RPS reads.

### Decision

Redis 7 in cluster mode (AWS ElastiCache at MVP) is the cache and ephemeral store. Sessions, rate-limit token buckets, JWKS, permission caches, revocation bloom filter, and short-lived authorization codes' presence checks live in Redis.

### Consequences

**Positive:**
- Sub-ms hot reads.
- Mature cluster-mode for horizontal scale.
- Portable across clouds.

**Negative / accepted trade-offs:**
- Redis can lose data on failure; durable state remains in Postgres.
- Memory cost grows with active sessions and rate-limit window granularity.

### Alternatives Considered

- **Memcached** — rejected: lacks cluster-mode + persistence + sorted sets needed for rate-limit windows.
- **Hazelcast** — rejected: less prevalent; team unfamiliar.

### References

- [Database Design §12](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)

---

## ADR-006: Kafka for Event Streaming

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Backend Lead, Solution Architect, SRE Lead
**Tags:** data, events, async

### Context

The platform emits a high volume of events (audit, webhooks, cross-service notifications) and needs durable, ordered, partitioned event log semantics. NFR SC-10: 500,000 audit writes/s at 24m. Loss tolerance is zero for audit (SL-08).

### Decision

Apache Kafka, hosted on AWS MSK at MVP, is the event-streaming backbone. Audit events, webhook payloads, and cross-service domain events all flow through Kafka topics.

### Consequences

**Positive:**
- Durable, ordered, partitioned event log.
- Tenant-level isolation via partition key.
- Mature consumer-group rebalancing.
- Replay capability within 7-day retention.

**Negative / accepted trade-offs:**
- Operational complexity higher than e.g. Amazon SQS.
- Consumer-side idempotency required (at-least-once delivery).

### Alternatives Considered

- **Amazon SQS / SNS** — rejected: lacks ordering and tenant-level partitioning required for audit fan-out.
- **AWS Kinesis** — rejected: AWS lock-in; smaller ecosystem.
- **NATS Streaming** — rejected: not at the maturity/scale of Kafka for our requirements.

### References

- [HLSA §7](Qeet ID%20%E2%80%94%20High-Level%20System%20Architecture.md)
- [Microservices Decomposition §6.2](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)

---

## ADR-007: REST + OpenAPI over GraphQL for Public APIs

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** API Designer, Backend Lead, DevRel Lead, Solution Architect
**Tags:** api, dx

### Context

Six SDK languages must integrate seamlessly. Customers expect a discoverable, cacheable, mature API style. REST has the broader tooling ecosystem (OpenAPI, Postman, conformance test suites, mature SDK generators). GraphQL has advantages for variable client needs but introduces complexity in caching, observability, and authorization.

### Decision

All public Qeet ID APIs are REST over HTTPS, with OpenAPI 3.1 as the single source of truth. GraphQL is deferred to post-MVP and may be added as a complementary surface in v2.0 if customer demand warrants.

### Consequences

**Positive:**
- Stronger SDK-generation story across 6 languages.
- Mature observability (per-endpoint metrics).
- Caching maps to HTTP standards.
- Tooling ecosystem (Stoplight, Redoc, Postman) is mature.

**Negative / accepted trade-offs:**
- Some clients over-fetch.
- Schema evolution requires more disciplined versioning than GraphQL's field-level deprecation.

### Alternatives Considered

- **GraphQL** — deferred: complexity not warranted at MVP; SDK story weaker for some target languages (Flutter, Go in particular).
- **gRPC for public** — rejected: HTTP-API expectations from customers; gRPC retained for *internal* service-to-service consideration but not adopted at MVP (Microservices AP-07).

### References

- [API Design Standards](Qeet ID%20%E2%80%94%20API%20Design%20Standards.md)

---

## ADR-008: Multi-Tenancy via Row-Level Security with `tenant_id`

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Solution Architect, Database Architect, Security Architect
**Tags:** multi-tenancy, data, security

### Context

Cross-tenant data leakage is classified as an existential failure (NFR ER-10, TO-07). The platform must support 100,000+ tenants at 24m with mixed traffic profiles, while enterprise customers need an isolated tier option.

### Decision

The default multi-tenancy model is **row-level security (RLS) with `tenant_id`** on every tenant table in a shared PostgreSQL cluster. Enterprise customers may opt into a **dedicated database shard** (L2 isolation tier; Multi-Tenancy §7). At ≥100K tenants, the L1 population is sharded across multiple Aurora clusters by hash of `tenant_id`.

Schema-per-tenant is **not** the default — it does not scale to 100K tenants administratively.

### Consequences

**Positive:**
- Database-enforced tenant isolation independent of application correctness.
- Mature pattern with strong test/audit story.
- Cost-efficient at MVP scale.

**Negative / accepted trade-offs:**
- Every tenant table carries the `tenant_id` overhead.
- Every transaction must `SET LOCAL qeetify.current_tenant_id`.
- Cross-tenant analytics goes through batch jobs, not OLTP.

### Alternatives Considered

- **Schema-per-tenant** — rejected for L1: administrative cost at our tenant count.
- **Database-per-tenant** — rejected for L1: cost; reserved for L3 v2.0.
- **Single tenant_id column without RLS** — rejected: relies on application correctness alone.

### References

- [Multi-Tenancy Architecture](Qeet ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md)

---

## ADR-009: JWT with RS256 for Access Tokens, Never HS256, Never `none`

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Security Architect, Backend Lead, CISO
**Tags:** auth, tokens, security

### Context

JWT misconfiguration is one of the most-exploited vulnerabilities in production auth systems. Algorithm confusion (RS256 → HS256), `none` algorithm acceptance, and trusting the `alg` header without server-side enforcement have produced public breaches at multiple high-profile platforms. Protocol Requirements §9 mandates asymmetric signing for public-facing tokens.

### Decision

All access tokens and ID tokens are JWTs signed with **RS256 (RSA-2048 minimum) or ES256 (ECDSA P-256)**. JWT libraries are configured to:

- Reject `alg: none` unconditionally.
- Reject `alg: HS256` for public-facing tokens.
- Enforce expected algorithm server-side, never blindly trust the header.
- Use algorithm-specific verification paths.

Signing keys live in KMS; private key material is never on disk in plaintext (IdP Core §5).

### Consequences

**Positive:**
- Eliminates the most common JWT vulnerability class.
- Public-key verification by resource servers (JWKS).
- Aligned with OIDC Foundation conformance.

**Negative / accepted trade-offs:**
- Larger tokens than HS256.
- KMS dependency on the issuance path.

### Alternatives Considered

- **HS256 throughout** — rejected: would expose every resource server to the signing secret, blocking JWKS-style verification and inviting algorithm-confusion attacks.

### References

- [Protocol Requirements §9](../phase-1/Qeet%20ID%20%E2%80%94%20Protocol%20Requirements%20Document.md)
- [IdP Core Engine Design §5](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md)

---

## ADR-010: Argon2id for Password Hashing

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Security Architect, Backend Lead, CISO
**Tags:** crypto, security, credentials

### Context

Password hashing must resist GPU and ASIC brute-force, accommodate parameter increases as hardware accelerates, and align with current NIST and OWASP guidance. Compliance EN-02 lists Argon2id (primary) and bcrypt (fallback).

### Decision

Argon2id is the password hashing algorithm. Initial parameters: m = 64 MiB, t = 3, p = 4 (NFR SE-07). A platform-wide pepper (HMAC-applied before Argon2id) is held in KMS. Parameters reviewed annually against current hardware.

### Consequences

**Positive:**
- Memory-hard hashing resistant to GPU/ASIC.
- PHC 2015 winner; broad library support.
- Future-proof via parameter tuning.

**Negative / accepted trade-offs:**
- Verification cost (~150 ms target) is a meaningful share of the login latency budget.
- Memory usage per verification is non-trivial; concurrent-login fan-in must be sized.

### Alternatives Considered

- **bcrypt** — relegated to fallback only; less memory-hard.
- **scrypt** — rejected: Argon2id is more widely adopted in contemporary libraries.

### References

- [IdP Core Engine Design §7.1](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md)
- Compliance EN-02

---

## ADR-011: Open-Source Base Layer Decision

**Status:** Proposed
**Date:** 2026-05-19
**Deciders:** CTO, Solution Architect, Legal Counsel (license audit), Backend Lead
**Tags:** idp-core, build-vs-buy

### Context

Phase 1 left this as the most consequential open decision. The choice between **Keycloak**, **Ory Stack (Hydra-centric)**, and **build-from-scratch** affects MVP timeline (3–4 months), long-term maintenance burden, and customisation ceiling. A Legal license audit is a prerequisite (Compliance CG-06).

### Decision (Proposed)

Adopt **Ory Hydra** as the OAuth 2.0 / OIDC base layer. Build SAML, SCIM, multi-tenancy, user/credential layer, and RBAC natively. This is the recommendation; the formal decision closes by Phase 2 Week 4 contingent on Legal's Apache 2.0 license confirmation.

If Legal blocks Ory: fallback to **Keycloak** with multi-tenancy retrofit budget. If Keycloak also blocks: build-from-scratch with 3-month timeline slip flagged to CEO.

### Consequences

**Positive (if Hydra adopted):**
- Saves ~2–3 months of OAuth/OIDC implementation.
- Strict OIDC conformance inherited.
- Permissive Apache 2.0 license.
- Bounded migration cost away from Hydra.

**Negative / accepted trade-offs:**
- One more dependency to track for CVEs and upgrades.
- We must run Hydra as a stateless deployment configured by our Token Service.

### Alternatives Considered

- **Keycloak** — full identity stack including SAML/SCIM out of the box, but multi-tenancy via realms degrades past tens of thousands.
- **Build from scratch** — highest control; longest timeline.

### References

- [IdP Core Engine Design §3](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md)
- [Open Decisions Register](Open-Decisions-Register.md)
- Compliance CG-06

---

## ADR-012: Zero Trust Network Architecture

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Security Architect, Solution Architect, CISO, DevOps Lead
**Tags:** security, network

### Context

Phase 1 stakeholder findings explicitly mandated Zero Trust from Day 1 — retrofitting security is expensive. The 99.9% uptime, SOC 2 readiness, and tenant-isolation requirements demand that compromised pods, nodes, or operator accounts cannot compromise the platform.

### Decision

Qeet ID operates under Zero Trust principles (Security §3). No request is trusted by virtue of being inside the VPC. Every internal request is authenticated (mTLS + service token), authorised (mesh AuthorizationPolicy + service-side checks), and audited. Egress is restricted to allow-listed destinations; ingress is segmented; secrets are never in environment variables.

### Consequences

**Positive:**
- Bounded blast radius on compromise.
- SOC 2 CC6 controls satisfied architecturally.
- Aligned with industry "BeyondCorp" thinking.

**Negative / accepted trade-offs:**
- Operational complexity — every service must participate in the model.
- Slight per-call latency overhead from mTLS and token verification.

### Alternatives Considered

- **Castle-and-moat (internal trust)** — rejected: stakeholder explicit prohibition; modern threat model invalidates the assumption.

### References

- [Security Architecture (Zero Trust)](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md)

---

## ADR-013: mTLS for Internal Service-to-Service Auth

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Security Architect, DevOps Lead, Backend Lead
**Tags:** security, network, services

### Context

Per ADR-012, internal traffic must be authenticated. The service mesh (Istio) is already required for traffic policy, observability, and circuit breaking; it naturally provides mTLS.

### Decision

All service-to-service traffic inside the Qeet ID VPC is mTLS-encrypted via Istio. Workload identities are bound to Kubernetes ServiceAccounts via Istio-issued certificates. In addition to mTLS, an application-layer **service token** (ES256 signed) carries identity, tenant_id, and request_id (IdP Core §12; Security §5.2).

### Consequences

**Positive:**
- Encrypted internal traffic.
- Workload identity verifiable on every hop.
- Audit-grade tenant propagation.

**Negative / accepted trade-offs:**
- Sidecar resource overhead (CPU, memory).
- Operational complexity managing mesh upgrades.
- Some performance overhead vs plain HTTP (mitigated by HTTP/2 connection reuse).

### Alternatives Considered

- **Plain HTTP inside VPC** — rejected: fails Zero Trust.
- **VPN / IPsec mesh** — rejected: lower fidelity identity; legacy pattern.

### References

- [Security Architecture §5](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md)
- [Microservices Decomposition §6.1](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)

---

## ADR-014: KMS-Managed Envelope Encryption for PII Fields

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Security Architect, Database Architect, CISO
**Tags:** crypto, security, pii

### Context

PII fields (email, phone, TOTP seed, billing details) require encryption at rest at the field level (Compliance EN-03; NFR SE-06). Envelope encryption with a per-tenant DEK wrapped by a platform KEK in KMS is the contemporary standard pattern, providing scope-bounded blast radius and key-rotation flexibility.

### Decision

PII fields are encrypted with **AES-256-GCM using a per-tenant Data Encryption Key (DEK)**. The DEK is wrapped by a platform-wide **Key Encryption Key (KEK)** held in AWS KMS. DEKs are cached in process memory for at most 15 minutes; the KEK never leaves KMS unwrapped.

### Consequences

**Positive:**
- Field-level confidentiality.
- Tenant-scoped key blast radius.
- KMS audit trail of every KEK use.
- Rotation possible per-tenant without touching data rows.

**Negative / accepted trade-offs:**
- Encrypted columns cannot be searched directly; deterministic hash columns are introduced for indexed lookup (e.g., `email_hash`).
- Per-call KMS dependency (mitigated by DEK caching).

### Alternatives Considered

- **Application-managed AES keys (no KMS)** — rejected: key custody is the value proposition of KMS.
- **Transparent disk encryption only** — rejected: insufficient for field-level access control on database queries.

### References

- [Security Architecture §7.3](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md)
- [Database Design §3-§5](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)
- [IdP Core §7.4](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md)

---

## ADR-015: OpenTelemetry for Distributed Tracing

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** SRE Lead, Solution Architect, Backend Lead
**Tags:** observability, tracing

### Context

Every customer-facing request must be traceable across services (NFR TR-01). The instrumentation must be vendor-neutral so the backend (Jaeger / Tempo / commercial) can change without re-instrumenting the platform.

### Decision

OpenTelemetry (OTel) SDK is the instrumentation standard across every Qeet ID service. W3C Trace Context is the propagation format.

### Consequences

**Positive:**
- Vendor neutrality.
- Wide library and language support.
- Standardised semantic conventions.

**Negative / accepted trade-offs:**
- Some early-stage rough edges; SDK versions need pinning and tested upgrades.

### Alternatives Considered

- **Jaeger / Zipkin native clients** — rejected: vendor-specific; less portable.
- **Vendor SDKs (Datadog, New Relic)** — rejected as the primary: vendor lock-in.

### References

- [Observability Architecture §6](Qeet ID%20%E2%80%94%20Observability%20Architecture.md)

---

## ADR-016: Terraform for Infrastructure as Code

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** DevOps Lead, Platform Lead, Solution Architect
**Tags:** infrastructure, iac

### Context

The platform requires reproducible infrastructure across dev / staging / prod / DR environments and across two regions at MVP (more at v1.2+). The team has Terraform expertise; the broader ecosystem is the largest in IaC.

### Decision

Terraform 1.x is the IaC tool. State stored in S3 + DynamoDB lock. Module library is shared; per-environment stacks compose modules. CI runs `plan` and policy checks; production `apply` flows through a controlled pipeline.

### Consequences

**Positive:**
- Reproducible, version-controlled infrastructure.
- Module sharing across environments.
- Mature ecosystem.

**Negative / accepted trade-offs:**
- State-file management requires discipline.
- Terraform language has known quirks at scale; mitigated with module patterns.

### Alternatives Considered

- **Pulumi** — rejected: team less experienced; smaller ecosystem.
- **AWS CDK** — rejected: AWS-specific; would harm cloud portability.

### References

- [Infrastructure & Deployment §16](Qeet ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md)

---

## ADR-017: GitHub Actions for CI/CD

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** DevOps Lead, Backend Lead
**Tags:** cicd, infrastructure

### Context

The source code lives on GitHub (Compliance SP-06). GitHub Actions is the native CI/CD with the lowest integration friction; the cost model fits the team size at MVP.

### Decision

GitHub Actions is the CI/CD platform. Pipelines are defined as YAML in each service repo, with shared reusable workflows for common stages (lint, test, scan, build, push, deploy).

### Consequences

**Positive:**
- Native GitHub integration.
- Mature marketplace of actions.
- Cost-effective at MVP scale.

**Negative / accepted trade-offs:**
- GitHub-hosted runners may be cost-inefficient at high build volumes; self-hosted runners adoption likely post-MVP.
- Some advanced patterns (deploy gating) require external tooling (Argo CD).

### Alternatives Considered

- **GitLab CI / Drone / Buildkite** — rejected: SCM is GitHub; cross-platform CI would add complexity.
- **CircleCI / Jenkins** — rejected: separate auth surface; team prefers GitHub-native.

### References

- [Infrastructure & Deployment §14](Qeet ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md)

---

## ADR-018: Synchronous Permission Checks (No Eventual Consistency for Auth)

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Security Architect, Backend Lead, Solution Architect
**Tags:** auth, authz

### Context

Authentication and authorization must always reflect the current state of the user — particularly on permission revocation, where a delay is a security exposure. NFR TO-01 records this trade-off as strong-consistency-over-availability for user records. Authorization Engine §5 defines two evaluation modes: a JWT-claim-embedded "Mode A" (zero hops, up to 15-min stale-revoke window) and a synchronous `/permissions/check` "Mode B" (source of truth).

### Decision

Permission checks are either:
- **Mode A** — embedded in the access token at issuance, with a 15-minute lifetime bound on staleness — used for general API endpoints and reads.
- **Mode B** — synchronous call to `/permissions/check`, always current, ≤ 60 ms p95 — used for privileged, financial, or money-moving endpoints and any endpoint where the customer's recommended mode is "source-of-truth."

No eventual-consistency model is used for authorization decisions. The Token Service and Session Service share a synchronous revocation contract (Database §13.1 / NFR DI-03).

### Consequences

**Positive:**
- Authoritative checks available when needed.
- 15-minute upper bound on stale-grant exposure for Mode A.
- Customers can choose mode per endpoint.

**Negative / accepted trade-offs:**
- Mode B adds a network hop on every check.
- Customers must know which mode to choose; documentation surfaces this trade-off.

### Alternatives Considered

- **Always synchronous** — rejected: defeats the purpose of token claims; latency cost too high for general APIs.
- **Always JWT-embedded** — rejected: insufficient for privileged endpoints with revocation sensitivity.

### References

- [Authorization Engine Design §5](Qeet ID%20%E2%80%94%20Authorization%20Engine%20Design.md)
- NFR TO-01

---

## ADR-019: Refresh Token Rotation Mandatory

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Security Architect, Backend Lead
**Tags:** auth, tokens, security

### Context

Long-lived refresh tokens are valuable to attackers. Rotation on every use is the modern standard (Protocol OS-06); reuse detection adds an explicit signal of compromise (OS-07).

### Decision

Refresh tokens are rotated on every successful use. The presented token is **marked used** (not deleted) atomically with the issuance of the new token. If the marked-used token is presented again, the entire authorization chain is revoked, the session is revoked, and a security alert fires (IdP Core §10.1 / §10.2).

For the first 30 days of production, reuse detection **alerts** but does not auto-revoke — to baseline real-world false-positive rates. After 30 days, auto-revoke is enabled.

### Consequences

**Positive:**
- Compromised refresh tokens are detected on second use.
- Rotation reduces the window of a stolen token's value.
- Aligned with OAuth 2.1 security BCP.

**Negative / accepted trade-offs:**
- Buggy customer SDKs that retry naively may trigger false positives.
- Implementation must use atomic UPDATE to avoid races.

### Alternatives Considered

- **No rotation** — rejected: violates Protocol OS-06.
- **Rotation without reuse detection** — rejected: leaves the attack window open.

### References

- [IdP Core Engine Design §10](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md)
- [Authentication Flow Designs §18](Qeet ID%20%E2%80%94%20Authentication%20Flow%20Designs.md)

---

## ADR-020: PKCE Mandatory for All OAuth Public Clients

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Security Architect, Backend Lead
**Tags:** oauth, security

### Context

PKCE (RFC 7636) closes the authorization-code interception attack window for public clients (mobile, SPA). Protocol Requirements OS-01 mandates `code_challenge_method=S256` and rejects `plain`. Modern OAuth 2.1 guidance applies PKCE to confidential clients as well, removing the historical "PKCE for public only" exception.

### Decision

PKCE with `code_challenge_method=S256` is **mandatory for all OAuth public clients without exception**. The `plain` method is not accepted. For confidential clients, PKCE is **strongly recommended** and on by default for new clients; existing customer configurations may opt out via support ticket (audited; deprecated by v1.2 — all clients PKCE-required).

### Consequences

**Positive:**
- Eliminates code-interception attacks.
- Aligned with OAuth 2.1 BCP.

**Negative / accepted trade-offs:**
- Customer SDKs (including ours) must compute the verifier and present it; small added complexity in client code.

### Alternatives Considered

- **PKCE optional** — rejected: violates Protocol OS-01.

### References

- [Protocol Requirements §4.6 OS-01](../phase-1/Qeet%20ID%20%E2%80%94%20Protocol%20Requirements%20Document.md)
- [Authentication Flow Designs §3](Qeet ID%20%E2%80%94%20Authentication%20Flow%20Designs.md)

---

### 5. ADR Process

### 5.1 When to Write an ADR

- A new technology is introduced.
- A previous principle is deviated from.
- A trade-off is made between two reasonable options.
- A decision binds the future (one-way door).
- A decision will be asked about in the next 12 months.

### 5.2 Authoring Workflow

1. Author opens a PR adding an ADR file (or appending here).
2. Status starts as `Proposed`.
3. Reviewers (Solution Architect always; Security Architect for security-sensitive; CTO for cross-cutting) review.
4. Status flips to `Accepted` on approval; merged.
5. Subsequent ADRs may `Supersede` an earlier one.

### 5.3 ADR Review Cadence

- Every major architectural change references the relevant ADRs.
- Annual review of all `Accepted` ADRs to identify candidates for `Superseded` or `Deprecated`.
- ADRs are immutable once `Accepted`; corrections happen via a new ADR.

---

### 6. ADR Index

| ADR | Title | Status |
| --- | --- | --- |
| ADR-001 | Microservices over Monolith | Accepted |
| ADR-002 | Kubernetes as Orchestration Platform | Accepted |
| ADR-003 | AWS as Primary Cloud Provider | Accepted |
| ADR-004 | PostgreSQL as Primary Database | Accepted |
| ADR-005 | Redis for Caching & Session Store | Accepted |
| ADR-006 | Kafka for Event Streaming | Accepted |
| ADR-007 | REST + OpenAPI over GraphQL for Public APIs | Accepted |
| ADR-008 | Multi-Tenancy via Row-Level Security with `tenant_id` | Accepted |
| ADR-009 | JWT with RS256 for Access Tokens, Never HS256, Never `none` | Accepted |
| ADR-010 | Argon2id for Password Hashing | Accepted |
| ADR-011 | Open-Source Base Layer Decision (Hydra recommended; pending Legal) | Proposed |
| ADR-012 | Zero Trust Network Architecture | Accepted |
| ADR-013 | mTLS for Internal Service-to-Service Auth | Accepted |
| ADR-014 | KMS-Managed Envelope Encryption for PII Fields | Accepted |
| ADR-015 | OpenTelemetry for Distributed Tracing | Accepted |
| ADR-016 | Terraform for Infrastructure as Code | Accepted |
| ADR-017 | GitHub Actions for CI/CD | Accepted |
| ADR-018 | Synchronous Permission Checks (No Eventual Consistency for Auth) | Accepted |
| ADR-019 | Refresh Token Rotation Mandatory | Accepted |
| ADR-020 | PKCE Mandatory for All OAuth Public Clients | Accepted |
| ADR-021+ | _(open seats — added as Phase 2 progresses)_ | — |

---

### 7. Approvals & Sign-off (for this document as a whole and for the seed ADRs)

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Solution Architect |  |  |  |
| Security Architect |  |  |  |
| CTO |  |  |  |
| Backend Engineering Lead |  |  |  |
| DevOps / Cloud Architect |  |  |  |
| Database Architect |  |  |  |
| API Designer |  |  |  |
| SRE Lead |  |  |  |
| Compliance Officer (ADR-011 license posture) |  |  |  |
| Legal Counsel (ADR-011 license posture) |  |  |  |

---

*This document is version controlled. Individual ADRs, once Accepted, are immutable. Changes to a decision require a new ADR that explicitly Supersedes the previous one. The ADR Index in §6 is the canonical list; any reference to an ADR by number anywhere in Phase 2 documentation points here.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
