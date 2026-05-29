# Qeet ID — High-Level System Architecture

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | High-Level System Architecture |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Solution Architect |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the high-level system architecture of the Qeet ID Authentication and Authorization platform. It is the architectural anchor for Phase 2 — every other Phase 2 deliverable (microservices decomposition, IdP core engine design, authentication flows, authorization engine, multi-tenancy, database, API standards, security, infrastructure, observability, ADRs) refines, depends on, or constrains the architectural shape established here.

The document defines the architectural goals and principles, presents the system at C4 Level 1 (System Context) and C4 Level 2 (Container), enumerates the logical layers and their responsibilities, summarises the technology stack, describes the multi-region topology, and surfaces the architectural constraints and open decisions that the rest of Phase 2 must resolve.

This document is **not** a microservices catalog — that belongs in [Qeet ID — Microservices Decomposition & Service Boundaries](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md). It is **not** an infrastructure runbook — that belongs in [Qeet ID — Infrastructure & Deployment Architecture](Qeet ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md). It is the shape of the system at the elevation that lets every stakeholder see how the parts fit together.

The audience is the Solution Architect, Security Architect, Backend Lead, DevOps Lead, SRE Lead, Database Architect, API Designer, and CTO. Product Management and Compliance read this document to confirm that Phase 2 design aligns with Phase 1 commitments.

---

### 3. Architecture Goals & Principles

### 3.1 Architecture Goals

| # | Goal | Linked Phase 1 Source |
| --- | --- | --- |
| AG-01 | Support 50,000 MAUs at launch and scale to 10,000,000 MAUs at 24 months without re-platforming | NFR §5.2 SC-01 |
| AG-02 | Sustain 99.9% platform uptime at launch and 99.99% for Enterprise tier within 24 months | NFR §6.1 AV-02/AV-04 |
| AG-03 | Meet OAuth /token p95 ≤ 200ms and end-to-end login p95 ≤ 800ms | NFR §4.2 PF-02, §4.4 |
| AG-04 | Architecturally enforce tenant isolation — cross-tenant data leakage must be impossible by design, not just policy | NFR §7.1 ER-10, §21 TO-07 |
| AG-05 | Achieve SOC 2 Type I, GDPR, FIDO2, and OIDC Basic OP certifications before production launch | Compliance Matrix §3.2 |
| AG-06 | Remain cloud-portable — auth-critical services run on Kubernetes + open-source dependencies; cloud-specific managed services confined to documented locations | NFR §14 PO-01/PO-02 |
| AG-07 | Enable a developer to ship working authentication in under five minutes via published SDKs | Business Goals §5.5; Competitive Analysis (differentiator) |
| AG-08 | Support enterprise federation (SAML 2.0, SCIM 2.0) and developer-grade flows (OAuth 2.0 + PKCE, OIDC, WebAuthn) in a single platform at MVP | Protocol Requirements §3.1 |
| AG-09 | Provide tamper-evident, append-only audit logging with 12-month retention for authentication events and 3 years for administrative and security events | NFR §11.1 LG-07/LG-08/LG-09; Compliance §9 |
| AG-10 | Make every architectural decision reversible at acceptable cost — no decision permanently locks the platform into a vendor, runtime, or pattern | NFR §14 PO-07, §21 TO-06 |

---

### 3.2 Architecture Principles

The principles below govern every design decision in Phase 2 and are referenced by name in every downstream architecture document. A design that contradicts a principle requires an Architecture Decision Record (ADR) documenting the rationale.

**P-01 — Cloud-Agnostic by Construction.** Qeet ID's auth-critical path runs on Kubernetes, PostgreSQL, Redis, and Kafka — all available across AWS, GCP, and Azure as either managed services or self-managed deployments. Cloud-vendor-specific services (e.g., AWS KMS, S3, CloudFront) are wrapped behind interfaces. Any direct binding to a cloud-specific API is itemised in the Cloud Lock-In Register reviewed annually.

**P-02 — Stateless by Default.** All application services are stateless. State lives in PostgreSQL, Redis, or Kafka — never in the application pod's memory or filesystem beyond a request's lifetime. Stateless services enable horizontal scaling, rapid failover, and rolling deployments without coordination.

**P-03 — Defence in Depth.** Security controls are layered. WAF rejects malformed input; the API gateway authenticates the caller; the service validates the tenant; the database enforces row-level tenant filtering; the audit log records the result. No single control is sufficient; no single failure is catastrophic.

**P-04 — Multi-Tenant from Day One.** Every data row, every cache key, every log entry, every metric label carries a tenant identifier. Tenant context is propagated end-to-end. There is no shared global state across tenants except platform-internal metadata.

**P-05 — Observable by Design.** Every service emits structured logs (JSON), metrics (Prometheus exposition), and traces (OpenTelemetry). Every customer-facing request carries a `request_id` that correlates across logs, metrics, and traces. Services without observability hooks are not production-eligible.

**P-06 — Secure by Default.** Defaults favour security over convenience. PKCE is mandatory for public clients. Refresh token rotation is on. MFA enrolment is prompted. Passkeys are the recommended primary credential. Insecure options (HS256 JWTs, `none` algorithm, implicit grant, ROPC grant) are not implementable.

**P-07 — API-First.** Every product feature is exposed through a documented public API (REST + OpenAPI 3.1) before the corresponding UI ships. The dashboard and developer portal consume the same APIs that customers use. SDKs are generated against — or carefully aligned to — the same OpenAPI specs.

**P-08 — Bounded Contexts.** Services own their data. No service reads another service's database directly. Cross-service queries go through the owning service's API or asynchronous events on Kafka.

**P-09 — Synchronous for Authorization; Asynchronous for Everything Else.** Permission checks and token issuance are synchronous — eventual consistency on the auth path is not acceptable (NFR TO-01). Audit log persistence, webhook delivery, analytics aggregation, and notification dispatch are asynchronous via Kafka.

**P-10 — Reversible Decisions Preferred.** Where a one-way door (a decision hard to undo) is unavoidable, it requires an ADR with an explicit rollback plan. Where a two-way door is available, take it and revisit later with production data.

**P-11 — Standards Conformance Over Convenience.** When a developer-experience desire conflicts with OAuth 2.1 / OIDC / SAML 2.0 / WebAuthn strict conformance, conformance wins (NFR TO-04). Deviations create long-term technical debt and security risk.

**P-12 — Open-Source-Friendly, Not Open-Source-Native.** Qeet ID ships as a managed cloud service. Open-source components inside the platform (the IdP core base layer if adopted; Kafka, PostgreSQL, Redis) are chosen for portability and community, not because Qeet ID itself is open-source.

---

### 4. System Context Diagram (C4 Level 1)

The System Context shows Qeet ID in relation to the actors and systems that interact with it.

```
                       ┌──────────────────────────────────────────────────────┐
                       │                  EXTERNAL ACTORS                     │
                       └──────────────────────────────────────────────────────┘

   ┌────────────────┐   ┌──────────────────┐   ┌────────────────┐   ┌────────────────┐
   │  End User      │   │  Developer       │   │  Tenant Admin  │   │  Enterprise IT │
   │  (Login        │   │  (SDK / API      │   │  (Dashboard    │   │  Admin         │
   │   ceremony)    │   │   integrator)    │   │   user)        │   │  (SSO / SCIM)  │
   └───────┬────────┘   └────────┬─────────┘   └───────┬────────┘   └───────┬────────┘
           │                     │                     │                     │
           │  Browser            │  HTTPS              │  HTTPS              │  SAML / SCIM
           │  Native app         │  SDK calls          │  Browser            │  HTTPS
           │  Passkey            │                     │                     │
           │  ceremony           │                     │                     │
           ▼                     ▼                     ▼                     ▼
   ┌──────────────────────────────────────────────────────────────────────────────────┐
   │                                                                                  │
   │                            ████  QEETIFY PLATFORM  ████                          │
   │                                                                                  │
   │   Authentication & Authorization as a Service                                    │
   │   - User authentication (passwords, passkeys, social, MFA)                       │
   │   - Federated identity (OAuth 2.0, OIDC, SAML 2.0)                               │
   │   - Provisioning (SCIM 2.0)                                                      │
   │   - Authorization (RBAC; ABAC in v1.5; FGA in v2.0)                              │
   │   - Multi-tenant administration & analytics                                      │
   │   - Audit & compliance evidence                                                  │
   │                                                                                  │
   └─────┬─────────────────┬────────────────┬─────────────────┬───────────────────────┘
         │                 │                │                 │
         │  OIDC / SAML    │  OAuth         │  Webhook        │  SMS / Email
         │                 │                │  (HMAC-signed)  │
         ▼                 ▼                ▼                 ▼
   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
   │  Customer    │  │  Social IdPs │  │  Customer    │  │  Twilio      │
   │  Application │  │  (Google,    │  │  Backend     │  │  SendGrid    │
   │  (Relying    │  │   GitHub,    │  │  (Webhook    │  │  AWS SNS/SES │
   │   Party)     │  │   MS, Apple) │  │   consumer)  │  │              │
   └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘

   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
   │  Enterprise  │  │  Stripe      │  │  HIBP        │  │  FIDO MDS3   │
   │  IdP (Entra, │  │  (Billing)   │  │  (Compromised│  │  (Authentic. │
   │  Okta, Ping) │  │              │  │   passwords) │  │  metadata)   │
   └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
                                  ▲
                                  │
                                  │
   ┌──────────────────────────────┴──────────────────────────────────────┐
   │                       SUB-PROCESSORS                                │
   │  AWS (primary), Cloudflare (CDN/WAF), Datadog/Grafana (observ.),    │
   │  HashiCorp Vault (secrets), GitHub (SCM), PagerDuty (oncall)        │
   └─────────────────────────────────────────────────────────────────────┘
```

---

### 4.1 External Actors

| Actor | Interaction | Reference |
| --- | --- | --- |
| End User | Authenticates via passkey, password+MFA, magic link, social login, or SSO; manages own profile and credentials | Persona: end user; NFR UX-01/UX-02 |
| Developer | Integrates Qeet ID via SDKs or direct REST API; manages applications, keys, and webhooks | Persona: Arjun, Maya, Daniel |
| Tenant Admin | Manages users, roles, SSO, SCIM connections, branding, billing via the admin dashboard | Persona: Sandra; Feature scope §Admin Dashboard |
| Enterprise IT Admin | Configures SAML / SCIM federation between enterprise IdP and Qeet ID; provisions/deprovisions workforce | Persona: Sandra; Protocol §6, §7 |

### 4.2 External Systems

| System | Role | Communication |
| --- | --- | --- |
| Customer Application (Relying Party) | Consumes Qeet ID tokens to authenticate users | OAuth 2.0 / OIDC over HTTPS |
| Social Identity Providers | Google, GitHub, Microsoft, Apple — upstream OIDC IdPs for social login | OIDC over HTTPS |
| Enterprise Identity Providers | Microsoft Entra ID, Okta, Google Workspace, Ping — federated SAML / OIDC IdPs | SAML 2.0 / OIDC over HTTPS |
| Customer Webhook Endpoints | Receive Qeet ID-emitted event notifications | HTTPS POST with HMAC-SHA256 signature |
| Twilio / AWS SNS | SMS delivery for OTP MFA | HTTPS REST API |
| SendGrid / AWS SES | Transactional email — magic links, verification, notifications | HTTPS REST API |
| Stripe | Payment processing and subscription billing | HTTPS REST API + webhooks |
| Have I Been Pwned (HIBP) | Compromised password detection on registration and login | k-anonymity HTTPS API |
| FIDO Metadata Service (MDS3) | Authenticator metadata for WebAuthn attestation verification | HTTPS JSON download (periodic) |

### 4.3 Sub-Processors

Aligned to [Compliance Matrix §11.2](../phase-1/Qeet%20ID%20%E2%80%94%20Compliance%20Requirements%20Matrix.md). The primary infrastructure sub-processor at MVP is **AWS** ([ADR-003](Qeet ID%20%E2%80%94%20Architecture%20Decision%20Records%20%28ADRs%29.md)). Cloudflare provides CDN, WAF, and DDoS protection at the edge.

---

### 5. Container Diagram (C4 Level 2)

The Container view decomposes the Qeet ID Platform box into the major deployable units. A Container in C4 vocabulary is anything that can be independently deployed — services, databases, message brokers, frontends. Each is described in detail in the documents listed in §11.

```
                                INTERNET (TLS 1.2+/1.3)
                                       │
                                       ▼
   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │                              EDGE TIER                                          │
   │                                                                                 │
   │   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                      │
   │   │  Cloudflare  │───▶│  AWS Shield  │───▶│  CloudFront  │                      │
   │   │  WAF + Bot   │    │  Advanced    │    │  (static     │                      │
   │   │  Management  │    │  (L3/L4/L7)  │    │   assets)    │                      │
   │   └──────┬───────┘    └──────────────┘    └──────────────┘                      │
   │          │                                                                      │
   └──────────┼──────────────────────────────────────────────────────────────────────┘
              │
              ▼
   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │                              INGRESS TIER (per region, multi-AZ)                │
   │                                                                                 │
   │   ┌────────────────────────────────────────────────────────┐                    │
   │   │  Application Load Balancer (AWS ALB / NLB)             │                    │
   │   └─────────────────────────┬──────────────────────────────┘                    │
   │                             │ TLS terminated; mTLS to mesh                      │
   │                             ▼                                                   │
   │   ┌────────────────────────────────────────────────────────┐                    │
   │   │  API Gateway + Service Mesh (Istio / Envoy)            │                    │
   │   │  - Identity propagation, mTLS, retries, circuit break  │                    │
   │   └─────────────────────────┬──────────────────────────────┘                    │
   └─────────────────────────────┼──────────────────────────────────────────────────-┘
                                 │
   ┌─────────────────────────────┼───────────────────────────────────────────────────┐
   │                             ▼      APPLICATION TIER (Kubernetes / EKS)          │
   │                                                                                 │
   │   ╔══════════════════════════════════════════════════════════════════════╗      │
   │   ║                         CORE AUTH PLANE                              ║      │
   │   ║                                                                      ║      │
   │   ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ║      │
   │   ║  │ Auth Svc    │  │ Token Svc   │  │ Session Svc │  │ MFA Svc     │  ║      │
   │   ║  │ (login,     │  │ (OAuth/OIDC │  │ (lifecycle, │  │ (TOTP, SMS, │  ║      │
   │   ║  │  passkey)   │  │  + JWKS)    │  │  revocation)│  │  WebAuthn)  │  ║      │
   │   ║  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  ║      │
   │   ╚══════════════════════════════════════════════════════════════════════╝      │
   │                                                                                 │
   │   ╔══════════════════════════════════════════════════════════════════════╗      │
   │   ║                         IDENTITY PLANE                               ║      │
   │   ║                                                                      ║      │
   │   ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ║      │
   │   ║  │ User Svc    │  │ Tenant Svc  │  │ RBAC Svc    │  │ Keys Svc    │  ║      │
   │   ║  │ (Qeet ID    │  │ (orgs,      │  │ (Qeet ID    │  │ (M2M,       │  ║      │
   │   ║  │  ID)        │  │  branding)  │  │  Access)    │  │  API keys)  │  ║      │
   │   ║  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  ║      │
   │   ╚══════════════════════════════════════════════════════════════════════╝      │
   │                                                                                 │
   │   ╔══════════════════════════════════════════════════════════════════════╗      │
   │   ║                         FEDERATION PLANE                             ║      │
   │   ║                                                                      ║      │
   │   ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   ║      │
   │   ║  │ SAML Svc    │  │ SCIM Svc    │  │ Social IdP  │                   ║      │
   │   ║  │ (Connect)   │  │ (Connect)   │  │ Bridge      │                   ║      │
   │   ║  │             │  │             │  │             │                   ║      │
   │   ║  └─────────────┘  └─────────────┘  └─────────────┘                   ║      │
   │   ╚══════════════════════════════════════════════════════════════════════╝      │
   │                                                                                 │
   │   ╔══════════════════════════════════════════════════════════════════════╗      │
   │   ║                         GUARD / EDGE-PROTECTION PLANE                ║      │
   │   ║                                                                      ║      │
   │   ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   ║      │
   │   ║  │ Guard Svc   │  │ Anomaly Svc │  │ Audit       │                   ║      │
   │   ║  │ (rate limit,│  │ (impossible │  │ Ingestion   │                   ║      │
   │   ║  │  brute force)│ │  travel etc)│  │ Svc         │                   ║      │
   │   ║  └─────────────┘  └─────────────┘  └─────────────┘                   ║      │
   │   ╚══════════════════════════════════════════════════════════════════════╝      │
   │                                                                                 │
   │   ╔══════════════════════════════════════════════════════════════════════╗      │
   │   ║                  EXPERIENCE / SURFACE PLANE                          ║      │
   │   ║                                                                      ║      │
   │   ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ║      │
   │   ║  │ Admin Dash  │  │ Dev Portal  │  │ Hosted Login│  │ Billing Svc │  ║      │
   │   ║  │ Backend     │  │ Backend     │  │ Pages       │  │ (Stripe)    │  ║      │
   │   ║  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  ║      │
   │   ╚══════════════════════════════════════════════════════════════════════╝      │
   │                                                                                 │
   │   ╔══════════════════════════════════════════════════════════════════════╗      │
   │   ║                    ASYNC / BACKGROUND PLANE                          ║      │
   │   ║                                                                      ║      │
   │   ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   ║      │
   │   ║  │ Webhook     │  │ Notification│  │ Background  │                   ║      │
   │   ║  │ Delivery    │  │ Svc (mail,  │  │ Workers     │                   ║      │
   │   ║  │ Workers     │  │  SMS, push) │  │ (jobs)      │                   ║      │
   │   ║  └─────────────┘  └─────────────┘  └─────────────┘                   ║      │
   │   ╚══════════════════════════════════════════════════════════════════════╝      │
   └─────────────────────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │                              DATA TIER                                          │
   │                                                                                 │
   │   ┌──────────────────────┐  ┌──────────────────────┐  ┌─────────────────────┐   │
   │   │  PostgreSQL Aurora   │  │  Redis Cluster       │  │  Kafka (MSK)        │   │
   │   │  (primary)           │  │  (cache, sessions,   │  │  (events, audit     │   │
   │   │  - Read replicas x N │  │   rate limit, JWKS)  │  │   stream)           │   │
   │   │  - Sharded by        │  │                      │  │                     │   │
   │   │    tenant_id (≥100K) │  │                      │  │                     │   │
   │   └──────────────────────┘  └──────────────────────┘  └─────────────────────┘   │
   │                                                                                 │
   │   ┌──────────────────────┐  ┌──────────────────────┐  ┌─────────────────────┐   │
   │   │  S3 (audit cold,     │  │  AWS KMS +           │  │  OpenSearch         │   │
   │   │   backups, exports)  │  │  HashiCorp Vault     │  │  (log search;       │   │
   │   │                      │  │  (secrets, JWKS,     │  │   audit log query)  │   │
   │   │                      │  │   envelope keys)     │  │                     │   │
   │   └──────────────────────┘  └──────────────────────┘  └─────────────────────┘   │
   └─────────────────────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │                            OBSERVABILITY PLANE                                  │
   │                                                                                 │
   │   ┌──────────────────────┐  ┌──────────────────────┐  ┌─────────────────────┐   │
   │   │  Prometheus +        │  │  OpenTelemetry +     │  │  Loki / ELK         │   │
   │   │  Grafana             │  │  Jaeger or Tempo     │  │  (structured        │   │
   │   │  (metrics, SLOs)     │  │  (distributed trace) │  │   logs, 30d hot)    │   │
   │   └──────────────────────┘  └──────────────────────┘  └─────────────────────┘   │
   │                                                                                 │
   │   ┌──────────────────────┐  ┌──────────────────────┐  ┌─────────────────────┐   │
   │   │  PagerDuty           │  │  Status Page         │  │  Synthetic Probes   │   │
   │   │  (alerting,          │  │  (statuspage.io      │  │  (multi-region      │   │
   │   │   on-call rotation)  │  │   or in-house)       │  │   auth-flow checks) │   │
   │   └──────────────────────┘  └──────────────────────┘  └─────────────────────┘   │
   └─────────────────────────────────────────────────────────────────────────────────┘
```

---

### 5.1 Container Inventory

| # | Container | Plane | Purpose | Detailed in |
| --- | --- | --- | --- | --- |
| C-01 | Cloudflare WAF + Bot Management | Edge | OWASP rules, edge rate limiting, bot scoring before request hits AWS | Security Architecture §7 |
| C-02 | AWS Shield Advanced | Edge | L3/L4/L7 DDoS mitigation | Security Architecture §7 |
| C-03 | CloudFront | Edge | CDN for static assets (admin dash, dev portal, hosted login pages) | Infrastructure §6 |
| C-04 | AWS Application Load Balancer | Ingress | Layer-7 routing, TLS termination | Infrastructure §6 |
| C-05 | API Gateway + Istio Service Mesh | Ingress | mTLS, identity propagation, retries, circuit breaker, traffic policy | Security §4; Microservices §6 |
| C-06 | Auth Service | Core Auth | Login orchestration; passkey ceremony; password verification; step-up | Microservices §4; IdP Core §3 |
| C-07 | Token Service | Core Auth | OAuth 2.0 / OIDC token issuance; JWKS endpoint; introspection; revocation | Microservices §4; IdP Core §4 |
| C-08 | Session Service | Core Auth | Session creation, lookup, revocation; refresh-token rotation enforcement | Microservices §4; IdP Core §6 |
| C-09 | MFA Service | Core Auth | TOTP, SMS OTP, WebAuthn registration & verification | Microservices §4; IdP Core §7 |
| C-10 | User Service (Qeet ID ID) | Identity | User profile CRUD; identity merging; account lifecycle | Microservices §4 |
| C-11 | Tenant Service | Identity | Organisation lifecycle; tenant configuration; branding | Microservices §4; Multi-Tenancy §5 |
| C-12 | RBAC Service (Qeet ID Access) | Identity | Role & permission management; permission evaluation API | Microservices §4; Authorization §4 |
| C-13 | Keys Service (Qeet ID Keys) | Identity | API keys & service-account management; M2M issuance | Microservices §4 |
| C-14 | SAML Service (Qeet ID Connect — SAML) | Federation | SAML 2.0 SP + IdP roles; SLO; assertion validation | Microservices §4 |
| C-15 | SCIM Service (Qeet ID Connect — Provisioning) | Federation | SCIM 2.0 endpoints; deprovisioning propagation | Microservices §4 |
| C-16 | Social IdP Bridge | Federation | OIDC / OAuth bridge to Google, GitHub, MS, Apple | Microservices §4 |
| C-17 | Guard Service | Guard | Per-tenant, per-IP, per-client rate limiting; brute-force protection | Microservices §4; Security §8 |
| C-18 | Anomaly Service | Guard | Impossible-travel; new-device; unusual-time signals | Microservices §4; Security §9 |
| C-19 | Audit Ingestion Service | Guard | Audit-event consumer from Kafka; tamper-evident hash chain | Microservices §4; Database §10 |
| C-20 | Admin Dashboard Backend | Experience | API for the admin dashboard SPA | Microservices §4 |
| C-21 | Developer Portal Backend | Experience | API for the developer portal SPA | Microservices §4 |
| C-22 | Hosted Login Pages | Experience | Server-rendered universal login (HTML / CSS / JS) | Microservices §4 |
| C-23 | Billing Service | Experience | Stripe-integrated subscription, MAU metering, invoice mgmt | Microservices §4 |
| C-24 | Webhook Delivery Workers | Async | Reliable webhook dispatch with retry & exponential backoff | Microservices §4 |
| C-25 | Notification Service | Async | Email (SendGrid/SES), SMS (Twilio/SNS) dispatch | Microservices §4 |
| C-26 | Background Workers | Async | Maintenance jobs — token cleanup, retention enforcement | Microservices §4 |
| D-01 | PostgreSQL (Aurora) | Data | Authoritative store for users, tenants, tokens, audit metadata | Database §3 |
| D-02 | Redis Cluster (ElastiCache) | Data | Cache, sessions, rate-limit counters, JWKS cache | Database §11 |
| D-03 | Kafka (MSK) | Data | Audit event stream; webhook fan-out; cross-service events | Database §12 |
| D-04 | S3 | Data | Audit cold storage; backups; user data exports | Infrastructure §6 |
| D-05 | AWS KMS + HashiCorp Vault | Data | Key management; secrets; envelope encryption | Security §6 |
| D-06 | OpenSearch | Data | Indexed audit-log search for dashboard queries | Database §10 |
| O-01 | Prometheus + Grafana | Observability | Metrics + dashboards | Observability §3 |
| O-02 | OpenTelemetry + Jaeger/Tempo | Observability | Distributed tracing | Observability §5 |
| O-03 | Loki / ELK | Observability | Structured-log aggregation | Observability §4 |
| O-04 | PagerDuty | Observability | Paging + on-call rotation | Observability §7 |
| O-05 | Status Page | Observability | Public uptime + incident communication | Observability §11 |
| O-06 | Synthetic Monitoring | Observability | Multi-region auth-flow probes | Observability §10 |

---

### 6. Logical Architecture Layers

The Container view shows what runs. The Logical Layer view shows the responsibility separation that each container falls into. A new service is placed by identifying its layer before identifying its name.

```
   ┌─────────────────────────────────────────────────────────────────┐
   │                       LAYER 1 — EDGE                            │
   │   WAF, DDoS, CDN, edge rate limiting, bot management            │
   └─────────────────────────────────────────────────────────────────┘
                                  │
   ┌─────────────────────────────────────────────────────────────────┐
   │                       LAYER 2 — API GATEWAY / MESH              │
   │   TLS termination, mTLS, identity propagation, traffic policy   │
   └─────────────────────────────────────────────────────────────────┘
                                  │
   ┌─────────────────────────────────────────────────────────────────┐
   │                       LAYER 3 — APPLICATION SERVICES            │
   │   Core Auth, Identity, Federation, Guard, Experience            │
   └─────────────────────────────────────────────────────────────────┘
                                  │
   ┌─────────────────────────────────────────────────────────────────┐
   │                       LAYER 4 — DATA                            │
   │   PostgreSQL, Redis, Kafka, S3, OpenSearch, KMS / Vault         │
   └─────────────────────────────────────────────────────────────────┘
                                  │
   ┌─────────────────────────────────────────────────────────────────┐
   │                       LAYER 5 — BACKGROUND WORKERS              │
   │   Webhook delivery, notifications, retention jobs, exports      │
   └─────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────┐
   │                       LAYER 6 — OBSERVABILITY (cross-cut)       │
   │   Logs, metrics, traces, alerts, status page, synthetic probes  │
   └─────────────────────────────────────────────────────────────────┘
```

### 6.1 Layer 1 — Edge

Responsible for traffic that arrives from the public internet *before* it enters the Qeet ID VPC. The edge layer is the first defence boundary: WAF rules drop OWASP Top 10 attack patterns; AWS Shield Advanced absorbs volumetric DDoS; bot management scores requests; edge rate limiting sheds excess load before it consumes application capacity. CloudFront caches static assets (login pages, JS bundles, documentation) close to the user.

### 6.2 Layer 2 — API Gateway / Mesh

Inside the VPC, the API gateway and service mesh (Istio over Envoy) handle Layer-7 routing, TLS termination at the AWS ALB, internal mTLS between every pair of services, identity propagation (signed service-to-service tokens — SPIFFE-style by v2.0), traffic shaping (retries, timeouts, circuit breakers), and policy enforcement (which services may call which).

### 6.3 Layer 3 — Application Services

The bulk of the Qeet ID platform. Decomposed into five planes (Core Auth, Identity, Federation, Guard, Experience) as shown in §5. Each service is stateless, owns its data through the Data layer, communicates synchronously via REST inside the mesh, and asynchronously via Kafka.

### 6.4 Layer 4 — Data

Authoritative state. PostgreSQL Aurora is the system of record for users, tenants, credentials, tokens (refresh-token hashes, authorization codes), roles, applications, SAML/SCIM connections, audit metadata, and billing. Redis is the cache and ephemeral store for sessions, rate-limit counters, JWKS, permission lookups, and revocation bloom filters. Kafka carries audit events, webhook payloads, and cross-service domain events. S3 holds cold audit storage (12–84 months), backups, and user data exports. AWS KMS and HashiCorp Vault hold cryptographic keys (JWT signing keys, envelope data keys, secrets). OpenSearch indexes audit logs for dashboard search.

### 6.5 Layer 5 — Background Workers

Asynchronous workers consume from Kafka. Webhook delivery workers fan out customer-facing event notifications with exponential-backoff retry (NFR RT-01). Notification workers send transactional email and SMS via SendGrid/SES and Twilio/SNS. Retention workers enforce GDPR storage limitation and audit-log tiering. Export workers produce GDPR Article 20 data portability bundles.

### 6.6 Layer 6 — Observability (Cross-Cutting)

Not a layer the request flows through; a plane every layer feeds. Every service emits Prometheus metrics, OpenTelemetry traces, and structured JSON logs. PagerDuty receives critical alerts. Public status page and synthetic probes complete the customer-facing observability story.

---

### 7. High-Level Technology Stack Summary

| Category | Choice | Rationale | ADR |
| --- | --- | --- | --- |
| Orchestration | Kubernetes (Amazon EKS) | Industry-standard for stateless microservices; portable; team expertise | ADR-002 |
| Primary cloud | AWS | CTO mandate; broadest enterprise compliance posture; team expertise | ADR-003 |
| Primary database | PostgreSQL (Aurora) | ACID for auth state; mature multi-tenant patterns (RLS); portable | ADR-004 |
| Cache & session store | Redis (ElastiCache) | Sub-ms latency; well-supported patterns; portable | ADR-005 |
| Event streaming | Apache Kafka (MSK) | Durable, ordered, partitioned event log; audit-grade guarantees | ADR-006 |
| Object store | Amazon S3 | 11 nines durability; mature lifecycle policies; lock-in documented | ADR-003 |
| Secrets / KMS | AWS KMS + HashiCorp Vault | KMS for envelope encryption; Vault for dynamic secrets & DB credentials | ADR-014 |
| Service mesh | Istio (Envoy) | mTLS, identity propagation, telemetry; CNCF maturity | ADR-013 |
| API style | REST + OpenAPI 3.1 | SDK-friendly; mature tooling; conformance test ecosystem | ADR-007 |
| Token format | JWT with RS256 / ES256 | OIDC mandate; library maturity; no HS256, no `none` | ADR-009 |
| Password hashing | Argon2id | PHC winner; resistant to GPU brute-force; NIST/SP-800-63B aligned | ADR-010 |
| IaC | Terraform | Industry standard; rich provider ecosystem | ADR-016 |
| CI/CD | GitHub Actions | Aligned with GitHub-hosted SCM; mature; cheap | ADR-017 |
| Metrics | Prometheus + Grafana | OSS standard; CNCF maturity | Observability doc |
| Logs | Loki or ELK (TBD) | Structured-JSON pipeline; cost vs maturity trade-off | Observability doc |
| Tracing | OpenTelemetry + Jaeger or Tempo | Vendor-neutral instrumentation | ADR-015 |
| WAF / CDN / DDoS | Cloudflare + AWS Shield Advanced | Belt-and-braces; Cloudflare at edge, Shield inside | Security doc |
| Email | SendGrid (primary) + AWS SES (failover) | NFR IC-07 | NFR §13.2 |
| SMS | Twilio (primary) + AWS SNS (failover) | NFR IC-08 | NFR §13.2 |
| Billing | Stripe | NFR IC-06; PCI burden offloaded; trusted | NFR §13.2 |
| SDKs at MVP | React, Next.js, Node.js, Python, Flutter, Go | Charter §5; Persona-driven priorities | Charter |
| IdP core base layer | Keycloak vs Ory vs Build — *Open Decision* | See §10 / IdP Core §3 / [Open Decisions Register](Open-Decisions-Register.md) | ADR-011 (Proposed) |

---

### 8. Multi-Region Topology

Qeet ID launches in two AWS regions and extends in scheduled waves.

| Phase | Region | Role | Status |
| --- | --- | --- | --- |
| Launch | AWS us-east-1 (N. Virginia) | Primary — US customers; primary control plane | MVP |
| Launch | AWS eu-west-1 (Ireland) | Primary — EU customers; GDPR data residency | MVP |
| v1.2 | AWS ap-southeast-1 (Singapore) | APAC residency; PDPA alignment | Roadmap |
| v1.2 | AWS eu-west-2 (London) | UK residency | Roadmap |
| v2.0 | GCP secondary | Multi-cloud readiness | Roadmap |

```
    ┌─────────────────────────────────────────────────────────────────┐
    │                  GLOBAL CONTROL PLANE                           │
    │  (Customer billing master, sub-processor registry, status page) │
    └─────────────────────────────────────────────────────────────────┘
                                  │
              ┌───────────────────┴────────────────────┐
              ▼                                        ▼
   ┌──────────────────────────┐           ┌──────────────────────────┐
   │   us-east-1 (Primary)    │           │   eu-west-1 (Primary)    │
   │                          │           │                          │
   │   - 3 AZ × EKS cluster   │           │   - 3 AZ × EKS cluster   │
   │   - Aurora PG cluster    │           │   - Aurora PG cluster    │
   │   - Redis Cluster        │           │   - Redis Cluster        │
   │   - MSK Kafka            │           │   - MSK Kafka            │
   │   - S3 (regional)        │           │   - S3 (regional)        │
   │                          │           │                          │
   │   Tenant data: US-only   │           │   Tenant data: EU-only   │
   │   (data residency        │           │   (data residency        │
   │    enforced at write     │           │    enforced at write     │
   │    time)                 │           │    time)                 │
   └──────────────────────────┘           └──────────────────────────┘
              │   (cross-region replication of                │
              │    Tier-1 backups only — encrypted)           │
              └──────────────────────────────┬─────────────────┘
                                             ▼
                            ┌─────────────────────────────┐
                            │   us-west-2 (DR replica)    │
                            │   Backup-only target;       │
                            │   warm-standby pattern.     │
                            └─────────────────────────────┘
```

Tenant data is **pinned** to one region. Cross-region replication is only for backups (encrypted, region-mirrored for disaster recovery — NFR DR-08). No tenant data crosses a region boundary in operational traffic without explicit customer-configured federation (e.g., an EU tenant deliberately federating to a US-hosted SAML IdP).

### 8.1 Data Residency Enforcement

Tenants select a residency region at creation. The tenant record stores `data_region`. Every write path checks `data_region` against the executing region; a tenant operation attempting to write outside its region is rejected at the API gateway. This is the mechanism that satisfies NFR CN-05 and the Compliance Matrix data-residency commitment.

### 8.2 Region Failover (Enterprise Tier)

For Enterprise tenants that opt into multi-region active-active in v1.5, a per-tenant active-passive PostgreSQL stream is established and a region-failover runbook activates. This is **post-MVP** — at launch, region failover is a manual disaster-recovery procedure with the 4-hour RTO target (NFR DR-01).

---

### 9. Cross-Cutting Concerns

### 9.1 Identity Propagation

Customer-facing requests carry a customer access token (OAuth bearer). Internally, services authenticate to each other via short-lived service tokens signed by an internal CA inside the service mesh — SPIFFE-style identities targeted for v2.0; AWS IAM-IRSA + mTLS via Istio at MVP (ADR-013). Every internal request includes a `tenant_id` header derived from the inbound token claims and validated at every hop.

### 9.2 Multi-Tenancy

`tenant_id` is the architectural backbone. It appears:
- In every JWT issued by Qeet ID (as `qeetify/org_id` per Protocol Requirements §5.6).
- In every HTTP request as `X-Tenant-ID` (server-derived, never client-asserted).
- In every database row (in compound indexes, in the WHERE clause of every query).
- In every cache key as a prefix.
- In every log line and metric label.
- In every Kafka event key (for partition-level isolation).

The detailed model is in [Qeet ID — Multi-Tenancy Architecture](Qeet ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md). The summary: PostgreSQL row-level security with `tenant_id` for shared tier; schema-per-tenant for Enterprise dedicated; database-per-shard from 100,000 tenants (NFR MT-05).

### 9.3 Observability

Detailed in [Qeet ID — Observability Architecture](Qeet ID%20%E2%80%94%20Observability%20Architecture.md). The principle here is that observability is a *first-class architectural concern*, not an operational afterthought. Every service includes observability instrumentation in its first PR; services that emit no metrics or traces fail their integration test gate.

### 9.4 Security

Detailed in [Qeet ID — Security Architecture (Zero Trust)](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md). Zero Trust is the operating model: no implicit trust based on network location; every request authenticated, authorised, and audited.

### 9.5 Idempotency

Every state-changing write supports idempotency. Public APIs accept an `Idempotency-Key` header (NFR ID-02). Internal services accept event IDs. Webhooks include unique event IDs (NFR ID-04). This is described in [Qeet ID — API Design Standards](Qeet ID%20%E2%80%94%20API%20Design%20Standards.md).

### 9.6 Versioning

Public APIs are versioned in the URI (`/v1/...`). Breaking changes require a new major version. The minimum backwards-compatibility window is 12 months (NFR AR-03). Internal service APIs are versioned via Kafka topic naming and HTTP headers; internal breaking changes are coordinated through the service-to-service contract test suite.

---

### 10. Architecture Constraints

| # | Constraint | Source | Implication |
| --- | --- | --- | --- |
| AC-01 | SOC 2 Type I before production launch | Compliance §5.1 | Architecture must produce auditable evidence — access logs, change logs, key rotations — by Phase 5 |
| AC-02 | GDPR compliance at launch | Compliance §4 | Data subject rights API + erasure + portability shipped at MVP |
| AC-03 | FIDO Alliance FIDO2 Server Certification before launch | Protocol §12.1 | WebAuthn implementation must use vetted library; conformance test suite must pass |
| AC-04 | OpenID Foundation Basic OP Certification before launch | Protocol §5.1 | OIDC discovery, JWKS, ID-token, UserInfo all conform to the Basic OP profile |
| AC-05 | Microservices on Kubernetes from Day 1 | Stakeholder findings; CTO mandate | No monolith fallback even for MVP velocity |
| AC-06 | Multi-tenant data isolation architecturally impossible to violate | NFR TO-07, MT-01 | RLS + tenant scoping at every layer; cross-tenant access cannot exist by code path |
| AC-07 | Auth-critical services must be cloud-portable | NFR PO-01 | No AWS-only managed dependency on the auth-critical path beyond ALB, EKS, Aurora, ElastiCache, MSK, KMS, S3 — all of which have GCP/Azure equivalents |
| AC-08 | Six SDKs at MVP (React, Next.js, Node.js, Python, Flutter, Go) | Charter §5 | OpenAPI 3.1 spec must be the single source of truth for SDK generation/validation |
| AC-09 | 99.9% uptime SLA on paid tiers from launch | NFR AV-02 | Multi-AZ from day one; no SPOF; automated failover |
| AC-10 | p95 OAuth `/token` < 200 ms; end-to-end login p95 < 800 ms | NFR PF-02, §4.4 | Latency budget binds service choices; synchronous dependency depth ≤ 3 hops on hot path |
| AC-11 | Refresh token rotation mandatory; reuse triggers session revocation | Protocol OS-06/OS-07 | Token Service holds the source-of-truth state; Redis cache must be invalidated at the same time |
| AC-12 | Passkeys are the default authentication method | Persona / Competitive analysis | Hosted login pages prompt passkey registration after email verification; password is a fallback path |
| AC-13 | Audit log integrity with hash-chaining | Compliance ALT-03 | Append-only architecture; no in-place mutation; Kafka topic → S3 cold tier with checksums |
| AC-14 | Backwards compatibility 12 months minimum | NFR AR-03 | Versioning, deprecation register, automated contract tests on every release |
| AC-15 | Data residency enforced at write time | NFR CN-05 | Region-pinned tenant records; gateway-level region guards |

---

### 11. Architecture Open Questions

These items are *not* fabricated resolutions — they are the open decisions Phase 2 must close. Each appears in [Open-Decisions-Register.md](Open-Decisions-Register.md).

| # | Question | Carried From | Owner | Target Resolution |
| --- | --- | --- | --- | --- |
| OQ-01 | IdP core base layer — Keycloak vs Ory vs build-from-scratch | Stakeholder findings; CTO/SA conflict | Solution Architect + CTO + Legal | Phase 2 Week 4 (License audit prerequisite) |
| OQ-02 | Final logging stack — Loki + Grafana vs ELK + Kibana | NFR §11.1; cost vs maturity | SRE Lead | Phase 2 close |
| OQ-03 | Service mesh — Istio vs Linkerd | Stakeholder team capacity | DevOps Lead + Solution Architect | Phase 2 close |
| OQ-04 | DPO appointment vs documented exemption | Compliance CG-01 | Legal Counsel | Phase 1 close — carried forward |
| OQ-05 | Sub-processor DPA confirmations (6 of 10 outstanding) | Compliance CG-02 | Legal + Compliance | Phase 3 |
| OQ-06 | Customer Support tooling (Intercom vs Zendesk) | Compliance SP-07 | Compliance Officer | Phase 2 close |
| OQ-07 | Hosted login pages — Qeet ID-rendered universal login vs SDK-rendered + tenant-hosted | UX vs federation flow complexity | Product + Solution Architect | Phase 3 entry |
| OQ-08 | Multi-region active-active vs warm-standby for Enterprise tier at v1.5 | NFR FO-06; sales pressure | DevOps + Solution Architect | Post-MVP planning |
| OQ-09 | SPIFFE/SPIRE adoption timing for workload identity | NFR NS-05 (target v2.0) | Security Architect | v2.0 design |
| OQ-10 | Database isolation per service (database-per-service vs schema-per-service in shared Aurora) | NFR AR-01; cost vs purity | Database Architect | Phase 2 — Database doc |

---

### 12. Dependencies on Other Phase 2 Documents

This document is the entry point of Phase 2. Every other document in Phase 2 depends on the goals, principles, container inventory, and constraints stated here. The relationships are:

```
        ┌─────────────────────────────────────┐
        │  1. High-Level System Architecture  │   ◀── (this document)
        └──────────────────┬──────────────────┘
                           │ refined by
   ┌───────────────────────┼───────────────────────┐
   ▼                       ▼                       ▼
2. Microservices    9. Security             6. Multi-Tenancy
   Decomposition       Architecture            Architecture
   │                    │                       │
   ▼                    ▼                       ▼
3. IdP Core Engine  4. Auth Flow Designs   5. Authorization Engine
   │                    │                       │
   └───────┬────────────┴───────────┬───────────┘
           ▼                        ▼
      7. Database              8. API Design Standards
         Design
           │                        │
           └────────────┬───────────┘
                       ▼
          10. Infrastructure & Deployment
                       │
                       ▼
              11. Observability
                       │
                       ▼
         12. Architecture Decision Records  ◀── (running log)
```

Cross-references in this document are not optional. Every architectural choice that any downstream document makes that is *not* derivable from a Phase 1 baseline must trace to a principle, a container, a constraint, or an open question stated here.

---

### 13. Architecture Risks

| # | Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| AR-01 | Open-source base-layer choice (OQ-01) slips → MVP timeline pressure on auth engine | High | High | Set a hard decision date of Phase 2 Week 4; if undecided, default to Ory (more permissive license + smaller surface) and revisit; document fallback in ADR-011 |
| AR-02 | Latency budget violated on hot path due to synchronous chain depth | Medium | High | Enforce ≤ 3-hop sync depth in design reviews; budget allocation matrix per service in NFR §4.4 |
| AR-03 | Tenant isolation breach via shared cache key collision | Low | Critical | Cache key namespacing tested in property-based tests; Phase 6 chaos-tested with adversarial tenant probes |
| AR-04 | JWKS rotation drops in-flight tokens | Low | High | Mandatory 24-hour retired-key retention (Protocol JW-07); rotation rehearsed quarterly in staging |
| AR-05 | Cloud lock-in accumulates faster than tracked | Medium | Medium | Annual Cloud Lock-In Register review (NFR PO-07); ADR required for any new vendor-specific dependency |
| AR-06 | SOC 2 readiness blocked by missing access-log evidence | Medium | High | Audit logging architecture committed in this Phase 2 (NFR LG-01 to LG-10) — wired in services from first commit |
| AR-07 | Kubernetes complexity outstrips team capacity at scale | Medium | Medium | Managed EKS chosen; service-mesh capability ramped progressively; on-call runbooks shipped per service |
| AR-08 | Refresh-token rotation race conditions cause valid user logouts | Medium | High | Single-writer pattern in Token Service; rotation transactional in Postgres; reuse alerts not auto-revokes during first 30 days of production (tune from real traffic) |

---

### 14. Out of Scope for This Document

The following are explicitly **not** in scope for this document and live elsewhere:

- Service-by-service responsibility, ownership, and SLO tier → [Microservices Decomposition](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)
- Detailed token lifecycle and key rotation procedures → [IdP Core Engine Design](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md)
- Step-by-step authentication flows (OAuth, SAML, WebAuthn) → [Authentication Flow Designs](Qeet ID%20%E2%80%94%20Authentication%20Flow%20Designs.md)
- RBAC model, permission evaluation algorithm, ABAC migration plan → [Authorization Engine Design](Qeet ID%20%E2%80%94%20Authorization%20Engine%20Design.md)
- Entity-relationship and schema details → [Database Design & Data Model](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)
- Concrete OpenAPI conventions → [API Design Standards](Qeet ID%20%E2%80%94%20API%20Design%20Standards.md)
- STRIDE threat model, control mapping → [Security Architecture (Zero Trust)](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md)
- Cloud account layout, IaC modules, environment promotion → [Infrastructure & Deployment Architecture](Qeet ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md)
- Metric catalog, log schema, trace sampling → [Observability Architecture](Qeet ID%20%E2%80%94%20Observability%20Architecture.md)
- Decision records — context, options, consequences → [Architecture Decision Records](Qeet ID%20%E2%80%94%20Architecture%20Decision%20Records%20%28ADRs%29.md)

---

### 15. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Solution Architect |  |  |  |
| Security Architect |  |  |  |
| CTO |  |  |  |
| Backend Engineering Lead |  |  |  |
| DevOps / SRE Lead |  |  |  |
| Database Architect |  |  |  |
| API Designer |  |  |  |
| Product Manager |  |  |  |
| Compliance Officer |  |  |  |

---

*This document is version controlled. The High-Level System Architecture is a living specification — it must be reviewed when a new container is added or removed, when a new region is brought online, when a constraint in the NFR or Compliance baseline changes, or when an Open Decision in §11 is resolved. Any deviation from the principles in §3 during downstream Phase 2 or Phase 4 work requires an Architecture Decision Record reviewed by the Solution Architect and CTO before the deviation is accepted.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
