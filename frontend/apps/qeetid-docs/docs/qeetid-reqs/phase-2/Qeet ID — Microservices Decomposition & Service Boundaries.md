# Qeet ID — Microservices Decomposition & Service Boundaries

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Microservices Decomposition & Service Boundaries |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Solution Architect + Backend Lead |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document decomposes the Qeet ID platform into independently deployable microservices. It defines each service's responsibility, the data it owns, its external and internal APIs, its dependencies, its SLO tier, and its owning team. It also defines the communication patterns between services and the anti-patterns that the team must refuse to adopt.

The High-Level System Architecture establishes the shape of the system; this document populates that shape. It is the contract between architecture and engineering. By Phase 4, every service in §4 has a repository, a CI pipeline, a runbook, and an on-call rotation. By Phase 9, every service in §4 is running in production.

The audience is the Backend Engineering Lead, every backend engineering team lead, the Solution Architect, the DevOps Lead, the SRE Lead, and the Product Manager.

This document depends on [Qeet ID — High-Level System Architecture](Qeet ID%20%E2%80%94%20High-Level%20System%20Architecture.md). It is referenced by every downstream Phase 2 document.

---

### 3. Decomposition Principles

Microservices are not free. Every service boundary is a network hop, a deployment pipeline, an on-call rotation, a database migration plan, and a coordination cost. The principles below are the rules by which Qeet ID accepts those costs.

**DP-01 — Bounded Contexts Define Boundaries.** A service exists because its model is meaningfully different from neighbouring models. User authentication state is not the same model as user profile state is not the same model as user authorization state — these are three services, not three modules in one service.

**DP-02 — Single Responsibility, Plural Capabilities.** A service does one thing. The Token Service issues, introspects, revokes tokens — that is one thing (token lifecycle). The User Service stores user identity — that is one thing (user identity). A service that "handles authentication and also sends marketing emails" is two services.

**DP-03 — Data Ownership is Exclusive.** Each piece of data has exactly one owning service. Cross-service reads go through the owning service's API or through asynchronous events on Kafka. No service reads another service's database directly. This is non-negotiable (NFR AR-01).

**DP-04 — Independently Deployable.** A service ships without coordinated deploys of other services. Breaking changes go through versioning and deprecation. A failure to deploy independently is treated as an architecture defect.

**DP-05 — Right-Sized, Not Nano-Sized.** A service is large enough to justify its own pipeline, on-call rotation, and database schema. Qeet ID does not chase "nanoservices" — a service that fits on half a screen of code and exists for its own sake is anti-pattern. We target services that a team of 2–4 engineers can own without becoming the only person who understands them.

**DP-06 — Synchronous on the Hot Path, Asynchronous Everywhere Else.** Authentication, token issuance, permission checks: synchronous REST. Audit-log writes, webhook delivery, notifications, analytics aggregation, retention enforcement: asynchronous Kafka. This division is enforced in design reviews (HLSA P-09).

**DP-07 — Service Hierarchy is Flat.** Services are peers. There is no "orchestrator service that calls 20 services in sequence" pattern in the Qeet ID auth path; the closest thing — the Auth Service — coordinates only its own work. Sagas and choreographed event flows replace orchestration where multi-step flows exist.

**DP-08 — Bounded Sync-Depth.** On the user-perceived hot path, a request crosses at most three synchronous service hops (NFR §4.4 latency budget). Beyond three, the design is reviewed and refactored.

**DP-09 — Tenancy is Explicit, Not Inferred.** Every service request — internal or external — carries `tenant_id`. No service infers tenancy from caller identity alone. The Multi-Tenancy doc defines propagation.

**DP-10 — Polyglot Within Reason.** Backend services default to Go or Node.js (TypeScript). Other languages (Python for ML/analytics, Rust for performance-critical components) require an ADR. SDKs are deliberately polyglot for customers; backend polyglot is a deliberate trade-off, not a default.

---

### 4. Service Catalog

This section is the authoritative list of services Qeet ID ships at MVP. Each service has a uniform specification.

The SLO tier values follow the High-Level Architecture model:

| Tier | Description | Examples |
| --- | --- | --- |
| Tier 0 | Auth hot path; outage = customer outage | Token Service, Auth Service, JWKS, Guard Service |
| Tier 1 | Auth supporting path; degraded function on outage | Session Service, MFA Service, User Service, RBAC Service, SAML, SCIM |
| Tier 2 | Administrative / experience; tolerates degradation | Admin Dashboard Backend, Dev Portal Backend, Billing |
| Tier 3 | Asynchronous; queue absorbs outage | Webhook Delivery, Notifications, Audit Ingestion (best-effort latency) |

Service ownership is allocated across five small backend teams plus a platform team:

- **Team Auth** — Core Auth Plane
- **Team Identity** — Identity Plane
- **Team Federation** — Federation Plane
- **Team Guard** — Guard Plane + audit pipeline
- **Team Experience** — Experience Plane (admin, dev portal, hosted login, billing)
- **Team Platform** — Service mesh, ingress, observability backbone, IaC modules

---

### 4.1 Auth Service

| Field | Value |
| --- | --- |
| Service ID | svc-auth |
| Plane | Core Auth |
| SLO Tier | Tier 0 |
| Owning Team | Team Auth |
| Responsibility | Orchestrates user authentication ceremonies — login, MFA challenge, passkey ceremony, step-up, account recovery. Decides which factor(s) are required for a given context and per-tenant policy. Issues the *authentication assertion* that the Token Service exchanges for tokens. |
| Owns | `authentication_attempts`, `mfa_challenges`, `recovery_tokens`, `passkey_ceremonies`. No long-lived credential state — that lives in User Service / MFA Service. |
| External API | `POST /v1/login`, `POST /v1/login/mfa/verify`, `POST /v1/login/passkey/options`, `POST /v1/login/passkey/verify`, `POST /v1/login/social/{provider}`, `POST /v1/login/magic-link`, `POST /v1/recover`, `POST /v1/step-up` |
| Internal API | `POST /internal/assertion` (issues short-lived signed authentication assertion to Token Service) |
| Sync deps | User Service (credential lookup), MFA Service, Guard Service (rate-limit check, anomaly score), Tenant Service (policy lookup) |
| Async deps | Audit events to Kafka topic `audit.authentication.*` |
| External deps | HIBP (compromised password), social IdPs via Social IdP Bridge |
| Performance | NFR PF-08 (login p95 500ms), PF-09 (passkey 300ms), §4.4 budget |

### 4.2 Token Service

| Field | Value |
| --- | --- |
| Service ID | svc-token |
| Plane | Core Auth |
| SLO Tier | Tier 0 (highest — `/token` and JWKS) |
| Owning Team | Team Auth |
| Responsibility | OAuth 2.0 / OIDC token issuance, refresh-token rotation, authorization-code single-use enforcement, introspection (RFC 7662), revocation (RFC 7009), JWKS publication, signing-key rotation. The cryptographic boundary of the platform. |
| Owns | `authorization_codes`, `refresh_tokens` (hashed), `signing_keys`, `revocation_list`. ID/access tokens are *issued* not stored. |
| External API | `GET /oauth/authorize`, `POST /oauth/token`, `POST /oauth/introspect`, `POST /oauth/revoke`, `GET /oidc/userinfo`, `GET /.well-known/openid-configuration`, `GET /.well-known/oauth-authorization-server`, `GET /.well-known/jwks.json` |
| Internal API | `POST /internal/keys/rotate`, `GET /internal/keys/status` |
| Sync deps | Auth Service (authentication assertion verification), User Service (subject claims), RBAC Service (roles/permissions claims), Tenant Service (issuer, scopes) |
| Async deps | Audit events `audit.token.*` |
| Performance | NFR PF-02 (200ms p95), PF-06 (50ms discovery), PF-07 (50ms JWKS) |

### 4.3 Session Service

| Field | Value |
| --- | --- |
| Service ID | svc-session |
| Plane | Core Auth |
| SLO Tier | Tier 1 |
| Owning Team | Team Auth |
| Responsibility | Lifecycle of authenticated sessions across the platform — creation on successful authentication, validation, idle / absolute timeouts, listing per user, revocation, propagation of revocation. Distinct from the OAuth token state owned by Token Service: a session is a logical authentication artefact; tokens are short-lived credentials issued within a session. |
| Owns | `sessions` (Redis for hot reads, PostgreSQL as system of record), `session_revocations` |
| External API | `GET /v1/sessions`, `DELETE /v1/sessions/{id}`, `DELETE /v1/users/{user_id}/sessions` (admin) |
| Internal API | `POST /internal/sessions`, `GET /internal/sessions/{id}`, `POST /internal/sessions/revoke` |
| Sync deps | User Service, Guard Service |
| Async deps | Audit events `audit.session.*`; revocation events broadcast on `auth.session.revoked` |
| Performance | Hot reads from Redis < 5ms p99 |

### 4.4 MFA Service

| Field | Value |
| --- | --- |
| Service ID | svc-mfa |
| Plane | Core Auth |
| SLO Tier | Tier 1 |
| Owning Team | Team Auth |
| Responsibility | MFA enrolment and verification for TOTP, SMS OTP, email OTP, and WebAuthn (passkey). Backup-code generation and validation. The cryptographic boundary for MFA secrets. |
| Owns | `mfa_factors`, `totp_seeds_encrypted`, `passkey_credentials`, `backup_codes_hashed`, `mfa_verification_attempts` |
| External API | `POST /v1/mfa/enroll/totp`, `POST /v1/mfa/enroll/passkey/options`, `POST /v1/mfa/enroll/passkey/verify`, `POST /v1/mfa/enroll/sms`, `POST /v1/mfa/factors`, `DELETE /v1/mfa/factors/{id}`, `POST /v1/mfa/backup-codes` |
| Internal API | `POST /internal/mfa/challenge`, `POST /internal/mfa/verify` |
| Sync deps | User Service, Notification Service (SMS/email OTP dispatch), Tenant Service (policy) |
| External deps | FIDO MDS3 (attestation); Twilio (SMS) |
| Performance | NFR PF-09 (passkey verify 300ms p95) |

### 4.5 User Service (Qeet ID ID)

| Field | Value |
| --- | --- |
| Service ID | svc-user |
| Plane | Identity |
| SLO Tier | Tier 1 |
| Owning Team | Team Identity |
| Responsibility | User profile management — create, read, update, delete users; identity merging; account states (active, suspended, deleted); user search within a tenant; user metadata; GDPR Art. 15 / 17 / 20 fulfilment hooks (export, erasure). System of record for *who* a user is. Does not hold authentication state (Auth Service) or authorization state (RBAC Service). |
| Owns | `users`, `user_profiles`, `user_metadata`, `user_status_history`, `email_verifications`, `phone_verifications` |
| External API | `POST /v1/users`, `GET /v1/users`, `GET /v1/users/{id}`, `PATCH /v1/users/{id}`, `DELETE /v1/users/{id}`, `POST /v1/users/{id}/export`, `POST /v1/users/{id}/erase` |
| Internal API | `GET /internal/users/{id}/credentials-summary`, `POST /internal/users/{id}/state` |
| Sync deps | Tenant Service |
| Async deps | Emits `user.created`, `user.updated`, `user.suspended`, `user.deleted` events |

### 4.6 Tenant Service

| Field | Value |
| --- | --- |
| Service ID | svc-tenant |
| Plane | Identity |
| SLO Tier | Tier 1 (cache-warm Tier 0 in practice — most tenant lookups served from Redis) |
| Owning Team | Team Identity |
| Responsibility | Organisation lifecycle — create, configure, suspend, delete tenants. Tenant configuration (branding, login policies, password policies, MFA policies, allowed identity factors, allowed grant types, residency region, default scopes). Tenant membership (which Qeet ID-internal admin users belong to which tenant). |
| Owns | `tenants`, `tenant_configurations`, `tenant_admins`, `tenant_branding`, `tenant_policies`, `tenant_residency` |
| External API | `POST /v1/organizations`, `GET /v1/organizations/{id}`, `PATCH /v1/organizations/{id}`, `DELETE /v1/organizations/{id}`, `GET /v1/organizations/{id}/configuration`, `PATCH /v1/organizations/{id}/configuration` |
| Internal API | `GET /internal/tenants/{id}/policy/{topic}` (cacheable) |
| Sync deps | None inbound (root of identity graph) |
| Async deps | Emits `tenant.created`, `tenant.updated`, `tenant.deleted` |

### 4.7 RBAC Service (Qeet ID Access)

| Field | Value |
| --- | --- |
| Service ID | svc-rbac |
| Plane | Identity |
| SLO Tier | Tier 0 on permission-check path; Tier 1 on management path |
| Owning Team | Team Identity |
| Responsibility | RBAC for MVP: role definition, permission definition, role assignment, group assignment, synchronous permission evaluation. Permission claims for inclusion in access tokens. Forward-compatibility hooks for ABAC (v1.5) and FGA / Zanzibar-style (v2.0). |
| Owns | `roles`, `permissions`, `role_permissions`, `user_role_assignments`, `group_role_assignments`, `permission_evaluation_log` |
| External API | `POST /v1/roles`, `GET /v1/roles`, `PATCH /v1/roles/{id}`, `DELETE /v1/roles/{id}`, `POST /v1/permissions`, `POST /v1/role-assignments`, `POST /v1/permissions/check` |
| Internal API | `GET /internal/permissions/{user_id}` (cacheable), `POST /internal/permissions/check` |
| Sync deps | User Service, Tenant Service |
| Performance | NFR PF-15 (permission check p95 60ms) |

### 4.8 SAML Service (Qeet ID Connect — SAML)

| Field | Value |
| --- | --- |
| Service ID | svc-saml |
| Plane | Federation |
| SLO Tier | Tier 1 |
| Owning Team | Team Federation |
| Responsibility | SAML 2.0 Service Provider AND Identity Provider roles. AuthnRequest generation, assertion validation, response signing, SLO. Per-tenant IdP-metadata storage. Attribute mapping configuration. Interop with Microsoft Entra ID, Okta, Google Workspace, Ping (NFR IT-01 to IT-04). |
| Owns | `saml_connections`, `saml_idp_metadata`, `saml_assertion_audit`, `saml_session_index` (for SLO) |
| External API | `GET /saml/{tenant}/metadata`, `POST /saml/{tenant}/acs`, `GET /saml/{tenant}/slo`, `POST /v1/saml/connections`, `POST /v1/saml/connections/{id}/metadata` |
| Internal API | `POST /internal/saml/issue-assertion` (Qeet ID-as-IdP) |
| Sync deps | User Service (JIT user upsert), Tenant Service (per-tenant config), Auth Service (issuing internal authentication assertion after SAML success) |
| Async deps | Audit events |
| Performance | NFR PF-10/PF-11 |

### 4.9 SCIM Service (Qeet ID Connect — Provisioning)

| Field | Value |
| --- | --- |
| Service ID | svc-scim |
| Plane | Federation |
| SLO Tier | Tier 1 |
| Owning Team | Team Federation |
| Responsibility | SCIM 2.0 endpoints. User and Group resource CRUD, PATCH semantics, filtering, schema discovery. Deprovisioning propagation within 60 seconds (NFR DI-04). |
| Owns | `scim_endpoints`, `scim_sync_state`, `scim_provisioning_log`, `scim_external_id_map` |
| External API | `GET/POST /scim/v2/Users`, `GET/PUT/PATCH/DELETE /scim/v2/Users/{id}`, `GET/POST /scim/v2/Groups`, `GET/PUT/PATCH/DELETE /scim/v2/Groups/{id}`, `GET /scim/v2/ServiceProviderConfig`, `GET /scim/v2/Schemas`, `GET /scim/v2/ResourceTypes` |
| Internal API | n/a (writes go to User and RBAC services via internal events) |
| Sync deps | User Service (user upsert), RBAC Service (role assignment via groups), Tenant Service |
| Async deps | On `active=false` PATCH — emits `user.deprovisioned` on Kafka; Session Service subscribes and revokes |
| Performance | NFR PF-12/PF-13 |

### 4.10 Social IdP Bridge

| Field | Value |
| --- | --- |
| Service ID | svc-social |
| Plane | Federation |
| SLO Tier | Tier 1 |
| Owning Team | Team Federation |
| Responsibility | OIDC / OAuth bridge to Google, GitHub, Microsoft, Apple. Token exchange. Profile normalisation into Qeet ID User model. Account-linking semantics. |
| Owns | `social_connections`, `social_id_map` |
| External API | `GET /v1/oauth/social/{provider}/authorize`, `GET /v1/oauth/social/{provider}/callback` |
| Internal API | `POST /internal/social/link`, `POST /internal/social/unlink` |
| Sync deps | User Service (JIT), Auth Service |

### 4.11 Keys Service (Qeet ID Keys)

| Field | Value |
| --- | --- |
| Service ID | svc-keys |
| Plane | Identity |
| SLO Tier | Tier 0 on validation path; Tier 1 on management |
| Owning Team | Team Identity |
| Responsibility | API key issuance, validation, revocation, rotation, scoping, environment separation. Service-account management for OAuth Client Credentials grant. Leak detection coordination. |
| Owns | `api_keys` (HMAC-SHA256 hash + prefix only), `service_accounts`, `api_key_usage_log` (aggregated), `api_key_rotation_state` |
| External API | `POST /v1/api-keys`, `GET /v1/api-keys`, `DELETE /v1/api-keys/{id}`, `POST /v1/api-keys/{id}/rotate`, `POST /v1/service-accounts` |
| Internal API | `POST /internal/keys/validate` (used by API Gateway / ingress) |
| Sync deps | Tenant Service, RBAC Service |
| Performance | NFR PF-14 (API key validation 40ms p95) |

### 4.12 Guard Service

| Field | Value |
| --- | --- |
| Service ID | svc-guard |
| Plane | Guard |
| SLO Tier | Tier 0 (gate on hot path) |
| Owning Team | Team Guard |
| Responsibility | Per-tenant, per-IP, per-client, per-endpoint rate limiting (NFR RL-01..RL-10). Brute-force lockout (Compliance AS-03). Edge bot signals consumption from Cloudflare. Per-tenant resource quotas. |
| Owns | `rate_limit_buckets` (Redis), `lockout_state`, `quota_state`, `bot_score_cache` |
| External API | n/a (interior service; consulted via internal call from API Gateway and Auth Service) |
| Internal API | `POST /internal/guard/check` (returns allow / deny / challenge), `POST /internal/guard/record` |
| Sync deps | Tenant Service (quotas), Cloudflare API (bot signal — async refresh) |
| Performance | < 20 ms p95 — sits in the request path of every authenticated request |

### 4.13 Anomaly Service

| Field | Value |
| --- | --- |
| Service ID | svc-anomaly |
| Plane | Guard |
| SLO Tier | Tier 2 (consumes events asynchronously; emits alerts) |
| Owning Team | Team Guard |
| Responsibility | Detects anomalous authentication patterns — impossible travel, new-device login, unusual time-of-day. Emits security signals consumed by Auth Service (step-up triggers) and Audit pipeline. ML-based detection is **deferred to v1.5**; MVP uses rule-based heuristics. |
| Owns | `device_fingerprints`, `recent_login_geo`, `anomaly_signals` |
| External API | `GET /v1/security-events` (for tenant admins) |
| Internal API | `POST /internal/anomaly/score` (synchronous fast-path); subscribes to `auth.login.succeeded` events |

### 4.14 Audit Ingestion Service

| Field | Value |
| --- | --- |
| Service ID | svc-audit-ingest |
| Plane | Guard |
| SLO Tier | Tier 1 (no acceptable loss — NFR SL-08; latency budget relaxed) |
| Owning Team | Team Guard |
| Responsibility | Consumes audit events from Kafka. Writes to PostgreSQL audit tables (hot tier). Computes hash chain. Tiers older events to S3 (cold). Indexes for OpenSearch (search tier). |
| Owns | `audit_log_hot`, `audit_log_hash_chain`, S3 audit-bucket lifecycle, OpenSearch index |
| External API | n/a — read access via Admin Dashboard Backend |
| Internal API | n/a |
| Sync deps | None (purely async) |
| Async deps | Subscribes to all `audit.*` Kafka topics |

### 4.15 Webhook Delivery Workers

| Field | Value |
| --- | --- |
| Service ID | svc-webhook |
| Plane | Async |
| SLO Tier | Tier 3 (queue absorbs outage) |
| Owning Team | Team Experience |
| Responsibility | Customer-facing webhook delivery. HMAC-SHA256 signing per subscription. Exponential backoff up to 10 retries / 24 hours (NFR RT-01). Delivery history. Dead-letter queue for permanent failures. |
| Owns | `webhook_subscriptions`, `webhook_deliveries`, `webhook_signing_secrets`, DLQ topic |
| External API | `POST /v1/webhooks`, `GET /v1/webhooks`, `DELETE /v1/webhooks/{id}`, `GET /v1/webhooks/{id}/deliveries` |
| Internal API | n/a |
| Async deps | Subscribes to platform event topics; publishes delivery results to `webhook.delivery.*` |
| Performance | NFR ER-05 (>99.95% within retry policy) |

### 4.16 Notification Service

| Field | Value |
| --- | --- |
| Service ID | svc-notification |
| Plane | Async |
| SLO Tier | Tier 3 |
| Owning Team | Team Experience |
| Responsibility | Transactional email and SMS dispatch. Provider failover (SendGrid → AWS SES; Twilio → AWS SNS). Template management. Localisation. Idempotent send via `Idempotency-Key`. |
| Owns | `email_templates`, `notification_outbox`, `notification_delivery_log` |
| External API | `POST /v1/notifications/test` (admin-only) |
| Internal API | `POST /internal/notifications/email`, `POST /internal/notifications/sms` |
| External deps | SendGrid, AWS SES, Twilio, AWS SNS |

### 4.17 Admin Dashboard Backend

| Field | Value |
| --- | --- |
| Service ID | svc-admin-bff |
| Plane | Experience |
| SLO Tier | Tier 2 |
| Owning Team | Team Experience |
| Responsibility | Backend-for-frontend for the admin dashboard SPA. Aggregates calls to underlying services. Page-shaped APIs (`/dashboard/overview`, `/users/list`, etc.) optimised for the UI's render needs. Not a substitute for the public APIs — admin users hit the same underlying services as customers. |
| Owns | Dashboard view-model caches only — no domain state |
| External API | `/v1/dashboard/*` (admin-only, authenticated as tenant admin) |

### 4.18 Developer Portal Backend

| Field | Value |
| --- | --- |
| Service ID | svc-portal-bff |
| Plane | Experience |
| SLO Tier | Tier 2 |
| Owning Team | Team Experience |
| Responsibility | Backend for the developer portal (docs, API explorer, SDK downloads, status). Search index for documentation. Code-sample generation. |

### 4.19 Hosted Login Pages

| Field | Value |
| --- | --- |
| Service ID | svc-hosted-login |
| Plane | Experience |
| SLO Tier | Tier 0 (on the user login path) |
| Owning Team | Team Experience + Team Auth |
| Responsibility | The server-rendered universal login experience that customers redirect end users to. Branded per tenant. Conditional UI for passkeys. Localisation in 10 languages at MVP (NFR IN-02). |
| Owns | Per-tenant branding cache, localisation bundles |

### 4.20 Billing Service

| Field | Value |
| --- | --- |
| Service ID | svc-billing |
| Plane | Experience |
| SLO Tier | Tier 2 |
| Owning Team | Team Experience |
| Responsibility | Stripe integration. Subscription lifecycle. MAU metering — counts unique users per tenant per month, rolls up nightly, emits usage to Stripe metered billing. Invoice generation. Tax handling. |
| Owns | `subscriptions`, `mau_counters`, `invoices`, `payment_methods` (Stripe references only) |
| External API | `GET /v1/billing/subscription`, `POST /v1/billing/upgrade`, `POST /v1/billing/portal-session` |
| External deps | Stripe (primary integration) |

### 4.21 Background Workers (Maintenance)

| Field | Value |
| --- | --- |
| Service ID | svc-workers |
| Plane | Async |
| SLO Tier | Tier 3 |
| Owning Team | Team Platform |
| Responsibility | Scheduled jobs and queue consumers that do not belong to any single business service: retention enforcement (delete expired tokens, prune audit hot tier), GDPR Art. 17 erasure execution, export bundle generation, MAU rollup, JWKS key-rotation timer, leak-detection scanner. |
| Owns | Job state in PostgreSQL; outputs in S3 |

---

### 5. Service Catalog Summary Table

| # | Service | Plane | Tier | Owning Team | Core Storage |
| --- | --- | --- | --- | --- | --- |
| 01 | Auth Service | Core Auth | 0 | Team Auth | Postgres + Redis |
| 02 | Token Service | Core Auth | 0 | Team Auth | Postgres + Redis + KMS |
| 03 | Session Service | Core Auth | 1 | Team Auth | Redis (hot) + Postgres |
| 04 | MFA Service | Core Auth | 1 | Team Auth | Postgres + KMS |
| 05 | User Service | Identity | 1 | Team Identity | Postgres |
| 06 | Tenant Service | Identity | 1 | Team Identity | Postgres + Redis cache |
| 07 | RBAC Service | Identity | 0/1 | Team Identity | Postgres + Redis cache |
| 08 | SAML Service | Federation | 1 | Team Federation | Postgres |
| 09 | SCIM Service | Federation | 1 | Team Federation | Postgres |
| 10 | Social IdP Bridge | Federation | 1 | Team Federation | Postgres |
| 11 | Keys Service | Identity | 0/1 | Team Identity | Postgres + Redis |
| 12 | Guard Service | Guard | 0 | Team Guard | Redis |
| 13 | Anomaly Service | Guard | 2 | Team Guard | Postgres |
| 14 | Audit Ingestion | Guard | 1 | Team Guard | Postgres + S3 + OpenSearch |
| 15 | Webhook Delivery | Async | 3 | Team Experience | Postgres + Kafka |
| 16 | Notification Service | Async | 3 | Team Experience | Postgres |
| 17 | Admin Dashboard BFF | Experience | 2 | Team Experience | none (BFF) |
| 18 | Dev Portal BFF | Experience | 2 | Team Experience | none (BFF) |
| 19 | Hosted Login Pages | Experience | 0 | Auth + Experience | none (stateless render) |
| 20 | Billing Service | Experience | 2 | Team Experience | Postgres + Stripe |
| 21 | Background Workers | Async | 3 | Team Platform | Postgres + S3 |

---

### 6. Service Communication Patterns

### 6.1 Synchronous (REST over HTTP/2, mTLS)

All synchronous service-to-service traffic is REST over HTTP/2 inside the service mesh. mTLS is enforced by Istio (ADR-013). The mesh injects a service identity header derived from the calling pod's identity; the receiving service validates that identity against an allow-list of permitted callers (NS-05).

Within the mesh, services use JSON request/response bodies. Internal endpoints are prefixed `/internal/*` and are blocked by ingress — they are mesh-reachable only.

**Hop-depth budget.** Per principle DP-08, the synchronous hop depth on the user-perceived hot path is at most three: e.g., `Gateway → Auth Service → User Service` and back. Deeper chains require approval at design review.

**Timeouts and retries.** Default sync call timeout: 800 ms. Default retry policy: 2 retries on idempotent calls with 100 ms / 300 ms backoff + jitter (NFR RT-06). Non-idempotent calls do not retry.

**Circuit breakers.** Istio circuit breakers open after consecutive 5xx threshold per upstream; mode is fail-fast. Auth-critical services degrade gracefully — e.g., RBAC Service failure does not block authentication, only blocks permission claims (token issuance proceeds with empty permissions claim and an audited degradation flag).

### 6.2 Asynchronous (Kafka)

Asynchronous events flow on Apache Kafka topics. Every event carries:

- `event_id` (UUID v7 — sortable)
- `event_type` (dotted namespace, e.g. `auth.login.succeeded`)
- `tenant_id`
- `actor_id` and `target_id` where applicable
- `timestamp` (ISO 8601 UTC)
- `version` (schema version)
- `payload`

Topics follow `{plane}.{aggregate}.{verb}` naming, e.g. `audit.authentication.login_succeeded`, `user.profile.updated`, `scim.user.deprovisioned`. Partition key is `tenant_id` for ordering guarantees per-tenant.

**Schema management.** Avro or JSON Schema; schema registry tracked in the Kafka cluster. Backwards-compatible schema evolution only — adding fields is allowed, removing or repurposing is not.

**Delivery guarantees.** At-least-once. Consumers must be idempotent. Idempotency hooks: dedupe on `event_id` for 24 hours in consumer-side Redis (NFR ID-06).

**Replay.** Kafka retention on `audit.*` topics is 7 days — sufficient for any consumer recovery; long-term durability is the S3 cold tier.

### 6.3 Topic Inventory (MVP)

| Topic | Producer | Consumers | Retention |
| --- | --- | --- | --- |
| `audit.authentication.*` | Auth Service | Audit Ingestion, Anomaly | 7 days |
| `audit.token.*` | Token Service | Audit Ingestion | 7 days |
| `audit.session.*` | Session Service | Audit Ingestion | 7 days |
| `audit.admin.*` | Admin BFF, Tenant Service | Audit Ingestion | 7 days |
| `audit.scim.*` | SCIM Service | Audit Ingestion | 7 days |
| `audit.saml.*` | SAML Service | Audit Ingestion | 7 days |
| `audit.security.*` | Guard, Anomaly | Audit Ingestion, Notification | 7 days |
| `user.*` | User Service | Webhook, Notification | 3 days |
| `tenant.*` | Tenant Service | Webhook, Notification | 3 days |
| `auth.session.revoked` | Session Service | Token Service, Webhook | 3 days |
| `scim.user.deprovisioned` | SCIM Service | Session Service, Audit | 3 days |
| `webhook.delivery.*` | Webhook | Observability ingestion | 1 day |
| `notification.outbox.*` | Notification | Notification dispatcher | 1 day |

---

### 7. Service Dependency Graph

The dependency graph below shows synchronous dependencies (solid arrows) and the most significant asynchronous topics (dashed arrows). It is the directed acyclic graph that the team must keep cycle-free.

```
                                 ┌───────────────┐
                                 │  API Gateway  │
                                 └───────┬───────┘
                                         │
              ┌───────────┬──────────────┼──────────────┬───────────┬──────────┐
              ▼           ▼              ▼              ▼           ▼          ▼
       ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────┐  ┌──────────┐
       │  Auth    │  │  Token   │  │  SCIM    │  │   SAML   │  │ Keys │  │ Admin BFF│
       │  Service │  │  Service │  │  Service │  │  Service │  │  Svc │  │          │
       └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──┬───┘  └────┬─────┘
            │             │             │             │           │           │
            │             ├─────────────┴─────────────┘           │           │
            │             ▼                                       │           │
            │        ┌──────────┐                                 │           │
            │        │ RBAC Svc │ ◀───────────────────────────────┘           │
            │        └────┬─────┘                                             │
            │             │                                                  │
            └─────┬───────┴───────┬──────────────┬──────────────┐            │
                  ▼               ▼              ▼              ▼            │
            ┌──────────┐    ┌──────────┐  ┌──────────┐   ┌──────────┐       │
            │  Guard   │    │  MFA Svc │  │ User Svc │   │Tenant Svc│ ◀─────┘
            │ Service  │    │          │  │          │   │          │
            └────┬─────┘    └────┬─────┘  └────┬─────┘   └────┬─────┘
                 │               │             │              │
                 │               ▼             ▼              ▼
                 │       ┌──────────────────────────────────────┐
                 │       │           PostgreSQL Aurora          │
                 │       └──────────────────────────────────────┘
                 ▼
            ┌──────────┐
            │  Redis   │
            └──────────┘

   Async (Kafka):
       Auth ──audit.*──▶ Audit Ingestion
       SCIM ──scim.user.deprovisioned──▶ Session Service ──auth.session.revoked──▶ Token Service
       User ──user.*──▶ Webhook Workers + Notification Service
       Session ──audit.session.*──▶ Audit Ingestion
       Anomaly ──audit.security.*──▶ Audit Ingestion + Notification
```

The graph is cycle-free by construction. There is no synchronous edge from Tenant Service or User Service back into any Core Auth service.

---

### 8. Anti-Patterns to Avoid

The following patterns are explicitly forbidden. A pull request that introduces any of them is rejected on review.

**AP-01 — Shared databases across services.** Service A reading Service B's tables directly. Every cross-service read is a contract violation. Use B's API or an event from B.

**AP-02 — The distributed monolith.** Services deployed together because they cannot deploy apart. If `svc-token` and `svc-session` must always release in lockstep, they are not independent services. The Token Service ↔ Session Service contract is held stable; any breaking change is versioned.

**AP-03 — The chatty hot path.** A login flow that fans out to twelve services before completing. The hop-depth budget (≤3) enforces this.

**AP-04 — The "auth orchestrator" anti-service.** A single service that coordinates everything because no one wanted to push logic to the right place. Each plane owns its responsibilities; Auth Service coordinates the authentication ceremony, not the universe.

**AP-05 — Cross-tenant data leakage via shared cache key.** Cache keys that omit `tenant_id`. Every cache key includes the tenant. This is verified in property-based tests in CI.

**AP-06 — Eventual consistency on the auth hot path.** Revocation that takes minutes to propagate. Token Service and Session Service share a synchronous revocation contract within 60 seconds (NFR DI-03).

**AP-07 — "Just a quick gRPC" inside the mesh.** Internal traffic is REST over HTTP/2 inside the mesh until v2.0. gRPC adoption requires an ADR — tooling, observability, and client diversity considerations.

**AP-08 — JWT for service-to-service auth without rotation.** Internal service tokens are short-lived (5 minutes) and rotated; we never embed a long-lived HS256 service token in code or config.

**AP-09 — Per-service auth-policy reimplementation.** Auth checks for incoming requests live in the mesh + API Gateway. Services trust the propagated identity; they do not reverify the customer token on every call.

**AP-10 — Drift between OpenAPI and implementation.** Public endpoints whose OpenAPI spec lags the code. The spec is the contract; CI fails when implementation drifts (NFR IO-07).

---

### 9. Service Sizing & Team Ownership

| Team | Services | Headcount Target | On-call Rotation |
| --- | --- | --- | --- |
| Team Auth | Auth, Token, Session, MFA, Hosted Login (co-own) | 5 engineers | Primary + secondary |
| Team Identity | User, Tenant, RBAC, Keys | 4 engineers | Primary + secondary |
| Team Federation | SAML, SCIM, Social IdP Bridge | 3 engineers | Primary + secondary |
| Team Guard | Guard, Anomaly, Audit Ingestion | 3 engineers | Primary + secondary |
| Team Experience | Admin BFF, Dev Portal BFF, Hosted Login (co-own), Billing, Webhook, Notification | 4 engineers | Primary + secondary |
| Team Platform | Mesh, gateway, IaC, observability, Background Workers | 3 engineers | Primary + secondary |

Total backend headcount target ≈ 22 engineers at MVP. Aligned to Charter §9 (Backend Engineers 3–4 underestimates the team Phase 1 actually needs; flagged for resource planning revision in Charter v1.1).

Each service has:

- A single owning team
- A primary + secondary on-call rotation (NFR IR-10)
- A runbook in the team's internal docs (NFR AR-09)
- An SLO target derived from §4 tier and the NFR §11.5 table
- A CI pipeline that runs unit, integration, contract, and security gates
- A staging deployment that mirrors production topology (ADR-017)

---

### 10. Service Lifecycle & Versioning

### 10.1 Service Birth

A new service is created only when:

1. It owns a bounded context not currently served by an existing service.
2. It has at least one identified data set that no other service currently owns.
3. The owning team has spare capacity and on-call commitment.
4. An ADR documents the introduction.

### 10.2 Service Versioning

- **External API:** versioned in URI (`/v1/`). New major version means new path. Old version coexists for ≥ 12 months (NFR AR-03).
- **Internal API:** versioned via Kafka topic naming and HTTP request headers. Breaking changes require coordinated deploy plan; contract tests in CI block accidental breaks.
- **Event Schema:** registered in the Kafka schema registry; backwards-compatible additions only without a version bump.

### 10.3 Service Death

A service is deprecated when its responsibility is merged into another, the bounded context disappears, or the v2.0 architecture supersedes it. Deprecation requires:

1. Customer-facing deprecation notice (12-month minimum for public APIs).
2. Internal communication and migration plan.
3. Read-only operation phase before deletion.
4. Final ADR documenting the wind-down.

---

### 11. Cross-References

- High-level shape: [High-Level System Architecture](Qeet ID%20%E2%80%94%20High-Level%20System%20Architecture.md) §5 (Container Diagram)
- IdP core internals (Auth Service, Token Service, MFA Service): [IdP Core Engine Design](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md)
- Authentication flows that traverse services: [Authentication Flow Designs](Qeet ID%20%E2%80%94%20Authentication%20Flow%20Designs.md)
- Authorization model (RBAC Service internals): [Authorization Engine Design](Qeet ID%20%E2%80%94%20Authorization%20Engine%20Design.md)
- Multi-tenancy enforcement at the data layer: [Multi-Tenancy Architecture](Qeet ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md)
- Database ownership per service: [Database Design & Data Model](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)
- Service mesh and ingress: [Infrastructure & Deployment Architecture](Qeet ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md)
- Service-to-service mTLS and identity propagation: [Security Architecture (Zero Trust)](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md)
- Service-level SLO mapping to monitoring: [Observability Architecture](Qeet ID%20%E2%80%94%20Observability%20Architecture.md)

---

### 12. Open Decisions Carried From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OQ-MS-01 | Should Audit Ingestion be a single service or split (writer + indexer + tiering)? | Team Guard + SA | Phase 2 close |
| OQ-MS-02 | Should Hosted Login be its own service or part of Auth Service for latency? | Team Auth + UX | Phase 3 entry |
| OQ-MS-03 | Should Background Workers be one service or per-team workers? | Team Platform | Phase 2 close |
| OQ-MS-04 | Default backend language — Go vs Node.js (TypeScript) | Backend Lead | Phase 2 Week 4 |
| OQ-MS-05 | gRPC adoption timing inside the mesh (post-v2.0?) | Solution Architect | Post-MVP |

All recorded in [Open-Decisions-Register.md](Open-Decisions-Register.md).

---

### 13. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Solution Architect |  |  |  |
| Backend Engineering Lead |  |  |  |
| DevOps / SRE Lead |  |  |  |
| Database Architect |  |  |  |
| Security Architect |  |  |  |
| Product Manager |  |  |  |
| Team Auth Lead |  |  |  |
| Team Identity Lead |  |  |  |
| Team Federation Lead |  |  |  |
| Team Guard Lead |  |  |  |
| Team Experience Lead |  |  |  |
| Team Platform Lead |  |  |  |

---

*This document is version controlled. The Service Catalog is a living register — services may be added, merged, or retired with a Solution Architect–signed ADR. Changes to a service's responsibility, ownership, or SLO tier require a Backend Engineering Lead and Solution Architect review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
