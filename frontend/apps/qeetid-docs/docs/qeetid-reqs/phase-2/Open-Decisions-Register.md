# Qeet ID — Open Decisions Register

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Open Decisions Register |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Solution Architect |
| **Date** | May 19, 2026 |
| **Status** | Living document — updated as decisions close |

---

### 2. Purpose

This register collects every open architectural decision surfaced during Phase 1 (carried forward) and during Phase 2. Each entry names the question, the owner accountable for resolution, the target resolution date, and a pointer to the document(s) where the open question is discussed.

Resolving an open decision typically produces an ADR. Once an ADR is `Accepted`, the corresponding row here is closed out (status `Closed`) with a pointer to the ADR.

---

### 3. Register

#### 3.1 Carried Forward From Phase 1

| # | Question | Source (Phase 1) | Owner | Target | Status |
| --- | --- | --- | --- | --- | --- |
| OQ-P1-01 | IdP core base layer — Keycloak vs Ory vs Build | Stakeholder findings; Compliance CG-06 | Solution Architect + CTO + Legal | Phase 2 Week 4 | ADR-011 Proposed |
| OQ-P1-02 | DPO appointment vs documented exemption | Compliance CG-01 | Legal Counsel | Phase 1 close (overdue) | Open |
| OQ-P1-03 | Sub-processor DPA confirmations (6 of 10 outstanding) | Compliance CG-02 | Legal + Compliance | Phase 3 | Open |
| OQ-P1-04 | FIDO2 certification process initiation | Compliance CG-03 | Engineering + QA | Phase 6 | Open |
| OQ-P1-05 | OIDC conformance test suite scheduling | Compliance CG-04 | QA + Engineering | Phase 6 | Open |
| OQ-P1-06 | SOC 2 audit firm engagement | Compliance CG-05 | Compliance Officer | Phase 5 | Open |
| OQ-P1-07 | Cloud provider region selection per residency | Compliance CG-06 | CTO + DevOps + Legal | Phase 2 close | Partially closed — ADR-003 confirms AWS primary; region detail in Infrastructure doc §4 |
| OQ-P1-08 | CCPA applicability threshold analysis | Compliance CG-07 | Legal Counsel | Phase 4 | Open |
| OQ-P1-09 | Bug bounty program scope and platform | Compliance CG-08 | Security + Legal | Phase 8 | Open |

#### 3.2 From Doc 1 — High-Level System Architecture

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-01 | IdP core base layer — same as OQ-P1-01 | SA + CTO + Legal | Phase 2 Week 4 | Tied to ADR-011 Proposed |
| OQ-02 | Final logging stack — Loki + Grafana vs ELK + Kibana | SRE Lead | Phase 2 close | Open |
| OQ-03 | Service mesh — Istio vs Linkerd | DevOps + Solution Architect | Phase 2 close | Open (preliminary direction: Istio per ADR-013 discussion) |
| OQ-07 | Hosted login pages — Qeet ID universal login vs SDK-rendered + tenant-hosted | Product + Solution Architect | Phase 3 entry | Open |
| OQ-08 | Multi-region active-active vs warm-standby for Enterprise tier at v1.5 | DevOps + Solution Architect | Post-MVP planning | Open |
| OQ-09 | SPIFFE/SPIRE adoption timing for workload identity | Security Architect | v2.0 design | Open |
| OQ-10 | Database isolation per service (database-per-service vs schema-per-service in shared Aurora) | Database Architect | Phase 2 close | Open |

#### 3.3 From Doc 2 — Microservices Decomposition

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-MS-01 | Should Audit Ingestion be a single service or split (writer + indexer + tiering)? | Team Guard + SA | Phase 2 close | Open |
| OQ-MS-02 | Should Hosted Login be its own service or part of Auth Service for latency? | Team Auth + UX | Phase 3 entry | Open |
| OQ-MS-03 | Should Background Workers be one service or per-team workers? | Team Platform | Phase 2 close | Open |
| OQ-MS-04 | Default backend language — Go vs Node.js (TypeScript) | Backend Lead | Phase 2 Week 4 | Open |
| OQ-MS-05 | gRPC adoption timing inside the mesh (post-v2.0?) | Solution Architect | Post-MVP | Open |

#### 3.4 From Doc 3 — IdP Core Engine Design

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-IDP-01 | Final base-layer choice (Hydra vs Keycloak vs Build) — ADR-011 | SA + CTO + Legal | Phase 2 Week 4 | Tied to ADR-011 Proposed |
| OQ-IDP-02 | RS256 default vs ES256 default for new tenants | Security Architect | Phase 2 close | Open |
| OQ-IDP-03 | Refresh-token rotation reuse-detect auto-revoke enable date | Backend Lead | 30 days post-launch | Open (date will be set on launch) |
| OQ-IDP-04 | Argon2id parameter re-tune review cadence (annual?) | Security Architect | Phase 2 close | Open (preliminary direction: annual) |
| OQ-IDP-05 | Default OAuth token endpoint auth method order (private_key_jwt vs client_secret_post) | API Designer + SA | Phase 2 close | Open |

#### 3.5 From Doc 4 — Authentication Flow Designs

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-AF-01 | Default behaviour when SAML IdP does not support SLO — local logout only with banner vs forced logout with warning | Product + Federation | Phase 3 entry | Open |
| OQ-AF-02 | Magic-link signing key rotation cadence (90 days vs shorter) | Security Architect | Phase 2 close | Open |
| OQ-AF-03 | Step-up: re-authenticate same factor vs require a stronger factor by default | Security Architect + Product | Phase 2 close | Open |
| OQ-AF-04 | Account recovery fallback when user has no enrolled factors — manual review queue vs hard-fail | Product + Compliance | Phase 3 entry | Open |

#### 3.6 From Doc 5 — Authorization Engine Design

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-AZ-01 | ABAC policy language (Cedar vs Rego/OPA vs custom DSL) | Solution Architect + Backend Lead | v1.5 planning | Open |
| OQ-AZ-02 | Default audit sampling rate for allow decisions (1% vs 5% vs 0.1%) | Compliance + SRE | Phase 2 close | Open |
| OQ-AZ-03 | Whether application-scoped roles ship at MVP or v1.1 | Product Manager | Phase 2 close | Open |
| OQ-AZ-04 | Default `permissions_claim_mode` (`full` vs `summary`) for new clients | Product + DX | Phase 3 entry | Open |
| OQ-AZ-05 | FGA store choice (OpenFGA vs SpiceDB vs Ory Keto vs build) for v2.0 | Solution Architect | v2.0 design | Open |

#### 3.7 From Doc 6 — Multi-Tenancy Architecture

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-MT-01 | Default L1 shard size (tenants per shard target) | DBA + DevOps | Phase 2 close | Open (preliminary: 20–30K) |
| OQ-MT-02 | Cooling-off period for tenant deletion (24h vs 7-day) | Compliance + Product | Phase 2 close | Open |
| OQ-MT-03 | Whether to expose tenant_id (UUID) or only slug to customers via API | API Designer | Phase 2 close | Open |
| OQ-MT-04 | L3 (fully dedicated) design timing — v2.0 vs v1.5 | CTO + Sales | Post-MVP planning | Open |
| OQ-MT-05 | Cross-region migration availability (Enterprise only?) | Product + Compliance | Phase 2 close | Open |

#### 3.8 From Doc 7 — Database Design & Data Model

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-DB-01 | Per-tenant JWKS for Enterprise tier (separate signing keys per Enterprise tenant)? | Security + SA | Phase 2 close | Open |
| OQ-DB-02 | Database-per-service vs schema-per-service in the shared Aurora cluster | Database Architect | Phase 2 close | Open |
| OQ-DB-03 | OpenSearch vs Elastic Cloud vs hosted self-managed for audit search | DevOps + SRE | Phase 2 close | Open |
| OQ-DB-04 | Pepper rotation procedure — sweep all hashes vs background re-hash on login | Security Architect | Phase 2 close | Open |
| OQ-DB-05 | Whether to expose `users.global_id` cross-tenant identity model in customer APIs at MVP | API Designer + Privacy | Phase 2 close | Open |

#### 3.9 From Doc 8 — API Design Standards

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-API-01 | Documentation renderer (Redoc vs Stoplight vs Scalar) | DevRel + Tech Writing | Phase 3 entry | Open |
| OQ-API-02 | Webhook signing — single secret per subscription vs key versioning at MVP | Security + Backend | Phase 2 close | Open (preliminary: key versioning) |
| OQ-API-03 | Bulk export job pattern — synchronous (≤30 s) vs always-async with job handle | API Designer + Product | Phase 2 close | Open |
| OQ-API-04 | Whether to support `_embed` / inlined related resources at MVP | DX + Backend | Phase 2 close | Open |
| OQ-API-05 | GraphQL post-MVP — v2.0 introduction vs deferred | DevRel + SA | Post-MVP planning | Open |

#### 3.10 From Doc 9 — Security Architecture

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-SEC-01 | SPIFFE/SPIRE adoption — v2.0 vs sooner | Security Architect | v2.0 design | Open |
| OQ-SEC-02 | Egress proxy choice (Cloudflare vs AWS Network Firewall vs custom PoC) | DevOps + Security | Phase 2 close | Open |
| OQ-SEC-03 | Bug bounty platform (HackerOne vs Bugcrowd vs Intigriti) | CISO + Legal | Phase 6 | Open |
| OQ-SEC-04 | DAST tool selection for staging post-deploy | QA Lead + Security | Phase 2 close | Open |
| OQ-SEC-05 | Customer-managed encryption keys (BYOK) for Enterprise tier — v1.5 target | Security + Product | v1.5 planning | Open |

#### 3.11 From Doc 10 — Infrastructure & Deployment

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-INF-01 | Monorepo vs multi-repo for service code | Backend Lead + DevOps | Phase 2 close | Open (preliminary: multi-repo) |
| OQ-INF-02 | Argo CD vs Flux for GitOps | Platform Team | Phase 2 close | Open |
| OQ-INF-03 | Schema registry — Karapace vs AWS Glue Schema Registry vs Confluent | DevOps | Phase 2 close | Open |
| OQ-INF-04 | Aurora Global Database (active-active EE) — v1.5 vs v1.2 | Product + DevOps | Post-MVP planning | Open |
| OQ-INF-05 | AWS Wickr vs PagerDuty for sensitive ops comms | CISO | Phase 2 close | Open |

#### 3.12 From Doc 11 — Observability Architecture

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OQ-OBS-01 | Logging stack — Loki vs ELK | SRE Lead | Phase 2 close | Open |
| OQ-OBS-02 | Tracing backend — Jaeger vs Tempo | SRE Lead | Phase 2 close | Open |
| OQ-OBS-03 | Synthetic monitoring — self-hosted vs Checkly | SRE Lead | Phase 2 close | Open |
| OQ-OBS-04 | RUM tool — Grafana Faro vs Datadog RUM vs Sentry | DX + SRE | Phase 2 close | Open |
| OQ-OBS-05 | Status page — Statuspage.io vs self-hosted | Product + SRE | Phase 2 close | Open |
| OQ-OBS-06 | Long-term metrics store — Mimir vs Thanos vs hosted Grafana Cloud | SRE Lead | Phase 2 close | Open |
| OQ-OBS-07 | Datadog as a secondary surface — adopt at MVP vs later | CTO + Finance | Phase 2 close | Open |

---

### 4. Resolution Cadence

The Solution Architect convenes a weekly Open Decisions review until Phase 2 close. Decisions resolved produce an ADR (or a smaller decision note for non-architectural choices) and update the corresponding row's status here. The register is the single source of truth for "what's still open"; do not rely on individual document open-question lists for tracking.

### 5. Phase 2 Close Gating

Phase 2 cannot be declared complete (per the Phase-2-Exit-Checklist) while any open question with target "Phase 2 close" remains unresolved. Items targeting later phases (Phase 3 entry, Phase 6, v1.5, v2.0) are tracked here for visibility but do not gate Phase 2 close.

---

### 6. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Solution Architect |  |  |  |
| Product Manager |  |  |  |
| Compliance Officer (Phase 1 carry-forwards) |  |  |  |

---

*This document is version controlled. The register is a living artefact — entries added as decisions are surfaced, closed as decisions are made. Phase 2 close requires every Phase-2-targeted entry to be resolved.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
