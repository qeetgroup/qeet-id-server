# Qeet ID — Non-Functional Requirements (NFR)

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Non-Functional Requirements (NFR) Document |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Solution Architect |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the complete set of Non-Functional Requirements (NFRs) for the Qeet ID Authentication and Authorization platform. While the Feature Prioritization Matrix defines *what* Qeet ID must do, this document defines *how well* it must do it. NFRs are the quality attributes that determine whether Qeet ID can be trusted in production: how fast it responds, how much load it can handle, how secure it is, how reliable it remains during failure, how observable it is in operation, and how maintainable it stays as it grows.

In an authentication platform, NFRs are not secondary concerns. A functional feature that fails to meet its performance SLA, security baseline, or availability commitment becomes a liability rather than a capability. A login system that works at 100 users per second but collapses at 10,000 is not a working login system at scale. A platform that returns correct authentication responses but logs nothing is not auditable. A service that achieves 99% uptime but never the 99.9% promised in customer contracts triggers SLA credits and erodes trust.

This document is the authoritative reference for the Solution Architect, Security Architect, DevOps Lead, SRE Lead, and QA Lead during Phase 2 (System Design), Phase 5 (Infrastructure & DevOps), and Phase 6 (Testing & QA). Every NFR specified here must be testable, measurable, and tracked through the platform's lifecycle. NFRs without measurement are aspirations, not requirements.

---

### 3. NFR Category Overview

| # | Category | Description | Priority Bias |
| --- | --- | --- | --- |
| 1 | Performance | Response time, throughput, latency, and resource efficiency targets | High |
| 2 | Scalability | Capacity to grow horizontally and vertically across users, tenants, and traffic | Critical |
| 3 | Availability | Uptime SLAs, redundancy, failover behaviour, and disaster recovery | Critical |
| 4 | Reliability | Fault tolerance, error rates, recovery objectives, data durability | Critical |
| 5 | Security | Encryption, vulnerability management, authentication of infrastructure itself, defence in depth | Critical |
| 6 | Compliance | Regulatory and certification obligations applied to system behaviour | Critical |
| 7 | Maintainability | Code quality, modularity, dependency management, technical debt control | High |
| 8 | Observability | Logging, metrics, tracing, alerting, and runbook readiness | Critical |
| 9 | Usability | UX consistency, accessibility, internationalization | High |
| 10 | Interoperability | Standards conformance, integration compatibility, API stability | High |
| 11 | Portability | Multi-cloud capability, deployment flexibility, vendor independence | Medium |
| 12 | Capacity & Resource | Storage, memory, compute budgets, and growth modeling | High |
| 13 | Data Integrity | Consistency models, durability guarantees, conflict handling | Critical |
| 14 | Operability | Operational readiness, runbooks, incident response, on-call posture | Critical |
| 15 | Cost Efficiency | Unit economics, infrastructure cost per MAU, budget governance | Medium |

---

### 4. Performance Requirements

### 4.1 Performance Principles

Performance for an authentication platform is measured at the percentile, not the average. A 50ms average response time is meaningless if the 99th percentile is 8 seconds, because that 1% of failures will appear in every customer support ticket, every status page incident, and every churn analysis. All performance targets in this document are stated as percentiles, with p50, p95, and p99 distinct measurements that all must be satisfied.

---

### 4.2 Response Time Requirements

| # | Endpoint / Operation | p50 | p95 | p99 | Max Acceptable | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| PF-01 | OAuth /oauth/authorize redirect | 50 ms | 150 ms | 300 ms | 500 ms | Backend Engineering |
| PF-02 | OAuth /oauth/token (auth code exchange) | 80 ms | 200 ms | 400 ms | 800 ms | Backend Engineering |
| PF-03 | OAuth /oauth/token (refresh) | 60 ms | 150 ms | 300 ms | 600 ms | Backend Engineering |
| PF-04 | OAuth /oauth/introspect | 30 ms | 100 ms | 200 ms | 400 ms | Backend Engineering |
| PF-05 | OIDC /userinfo | 40 ms | 120 ms | 250 ms | 500 ms | Backend Engineering |
| PF-06 | OIDC /.well-known/openid-configuration | 20 ms (cached) | 50 ms | 100 ms | 200 ms | Backend Engineering |
| PF-07 | JWKS endpoint | 20 ms (cached) | 50 ms | 100 ms | 200 ms | Backend Engineering |
| PF-08 | Password login (full flow) | 200 ms | 500 ms | 1,000 ms | 2,000 ms | Backend Engineering |
| PF-09 | Passkey assertion verification | 100 ms | 300 ms | 500 ms | 1,000 ms | Backend Engineering |
| PF-10 | SAML AuthnRequest generation | 80 ms | 200 ms | 400 ms | 800 ms | Backend Engineering |
| PF-11 | SAML assertion processing | 150 ms | 400 ms | 800 ms | 1,500 ms | Backend Engineering |
| PF-12 | SCIM user create / update | 100 ms | 300 ms | 600 ms | 1,200 ms | Backend Engineering |
| PF-13 | SCIM user delete / deactivate | 80 ms | 250 ms | 500 ms | 1,000 ms | Backend Engineering |
| PF-14 | API key validation | 10 ms | 40 ms | 80 ms | 150 ms | Backend Engineering |
| PF-15 | Permission check (authorization API) | 20 ms | 60 ms | 120 ms | 250 ms | Backend Engineering |
| PF-16 | Webhook delivery initiation | 50 ms | 150 ms | 300 ms | 600 ms | Backend Engineering |
| PF-17 | Admin dashboard page load (TTFB) | 200 ms | 500 ms | 1,000 ms | 2,000 ms | Frontend Engineering |
| PF-18 | Admin dashboard user list query | 100 ms | 300 ms | 600 ms | 1,200 ms | Backend Engineering |
| PF-19 | Audit log search query | 150 ms | 500 ms | 1,000 ms | 2,500 ms | Backend Engineering |
| PF-20 | Developer portal page load (TTFB) | 100 ms | 250 ms | 500 ms | 1,000 ms | Frontend Engineering |

### 4.3 Throughput Requirements

| # | Operation | Launch Target | 6-Month Target | 12-Month Target | 24-Month Target |
| --- | --- | --- | --- | --- | --- |
| TH-01 | Successful logins / second (platform-wide) | 200 | 500 | 2,000 | 10,000 |
| TH-02 | Token validations / second (introspection + JWT validation) | 5,000 | 15,000 | 50,000 | 250,000 |
| TH-03 | OAuth /token requests / second | 100 | 300 | 1,000 | 5,000 |
| TH-04 | SCIM operations / second | 50 | 150 | 500 | 2,500 |
| TH-05 | Webhook deliveries / second | 200 | 500 | 2,000 | 10,000 |
| TH-06 | Admin dashboard concurrent users | 500 | 1,500 | 5,000 | 20,000 |
| TH-07 | API key validations / second | 1,000 | 5,000 | 20,000 | 100,000 |

---

### 4.4 Latency Budget Allocation (End-to-End Login Flow)

For a complete password-based login flow with MFA, the user-perceived latency is the sum of multiple system component latencies. The end-to-end p95 target is 800ms. The budget below allocates that target across components.

| Component | p95 Budget | Notes |
| --- | --- | --- |
| TLS handshake (client side) | 50 ms | Optimised via TLS 1.3 + session resumption |
| CDN / edge routing | 20 ms | Cloudflare or equivalent edge POP |
| WAF rule evaluation | 15 ms | Pre-compiled rule sets |
| Load balancer routing | 10 ms | Layer 7 routing |
| Application authentication logic | 150 ms | Argon2id password verification dominates |
| Database query (user lookup + session insert) | 60 ms | Indexed query on tenant_id + email |
| Audit log write (async) | 0 ms (user-perceived) | Fire-and-forget to logging pipeline |
| MFA challenge generation | 30 ms | TOTP / OTP generation |
| Session token issuance + JWT signing | 40 ms | RSA-2048 or ECDSA P-256 signing |
| Response serialization & TLS encryption | 25 ms |  |
| Network round-trip variability | 400 ms | User-side network, geographic distance |
| **Total p95 Budget** | **800 ms** |  |

---

### 4.5 Caching Requirements

| # | Cached Resource | Cache Layer | TTL | Invalidation Trigger |
| --- | --- | --- | --- | --- |
| CA-01 | JWKS public keys (server-side) | Application + CDN | 1 hour | Key rotation event |
| CA-02 | OIDC discovery document | CDN | 1 hour | Configuration change |
| CA-03 | Tenant configuration | Redis (in-memory) | 5 minutes | Tenant configuration update |
| CA-04 | RBAC role definitions | Redis (in-memory) | 5 minutes | Role definition update |
| CA-05 | User permissions (per session) | Redis (per request) | 5 minutes | Permission change |
| CA-06 | Rate limit counters | Redis (sliding window) | Rolling | Window expiry |
| CA-07 | Token revocation list | Redis (bloom filter) | 1 hour | Token revocation event |
| CA-08 | API key validation cache | Redis (in-memory) | 5 minutes | API key revocation |
| CA-09 | SAML IdP metadata | Application | 24 hours | Manual metadata refresh |
| CA-10 | Geolocation lookups | Application | 24 hours | None (immutable) |

---

### 5. Scalability Requirements

### 5.1 Scalability Principles

Scalability for Qeet ID is defined along three axes: traffic scalability (requests per second), data scalability (users, tenants, audit logs), and tenant scalability (concurrent organizations with isolated configurations). All three must scale independently. A platform that handles traffic linearly but degrades when tenant count crosses 10,000 is not scalable. A platform that handles many tenants but cannot exceed 1,000 RPS per tenant is not scalable.

All Qeet ID services must be designed as horizontally scalable from day one. Vertical scaling is permitted only as a short-term tactical lever, never as a strategic architecture choice.

---

### 5.2 Capacity Targets

| # | Capacity Dimension | Launch Target | 12-Month Target | 24-Month Target |
| --- | --- | --- | --- | --- |
| SC-01 | Monthly Active Users (MAUs) platform-wide | 50,000 | 1,000,000 | 10,000,000 |
| SC-02 | Total registered users platform-wide | 500,000 | 10,000,000 | 100,000,000 |
| SC-03 | Concurrent tenants (organizations) | 1,000 | 10,000 | 100,000 |
| SC-04 | Users per single tenant (Enterprise tier) | 100,000 | 500,000 | 2,000,000 |
| SC-05 | Roles per tenant | 100 | 500 | 1,000 |
| SC-06 | Custom permissions per tenant | 500 | 2,000 | 10,000 |
| SC-07 | Applications (clients) per tenant | 50 | 200 | 1,000 |
| SC-08 | API keys per tenant | 100 | 500 | 5,000 |
| SC-09 | Active sessions concurrent (platform-wide) | 500,000 | 10,000,000 | 100,000,000 |
| SC-10 | Audit log writes per second | 5,000 | 50,000 | 500,000 |
| SC-11 | Audit log entries retained (12 months) | 5 billion | 50 billion | 500 billion |
| SC-12 | Webhook subscriptions platform-wide | 10,000 | 100,000 | 1,000,000 |
| SC-13 | SAML connections (per tenant) | 10 | 50 | 200 |
| SC-14 | OIDC connections (per tenant) | 50 | 200 | 1,000 |

### 5.3 Horizontal Scaling Requirements

| # | Component | Scaling Model | Trigger | Maximum |
| --- | --- | --- | --- | --- |
| HS-01 | Auth API service | Horizontal pod autoscaling (Kubernetes HPA) | CPU > 60% or p95 latency > target | 200 pods per region |
| HS-02 | Token issuance service | Horizontal pod autoscaling | RPS-based — 100 RPS per pod | 100 pods per region |
| HS-03 | SCIM service | Horizontal pod autoscaling | CPU > 70% | 50 pods per region |
| HS-04 | Admin dashboard backend | Horizontal pod autoscaling | CPU > 70% | 30 pods per region |
| HS-05 | Webhook delivery workers | Queue-depth-based scaling | Pending deliveries > 1,000 | 100 workers per region |
| HS-06 | Audit log ingestion | Kafka partition-based scaling | Partition lag > 30 seconds | 200 consumers per region |
| HS-07 | Background job workers | Queue-depth-based scaling | Pending jobs > 500 | 50 workers per region |
| HS-08 | Primary database (PostgreSQL) | Read replica scaling + sharding by tenant | Read replica CPU > 70% | 10 read replicas per region; tenant sharding from 100K tenants |
| HS-09 | Redis cache layer | Cluster mode with auto-sharding | Memory > 75% | 50 nodes per region |
| HS-10 | Kafka brokers | Manual scaling with planning | Disk > 70% or throughput > 80% | 30 brokers per cluster |

---

### 5.4 Multi-Tenancy Scalability Model

| # | Requirement | Description |
| --- | --- | --- |
| MT-01 | Tenant isolation at data layer | Tenant ID enforced at every database query; cross-tenant access architecturally impossible |
| MT-02 | Noisy neighbour protection | Per-tenant rate limiting prevents one tenant from impacting another |
| MT-03 | Per-tenant resource quotas | Configurable quotas per tenant — API requests, webhook deliveries, audit log volume |
| MT-04 | Dedicated tier for enterprise | Enterprise customers can opt into dedicated database shards and isolated worker pools |
| MT-05 | Tenant sharding strategy | From 100,000 tenants, automatic sharding across database clusters by tenant_id hash |
| MT-06 | Tenant migration capability | Ability to move a tenant between shards without downtime |

---

### 5.5 Burst Traffic Handling

Authentication traffic is bursty. A customer's Monday morning login surge can exceed steady-state traffic by 5–10x. A new product launch by a Qeet ID customer can drive a 20x burst. The platform must absorb these bursts without degradation.

| # | Requirement | Description |
| --- | --- | --- |
| BT-01 | Burst capacity headroom | Provision 200% steady-state capacity at all times — burst headroom |
| BT-02 | Autoscale reaction time | Autoscaling must add new capacity within 60 seconds of trigger |
| BT-03 | Queue-based load smoothing | Non-critical operations (webhooks, audit log persistence, analytics) queued and processed asynchronously |
| BT-04 | Graceful degradation under overload | Non-critical paths (dashboard analytics, optional metadata enrichment) degrade first; critical auth paths preserved |
| BT-05 | Circuit breaker on dependency overload | Downstream dependency failures trigger circuit breakers — fail fast, do not amplify load |
| BT-06 | Rate limit shedding | Excess traffic beyond capacity returns 429 with Retry-After — never silent timeout |

---

### 6. Availability Requirements

### 6.1 Availability SLA Definitions

| # | Service Tier | Uptime SLA | Allowed Monthly Downtime | Effective From |
| --- | --- | --- | --- | --- |
| AV-01 | Free Tier | 99.5% | ~3 hours 38 minutes | Launch |
| AV-02 | Growth Tier | 99.9% | ~43 minutes 28 seconds | Launch |
| AV-03 | Enterprise Tier | 99.9% | ~43 minutes 28 seconds | Launch |
| AV-04 | Enterprise Tier (Year 2) | 99.99% | ~4 minutes 22 seconds | 24 months post-launch |
| AV-05 | Authorization endpoint (/oauth/authorize) | 99.95% | ~21 minutes 44 seconds | Launch |
| AV-06 | Token endpoint (/oauth/token) | 99.95% | ~21 minutes 44 seconds | Launch |
| AV-07 | JWKS endpoint | 99.99% | ~4 minutes 22 seconds | Launch |
| AV-08 | Admin dashboard | 99.5% | ~3 hours 38 minutes | Launch |
| AV-09 | Developer portal | 99.5% | ~3 hours 38 minutes | Launch |
| AV-10 | Public status page | 99.99% | ~4 minutes 22 seconds | Launch (hosted independently) |

The authentication endpoints (authorize, token, JWKS) have stricter SLAs than the overall platform because they sit on the critical user login path. The dashboard and developer portal can tolerate degradation without breaking end-user authentication.

### 6.2 Redundancy Requirements

| # | Requirement | Description |
| --- | --- | --- |
| RD-01 | Multi-AZ deployment | All production services deployed across minimum 3 availability zones in each region |
| RD-02 | No single point of failure (SPOF) | Every component has redundant replicas; SPOF analysis documented and remediated |
| RD-03 | Active-active database read replicas | Read traffic distributed across replicas; reader endpoint provides automatic failover |
| RD-04 | Database failover | Automated failover from primary to standby within 60 seconds on primary failure |
| RD-05 | Cache layer redundancy | Redis Cluster with replica per shard; automatic failover |
| RD-06 | Message broker redundancy | Kafka replication factor ≥ 3 for all critical topics |
| RD-07 | DNS redundancy | Multiple DNS providers (primary + secondary); health-checked routing |
| RD-08 | CDN redundancy | Multi-CDN strategy for static assets; automatic origin failover |
| RD-09 | Object storage replication | S3 / GCS cross-region replication enabled for backups and audit logs |
| RD-10 | Stateless application layer | All application services stateless — any pod can serve any request |

---

### 6.3 Failover Requirements

| # | Requirement | Recovery Time Objective (RTO) | Recovery Point Objective (RPO) | Trigger |
| --- | --- | --- | --- | --- |
| FO-01 | Single pod failure | < 30 seconds (Kubernetes restart) | 0 (stateless) | Pod health check failure |
| FO-02 | Single node failure | < 2 minutes | 0 (stateless workloads) | Kubernetes node not-ready |
| FO-03 | Availability zone failure | < 5 minutes | < 1 second | AZ-wide outage signal |
| FO-04 | Primary database failure | < 60 seconds | < 5 seconds | Database health check failure |
| FO-05 | Cache cluster failure | < 30 seconds | 0 (rebuilt from source of truth) | Redis cluster failure |
| FO-06 | Region failure (Enterprise tier multi-region) | < 15 minutes | < 60 seconds | Region-wide outage |
| FO-07 | CDN provider failure | < 60 seconds (DNS-based failover) | 0 | CDN health check failure |
| FO-08 | Identity provider (social login) failure | Graceful degradation — log failure, continue serving other flows | N/A | Provider error rate threshold |

---

### 6.4 Disaster Recovery Requirements

| # | Requirement | Target | Owner |
| --- | --- | --- | --- |
| DR-01 | RTO for full regional disaster | 4 hours | DevOps / SRE |
| DR-02 | RPO for full regional disaster | 5 minutes | DevOps / SRE |
| DR-03 | Backup frequency | Continuous (transaction log streaming) + snapshot every 6 hours | DevOps |
| DR-04 | Backup retention | Daily for 30 days; weekly for 90 days; monthly for 1 year; yearly for 7 years (billing only) | DevOps + Compliance |
| DR-05 | Backup encryption | AES-256-GCM with KMS-managed keys | DevOps + Security |
| DR-06 | Backup integrity verification | Automated restore tests weekly to validation environment | DevOps + QA |
| DR-07 | Disaster recovery drills | Annual full DR exercise; quarterly tabletop exercises | DevOps + SRE + Compliance |
| DR-08 | Off-site backup storage | Cross-region replication of all backups | DevOps |
| DR-09 | DR runbook | Documented, version-controlled runbook accessible to all on-call engineers | DevOps + SRE |
| DR-10 | Data corruption recovery | Point-in-time recovery to any moment within last 30 days | DevOps |

---

### 6.5 Maintenance Window Policy

| # | Requirement | Description |
| --- | --- | --- |
| MW-01 | Zero-downtime deployments | All standard deployments use rolling updates with no service interruption |
| MW-02 | Database schema migrations | Online schema changes only; no downtime for schema evolution |
| MW-03 | Scheduled maintenance | Enterprise-tier customers receive 14-day advance notice of any scheduled maintenance window |
| MW-04 | Emergency maintenance | Critical security patches may be applied with as little as 1-hour notice — customers notified via status page and email |
| MW-05 | Maintenance windows count toward SLA | Any planned maintenance counts against monthly availability — there is no "free downtime" |

### 7. Reliability Requirements

### 7.1 Error Rate Requirements

| # | Operation | Acceptable Error Rate | Critical Threshold |
| --- | --- | --- | --- |
| ER-01 | OAuth /token (server-side errors only — 5xx) | < 0.1% | > 0.5% |
| ER-02 | Login flow completion rate | > 99.5% | < 99% |
| ER-03 | SAML assertion processing | > 99.9% | < 99.5% |
| ER-04 | SCIM provisioning operations | > 99.9% | < 99.5% |
| ER-05 | Webhook delivery success (within retry policy) | > 99.95% | < 99.9% |
| ER-06 | Email delivery (transactional) | > 99% | < 98% |
| ER-07 | SMS delivery (OTP) | > 98% | < 95% |
| ER-08 | Token validation accuracy (no false rejections of valid tokens) | 100% | Any false rejection |
| ER-09 | Password hash verification (no false matches) | 100% | Any false match |
| ER-10 | Tenant isolation breach rate | 0 | Any breach |

---

### 7.2 Retry & Backoff Requirements

| # | Operation | Retry Policy | Backoff |
| --- | --- | --- | --- |
| RT-01 | Webhook delivery to customer | Up to 10 retries over 24 hours | Exponential — 1s, 2s, 4s, 8s, 16s, 32s, 1m, 5m, 30m, 2h, 6h |
| RT-02 | Email delivery (transactional provider failure) | Up to 5 retries over 1 hour | Exponential — 30s, 1m, 5m, 15m, 30m |
| RT-03 | SMS delivery | Up to 3 retries over 5 minutes | Linear — 30s, 1m, 2m |
| RT-04 | Database transaction retry (transient errors only) | Up to 3 retries | Exponential — 50ms, 100ms, 200ms |
| RT-05 | External IdP request (social login) | Up to 2 retries | Linear — 200ms, 500ms |
| RT-06 | Internal service-to-service call | Up to 2 retries | 100ms, 300ms with jitter |
| RT-07 | Kafka producer | Idempotent retries until acknowledged | Exponential with jitter |

---

### 7.3 Idempotency Requirements

| # | Operation | Idempotency Mechanism |
| --- | --- | --- |
| ID-01 | OAuth token issuance | Authorization code single-use enforcement |
| ID-02 | User creation via API | Idempotency-Key header support — same key returns same result for 24 hours |
| ID-03 | SCIM user creation | externalId-based deduplication; HTTP 409 on duplicate |
| ID-04 | Webhook event delivery | Event ID included; receivers expected to deduplicate |
| ID-05 | Billing event processing | Stripe event ID-based deduplication |
| ID-06 | Audit log writes | Event ID + timestamp ensures duplicate detection |
| ID-07 | Email send requests | Idempotency key for transactional emails to prevent duplicate sends |

---

### 7.4 Data Durability Requirements

| # | Data Class | Durability Target | Storage Strategy |
| --- | --- | --- | --- |
| DU-01 | User account data | 99.999999999% (11 nines) | PostgreSQL with synchronous replication + S3-backed backups |
| DU-02 | Authentication credentials (password hashes, passkey credentials) | 99.999999999% | Same as user data + encryption at rest |
| DU-03 | Audit logs | 99.999999999% | Append-only log; cross-region replicated |
| DU-04 | Session data | 99.99% (acceptable to lose on cache failure) | Redis with snapshotting + database fallback for critical sessions |
| DU-05 | Token revocation list | 99.999999999% | PostgreSQL (source of truth) + Redis (cache) |
| DU-06 | Billing records | 99.999999999% | PostgreSQL + Stripe (source of truth dual-write) |
| DU-07 | Configuration data (tenants, applications, roles) | 99.999999999% | PostgreSQL + version history |
| DU-08 | Webhook delivery history | 99.99% | PostgreSQL with 90-day retention |

---

### 8. Security Requirements

Security NFRs are extensive in the Compliance Requirements Matrix and the Protocol Requirements Document. This section captures the *operational and infrastructural* security NFRs that determine how the platform defends itself in production, beyond protocol-level correctness.

### 8.1 Encryption Requirements

| # | Requirement | Standard |
| --- | --- | --- |
| SE-01 | TLS minimum version | TLS 1.2; TLS 1.3 preferred |
| SE-02 | TLS cipher suites | Only AEAD ciphers (AES-GCM, ChaCha20-Poly1305); CBC and stream ciphers disabled |
| SE-03 | Certificate management | Automated renewal via cert-manager; expiry monitoring with 30-day alert |
| SE-04 | HSTS enforcement | Strict-Transport-Security: max-age=63072000; includeSubDomains; preload |
| SE-05 | Data at rest — disk-level | AES-256 disk encryption on all storage volumes |
| SE-06 | Data at rest — field-level (PII) | AES-256-GCM with envelope encryption — KMS-managed data keys |
| SE-07 | Data at rest — password hashes | Argon2id with memory cost 64 MB, iterations 3, parallelism 4 minimum |
| SE-08 | Data at rest — backups | AES-256-GCM with separate backup encryption keys |
| SE-09 | JWT signing | RS256 (RSA-2048 minimum) or ES256 (ECDSA P-256) — keys in KMS / Vault |
| SE-10 | TLS termination location | Edge (CDN/WAF layer); internal mTLS between services |

---

### 8.2 Network Security Requirements

| # | Requirement | Description |
| --- | --- | --- |
| NS-01 | VPC isolation | All production workloads in private VPC; no direct internet exposure of compute instances |
| NS-02 | Network segmentation | Production, staging, and development VPCs fully isolated; no peering |
| NS-03 | Subnet design | Public subnets for load balancers only; private subnets for application; isolated subnets for data layer |
| NS-04 | Egress filtering | Outbound traffic from production restricted to approved destinations via NAT gateway and egress proxy |
| NS-05 | Internal mTLS | Service-to-service traffic encrypted with mutual TLS — SPIFFE-style identity (v2.0 target) |
| NS-06 | WAF deployment | OWASP Top 10 rule set enabled; custom Qeet ID-specific rules deployed |
| NS-07 | DDoS protection | Cloud-native DDoS protection (AWS Shield Advanced / GCP Cloud Armor) at L3/L4/L7 |
| NS-08 | Bot protection | Bot management solution at edge — fingerprinting, behavioural analysis |
| NS-09 | Rate limiting at edge | Initial rate limiting at CDN/WAF layer before request reaches application |
| NS-10 | IP allowlisting (enterprise) | Enterprise tenants can restrict API access to specific IP CIDR ranges |
| NS-11 | DNS security | DNSSEC enabled on qeetify.com; CAA records published |

---

### 8.3 Application Security Requirements

| # | Requirement | Description |
| --- | --- | --- |
| AS-01 | Input validation | All inputs validated at API boundary — type, length, format, range, encoding |
| AS-02 | Output encoding | Context-aware output encoding (HTML, URL, JS, JSON) to prevent XSS |
| AS-03 | SQL injection prevention | Parameterised queries only; no string concatenation in SQL |
| AS-04 | CSRF protection | CSRF tokens for state-changing operations; SameSite=Lax cookies |
| AS-05 | CORS policy | Strict CORS policy — no wildcard origins for credentialed requests |
| AS-06 | Content Security Policy | Strict CSP headers on all customer-facing pages; nonce-based script execution |
| AS-07 | Subresource Integrity | All third-party scripts include SRI hashes |
| AS-08 | Anti-clickjacking | X-Frame-Options: DENY; CSP frame-ancestors directive |
| AS-09 | Secure cookies | HttpOnly + Secure + SameSite=Lax on all session cookies |
| AS-10 | XML parser hardening | XML External Entity (XXE) processing disabled; signature wrapping protection |
| AS-11 | Deserialization safety | No deserialization of untrusted data; allow-lists for permitted types |
| AS-12 | File upload restrictions | Profile pictures only; size limit 5MB; MIME type validation; virus scanning |

---

### 8.4 Vulnerability Management Requirements

| # | Requirement | SLA |
| --- | --- | --- |
| VM-01 | Critical CVE patching | Within 72 hours of public disclosure |
| VM-02 | High CVE patching | Within 7 days |
| VM-03 | Medium CVE patching | Within 30 days |
| VM-04 | Low CVE patching | Within 90 days |
| VM-05 | Dependency scanning frequency | On every commit (CI pipeline) |
| VM-06 | Container image scanning | On every build; production images re-scanned daily |
| VM-07 | Infrastructure as Code scanning | On every PR; required passing check |
| VM-08 | Secret scanning | Pre-commit hook + CI pipeline + production code repository scan daily |
| VM-09 | External penetration test | Annual minimum + after significant architectural changes |
| VM-10 | Bug bounty program | Active public bug bounty at launch; payouts per published policy |
| VM-11 | Coordinated Vulnerability Disclosure | Published VDP with 90-day disclosure default timeline |

---

### 8.5 Access Control Requirements (Internal — Qeet ID Operations)

| # | Requirement | Description |
| --- | --- | --- |
| AC-01 | Production access — MFA | All staff accessing production systems must use hardware-key MFA |
| AC-02 | Production access — least privilege | IAM roles scoped to minimum required permissions; no shared accounts |
| AC-03 | Production access — just-in-time | Privileged access granted on-demand with time-bound elevation; no standing admin access |
| AC-04 | Access logging | All production access logged — actor, action, target, timestamp, source IP |
| AC-05 | Access review | Quarterly access reviews; departed staff access revoked within 24 hours of separation |
| AC-06 | Customer data access | Engineer access to customer data requires customer consent OR explicit incident response justification, fully logged |
| AC-07 | Database direct access | Read-only by default; write access only via approved migration scripts |
| AC-08 | Production deployment access | Restricted to CI/CD pipeline; no manual production deployments |

---

### 9. Compliance Requirements (NFR Crossover)

The Compliance Requirements Matrix is the authoritative source for compliance obligations. The NFRs below define the *system behaviours* required to satisfy those compliance obligations operationally.

| # | Requirement | Description |
| --- | --- | --- |
| CN-01 | GDPR data subject request fulfilment SLA | Acknowledge within 72 hours; complete within 30 days |
| CN-02 | GDPR breach notification timeline | Initial notification to supervisory authority within 72 hours of awareness |
| CN-03 | Data retention enforcement | Automated retention policy enforcement — data deleted at retention expiry |
| CN-04 | Right to erasure completion time | User deletion fully propagated across primary, cache, backup, and downstream systems within 30 days |
| CN-05 | Data residency enforcement | Tenant data physically stored only in tenant-selected region; no cross-region replication outside that boundary |
| CN-06 | Audit log retention | 12 months minimum for authentication events; 3 years for administrative and security events |
| CN-07 | Audit log tamper-evidence | Cryptographic hash chaining; append-only storage |
| CN-08 | SOC 2 control evidence collection | Automated control evidence collection where possible — access logs, change logs, monitoring data |
| CN-09 | DPA execution requirement | DPA signed by customer before processing any personal data — enforced at signup for paid tiers |
| CN-10 | Sub-processor notification | 30-day advance notice of new sub-processors via dashboard and email |

---

### 10. Maintainability Requirements

### 10.1 Code Quality Requirements

| # | Requirement | Target |
| --- | --- | --- |
| MN-01 | Unit test coverage (business logic) | ≥ 80% line coverage; ≥ 70% branch coverage |
| MN-02 | Integration test coverage (critical paths) | 100% of authentication flows, token issuance, SCIM operations |
| MN-03 | Code review requirement | All code merged to main requires minimum 1 reviewer approval; security-sensitive code requires 2 |
| MN-04 | Static analysis | Run on every PR — linting, type checking, security analysis (Semgrep / CodeQL) |
| MN-05 | Code style enforcement | Automated formatting (Prettier, Black, gofmt) enforced via pre-commit hooks |
| MN-06 | Public API documentation coverage | 100% of public APIs documented with examples |
| MN-07 | Internal API documentation coverage | 100% of internal service APIs documented via OpenAPI spec |
| MN-08 | Dependency freshness | Dependencies updated minimum monthly; critical security updates within 72 hours |
| MN-09 | Technical debt tracking | Tech debt logged in dedicated backlog; 20% of every sprint allocated to tech debt |

---

### 10.2 Architectural Maintainability

| # | Requirement | Description |
| --- | --- | --- |
| AR-01 | Service modularity | Microservices boundaries align with bounded contexts; no shared databases across services |
| AR-02 | API versioning | All public APIs versioned (/v1/, /v2/); breaking changes require new version |
| AR-03 | Backwards compatibility | Public APIs maintain backwards compatibility for minimum 12 months after deprecation announcement |
| AR-04 | Deprecation policy | Deprecated APIs flagged in responses; deprecation notice 12 months minimum before removal |
| AR-05 | Configuration externalization | All environment-specific config externalized; no hardcoded environment values |
| AR-06 | Feature flags | All non-trivial features behind feature flags; instant disable capability |
| AR-07 | Architecture Decision Records (ADRs) | All major architectural decisions documented as ADRs; version controlled |
| AR-08 | Service ownership | Every service has documented owning team; on-call rotation defined |
| AR-09 | Runbook coverage | Every production service has a runbook covering common incidents |

---

### 11. Observability Requirements

### 11.1 Logging Requirements

| # | Requirement | Description |
| --- | --- | --- |
| LG-01 | Structured logging | All logs in structured JSON format with consistent schema |
| LG-02 | Standard log fields | timestamp (ISO 8601 UTC), level, service, environment, request_id, tenant_id, user_id (where applicable), event |
| LG-03 | Request correlation | Every request assigned a unique request_id; propagated across all services |
| LG-04 | No PII in logs | Personal data never written to application logs; user identifiers via opaque IDs only |
| LG-05 | Log levels | DEBUG, INFO, WARN, ERROR, CRITICAL; production default INFO |
| LG-06 | Log ingestion latency | < 60 seconds from event to searchable in centralized log store |
| LG-07 | Log retention — application logs | 30 days hot storage; 12 months cold storage |
| LG-08 | Log retention — audit logs | 12 months hot; 3 years cold (per compliance) |
| LG-09 | Log retention — security events | 3 years hot |
| LG-10 | Log access control | Log search access restricted by RBAC; PII redaction enforced for non-privileged roles |

---

### 11.2 Metrics Requirements

| # | Metric Category | Examples | Granularity | Retention |
| --- | --- | --- | --- | --- |
| MX-01 | Request metrics | RPS, latency p50/p95/p99, error rate (per endpoint, per tenant) | 10 seconds | 13 months |
| MX-02 | Business metrics | MAUs, login success rate, MFA adoption rate, passkey adoption | 1 minute | 5 years |
| MX-03 | Resource metrics | CPU, memory, disk, network per service | 30 seconds | 13 months |
| MX-04 | Database metrics | Query latency, connection pool, replication lag, lock wait time | 30 seconds | 13 months |
| MX-05 | Queue metrics | Queue depth, processing rate, age of oldest message | 30 seconds | 13 months |
| MX-06 | Dependency metrics | External provider error rate, latency (Stripe, Twilio, SendGrid, social IdPs) | 1 minute | 13 months |
| MX-07 | Security metrics | Failed logins, MFA failures, anomalous events, blocked requests | 1 minute | 3 years |
| MX-08 | SLO metrics | Service Level Objective tracking with error budget calculation | Continuous | 13 months |

---

### 11.3 Distributed Tracing Requirements

| # | Requirement | Description |
| --- | --- | --- |
| TR-01 | Trace coverage | 100% of customer-facing requests instrumented |
| TR-02 | Sampling strategy | Head-based sampling — 10% of requests; 100% of errors and slow requests |
| TR-03 | Trace propagation | W3C Trace Context standard headers; propagated across all services |
| TR-04 | Span attributes | Standard attributes: tenant_id (hashed), endpoint, response code, duration |
| TR-05 | Trace retention | 7 days hot; 30 days cold |
| TR-06 | Trace correlation | Trace ID linkable from logs, metrics, and incident tickets |

---

### 11.4 Alerting Requirements

| # | Alert Class | Trigger Examples | Response Time | Routing |
| --- | --- | --- | --- | --- |
| AL-01 | Critical (P1) | Auth endpoint down; tenant data exposure; security breach detected | < 5 minutes acknowledgement; < 30 minutes mitigation | PagerDuty — primary on-call + CISO |
| AL-02 | High (P2) | p95 latency > target for 5 minutes; error rate > 1%; database failover | < 15 minutes acknowledgement | PagerDuty — primary on-call |
| AL-03 | Medium (P3) | Single AZ degradation; queue lag > threshold; non-critical dependency failure | < 1 hour acknowledgement | Slack channel + ticket |
| AL-04 | Low (P4) | Capacity approaching threshold; certificate expiry approaching; deprecated API usage | Next business day | Slack channel |
| AL-05 | Informational | Deployment completed; routine maintenance; scheduled jobs | None | Slack channel — informational only |

---

### 11.5 Service Level Objectives (SLOs)

| # | SLO | Target | Error Budget (monthly) |
| --- | --- | --- | --- |
| SL-01 | OAuth /token success rate | 99.95% | 21.9 minutes |
| SL-02 | OAuth /token p95 latency < 200ms | 99.5% | 3.6 hours |
| SL-03 | Login flow completion rate | 99.5% | 3.6 hours |
| SL-04 | SAML assertion processing success | 99.9% | 43.8 minutes |
| SL-05 | SCIM provisioning success | 99.9% | 43.8 minutes |
| SL-06 | Webhook delivery (within retry policy) | 99.95% | 21.9 minutes |
| SL-07 | Admin dashboard availability | 99.5% | 3.6 hours |
| SL-08 | Audit log ingestion completeness | 100% | 0 — no acceptable loss |

When an SLO error budget is exhausted, deployments to that service are paused until reliability is restored.

---

### 12. Usability Requirements

### 12.1 End-User Login Experience

| # | Requirement | Target |
| --- | --- | --- |
| UX-01 | Time to complete login (passkey) | < 5 seconds from page load to authenticated state |
| UX-02 | Time to complete login (password + MFA) | < 30 seconds median |
| UX-03 | Passkey registration completion rate | > 70% of users prompted complete registration |
| UX-04 | Password reset completion rate | > 90% of initiated resets complete successfully |
| UX-05 | Mobile responsiveness | All end-user pages functional on viewports from 320px to 2560px wide |
| UX-06 | Browser support | Chrome, Edge, Safari, Firefox — latest 2 major versions of each |
| UX-07 | Mobile browser support | iOS Safari, Chrome Android — latest 2 major versions |

---

### 12.2 Accessibility Requirements

| # | Requirement | Standard |
| --- | --- | --- |
| AX-01 | WCAG conformance | WCAG 2.1 Level AA conformance for all end-user and admin interfaces |
| AX-02 | Screen reader compatibility | Tested with NVDA, JAWS, VoiceOver |
| AX-03 | Keyboard navigation | All interactive elements reachable and operable via keyboard |
| AX-04 | Focus indicators | Visible focus indicators on all interactive elements |
| AX-05 | Colour contrast | Minimum 4.5:1 for text; 3:1 for large text and UI components |
| AX-06 | No reliance on colour alone | Information never conveyed by colour alone |
| AX-07 | Form labelling | All form inputs have associated labels; error messages associated with fields |
| AX-08 | Captions and transcripts | All instructional video content has captions and text transcripts |
| AX-09 | Accessibility audit | Annual third-party accessibility audit |

---

### 12.3 Internationalization Requirements

| # | Requirement | Description |
| --- | --- | --- |
| IN-01 | UTF-8 throughout | All systems handle UTF-8 input and output correctly |
| IN-02 | End-user-facing login pages | Localized in 10 languages at launch: English, Spanish, French, German, Portuguese, Italian, Japanese, Korean, Mandarin, Hindi |
| IN-03 | Date / time formatting | Locale-aware date and time display; ISO 8601 for machine interfaces |
| IN-04 | Number formatting | Locale-aware number formatting in user-facing displays |
| IN-05 | Right-to-left (RTL) support | RTL layouts for Arabic and Hebrew (post-launch v1.2 target) |
| IN-06 | Timezone handling | All timestamps stored as UTC; displayed in user's local timezone |
| IN-07 | Email localization | Transactional emails sent in user's preferred language |
| IN-08 | Admin dashboard localization | English at launch; additional languages in v1.5 |

---

### 13. Interoperability Requirements

### 13.1 Standards Conformance

| # | Standard | Conformance Level | Validation |
| --- | --- | --- | --- |
| IO-01 | OpenID Connect Core 1.0 | OpenID Foundation Certified — Basic OP profile | Pre-launch certification |
| IO-02 | OAuth 2.0 (RFC 6749) + Security BCP (RFC 9700) | Full conformance | Internal audit + pen test |
| IO-03 | SAML 2.0 (OASIS) | Full conformance | Interop tested with Entra ID, Okta, Google, Ping |
| IO-04 | SCIM 2.0 (RFC 7642/7643/7644) | Full conformance | Tested against Okta SCIM validator |
| IO-05 | WebAuthn Level 2 | Full conformance | FIDO Alliance FIDO2 Server Certification |
| IO-06 | JWT (RFC 7519) + JWS (RFC 7515) | Full conformance | jwt.io validation + algorithm confusion tests |
| IO-07 | OpenAPI Specification | OpenAPI 3.1 published for all public REST APIs | Validated via openapi-spec-validator |
| IO-08 | W3C WCAG 2.1 AA | Full conformance | Annual audit |

---

### 13.2 Integration Compatibility

| # | Requirement | Target Integrations |
| --- | --- | --- |
| IC-01 | Identity Providers (federation) | Microsoft Entra ID, Okta, Google Workspace, Ping Identity, OneLogin, JumpCloud, Keycloak |
| IC-02 | Social Login Providers | Google, GitHub, Microsoft, Apple, Facebook (v1.2), LinkedIn (v1.2) |
| IC-03 | HR / Provisioning Systems | Okta as provisioning source, Microsoft Entra ID, Workday (v1.2), BambooHR (v1.5) |
| IC-04 | SIEM Integration | Splunk, Microsoft Sentinel, Datadog, Sumo Logic |
| IC-05 | Webhook Consumers | Any HTTPS endpoint with HMAC signature verification |
| IC-06 | Payment Processing | Stripe (primary), payment data never touches Qeet ID systems directly |
| IC-07 | Email Delivery | SendGrid (primary), AWS SES (failover) |
| IC-08 | SMS Delivery | Twilio (primary), AWS SNS (failover) |
| IC-09 | IaC Tooling | Terraform provider (v1.1), Pulumi provider (v1.5) |

---

### 14. Portability Requirements

| # | Requirement | Description |
| --- | --- | --- |
| PO-01 | Cloud-agnostic architecture | Core services designed against Kubernetes + open-source dependencies — not cloud-vendor-specific managed services where avoidable |
| PO-02 | Multi-cloud capability | Platform deployable to AWS or GCP without code changes; infrastructure differences abstracted via IaC |
| PO-03 | Container-native | All services run as containers; orchestrated via Kubernetes |
| PO-04 | Database portability | PostgreSQL (open standard); managed via cloud-managed Postgres OR self-managed |
| PO-05 | Cache portability | Redis (open standard); managed or self-managed |
| PO-06 | Message broker portability | Kafka (open standard); managed (Confluent Cloud, MSK) or self-managed |
| PO-07 | Cloud lock-in audit | Annual review of cloud-vendor-specific dependencies; ADR required for any new lock-in |
| PO-08 | On-premise deployment readiness (v2.0) | Architecture supports on-premise deployment for enterprise customers from v2.0 |
| PO-09 | Sovereign cloud readiness (v3.0) | Architecture supports deployment to sovereign cloud regions (GCC, AWS GovCloud, etc.) |

---

### 15. Capacity & Resource Requirements

### 15.1 Storage Capacity Planning

| # | Data Class | Launch Capacity | 12-Month Capacity | 24-Month Capacity |
| --- | --- | --- | --- | --- |
| CP-01 | User database | 100 GB | 2 TB | 20 TB |
| CP-02 | Audit logs (hot — 12 months) | 5 TB | 50 TB | 500 TB |
| CP-03 | Audit logs (cold — 7 years) | 5 TB | 100 TB | 2 PB |
| CP-04 | Session data (Redis) | 50 GB | 500 GB | 5 TB |
| CP-05 | Webhook delivery history | 200 GB | 2 TB | 20 TB |
| CP-06 | Backup storage | 50 TB | 500 TB | 5 PB |
| CP-07 | Object storage (profile pictures, exports) | 1 TB | 20 TB | 200 TB |

---

### 15.2 Connection & Resource Limits

| # | Resource | Per Tenant (Free) | Per Tenant (Growth) | Per Tenant (Enterprise) |
| --- | --- | --- | --- | --- |
| RL-01 | API requests per minute | 600 | 6,000 | Custom (default 60,000) |
| RL-02 | Login attempts per IP per hour | 100 | 1,000 | Custom |
| RL-03 | Webhook deliveries per minute | 60 | 600 | Custom |
| RL-04 | Concurrent SCIM operations | 5 | 25 | 100 |
| RL-05 | Maximum applications (clients) | 5 | 50 | Custom (default 200) |
| RL-06 | Maximum custom roles | 10 | 100 | Custom (default 500) |
| RL-07 | Maximum webhook subscriptions | 5 | 50 | Custom (default 200) |
| RL-08 | Maximum API keys | 10 | 100 | Custom (default 500) |
| RL-09 | Maximum SSO connections | 1 | 10 | Custom (default 50) |
| RL-10 | Audit log export volume per day | 100 MB | 10 GB | Unlimited |

---

### 16. Data Integrity Requirements

| # | Requirement | Description |
| --- | --- | --- |
| DI-01 | Transactional consistency | All operations involving authentication state changes use database transactions with appropriate isolation levels |
| DI-02 | Eventual consistency tolerance | Read replicas may lag primary by maximum 5 seconds; critical reads route to primary |
| DI-03 | Token revocation propagation | Revocation events propagate to all cache and read replicas within 60 seconds |
| DI-04 | SCIM deprovisioning consistency | active=false propagated to all session stores within 60 seconds |
| DI-05 | Concurrent modification handling | Optimistic concurrency control via ETags / version fields on SCIM resources |
| DI-06 | Idempotency of provisioning operations | Same SCIM operation produces same result regardless of retry count |
| DI-07 | Cross-shard transaction handling | Operations spanning multiple tenant shards use saga pattern, not distributed transactions |
| DI-08 | Data validation at write time | Schema validation enforced at database layer, not just application layer |
| DI-09 | Foreign key integrity | Referential integrity enforced at database layer where possible |
| DI-10 | Data corruption detection | Periodic integrity checks on critical tables; checksums on backups |

---

### 17. Operability Requirements

### 17.1 Deployment Requirements

| # | Requirement | Description |
| --- | --- | --- |
| OP-01 | Deployment frequency capability | Multiple deployments per day per service supported |
| OP-02 | Deployment strategy | Rolling deployments by default; blue-green for high-risk changes; canary for new features |
| OP-03 | Deployment automation | All production deployments fully automated via CI/CD; no manual production deployments |
| OP-04 | Deployment rollback | Automated rollback on health check failure within 60 seconds |
| OP-05 | Deployment auditing | Every deployment logged — who, what, when, version, approval status |
| OP-06 | Pre-deployment validation | Automated tests, security scans, and policy checks must pass before deploy |
| OP-07 | Production change windows | Standard deployments any time; high-risk changes scheduled outside peak traffic windows |
| OP-08 | Database migration safety | Online schema migrations only; destructive migrations require staged rollout |

---

### 17.2 Incident Response Requirements

| # | Requirement | Description |
| --- | --- | --- |
| IR-01 | Incident classification | P1 / P2 / P3 / P4 classification with documented criteria |
| IR-02 | Incident response SLA — P1 | Acknowledged < 5 minutes; mitigation < 30 minutes; resolution best effort |
| IR-03 | Incident commander assignment | Every P1/P2 incident has named Incident Commander within 10 minutes |
| IR-04 | Customer communication — P1 | Status page updated within 15 minutes of P1 declaration |
| IR-05 | Internal communication | Dedicated Slack channel created per incident; war room called for P1 |
| IR-06 | Post-incident review | Blameless post-mortem within 5 business days for P1/P2 incidents |
| IR-07 | Post-mortem publication | P1 incident summaries published to status page within 7 days |
| IR-08 | Runbook coverage | Every alert links to a runbook with mitigation steps |
| IR-09 | Game days | Quarterly game day exercises simulating production incidents |
| IR-10 | On-call rotation | 24/7 on-call coverage with documented escalation paths; secondary on-call backup |

---

### 18. Cost Efficiency Requirements

| # | Requirement | Target |
| --- | --- | --- |
| CE-01 | Infrastructure cost per MAU at scale | < $0.05 per MAU per month at 1M MAUs |
| CE-02 | Gross margin target | > 70% gross margin on Growth tier; > 80% on Enterprise tier |
| CE-03 | Cost monitoring | Real-time cloud spend dashboards; daily anomaly alerts |
| CE-04 | Budget alerts | Automated alerts at 50%, 75%, 90%, 100% of monthly budget per service |
| CE-05 | Resource utilization | Average CPU utilization > 40%; memory utilization > 50% — below these triggers right-sizing review |
| CE-06 | Reserved capacity | Long-running workloads use reserved instances / committed use discounts |
| CE-07 | Spot / preemptible workloads | Non-critical batch workloads use spot/preemptible compute where appropriate |
| CE-08 | Cost review cadence | Monthly infrastructure cost review with engineering leadership |
| CE-09 | Per-tenant cost attribution | Infrastructure cost attributable per tenant for unit economics analysis |
| CE-10 | Idle resource cleanup | Automated cleanup of unused dev/staging environments and orphaned resources |

---

### 19. NFR Verification & Testing Strategy

Every NFR in this document must be verifiable. Aspirational requirements that cannot be measured are excluded from this document. The verification methods below define how each NFR category is tested before launch and monitored in production.

| # | NFR Category | Verification Method | Phase |
| --- | --- | --- | --- |
| VR-01 | Performance | Load testing with k6 / Locust — sustained and burst scenarios | Phase 6 + ongoing |
| VR-02 | Scalability | Scaling tests at 2x, 5x, 10x baseline load; capacity model validation | Phase 6 + quarterly |
| VR-03 | Availability | Chaos engineering — pod kills, AZ simulation, dependency failures (Chaos Mesh / Gremlin) | Phase 6 + quarterly |
| VR-04 | Reliability | Long-running soak tests; failure injection testing | Phase 6 + ongoing |
| VR-05 | Security | Penetration testing (external annual + internal continuous); SAST/DAST in CI/CD | Phase 6 + annually |
| VR-06 | Compliance | SOC 2 audit; GDPR DPIA; FIDO2 certification; OIDC conformance testing | Phase 7 + annually |
| VR-07 | Maintainability | Code quality metrics (SonarQube); test coverage gates in CI/CD | Continuous |
| VR-08 | Observability | Alert fire-drill exercises; metric coverage audit; trace sampling validation | Phase 6 + quarterly |
| VR-09 | Usability | Usability testing with target personas; accessibility audit | Phase 3 + annually |
| VR-10 | Interoperability | Conformance testing suites; interop testing matrix execution | Phase 6 + per release |
| VR-11 | Portability | Cross-cloud deployment validation in staging | Annually |
| VR-12 | Capacity | Capacity forecasting model validation against actuals | Monthly |
| VR-13 | Data Integrity | Database integrity checks; consistency model validation tests | Continuous |
| VR-14 | Operability | Deployment success rate; rollback tests; runbook walkthroughs | Continuous |
| VR-15 | Cost Efficiency | Unit economics tracking; cost per MAU monitoring | Monthly |

---

### 20. NFR Governance

| Activity | Frequency | Owner |
| --- | --- | --- |
| SLO review (error budget consumption) | Weekly | SRE Lead |
| Capacity planning review | Monthly | SRE Lead + DevOps Lead |
| Performance regression review | Per release | QA Lead + Backend Lead |
| Security NFR review | Quarterly | CISO + Security Architect |
| Compliance NFR review | Quarterly | Compliance Officer |
| NFR document review and update | Bi-annual | Solution Architect |
| Disaster recovery drill | Annual (full) + Quarterly (tabletop) | SRE Lead |
| Architecture Decision Records review | Per major architectural change | Solution Architect |

---

### 21. NFR Trade-off Decisions

Non-functional requirements are interdependent. Improving one often costs another. The following trade-off decisions are documented to guide future architectural choices when conflicts arise.

| # | Trade-off | Decision | Rationale |
| --- | --- | --- | --- |
| TO-01 | Strong consistency vs availability (CAP) for user records | Strong consistency | A user must never see "user not found" immediately after creation. Availability degradation during partition is acceptable; data correctness is not. |
| TO-02 | Latency vs durability for audit logs | Durability | Audit logs must never be lost. Async durability with backpressure is preferred over best-effort low-latency writes. |
| TO-03 | Cost vs availability for free tier | Cost (within stated SLA) | Free tier has lower SLA (99.5%) to enable cost-efficient infrastructure. Paid tiers receive 99.9%+ with redundancy investment. |
| TO-04 | Developer experience vs strict standards conformance | Conformance | Where DX desires conflict with OAuth 2.1 / OIDC strict conformance, conformance wins. Deviations from standards introduce long-term technical debt and security risk. |
| TO-05 | Feature velocity vs maintainability | Maintainability | Engineering velocity short-term is sacrificed when it would compromise long-term maintainability. Tech debt creates compounding cost. |
| TO-06 | Multi-cloud portability vs cloud-native optimization | Portability for core paths; optimization for non-critical paths | Auth-critical services remain cloud-portable. Ancillary services (analytics, batch processing) may use cloud-native services with documented lock-in. |
| TO-07 | Tenant isolation strictness vs operational efficiency | Isolation | Cross-tenant data leakage is an existential failure. Operational inefficiency in service of isolation is acceptable. |
| TO-08 | Backwards compatibility vs API evolution | Backwards compatibility for 12 months minimum | Customers depend on API stability. New API versions launched in parallel; old versions deprecated only with full migration path. |

---

### 22. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Solution Architect |  |  |  |
| Security Architect |  |  |  |
| CTO |  |  |  |
| DevOps / SRE Lead |  |  |  |
| Backend Engineering Lead |  |  |  |
| Frontend Engineering Lead |  |  |  |
| QA Lead |  |  |  |
| Compliance Officer |  |  |  |
| Product Manager |  |  |  |

---

*This document is version controlled. Non-Functional Requirements are a living specification — they must be reviewed when traffic patterns change materially, when new regulatory obligations emerge, when significant architectural decisions are made, or when post-incident reviews identify gaps. Any material deviation from a stated NFR target during engineering implementation requires a formal Architecture Decision Record (ADR) reviewed and approved by the Solution Architect and the relevant functional owner before the deviation is accepted.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*