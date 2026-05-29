# Qeet ID — Infrastructure & Deployment Architecture

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Infrastructure & Deployment Architecture |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | DevOps / Cloud Architect |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the infrastructure and deployment architecture that hosts Qeet ID. It covers cloud provider strategy, region selection, multi-AZ topology, Kubernetes cluster layout, namespace and workload segmentation, ingress, CDN, database/cache/Kafka hosting, object storage, secrets management infrastructure, CI/CD pipelines, environments (Dev, Staging, Production, PR-ephemeral), Infrastructure as Code, networking (VPC, subnets, peering, PrivateLink), cost optimisation, disaster recovery topology, and the data residency enforcement mechanism.

The audience is the DevOps / Cloud Architect, the SRE Lead, the Platform Team Lead, the Security Architect, the Solution Architect, the CTO, and Finance (for cost posture).

This document depends on every other Phase 2 architecture document for what must be deployed; it specifies *where* and *how*.

---

### 3. Cloud Provider Strategy

### 3.1 Primary: AWS

AWS is the primary cloud (ADR-003) for MVP. The selection rationale and the Phase 1 stakeholder context are summarised in the ADR; the engineering bottom-line: AWS has the broadest enterprise compliance posture (FedRAMP, GovCloud, sovereign regions on the v2.0 roadmap), the deepest set of managed services we need (Aurora, EKS, MSK, ElastiCache, KMS, S3, Shield Advanced), the strongest team-internal expertise, and the most mature partner ecosystem.

### 3.2 Secondary Readiness: GCP

GCP is the secondary cloud (NFR PO-02) — *readiness* in the architecture, not active deployment. We maintain GCP-parity in IaC modules (Terraform modules abstract cloud-specific providers), validate cloud-portability with an annual exercise in a non-production environment, and document any AWS-specific dependency. Adoption of GCP as a co-primary is on the v2.0 roadmap.

### 3.3 Azure

Azure is not on the active roadmap at MVP. Azure-parity in IaC is targeted *opportunistically* — when a customer demands it. The architectural commitment is that nothing in core Qeet ID (excluding Marketplace-style integrations) couples to an AWS-specific paradigm.

### 3.4 Cloud Lock-In Register

A document maintained by the Cloud Architect lists every AWS-specific dependency in production. New entries require an ADR. Reviewed annually (NFR PO-07).

Items expected at MVP:

- AWS KMS (key management; the KEKs cannot move clouds without re-issuance)
- AWS Shield Advanced (DDoS-protection; GCP / Cloudflare equivalents differ)
- AWS Aurora (managed Postgres; portable to GCP Cloud SQL with operational lift)
- AWS MSK (managed Kafka; portable to Confluent Cloud or GCP MSK-equivalents)
- AWS S3 (object storage; trivially portable to GCS / Azure Blob)
- AWS Cognito — **not** used; we are the auth platform.

---

### 4. Region Selection

### 4.1 MVP Regions

| Region | AWS Code | Purpose | Status |
| --- | --- | --- | --- |
| US East 1 | us-east-1 (N. Virginia) | Primary US; global control plane; cheapest / lowest-latency | MVP |
| EU West 1 | eu-west-1 (Ireland) | Primary EU; GDPR residency | MVP |
| US West 2 | us-west-2 (Oregon) | DR-only for us-east-1 backups | MVP — backup target |
| EU Central 1 | eu-central-1 (Frankfurt) | DR-only for eu-west-1 backups | MVP — backup target |

### 4.2 Roadmap

| Region | Code | Purpose | Phase |
| --- | --- | --- | --- |
| London | eu-west-2 | UK residency | v1.2 |
| Singapore | ap-southeast-1 | APAC; PDPA | v1.2 |
| Sydney | ap-southeast-2 | Australian PDP | v1.5 |
| Tokyo | ap-northeast-1 | Japan | v1.5 |
| Mumbai | ap-south-1 | India; DPDPA | v1.5 |
| São Paulo | sa-east-1 | LATAM; LGPD | v2.0 |

### 4.3 Tenant Pinning

Per Multi-Tenancy §8, tenants are pinned to one region. Customer-visible region selection happens at tenant creation. The region is recorded in `tenants.data_region` and enforced at every write — a write against a region different from the tenant's `data_region` is rejected.

---

### 5. Multi-AZ Topology

Each production region is deployed across **a minimum of three Availability Zones** (NFR RD-01). Every stateful service is replicated cross-AZ; every stateless service runs ≥ 1 pod per AZ.

```
   ┌───────────────────────────────────────────────────────────────────┐
   │                       Region: us-east-1                           │
   │                                                                   │
   │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐         │
   │  │   AZ-A       │    │   AZ-B       │    │   AZ-C       │         │
   │  │              │    │              │    │              │         │
   │  │ EKS Nodes    │    │ EKS Nodes    │    │ EKS Nodes    │         │
   │  │ Aurora       │    │ Aurora       │    │ Aurora       │         │
   │  │  Writer      │    │  Reader      │    │  Reader      │         │
   │  │ ElastiCache  │    │ ElastiCache  │    │ ElastiCache  │         │
   │  │  Primary     │    │  Replica     │    │  Replica     │         │
   │  │ MSK Broker 1 │    │ MSK Broker 2 │    │ MSK Broker 3 │         │
   │  └──────────────┘    └──────────────┘    └──────────────┘         │
   │                                                                   │
   └───────────────────────────────────────────────────────────────────┘
```

**Failover behaviour:** Aurora failover < 60 s (NFR FO-04); ElastiCache replica promotion < 30 s; MSK survives a single broker loss; EKS reschedules pods to surviving AZs within 2 min (NFR FO-02 / FO-03).

---

### 6. Kubernetes Cluster Topology

### 6.1 Cluster Structure

One EKS cluster per (environment, region) combination:

| Cluster | Purpose |
| --- | --- |
| qeetify-dev | Shared developer environment |
| qeetify-staging | Pre-prod (mirrors prod topology smaller) |
| qeetify-prod-use1 | Production us-east-1 |
| qeetify-prod-euw1 | Production eu-west-1 |

EKS version pinned with planned upgrade cadence (every 6 months, blue/green node groups).

### 6.2 Node Groups

| Node Group | Workload | Instance | Scaling |
| --- | --- | --- | --- |
| `system` | Cluster components, controllers, observability collectors | m6i.large | min 3, max 10 |
| `core-auth` | Auth, Token, Session, MFA pods | c6i.large to c6i.2xlarge | HPA + cluster autoscaler |
| `identity` | User, Tenant, RBAC, Keys pods | c6i.large to c6i.2xlarge | HPA |
| `federation` | SAML, SCIM, Social IdP Bridge | c6i.large | HPA |
| `guard` | Guard, Anomaly, Audit Ingestion | c6i.xlarge | HPA |
| `experience` | Admin BFF, Dev Portal BFF, Hosted Login, Billing | m6i.large | HPA |
| `async` | Webhook workers, Notification, Background Workers | m6i.large | Queue-depth-based |
| `mesh-ingress` | Istio ingress gateways | c6i.large | HPA on RPS |

Critical workloads avoid spot instances (NFR CE-07 nuance — non-critical only). Async workers can use spot for cost optimisation.

### 6.3 Namespace Layout

```
   kube-system            cluster controllers
   istio-system           service mesh control plane
   observability          Prometheus, Grafana, Jaeger, Loki, otel-collector
   ingress                Istio ingress gateways
   auth                   Auth, Token, Session, MFA
   identity               User, Tenant, RBAC, Keys
   federation             SAML, SCIM, Social-Bridge
   guard                  Guard, Anomaly, Audit-Ingestion
   experience             Admin-BFF, Portal-BFF, Hosted-Login, Billing
   async                  Webhook, Notification, Background-Workers
   platform               cert-manager, external-dns, vault-agent injector
```

Namespaces map 1:1 to team ownership boundaries. NetworkPolicies enforce inter-namespace default-deny ([Security §6.2]).

### 6.4 Workload Manifests

- Each service ships a Helm chart with environment-specific values overlays.
- Argo CD (or Flux) reconciles cluster state from a single source-of-truth Git repository.
- Pod Security Standards: `restricted` profile enforced.
- All workloads define resource requests/limits; CPU/memory monitored and right-sized monthly.

---

### 7. Ingress Architecture

```
   Public DNS qeetify.com / *.qeetify.com (route 53)
        │
        ▼
   Cloudflare (CDN + WAF + Bot)
        │
        ▼
   AWS Shield Advanced
        │
        ▼
   AWS Application Load Balancer (per environment, per region)
        │  TLS terminated; HTTP/2; HSTS
        ▼
   Istio Ingress Gateway (per region)
        │  mTLS inside mesh from here
        ▼
   Service mesh — routes to namespace/service per VirtualService
```

- Wildcard cert `*.qeetify.com` issued by AWS Certificate Manager; per-tenant subdomain certs covered by wildcard.
- HTTP → HTTPS redirect at the edge.
- HSTS `max-age=63072000; includeSubDomains; preload`.
- ALB connection draining 30 s during pod rolling updates.
- Istio gateway enforces per-tenant rate limit (Guard call-out) before routing to services.

---

### 8. CDN Strategy

### 8.1 Edge Caching

Cloudflare is the primary CDN. Cacheable assets:

- Static JS/CSS bundles for hosted login pages, dev portal, admin dashboard.
- `/.well-known/openid-configuration` and `/.well-known/jwks.json` (NFR CA-01 / CA-02 — short TTL).
- Documentation site content.
- Status page assets (hosted independently per NFR AV-10).

### 8.2 Multi-CDN

Per NFR RD-08, a multi-CDN strategy for static assets is mandatory. AWS CloudFront is the secondary CDN. Failover is DNS-driven; CDN-health monitoring switches origin behaviour automatically.

### 8.3 No CDN on Authenticated API Paths

API requests against `/v1/*`, `/oauth/*`, `/scim/*`, `/saml/*` bypass CDN caching — they reach the origin directly through Cloudflare's pass-through.

---

### 9. Database Hosting (Aurora PostgreSQL)

### 9.1 Cluster Configuration

| Setting | Value |
| --- | --- |
| Engine | Aurora PostgreSQL 16.x (latest minor) |
| Cluster type | Provisioned (not Serverless v2 at MVP — predictable cost) |
| Topology | 1 writer + N readers across 3 AZs |
| Instance class | db.r6i.2xlarge writer; db.r6i.xlarge readers (sized to load) |
| Storage | Aurora storage (auto-scaling, encrypted) |
| Backups | Continuous (RPO ≤ 5 s); snapshots per Database §11 |
| TLS | Required |
| IAM authentication | Disabled at MVP (Vault dynamic creds preferred) |
| Performance Insights | Enabled |
| Enhanced Monitoring | Enabled, 30-second granularity |

### 9.2 Sharding (post-100K tenants)

Per Multi-Tenancy §6, additional clusters spawn. Each shard cluster has identical topology. The Tenant Service holds the tenant → shard mapping.

### 9.3 Dedicated Enterprise Clusters (L2)

Per Multi-Tenancy §7, Enterprise customers in L2 get dedicated clusters. Sized to commitment; SLA-backed.

### 9.4 Database Credentials

Provisioned dynamically by Vault — each pod gets a per-pod role with bounded lifetime. No static `qeetify_app` superuser sitting in a Kubernetes secret.

---

### 10. Cache Hosting (ElastiCache Redis)

| Setting | Value |
| --- | --- |
| Engine | Redis 7 cluster mode |
| Topology | 3 shards (initial); auto-resharding as memory pressure rises |
| Replicas | 2 per shard (NFR HS-09) |
| Multi-AZ | Yes |
| Encryption | In-transit + at-rest (KMS-managed) |
| AUTH | Enabled with rotated AUTH token (Vault) |
| Persistence | Snapshotting enabled; primary source of truth is Postgres for durability tier |
| Maintenance window | Sunday 04:00 UTC; coordinated with deploy freeze |

Cluster mode enables horizontal scaling via hash-slot rebalancing.

---

### 11. Kafka Hosting (Amazon MSK)

| Setting | Value |
| --- | --- |
| Cluster size | 3 brokers initial; scaled per NFR HS-10 (max 30) |
| Instance | kafka.m5.large initial; sized up as volume grows |
| Multi-AZ | Brokers spread across 3 AZs |
| Replication factor | ≥ 3 for all critical topics (NFR RD-06) |
| Encryption | In-transit (TLS) + at-rest |
| Authentication | SASL/SCRAM via Vault-rotated credentials |
| Authorization | Kafka ACLs per topic |
| Retention | per-topic (per Microservices §6.3) |
| Schema registry | Self-hosted Karapace / AWS Glue Schema Registry — open decision |

---

### 12. Object Storage (Amazon S3)

| Bucket | Purpose | Versioning | Lifecycle |
| --- | --- | --- | --- |
| qeetify-audit-cold-{region} | Audit log cold tier | Yes + Object Lock | Glacier transition at 12m; expiry at retention horizon |
| qeetify-backups-{region} | DB & service backups | Yes | Retention per Database §11 |
| qeetify-user-exports-{region} | GDPR Article 20 exports | No | 30-day expiry |
| qeetify-branding-{region} | Tenant logos, login-page assets | Yes | None |
| qeetify-static-{region} | CDN-origin static assets | Yes | None |

Cross-region replication for `qeetify-audit-cold-*` and `qeetify-backups-*` to a paired DR region.

All buckets:

- Block Public Access enabled at bucket and account level.
- SSE-KMS encryption with per-bucket CMK.
- Access logging to a separate `qeetify-s3-access-logs-{region}` bucket.

---

### 13. Secrets Management (AWS KMS + HashiCorp Vault)

Architecture detail in [Security Architecture §8](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md). Infrastructure aspects:

- Vault deployed in HA on dedicated EKS namespace `platform`.
- 3-node Vault cluster; Raft storage backend.
- Auto-unseal via AWS KMS.
- Vault Agent sidecar injector configured cluster-wide.
- KMS CMKs are environment-scoped (`qeetify-prod-jwt-signing`, `qeetify-prod-envelope-master`, `qeetify-prod-backup`, etc.) with rotation policies.

---

### 14. CI/CD Pipeline Architecture

### 14.1 Source Control

- GitHub (per Charter; Compliance SP-06).
- Branch protection on `main`: required reviews (≥1; ≥2 for security-sensitive paths — NFR MN-03), CI pass, signed commits, no force push.
- Monorepo OR multi-repo per service — **open decision** (OQ-INF-01); preliminary direction: multi-repo with shared template repo for consistency.

### 14.2 GitHub Actions (ADR-017)

Pipeline stages (per service):

```
   PR opened or pushed to main:
   ─────────────────────────────────────────────
   ▼ Lint, format, type-check
   ▼ Unit tests
   ▼ Integration tests (with ephemeral PG + Redis containers)
   ▼ SAST (Semgrep + CodeQL)
   ▼ Dependency scan (Snyk)
   ▼ Secret scan (gitleaks)
   ▼ OpenAPI spec validation
   ▼ Contract tests (consumer-driven)
   ▼ Docker image build
   ▼ Container scan (Trivy)
   ▼ Image sign (Cosign)
   ▼ Push to ECR
   ▼ Generate SBOM
   ─────────────────────────────────────────────
   On main merge:
   ▼ Deploy to dev (auto)
   ▼ Smoke tests
   ▼ Manual approval → staging
   ▼ Staging deploy
   ▼ Staging smoke + DAST
   ▼ Manual approval → production (with deploy window check)
   ▼ Canary deploy (5% traffic)
   ▼ SLO-based gates (15-min observation window)
   ▼ Full rollout
   ▼ Post-deploy synthetic verification
   ─────────────────────────────────────────────
   On failure:
   ▼ Automatic rollback within 60 s (NFR OP-04)
   ▼ PagerDuty alert
```

### 14.3 PR Preview Environments

Every PR spawns an ephemeral environment via Argo CD `ApplicationSet`. Provides preview URLs for visual review of UI changes. Auto-destroyed on PR close + 24 h grace.

### 14.4 Deploy Cadence

- Standard deploys: any time (NFR OP-07).
- High-risk deploys (schema migrations, ingress changes, mesh config): scheduled outside peak.
- Deploy window check verifies no active P1/P2 incident, no error-budget exhaustion (NFR SL — when budget burned, deploys to that service pause).

---

### 15. Environments

| Environment | Purpose | Data | Access |
| --- | --- | --- | --- |
| dev | Active development; integrated testing | Synthetic data only | All engineering |
| staging | Pre-production validation; SOC 2 evidence environment | Anonymised production-like data | Engineering + QA |
| prod-use1 | Production us-east-1 | Real customer data | Just-in-time elevated only |
| prod-euw1 | Production eu-west-1 | Real customer data (EU residency) | Just-in-time elevated only |
| PR-ephemeral | Per-PR preview | Synthetic seeded | PR author + reviewers |
| DR drill | Quarterly DR rehearsal target | Restored from production backups | DR team during exercise |

Production VPCs are fully isolated from staging and dev (NFR NS-02). No peering. Staging gets a snapshot of anonymised production data nightly for parity testing.

---

### 16. Infrastructure as Code (Terraform)

### 16.1 Module Structure

```
   terraform/
     modules/                    Reusable, generic modules
       vpc/
       eks-cluster/
       aurora-cluster/
       elasticache-redis/
       msk/
       s3-bucket/
       iam-role/
       cloudfront-distribution/
       ...
     stacks/                     Deployable, environment-targeting compositions
       prod-use1/
         main.tf                 Composes modules
         backend.tf              State backend (S3 + DynamoDB lock)
         variables.tf
         outputs.tf
       prod-euw1/
       staging/
       dev/
     policy/                     OPA / Sentinel policy library
```

### 16.2 Conventions

- Terraform 1.x; provider versions pinned.
- State in S3 with DynamoDB state locking; per-stack state file.
- Every PR runs `terraform plan` + `tfsec` + `Checkov` + OPA policy checks.
- No `apply` from a developer laptop; only via the deployment pipeline (Atlantis or Terraform Cloud agent).
- Every change is reviewed; production changes require two approvers.

### 16.3 Cloud-Portability Posture

Modules abstract provider-specific resources behind interface variables. The Aurora module would have a hypothetical `cloud_sql_postgres` sibling in GCP-readiness. The exercise of swapping out cloud-specific modules is performed annually against a non-production environment to validate portability isn't theoretical.

---

### 17. Networking

### 17.1 VPC Layout

Detail in [Security Architecture §6.1](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md). One VPC per (environment, region).

### 17.2 PrivateLink

Where applicable, AWS service access uses VPC endpoints / PrivateLink to keep traffic off the public internet:

- S3 Gateway endpoint
- KMS Interface endpoint
- Secrets Manager Interface endpoint (for AWS-native fallbacks)
- ECR Interface endpoint
- STS Interface endpoint
- CloudWatch Logs Interface endpoint

### 17.3 Peering

No VPC peering between environments. Cross-account access via assume-role with audit. Inter-region replication uses cross-region replication services (Aurora Global Database for v1.5 enterprise; S3 CRR for backups at MVP) — not VPC peering.

### 17.4 NAT Egress

Egress to the public internet from production goes via NAT Gateway with allow-listed destination filtering (Security §6.4). NAT is multi-AZ; failover automatic.

---

### 18. Cost Optimisation Strategy

### 18.1 Cost Targets

Per NFR CE-01: **infrastructure cost < $0.05 per MAU per month at 1M MAUs.** This is the platform-level economic constraint.

### 18.2 Tactics

- **Reserved instances / Savings Plans** for steady-state EKS, Aurora, ElastiCache, MSK (NFR CE-06).
- **Spot instances** for non-critical async workers, batch jobs (NFR CE-07).
- **Right-sizing reviews** monthly (NFR CE-05); CPU < 40% or memory < 50% utilization triggers review.
- **Cost allocation tags** on every resource: `qeetify:tenant`, `qeetify:service`, `qeetify:env`, `qeetify:owner`.
- **Cost dashboards** in Grafana fed by AWS Cost Explorer / CUR.
- **Budget alerts** at 50% / 75% / 90% / 100% of monthly budget (NFR CE-04).
- **Idle resource sweepers** identify and notify on unused dev/staging environments (NFR CE-10).
- **Per-tenant cost attribution** (NFR CE-09) — for unit-economics analysis; informs pricing.

### 18.3 Forecasting

Monthly capacity-planning meeting reviews cost-per-MAU trend, projects forward 90 days against MAU growth, and flags Mid-air adjustments. Output goes to Finance.

---

### 19. Disaster Recovery Architecture

### 19.1 DR Objectives

| Metric | Target | NFR |
| --- | --- | --- |
| RTO regional disaster | 4 hours | DR-01 |
| RPO regional disaster | 5 minutes | DR-02 |
| Single-AZ failure RTO | < 5 minutes | FO-03 |
| Database failover RTO | < 60 s | FO-04 |

### 19.2 DR Posture (MVP)

**Warm-standby cross-region pattern.** The DR region (us-west-2 for us-east-1; eu-central-1 for eu-west-1) is **not** running an active mirror of production; it is the **backup target** plus pre-baked infrastructure-as-code waiting to receive activation.

Activation procedure (runbook):

1. Declare DR (Incident Commander).
2. Spin up EKS cluster in DR region from Terraform (≤ 60 min for stable cluster).
3. Restore latest Aurora snapshot to DR cluster (≤ 60 min for our anticipated size).
4. Restore Redis from snapshot (≤ 15 min).
5. Restore MSK from backup (or accept reset — events older than DR are replayed from S3 audit cold).
6. Update DNS to point at DR region's ALB.
7. Customers see ≤ 4-hour outage; ≤ 5 min data loss.

The 4-hour RTO is achievable because the IaC is committed and ready; the cluster does not need to be designed at the moment of disaster.

### 19.3 Active-Active Roadmap

v1.5 — for **Enterprise** tier, an active-active multi-region option (NFR FO-06) lets the customer continue operating during a region failure. Requires per-tenant Aurora Global Database, multi-region session storage, and conflict-resolution policy for SCIM writes. Tracked in the v1.5 roadmap.

### 19.4 DR Drills

- Quarterly tabletop exercise (NFR DR-07).
- Annual full DR exercise: restore production into a non-production DR region; validate runbook; measure actual RTO/RPO; publish post-exercise report.

---

### 20. Data Residency Enforcement Mechanism

Tenants are pinned to a region (Multi-Tenancy §8.1). Enforcement layers:

| Layer | Mechanism |
| --- | --- |
| Tenant record | `tenants.data_region` set at creation; immutable except by explicit support-initiated migration |
| Tenant routing | Cache + Tenant Service returns `data_region`; application services know which region they live in |
| Application | A service running in `us-east-1` rejects requests carrying `tenant.data_region != us-east-1` with 421 Misdirected Request and a `Location: https://{tenant}.qeetify.com/...` hint (the per-tenant subdomain maps to the right region at the DNS layer) |
| API Gateway | Tenant routing rules at the gateway redirect cross-region traffic to the correct region |
| Backups | Replicated only to the same residency boundary's DR target (us-east → us-west; eu-west → eu-central) |

A customer in the EU region with a US-based engineer querying the API still gets routed to the EU region; the data never leaves the EU.

The audit trail records data_region for every write; a tooling check verifies no data is written outside its declared region. Violations are a P1 audit-evidence issue.

---

### 21. Open Decisions Carried From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OQ-INF-01 | Monorepo vs multi-repo for service code | Backend Lead + DevOps | Phase 2 close |
| OQ-INF-02 | Argo CD vs Flux for GitOps | Platform Team | Phase 2 close |
| OQ-INF-03 | Schema registry — Karapace vs AWS Glue Schema Registry vs Confluent | DevOps | Phase 2 close |
| OQ-INF-04 | Aurora Global Database (active-active EE) — v1.5 vs v1.2 | Product + DevOps | Post-MVP planning |
| OQ-INF-05 | Whether to use AWS Wickr or PagerDuty for sensitive ops comms | CISO | Phase 2 close |

---

### 22. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| DevOps / Cloud Architect |  |  |  |
| SRE Lead |  |  |  |
| Platform Team Lead |  |  |  |
| Solution Architect |  |  |  |
| Security Architect |  |  |  |
| Database Architect |  |  |  |
| CTO |  |  |  |
| Finance Lead (cost posture) |  |  |  |

---

*This document is version controlled. Infrastructure changes that affect blast radius, cost posture, or residency posture require Cloud Architect, Security Architect, and CTO review. Region additions require Compliance Officer review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
