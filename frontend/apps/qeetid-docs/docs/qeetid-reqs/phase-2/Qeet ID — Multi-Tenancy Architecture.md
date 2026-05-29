# Qeet ID — Multi-Tenancy Architecture

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Multi-Tenancy Architecture |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Solution Architect + Backend Lead |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the multi-tenancy architecture of Qeet ID. It specifies the isolation model, the database isolation strategy, the sharding strategy, the Enterprise dedicated tier, the noisy-neighbour protections, the tenant migration capability, the propagation mechanism for tenant context, the cross-tenant access-prevention guarantees, the tenant lifecycle (creation, suspension, deletion with GDPR erasure), and the test strategy for tenant isolation.

Multi-tenancy at Qeet ID is a **core, architecturally enforced property** — not a configuration option. Cross-tenant data leakage is classified as an existential failure (NFR ER-10, TO-07). Every other architecture document must be consistent with this one.

The audience is the Solution Architect, Backend Lead, Database Architect, Security Architect, DevOps Lead, Product Manager, and Compliance Officer.

This document depends on [High-Level System Architecture](Qeet ID%20%E2%80%94%20High-Level%20System%20Architecture.md), [Microservices Decomposition](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md), and informs [Database Design & Data Model](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md) and [Security Architecture](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md).

---

### 3. Multi-Tenancy Principles

**MTP-01 — `tenant_id` is the architectural backbone.** It appears in every JWT, every HTTP header on the data path, every database row, every cache key, every log line, every metric label, every Kafka event partition key. There is no Qeet ID data object that does not carry it.

**MTP-02 — Defence in depth.** Tenant isolation is enforced at (a) the JWT (`qeetify/org_id` claim — Protocol §5.6), (b) the application layer (request scope), (c) the database layer (row-level security), (d) the cache layer (key namespacing), and (e) the audit layer (logged, queried only within tenant boundaries).

**MTP-03 — Tenant context is always derived, never asserted by the client.** A client may not pass `X-Tenant-ID` and have it be trusted. Tenant context is computed from the authenticated token's `qeetify/org_id` claim. Clients can be told what tenant they are addressing, but they cannot tell us.

**MTP-04 — Cross-tenant access is architecturally impossible, not policy-enforced.** A code path that could in principle read another tenant's data is a defect — not because of a missing guard but because the code path itself should not exist (NFR MT-01). RLS policies catch the rest.

**MTP-05 — Tenants are independent.** Performance, availability, security, and configuration of one tenant cannot affect another (NFR MT-02). Noisy-neighbour mitigation is mandatory.

**MTP-06 — Tenancy is independent of users.** A user can belong to multiple tenants (e.g., a consultant working with five client organisations); their identity is global across Qeet ID (the User Service's `users.global_id`) but their roles, sessions, and tokens are tenant-scoped.

**MTP-07 — Tenancy is observable.** Per-tenant metrics, logs, and trace tags allow us to debug a single tenant's issue without query-scanning the rest. Per-tenant resource consumption is attributable for billing and capacity planning.

**MTP-08 — Tenancy survives all platform evolution.** Schema migrations, service splits, region additions, and architecture refactors must preserve the tenant boundary. Any change that risks the boundary requires Security Architect sign-off.

---

### 4. Tenant Isolation Model

### 4.1 The Three-Tier Isolation Model

Qeet ID uses three isolation levels chosen per workload class:

| Level | Description | Used For |
| --- | --- | --- |
| L1 — Shared infrastructure, isolated data (default) | All tenants share Kubernetes namespaces, services, databases. Data is row-level isolated via `tenant_id` + RLS. | All Free and Growth tier customers. Default for all new tenants. |
| L2 — Shared infrastructure, dedicated database shard | All tenants share Kubernetes / services. Tenant data lives on a dedicated PostgreSQL shard. | Enterprise tier customers who opt in. |
| L3 — Dedicated everything (post-MVP v2.0) | A dedicated Kubernetes namespace, dedicated Postgres / Redis / Kafka clusters, dedicated region if requested. | Enterprise customers with regulatory or contractual dedicated-tenancy requirements. |

L1 is the platform default. L2 is the dedicated-shard option (NFR MT-04). L3 is the "single-tenant cloud" offering scheduled for v2.0 alongside on-premise readiness (NFR PO-08).

This document focuses on L1 and L2 — both are MVP.

### 4.2 Tenant Identifier

`tenant_id` is a UUID v7 (sortable; we use UUID v7 platform-wide for primary keys to enable B-tree-friendly index access). The display form to customers is the `slug` (`acme`) but the durable identifier is the UUID.

```
   tenants
   ──────────────────────────────────────────────
   id (uuid, PK)                — internal canonical id
   slug (text, unique)          — customer-facing
   display_name (text)
   plan (free|growth|enterprise)
   data_region (us-east-1|eu-west-1|...)
   isolation_tier (l1|l2|l3)
   status (active|suspended|pending_deletion|deleted)
   shard_id (text, nullable)    — non-null for l2/l3
   created_at, updated_at, deleted_at
```

---

### 5. Database Isolation Strategy

### 5.1 Per-Service Strategy

The recommendation is **not uniform** — services with different data shapes warrant different isolation strategies.

| Service | Default isolation | Rationale |
| --- | --- | --- |
| User Service | RLS on shared Postgres | Heavy cross-service joins; one writer per user |
| Tenant Service | RLS on shared Postgres | Tenant records are by definition tenant-scoped |
| RBAC Service | RLS on shared Postgres | Permission checks are hot; co-location with cache wins |
| Token Service | RLS on shared Postgres | Tokens are short-lived; RLS overhead acceptable |
| Session Service | RLS on shared Postgres + Redis namespace | Hot reads from Redis; Postgres is source of truth |
| MFA Service | RLS on shared Postgres | Credential data; field-encrypted; RLS enforces tenancy |
| Keys Service | RLS on shared Postgres | API key lookups dominated by Redis cache |
| SAML Service | RLS on shared Postgres | IdP metadata is per-tenant; few cross-tenant queries |
| SCIM Service | RLS on shared Postgres | Per-tenant provisioning state |
| Audit Ingestion | Partitioned by `(tenant_id, date)` + RLS | Tenant queries scoped at partition level for performance |
| Webhook Delivery | Partitioned by `tenant_id` + RLS | High write rate; tenant-level isolation matters for delivery fairness |
| Billing | RLS on shared Postgres | Per-tenant billing records |

There is **no schema-per-tenant default**. Schema-per-tenant introduces migration complexity (N schema upgrades per release), connection pool fragmentation (each tenant connection isolated to its schema), and operational toil that does not scale to 100,000+ tenants. RLS is the default.

**Schema-per-tenant** is **available** for Enterprise customers opting into L2 isolation tier (§6) — but L2 uses **database-per-shard** rather than schema-per-tenant within a shared cluster. This achieves better isolation without schema-explosion.

### 5.2 Row-Level Security (RLS) Policy

Every table that holds tenant data has the column `tenant_id NOT NULL` and an RLS policy:

```sql
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON users
USING (tenant_id = current_setting('qeetify.current_tenant_id')::uuid);
```

Application connections set `qeetify.current_tenant_id` per-transaction:

```sql
BEGIN;
SET LOCAL qeetify.current_tenant_id = 'tenant-uuid-here';
-- queries within transaction filter automatically
SELECT * FROM users WHERE id = $1;
COMMIT;
```

The setting is **per-transaction**, not per-connection — to prevent pool-reuse leakage. Every transaction begins with the SET LOCAL.

**Bypass.** A handful of platform-internal roles (`postgres`, `qeetify_admin`) bypass RLS for migrations and cross-tenant queries (analytics, support). These roles are not used by application services; they are used by operators with audited access (NFR AC-04).

### 5.3 Compound Indexes

Every index on a tenant table has `tenant_id` as the leading column (NFR — implied by the latency targets and validated in [Database Design](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)).

```sql
CREATE UNIQUE INDEX users_tenant_email_idx
  ON users (tenant_id, email_hash);

CREATE INDEX user_role_assignments_tenant_user_idx
  ON user_role_assignments (tenant_id, user_id);
```

Without leading `tenant_id`, the planner cannot efficiently use the index for tenant-scoped queries — at our 100M-row 24-month scale, this is the difference between an index scan and a sequential scan.

---

### 6. Tenant Sharding Strategy

### 6.1 Trigger for Sharding

Per NFR MT-05, automatic sharding activates **from 100,000 tenants**. Before that, a single PostgreSQL Aurora cluster (with read replicas) serves all L1 tenants in a region. After 100,000, the L1 tenant population is sharded across N clusters.

### 6.2 Shard Selection

Sharding is by **hash of `tenant_id`** to one of N shards. The hash uses a stable algorithm (xxhash64 or SipHash with a fixed key) so the same tenant always lands on the same shard given a fixed N.

```
   shard_id = "shard_" + (xxhash64(tenant_id) % N).hex()
```

The shard ID is stored on the `tenants` row (see §4.2) so we don't recompute on every query — the application reads `tenants.shard_id` from a tenant-routing cache (Redis; 5-min TTL) and routes connections accordingly.

### 6.3 Resharding

Increasing N is the operationally interesting case. Approach:

1. Provision new shard cluster(s).
2. For each tenant whose computed new-shard differs from current-shard, perform an online migration (see §10).
3. After all tenants migrated, decommission empty old-shard capacity.

We do **not** use consistent hashing at MVP — its operational complexity is not warranted at our tenant counts. We accept that a resharding event is a planned operations exercise, expected at most once per year.

### 6.4 Per-Shard Capacity

Each L1 shard targets approximately 20,000–30,000 tenants and approximately 500K MAUs. At 1M tenants forecast (post-24-month), this implies 30–50 shards per region — operationally tractable with shard automation tooling.

### 6.5 Cross-Shard Queries

There are essentially none on the hot path. Tenant operations stay within a shard. Cross-shard reporting (e.g., "total MAUs platform-wide") goes through the audit pipeline and analytics aggregation, never through online OLTP.

---

### 7. Dedicated Tier Architecture (L2)

### 7.1 L2 Definition

An Enterprise customer opting into the dedicated tier receives:

- A **dedicated PostgreSQL cluster** (single-AZ small or multi-AZ regular Aurora cluster sized to their commitment).
- A **dedicated Redis shard** (separate from the shared cache cluster).
- A **dedicated Kafka consumer group** isolation (not dedicated brokers — but isolated topic prefix and consumer SLAs).
- A **dedicated worker pool** for webhook delivery and notification dispatch (preventing noisy-neighbour effect on async tier).

Application services (Token, Auth, User, etc.) remain shared; the customer accepts shared compute in exchange for isolated data. Their data does not commingle with other tenants' data at any storage layer.

### 7.2 L2 Routing

A tenant in L2 has `tenants.shard_id` set to a dedicated shard identifier. The tenant-routing cache returns this shard for every connection request from the application services, which then route via shard-aware connection pools.

### 7.3 Promoting L1 → L2

A customer upgrades from L1 to L2 by:

1. Provisioning the dedicated cluster (operator runbook).
2. Triggering a live tenant migration (§10).
3. Updating `tenants.isolation_tier = 'l2'` and `tenants.shard_id = '<dedicated-cluster-id>'`.
4. Tenant traffic redirects on the next request (cache eviction; 5-min worst case during transition).

No downtime to the tenant.

### 7.4 Demoting L2 → L1

By symmetric procedure. Customer must agree (contractual; downgrades typically come with a contract change).

---

### 8. Noisy Neighbour Protection

### 8.1 Per-Tenant Rate Limiting

Per NFR RL-01..RL-10, every tenant has rate limits proportional to their plan. The Guard Service enforces these:

- Token bucket per `(tenant_id, endpoint_class)` in Redis.
- Excess returns HTTP 429 with `Retry-After` (NFR BT-06).
- Limits surface in response headers `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.

### 8.2 Per-Tenant Quotas

Distinct from rate limits, quotas are *count* limits:

- Maximum applications, custom roles, webhooks, API keys, SSO connections (NFR RL-05..RL-09).
- Maximum audit log export volume per day (NFR RL-10).
- Maximum MAUs per month (plan-defined; metered by Billing Service).

Quota violations surface as HTTP 402 (Payment Required) or HTTP 409 (Conflict) depending on whether the violation is an upgrade-able usage cap or an absolute platform max.

### 8.3 Compute Fairness

Within shared Kubernetes services, no tenant should monopolise CPU. The Guard Service tracks `(tenant_id, endpoint)` request-volume rolling averages and feeds the autoscaler. A tenant whose traffic exceeds its allocation triggers either rate-limit shedding (if the spike is unauthorised) or autoscale (if the customer purchased capacity for it).

### 8.4 Storage Fairness

Per-tenant audit-log volume is bounded by quota. Per-tenant database storage in L1 is bounded by the row counts implied by the user/role/webhook/etc. limits. Outsized growth triggers anomaly alerts and a billing-team review.

### 8.5 Kafka Partition Fairness

Topics are partitioned by `tenant_id`. A tenant generating outsized event volume monopolises its partition; it cannot back up other tenants' partitions. The audit pipeline scales consumer groups based on aggregate lag (NFR HS-06).

---

### 9. Tenant Context Propagation

### 9.1 The Propagation Chain

```
   Client request (with bearer token)
        │
        ▼
   Edge (CDN / WAF) — no tenant interpretation; pass through
        │
        ▼
   API Gateway / Mesh Ingress
     - Validate JWT signature; extract qeetify/org_id from claims
     - Set X-Qeetify-Tenant-Id header (overwrite anything client sent)
     - Set X-Qeetify-User-Id header (from sub)
     - Set X-Qeetify-Request-Id header (W3C trace context)
        │
        ▼
   Service A (Auth, Token, ...)
     - Read X-Qeetify-Tenant-Id; reject if missing on a tenant-scoped endpoint
     - Open DB transaction with SET LOCAL qeetify.current_tenant_id
     - Issue Redis ops with key prefix tenant:{id}:
     - Emit logs / metrics with tenant label
        │
        ▼ (internal sync call via mesh)
   Service B
     - mTLS identity established
     - Service-token header carries tenant_id claim
     - Receiver validates service token AND tenant_id matches inbound context
     - Apply identical scoping
        │
        ▼ (async via Kafka)
   Kafka event
     - Partition key = tenant_id
     - Event payload includes tenant_id field
     - Consumer applies identical scoping
```

### 9.2 Header Hygiene

Client-supplied `X-Qeetify-Tenant-Id` headers are **always overwritten** by the API Gateway. Clients cannot impersonate a tenant by asserting an ID; the gateway derives from the bearer token claim and trusts only that derivation.

### 9.3 OAuth Client → Tenant Binding

An OAuth `client_id` belongs to exactly one tenant. The `client_credentials` grant produces tokens for that tenant; the `authorization_code` grant produces tokens for users of that tenant. A token's `qeetify/org_id` claim is the authoritative tenant signal.

### 9.4 Tokens Without Tenant Context

A handful of platform-internal endpoints (status page, public OIDC discovery for the platform — which is not the per-tenant discovery doc) operate without a tenant context. These endpoints are **read-only, public, and serve no tenant data**.

---

### 10. Tenant Migration Capability

### 10.1 Why Migrations Happen

- Resharding (§6.3).
- L1 → L2 promotion (§7.3) or L2 → L1 demotion.
- Data residency change (rare; contractual; treated as a region migration).
- Recovery from a corrupted shard.

### 10.2 Migration Pattern

A tenant migration is **online and zero-downtime** (NFR MT-06):

```
   Phase 1 — Prepare
   ────────────────────────────────
   - Provision target shard (if not exists)
   - Replicate tenant rows from source to target via logical replication
     (Postgres pglogical or AWS DMS)
   - Source remains authoritative; target is read-only catching up
   - Verify row counts and checksums match

   Phase 2 — Switch (window: a few seconds)
   ────────────────────────────────
   - Set tenants.migration_state = 'switching'
   - Force readers to refresh tenant-routing cache (Redis bust)
   - Application services see "tenant in switching" status: queue writes briefly
   - Drain inflight writes on source
   - Update tenants.shard_id = target
   - Allow writes to resume against target
   - Set tenants.migration_state = 'completed'

   Phase 3 — Cleanup
   ────────────────────────────────
   - Stop replication; source rows retained for 7 days
   - After verification window, drop source rows
```

The **switching** window is the only moment of write-blocking. It is bounded to a few seconds by carefully draining inflight writes and using small transactions. End users see at worst a single retried request.

### 10.3 Tenant Migration Audit

Every migration event is recorded: `audit.tenant.migration_started`, `audit.tenant.migration_completed`, `audit.tenant.migration_aborted`. The Compliance team receives a monthly migration report.

---

### 11. Cross-Tenant Access Prevention

### 11.1 The Five-Layer Guarantee

| Layer | Mechanism | Failure mode if absent |
| --- | --- | --- |
| Token | `qeetify/org_id` claim required and signed | Anyone could assert any tenant |
| Gateway | Overwrites client tenant headers from token claim | Client could impersonate |
| Application | Every database call sets `qeetify.current_tenant_id`; SCIM/REST endpoints assert tenant matches resource | Bug in code lets cross-tenant query slip through |
| Database (RLS) | `USING (tenant_id = current_setting...)` policy on every tenant table | Cross-tenant rows returned despite code bug |
| Audit | Cross-tenant log access blocked by tenant_id label scope in OpenSearch index | Operator could view other tenant's logs |

A single layer failure does not result in a breach because the next layer below blocks the request. This is the literal Defence-in-Depth implementation.

### 11.2 Application-Level Guards

Beyond the DB layer, application code uses a wrapper that asserts tenant alignment:

```python
def get_user(tenant_id: UUID, user_id: UUID) -> User:
    with transaction(tenant_id=tenant_id):
        row = db.fetch_one("SELECT * FROM users WHERE id = %s", user_id)
        assert row["tenant_id"] == tenant_id, f"tenant mismatch: {row['tenant_id']} vs {tenant_id}"
        return User(**row)
```

The assertion is belt-and-braces. RLS prevents the fetch returning a foreign row in practice; the assertion is an in-code tripwire that flips if RLS were ever bypassed.

### 11.3 Inter-Service Calls

When Service A calls Service B, both sides participate in tenancy:

- A's request carries `X-Qeetify-Tenant-Id`.
- A's service token (§12 of [IdP Core](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md)) has `tenant_id` claim.
- B verifies both match. Mismatch → reject as `tenant_assertion_inconsistency` (a P1 alert).

### 11.4 Operator Cross-Tenant Access

There are rare cases where Qeet ID operations needs cross-tenant queries — incident response, billing audits, analytics. Procedure:

1. Operator submits a justification ticket.
2. Privileged access granted just-in-time with a time bound (NFR AC-03).
3. Every cross-tenant query logged with the actor and the ticket reference (NFR AC-06).
4. Compliance reviews cross-tenant access weekly.

---

### 12. Tenant Lifecycle

### 12.1 Creation

```
   POST /v1/organizations
     - slug, display_name, data_region, plan
        │
        ▼
   Tenant Service
     1. Validate slug uniqueness
     2. Insert tenants row with status='active', isolation_tier='l1',
        shard_id = compute_shard(id, current_shard_count)
     3. Bootstrap built-in roles (admin/member/viewer)
     4. Create default tenant_configuration (policies, branding)
     5. Emit tenant.created on Kafka
     6. Audit audit.admin.tenant_created
```

Onboarding completes synchronously in ~300 ms. No background work blocks first-use.

### 12.2 Suspension

A tenant may be suspended (admin-triggered, billing-driven, or platform-mandated):

```
   PATCH /v1/organizations/{id} { status: "suspended" }
        │
        ▼
   Tenant Service
     1. Update tenants.status = 'suspended'
     2. Emit tenant.suspended
     3. Session Service revokes all active sessions for the tenant
     4. Token Service revokes all refresh tokens
     5. Subsequent /token requests for this tenant return 403
     6. Read endpoints for tenant configuration continue to work (so admins can un-suspend)
     7. Audit
```

Suspension is reversible — `status = 'active'` restores all but the revoked sessions/tokens (users must re-authenticate).

### 12.3 Deletion (GDPR Article 17 — Right to Erasure)

A tenant deletion is **destructive** and time-bounded by NFR CN-04 (within 30 days, all personal data removed).

```
   DELETE /v1/organizations/{id}     [requires elevated MFA + 24h cooling-off]
        │
        ▼
   Tenant Service
     1. Update tenants.status = 'pending_deletion', deletion_scheduled_at = now() + 24h
     2. Suspend tenant immediately (revoke sessions, tokens)
     3. After 24h cooling-off (allows abort), background worker begins erasure:
        a. Anonymise tenant audit log (replace PII with deterministic pseudonyms)
        b. Delete users, sessions, tokens, MFA factors, passkeys, API keys
        c. Delete SAML / SCIM connections; revoke client_ids
        d. Delete webhook subscriptions
        e. Delete tenant_configuration, branding assets in S3
        f. Delete cached objects in Redis matching tenant prefix
        g. Cancel Stripe subscription via Billing Service
     4. Update tenants.status = 'deleted'; retain tenants row for audit purposes
     5. Backups age out per retention schedule (30d daily, 90d weekly, 1y monthly, 7y yearly for billing only)
     6. Emit tenant.deleted on Kafka
     7. Audit audit.admin.tenant_deleted (retained 3y per CC-AL-05)
```

Anonymisation rather than hard-delete of audit logs preserves immutable audit history while removing personal data — satisfying both Article 17 and SOC 2 audit requirements.

The 30-day SLA (CN-04) accounts for backup-rotation removal: the data is removed from live systems within hours; backups containing the data expire within 30 days at most (the daily backup tier).

### 12.4 Tenant Lifecycle State Diagram

```
                  ┌──────────────┐
                  │   pending    │  (rare — only during async provisioning)
                  └──────┬───────┘
                         │ activate
                         ▼
   ┌─────────────────────────────────────────────────┐
   │                                                 │
   │           ┌──────────────┐                      │
   │           │    active    │ ◀────unsuspend───────┤
   │           └──────┬───────┘                      │
   │                  │ suspend                      │
   │                  ▼                              │
   │           ┌──────────────┐                      │
   │           │  suspended   │──────unsuspend──────▶│
   │           └──────┬───────┘                      │
   └──────────────────┼──────────────────────────────┘
                      │ schedule deletion
                      ▼
              ┌────────────────────┐
              │ pending_deletion   │── abort (≤24h) ─▶ back to suspended
              └─────────┬──────────┘
                        │ 24h cooling-off elapsed
                        ▼
              ┌────────────────────┐
              │      deleted        │  (terminal)
              └────────────────────┘
```

---

### 13. Test Strategy for Tenant Isolation

Multi-tenancy testing is a first-class concern in Phase 6 (NFR VR-02, VR-05). The test strategy:

### 13.1 Unit Tests

Every repository function that touches tenant data has tests proving:

- Reading with `tenant_id = A` does not return a row inserted with `tenant_id = B`.
- An attempt to insert a row whose `tenant_id` differs from the current transaction's setting fails (RLS).
- An attempt to update a foreign tenant's row fails.

### 13.2 Property-Based Tests (Hypothesis / fast-check)

Property: *For any two tenants A and B and any operation O, executing O within A's context never returns or affects B's state.*

The test framework generates random pairs of tenant scenarios and verifies the property holds. Discovery of a violation is a hard CI failure.

### 13.3 Integration Tests

End-to-end tests for each authentication flow include a "tenant isolation" variant:

- Tenant A authenticates; obtains tokens.
- Tenant A's token is used against Tenant B's resources.
- Test asserts every endpoint returns 403 / 404 (without leaking that the resource exists in B).

### 13.4 Contract Tests

Every service's contract tests include the assertion `request.tenant_id == response.tenant_context`. A service that returns data with a different tenant ID than requested fails contract verification.

### 13.5 Chaos Tests (Phase 6+, quarterly)

A chaos test deliberately tries to:

- Submit forged `qeetify/org_id` claims (signed by an attacker key) — should be rejected at JWT verification.
- Submit valid Tenant A token to Tenant B's SAML ACS — should be rejected because connection-tenancy mismatch.
- Manipulate `tenant_id` parameters in URL paths — should be ignored in favour of token claim.
- Cache poisoning attempts: write under Tenant A's prefix, read with Tenant B's prefix — should miss.

### 13.6 Production Telemetry

A production-grade metric `qeetify_cross_tenant_access_detected_total` is exported. Anything > 0 over any window is a P1 incident. The metric counts assertion failures from §11.2.

### 13.7 Penetration Testing

The annual external pen test (NFR VM-09; Compliance IN-08) includes a tenant-isolation scenario. The pen-test scope explicitly tests for cross-tenant leakage in API, dashboard, SAML, SCIM, and webhook surfaces.

---

### 14. Cross-References

- Tenant claim in tokens: [IdP Core Engine Design](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md) §4
- Tenant routing at API Gateway: [Security Architecture](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md)
- Database schema with `tenant_id` columns + RLS: [Database Design & Data Model](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)
- Tenant-level metrics, dashboards, alerts: [Observability Architecture](Qeet ID%20%E2%80%94%20Observability%20Architecture.md)
- Tenant lifecycle events on Kafka: [Microservices Decomposition](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md) §6.3

---

### 15. Open Decisions Carried From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OQ-MT-01 | Default L1 shard size (tenants per shard target) | DBA + DevOps | Phase 2 close |
| OQ-MT-02 | Cooling-off period for tenant deletion (24h vs 7-day) | Compliance + Product | Phase 2 close |
| OQ-MT-03 | Whether to expose tenant_id (UUID) or only slug to customers via API | API Designer | Phase 2 close |
| OQ-MT-04 | L3 (fully dedicated) design timing — v2.0 vs v1.5 | CTO + Sales | Post-MVP planning |
| OQ-MT-05 | Cross-region migration availability (Enterprise only?) | Product + Compliance | Phase 2 close |

---

### 16. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Solution Architect |  |  |  |
| Backend Engineering Lead |  |  |  |
| Database Architect |  |  |  |
| Security Architect |  |  |  |
| DevOps / SRE Lead |  |  |  |
| Compliance Officer |  |  |  |
| Product Manager |  |  |  |
| QA Lead |  |  |  |

---

*This document is version controlled. Multi-tenancy is the most architecturally sensitive area of Qeet ID. Any change to the isolation model, sharding strategy, or propagation chain requires a Solution Architect + Security Architect + CTO review, and explicit testing in Phase 6 to validate the change does not weaken the cross-tenant guarantee.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
