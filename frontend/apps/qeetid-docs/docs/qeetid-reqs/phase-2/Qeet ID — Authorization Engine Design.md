# Qeet ID — Authorization Engine Design

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Authorization Engine Design |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Solution Architect |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the design of the Qeet ID authorization engine — *Qeet ID Access*. It specifies the authorization model (RBAC for MVP; ABAC for v1.5; FGA / Zanzibar-style for v2.0), the role and permission data model, the runtime permission-evaluation architecture, the way permission claims are placed in JWT access tokens, the sources of role assignments (manual, SCIM group, SAML attribute, OIDC claim, API), the permission-caching strategy, the public authorization API specification, the audit-logging contract, and the migration path that keeps v1.5 / v2.0 evolution non-breaking.

The audience is the Solution Architect, Backend Lead, every engineer on Team Identity (owners of the RBAC Service), Security Architect, and Product Manager (for the customer-facing surface).

This document depends on [Microservices Decomposition](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md) for the RBAC Service definition, [IdP Core Engine Design](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md) for the token issuance flow, and [Multi-Tenancy Architecture](Qeet ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md) for tenant-scoping enforcement.

---

### 3. Authorization Model Choice

### 3.1 MVP — RBAC

The MVP shipping authorization model is **Role-Based Access Control (RBAC)**. This is the choice that satisfies the Phase 1 MVP feature set ("RBAC with custom roles", "permissions in access tokens", "predefined roles Admin/Member/Viewer") with a model the engineering team can ship in the MVP window and that customers can adopt with minimal friction.

The MVP authorization vocabulary is:

- **Permission** — an atomic action on a resource type (`documents:read`, `invoices:write`, `users:delete`). A string with the format `{resource}:{action}`.
- **Role** — a named bag of permissions. A role belongs to a tenant. A role has 0..N permissions. Examples per tenant: `admin`, `member`, `viewer`, `billing_manager`.
- **Role Assignment** — a (user, role, scope) triple. Scope at MVP is either *tenant-wide* (default) or *application-scoped* (limited to a particular Qeet ID OAuth client). Resource-level scoping is deferred to ABAC.
- **Group** — a named set of users. Groups carry role assignments; users inherit roles from their group memberships. Groups primarily exist to receive SCIM group syncs from enterprise IdPs.

### 3.2 v1.5 — ABAC (Attribute-Based Access Control)

ABAC introduces *policies* that reason over *attributes* of the subject (user), the resource, and the environment (time, IP, MFA state). Policies are expressed in a declarative language (open decision: Cedar-style vs Rego/OPA — see §11). At v1.5:

- Existing RBAC permissions continue to function unchanged.
- A new policy layer evaluates after RBAC. A request that satisfies RBAC may be *additionally* gated by an ABAC policy (e.g., "even if the user has `documents:read`, only allow if document's classification ≤ user clearance").
- Policy authoring UI is part of the v1.5 admin dashboard.

### 3.3 v2.0 — Fine-Grained Authorization (FGA)

FGA / relationship-based authorization (Zanzibar style — Auth0 FGA, OpenFGA, SpiceDB, Ory Keto) handles resource hierarchies and shared resources well (`folder:foo#viewer@user:alice`, `document:bar#parent@folder:foo`, transitive permission lookup). Adopting a Zanzibar-derivative is on the v2.0 roadmap as **Qeet ID Access — Relationships**. RBAC and ABAC remain available; the relationship store is an additional decision input.

### 3.4 Why This Phased Plan

| Concern | RBAC MVP | ABAC v1.5 | FGA v2.0 |
| --- | --- | --- | --- |
| Time-to-ship | Fastest | Adds policy authoring UI, evaluator | Adds relationship store, language, eventual consistency |
| Coverage | 80% of customer use cases | Adds dynamic conditions | Adds shared-resource hierarchies |
| Mental model | Familiar (everyone has used RBAC) | Higher complexity | Highest complexity |
| Performance | Permission lookup is a join | Policy evaluation per-request | Relationship lookup with caching; latency-sensitive |

Phase 1 explicitly defers ABAC and FGA. This document keeps the MVP shape compatible with both later layers.

---

### 4. Role & Permission Data Model

The full schema is in [Database Design](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md). The model summary:

```
   ┌─────────────────────────┐         ┌─────────────────────────┐
   │   permissions           │         │   roles                 │
   │   ─────────────────     │         │   ─────────────────     │
   │   id (uuid)             │         │   id (uuid)             │
   │   tenant_id ◀──────┐    │         │   tenant_id ◀───────┐   │
   │   name              │   │         │   name              │   │
   │     (e.g.           │   │         │     (e.g. "admin",  │   │
   │      documents:read)│   │         │      "viewer")      │   │
   │   description       │   │         │   description       │   │
   │   built_in (bool)   │   │         │   built_in (bool)   │   │
   │   created_at        │   │         │   created_at        │   │
   └─────────────┬───────┘   │         └────────────┬────────┘   │
                 │           │                       │            │
                 │           │  many-to-many         │            │
                 └────────── role_permissions ──────┘            │
                              │ tenant_id                         │
                              │ role_id ──────────────────────────┘
                              │ permission_id
                              │                                   ┌─────────────────────────┐
                              │                                   │   user_role_assignments │
                              │                                   │   ───────────────────── │
                              │                                   │   id                    │
                              │                                   │   tenant_id ◀───────┐   │
                              │                                   │   user_id           │   │
                              │                                   │   role_id ──────────┘   │
                              │                                   │   scope_type            │
                              │                                   │     (tenant|application)│
                              │                                   │   scope_value (nullable;│
                              │                                   │     client_id when app  │
                              │                                   │     scoped)             │
                              │                                   │   source                │
                              │                                   │     (manual|scim|saml|  │
                              │                                   │      oidc|api)          │
                              │                                   │   assigned_at, by       │
                              │                                   └─────────────────────────┘
                              │
                              │                                   ┌─────────────────────────┐
                              │                                   │   groups                │
                              │                                   │   ───────────────────── │
                              │                                   │   id, tenant_id, name   │
                              │                                   └────────────┬────────────┘
                              │                                                │
                              │                                                │
                              │                                   ┌────────────▼────────────┐
                              │                                   │   group_role_assignments│
                              │                                   │   group_id, role_id,    │
                              │                                   │   scope_type, scope_val │
                              │                                   └─────────────────────────┘
                              │
                              │                                   ┌─────────────────────────┐
                              │                                   │   user_group_membership │
                              │                                   │   tenant_id, user_id,   │
                              │                                   │   group_id, source      │
                              │                                   └─────────────────────────┘
```

### 4.1 Permission Naming Convention

`{resource}:{action}` — both segments are lowercase, `[a-z0-9_]` only, separated by a single `:`. Examples:

- `users:read`, `users:write`, `users:delete`
- `documents:read`, `documents:write`
- `invoices:read`, `invoices:create`
- `audit_logs:read`
- `billing:manage`
- `*:read` — wildcard read across resources (use with care; auto-flagged in security review)
- `*:*` — superuser; only assignable to the `admin` role

Wildcards expand at evaluation time, not at storage time, so a permission set is finite and reviewable in the dashboard.

### 4.2 Built-In Roles

Every tenant is created with three built-in roles:

| Role | Description | Default permissions |
| --- | --- | --- |
| `admin` | Full tenant administration | `*:*` |
| `member` | Standard authenticated user | per-tenant default (none at platform level — tenant configures) |
| `viewer` | Read-only | `*:read` |

Built-in roles cannot be deleted but their permission set can be customised (except `admin`'s `*:*`, which is fixed). Custom roles are unrestricted in number up to NFR SC-05 (100 at launch, 500 at 12 months, 1000 at 24 months).

### 4.3 Scope

A role assignment carries a scope:

- `tenant` — role applies to the entire tenant.
- `application` — role applies only when the user is accessing a particular OAuth client (e.g., a user who is `admin` of the analytics app but only `member` of the support app).

Scope is the lowest-friction extension we can ship at MVP that addresses the most-common multi-app-per-tenant use case. ABAC will subsume this with policy.

### 4.4 Group Membership

Groups exist primarily because enterprise IdPs sync groups, not individual user-role mappings. The model is:

- A SCIM Group sync creates / updates `groups` and `user_group_membership` rows.
- Groups have role assignments via `group_role_assignments`.
- A user's effective roles = direct roles ∪ roles inherited from group memberships.
- Group assignments coming from SCIM carry `source = "scim"` and the SCIM external ID; manual assignments carry `source = "manual"`.

---

### 5. Permission Evaluation Engine — Runtime Architecture

```
                                Permission Check Request
                                          │
                                          ▼
                          ┌────────────────────────────────┐
                          │   API Gateway / Resource Server │
                          └──────────────────┬─────────────┘
                                             │
                  ┌──────────────────────────┴──────────────────────────┐
                  │                                                     │
                  ▼  fast path                                          ▼  source-of-truth
   ┌──────────────────────────────┐                       ┌──────────────────────────────┐
   │  Permissions claim in JWT     │                       │  RBAC Service (synchronous)  │
   │  qeetify/permissions: [       │                       │  POST /internal/permissions  │
   │    "documents:read",          │                       │     /check                   │
   │    "users:read"               │                       │  body: {user_id, tenant_id,  │
   │  ]                            │                       │   action, resource, scope}   │
   │  qeetify/roles: ["admin"]     │                       └──────────────────────────────┘
   └──────────────────────────────┘                                    │
                  │                                                     │
                  ▼                                                     ▼
       Local check (zero hops)                            ┌──────────────────────────────┐
       - If permission ∈ claim → allow                    │  Permission evaluation:      │
       - If wildcard match → allow                        │  1. Resolve effective roles  │
       - Else → fall to source-of-truth                   │     (user roles + group roles)│
                                                          │  2. Resolve permissions of   │
                                                          │     those roles              │
                                                          │  3. Apply wildcard expansion │
                                                          │  4. Check action ∈ permissions
                                                          │  5. Optional ABAC layer (v1.5)
                                                          │  6. Return allow / deny     │
                                                          │  7. Emit audit.authz.checked │
                                                          └──────────────────────────────┘
```

There are **two evaluation modes**:

**Mode A — JWT-embedded permissions (fast path).** The resource server inspects the `qeetify/permissions` and `qeetify/roles` claims in the access token and decides locally. Zero network hops. Latency ≪ 1 ms. The cost: the JWT was issued up to 15 minutes ago, so revoked permissions may grant access for up to 15 minutes.

**Mode B — Synchronous permission check (source-of-truth path).** The resource server calls Qeet ID's `/v1/permissions/check` API with `{user_id, tenant_id, action, resource, scope}`. Latency ≤ 60 ms p95 (NFR PF-15). Always current. Cost: network hop on every check.

Customers choose per resource server, per endpoint, or per request. Recommended pattern:

| Endpoint sensitivity | Recommended mode |
| --- | --- |
| Public read endpoints | Mode A — JWT claim |
| Mutation endpoints | Mode A — JWT claim (accept up to 15-min stale-revoke window) |
| Privileged admin endpoints | Mode B — source-of-truth |
| Money-moving, account-takeover-impacting endpoints | Mode B — source-of-truth |
| Endpoints during an active security incident | Mode B — by default for the affected tenant |

### 5.1 Wildcard Expansion

Wildcard permissions are stored as strings (`documents:*`, `*:read`, `*:*`). At evaluation time:

- The action requested is `documents:write`.
- The evaluator walks the user's effective permissions and matches both exact strings and wildcard patterns.
- Matching is left-anchored on segments: `documents:*` matches `documents:read`, `documents:write`, but not `users:read`.

Wildcard expansion is **not materialised** — we never expand `*:*` into a list of every concrete permission. This keeps the data model bounded and the dashboard explainable.

### 5.2 Tenant Scoping (Hard Invariant)

Every permission evaluation request includes a `tenant_id`. The RBAC Service:

1. Verifies the subject's user record belongs to the tenant.
2. Verifies all role assignments are within the tenant.
3. Refuses any cross-tenant role assignment lookup.

Cross-tenant permission grant is **architecturally impossible**: `user_role_assignments.tenant_id` is in the primary key; the SQL query is always `WHERE tenant_id = ? AND user_id = ?`; row-level security at the database layer enforces this even if the application code were defective ([Multi-Tenancy Architecture](Qeet ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md) §4).

### 5.3 Application Scope

A role assignment with `scope_type = 'application'` and `scope_value = '<client_id>'` is honoured only when:

- The access token was issued to the corresponding `client_id` (the `azp` / `aud` claim matches).
- The resource server queries `/permissions/check` with the `client_id` carried in the access token.

For mode-A evaluation, the JWT claims for application-scoped roles are emitted **only when the JWT is issued for that application**. This means the same user holds different permission claim sets in tokens issued for different applications.

---

### 6. Permissions in JWT Access Tokens

### 6.1 Claim Structure

Per Protocol §5.6 plus this document:

```json
{
  "iss": "https://acme.qeetify.com",
  "sub": "user_8f3...",
  "aud": "client_1234",
  "exp": 1746374400,
  "iat": 1746373500,
  "scope": "openid profile documents",
  "qeetify/org_id": "org_acme",
  "qeetify/user_id": "user_8f3...",
  "qeetify/roles": ["admin", "billing_manager"],
  "qeetify/permissions": [
    "documents:read", "documents:write",
    "invoices:read", "invoices:create",
    "users:read"
  ],
  "qeetify/plan": "enterprise",
  "qeetify/mfa_enrolled": true,
  "qeetify/passkey_enrolled": true
}
```

The `qeetify/permissions` claim is **flattened** at issuance — the expansion is what the resource server sees. Wildcards in the underlying role definitions are preserved as `"<resource>:*"` style entries in the claim so resource servers don't need an expansion library.

### 6.2 Claim Size Management

A user with hundreds of granular permissions produces a large JWT. We mitigate:

- The default representation includes wildcards rather than the expansion (`documents:*` is 13 chars; the expansion may be 200 chars).
- A maximum claim size of 4 KB is enforced. Above this, the token includes `qeetify/permissions_overflow: true` and the resource server must use Mode B (`/permissions/check`) for the user.
- Customers can configure `permissions_claim_mode = "summary"|"full"|"none"` per OAuth client. `"summary"` includes only role names; `"none"` includes neither roles nor permissions and forces Mode B.

### 6.3 Token Size Trade-off

We accept slightly larger JWTs because the bandwidth saved by larger tokens is recovered many times over by skipping the synchronous `/permissions/check` call per request. The break-even is roughly: a 500-byte permission claim avoids hundreds of API calls per session.

---

### 7. Role Assignment Sources

Roles can be assigned to users from five sources. The `source` column on `user_role_assignments` records which.

### 7.1 Manual

Admin assigns role via dashboard or API:

- `POST /v1/role-assignments` body `{user_id, role_id, scope_type, scope_value?}`
- Authorisation: caller must have `users:manage` permission within tenant.
- Audit: `audit.authz.role_assigned` with `source = "manual"`, actor = admin user id.

### 7.2 SAML Attribute

When a user authenticates via SAML, the connection's attribute mapping (Protocol §6.6) may include a roles attribute. The SAML Service:

1. Extracts the roles attribute (e.g., `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` or a custom claim).
2. Maps the SAML role string to a Qeet ID role name via the connection's `role_mapping` config.
3. Updates the user's `user_role_assignments` with `source = "saml"` — adds new mappings, removes obsolete ones.
4. Audit: `audit.authz.role_assigned` source=saml.

Per-tenant configuration controls whether SAML role attributes are *authoritative* (overwrite Qeet ID-managed assignments on each login) or *additive* (only add, never remove). Default: authoritative for `source = "saml"` assignments only — manual assignments persist.

### 7.3 OIDC Claim

When a user authenticates via an upstream OIDC provider, the configured claim mapping may include `roles`. Same semantics as SAML, with `source = "oidc"`.

### 7.4 SCIM Group Mapping

SCIM Service writes group memberships and role assignments derived from group mappings:

- Group from external IdP → mapped to a Qeet ID role via the SCIM connection config.
- `user_group_membership` for the user; `group_role_assignments` for the group.
- The user's effective roles include those from group memberships.
- `source = "scim"`.

### 7.5 API

Customer-built integrations call `POST /v1/role-assignments` directly. Same audit story.

---

### 8. Permission Caching Strategy

The permission-check hot path needs sub-60-ms p95 latency (NFR PF-15). The straight-through SQL path of joining users → roles → role_permissions can hit that, but only if the query plan is right and the cache is warm.

### 8.1 Cache Layers

| Layer | What's cached | TTL | Invalidation |
| --- | --- | --- | --- |
| In-process (per RBAC Service pod) | Role-to-permissions map per role | 60 s | Pub/Sub on role-permission change events |
| Redis | Effective-permissions set per user (computed) | 5 min (CA-05) | On role assignment change, group membership change, or role-permission change |
| Redis | Role definitions per tenant | 5 min (CA-04) | On role/permission change |
| Token Service local | Per-issuance permission snapshot (not strictly cache; embedded in token) | Token lifetime (15 min default) | Token expiry |

### 8.2 Cache Invalidation

Invalidation is **synchronous within RBAC Service plus eventual via Kafka**:

- A write (role create, permission grant, role assignment change) updates Postgres + invalidates Redis keys for the affected tenant/user in the same request.
- A `rbac.cache.invalidate` event is emitted on Kafka with the affected keys; all RBAC Service replicas subscribe and clear their in-process caches.

This means an admin-driven permission change is visible everywhere within ~1 second. Issued tokens still carry the stale claim set for up to 15 minutes (their lifetime) — Mode A trade-off documented in §5.

### 8.3 Negative Caching

Failed `/permissions/check` results are *not* cached. A user gaining a permission must see access immediately on the next request.

---

### 9. Authorization API Specification

### 9.1 Public API Surface

| Method + Path | Purpose |
| --- | --- |
| `POST /v1/roles` | Create role |
| `GET /v1/roles` | List roles in tenant |
| `GET /v1/roles/{id}` | Get role |
| `PATCH /v1/roles/{id}` | Update role |
| `DELETE /v1/roles/{id}` | Delete role (not allowed for built-ins) |
| `POST /v1/roles/{id}/permissions` | Assign permission to role |
| `DELETE /v1/roles/{id}/permissions/{perm}` | Revoke permission from role |
| `POST /v1/permissions` | Create permission (custom) |
| `GET /v1/permissions` | List permissions |
| `POST /v1/role-assignments` | Assign role to user (or group) |
| `DELETE /v1/role-assignments/{id}` | Remove assignment |
| `GET /v1/users/{user_id}/permissions` | List effective permissions for a user (admin only) |
| `POST /v1/permissions/check` | Permission check (Mode B; high-throughput) |
| `POST /v1/permissions/batch-check` | Batch up to 100 checks in a single request |

### 9.2 `POST /v1/permissions/check`

The most-called endpoint in the public surface. Designed for high RPS and low latency.

**Request:**

```http
POST /v1/permissions/check HTTP/1.1
Authorization: Bearer <token>
Content-Type: application/json

{
  "user_id": "user_8f3...",
  "tenant_id": "org_acme",
  "action": "documents:write",
  "resource": "doc_123",          // optional; ignored at MVP (RBAC); used in v1.5 ABAC
  "client_id": "client_app_42",   // optional; required for application-scoped roles
  "context": {                    // optional; passed through to v1.5 ABAC policies
    "ip": "203.0.113.1",
    "method": "POST"
  }
}
```

**Response:**

```http
200 OK
Content-Type: application/json

{
  "allow": true,
  "decision_id": "dec_01HX...",
  "matched_role": "admin",
  "matched_permission": "documents:*",
  "ttl": 60,
  "metadata": { "evaluated_at": "2026-05-19T12:34:56Z" }
}
```

The `decision_id` is the audit primary key — referencing the decision in a later audit query reveals the inputs, the policy version, and the result.

The `ttl` hint tells the caller it may cache this decision for that many seconds. Callers that respect TTL hints amortise the call cost dramatically.

**Latency contract.** p50 ≤ 20 ms; p95 ≤ 60 ms (NFR PF-15); p99 ≤ 120 ms.

### 9.3 `POST /v1/permissions/batch-check`

Up to 100 check requests in a single body. Avoids HTTP overhead for callers needing many permission decisions for a single rendered page.

### 9.4 Internal API

`POST /internal/permissions/check` is identical in shape but is mesh-only and accepts service-token identity. Used by Token Service at issuance to compose the `qeetify/permissions` claim.

`GET /internal/permissions/{user_id}` returns the full effective permission set for token-issuance use. Cacheable on the Token Service side for the token lifetime.

---

### 10. Audit Logging for Permission Grants & Revocations

Authorization decisions are first-class audit subjects. The audit contract:

| Event | Payload (key fields) |
| --- | --- |
| `audit.authz.role_created` | tenant_id, actor_id, role_id, role_name, permissions |
| `audit.authz.role_updated` | tenant_id, actor_id, role_id, before, after |
| `audit.authz.role_deleted` | tenant_id, actor_id, role_id |
| `audit.authz.permission_created` | tenant_id, actor_id, permission |
| `audit.authz.role_assigned` | tenant_id, actor_id, user_id|group_id, role_id, source, scope |
| `audit.authz.role_revoked` | tenant_id, actor_id, user_id|group_id, role_id, source, scope |
| `audit.authz.group_membership_added` | tenant_id, actor_id, user_id, group_id, source |
| `audit.authz.group_membership_removed` | tenant_id, actor_id, user_id, group_id, source |
| `audit.authz.checked` | tenant_id, user_id, action, allow|deny, matched_role, matched_permission, decision_id (sampled at 1% for high-volume endpoints; 100% for deny decisions) |

Retention follows the Compliance Matrix: 12 months hot for authentication-context authorization events; 3 years for administrative events (role/permission grants). Hash-chained per [Database Design](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md) §10.

A tenant admin must be able to answer "who could `documents:write` on April 1 at 14:00?" — the audit history of role assignments and role definitions together makes this answerable.

### 10.1 Decision Audit Sampling

Logging every `audit.authz.checked` at full fidelity exceeds the audit-log volume budget (NFR SC-10: 500,000 events/s at 24 months). Therefore:

- **Deny decisions:** logged at 100% (low volume; security-critical).
- **Allow decisions:** sampled at 1% — sufficient to detect drift, with the decision_id available for forensic replay on demand.
- Customers may opt their tenant into 100% logging for compliance reasons (per-tenant configuration; cost passed through Enterprise pricing).

---

### 11. Performance Targets

| Metric | Target | NFR Reference |
| --- | --- | --- |
| `/v1/permissions/check` p50 | ≤ 20 ms | PF-15 |
| `/v1/permissions/check` p95 | ≤ 60 ms | PF-15 |
| `/v1/permissions/check` p99 | ≤ 120 ms | PF-15 |
| Token claim composition at issuance | ≤ 20 ms p95 (fits into Token Service's 200 ms /token budget) | §4.4 latency budget |
| Cache hit ratio in production | > 90% (target) | — |
| RBAC Service availability | 99.95% (Tier 0 on permission-check path) | NFR §6.1 |

Performance is verified in Phase 6 with load tests at 2×, 5×, 10× of the 24-month throughput target (TH-02 = 250,000 token validations/s; the related permission-check rate at that scale is plausibly 50,000/s).

---

### 12. ABAC Migration Path — Forward Compatibility Hooks

To make v1.5 ABAC adoption painless, the MVP authorization API includes hooks today that are no-ops at MVP and meaningful at v1.5:

| Hook | MVP behaviour | v1.5 behaviour |
| --- | --- | --- |
| `resource` field on `/permissions/check` | Accepted; ignored | Used to fetch resource attributes for policy evaluation |
| `context` field on `/permissions/check` | Accepted; ignored | Passed to policy evaluator as `environment` attributes |
| `decision_id` in audit | Always emitted | Stable across MVP → v1.5 transition |
| Permission naming `{resource}:{action}` | Required | Continues to work; policies layer on top |
| Roles in JWT | Unchanged | Continues; policies can read additional claims |

The forward-compatible result is: a customer that integrates `/permissions/check` at MVP does not need to change a line of their integration when ABAC ships. They get more expressive policy authoring; the API contract is unchanged.

### 12.1 Policy Language Options (Carried Forward)

The decision between **Cedar** (Amazon's policy language; familiar to AWS IAM users), **Rego / OPA** (broadest community; familiar to DevOps), and a **custom DSL** is deferred to v1.5 planning. It is recorded in [Open-Decisions-Register.md](Open-Decisions-Register.md) (OQ-AZ-01).

### 12.2 v2.0 FGA Migration

Zanzibar-style FGA introduces a relationship store with a different data shape. Migration approach:

- The MVP RBAC store remains the authoritative role/permission source.
- The FGA store ingests RBAC assignments via a one-way sync — every role assignment becomes a `relation`.
- The `/permissions/check` API gains a `mode = "rbac" | "abac" | "fga" | "any"` parameter; default at v2.0 = `"any"` which means an allow decision from any layer permits access.
- Existing customer integrations continue to work; new customers adopt FGA directly.

---

### 13. Failure Modes & Degradation

| Scenario | Behaviour | Rationale |
| --- | --- | --- |
| RBAC Service unreachable from Token Service at issuance | Issue token with empty `qeetify/permissions`; flag `degraded` in audit | Don't block authentication |
| RBAC Service unreachable from `/permissions/check` | Return HTTP 503; client should fail closed | Authorization without ground truth must not be silently permissive |
| Redis cache unavailable | Falls back to Postgres; latency rises to ~150 ms p95; alert fires | Service degrades but remains correct |
| Postgres failover | Brief (≤60 s) pause; reads continue from replicas with bounded staleness | NFR FO-04 |
| Cache poisoned by stale read after writer failover | TTL bounded at 5 minutes; write-path invalidation forces refresh | Self-healing within 5 min |

---

### 14. Open Decisions Carried From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OQ-AZ-01 | ABAC policy language (Cedar vs Rego/OPA vs custom DSL) | Solution Architect + Backend Lead | v1.5 planning |
| OQ-AZ-02 | Default audit sampling rate for allow decisions (1% vs 5% vs 0.1%) | Compliance + SRE | Phase 2 close |
| OQ-AZ-03 | Whether application-scoped roles ship at MVP or v1.1 | Product Manager | Phase 2 close |
| OQ-AZ-04 | Default `permissions_claim_mode` (`full` vs `summary`) for new clients | Product + DX | Phase 3 entry |
| OQ-AZ-05 | FGA store choice (OpenFGA vs SpiceDB vs Ory Keto vs build) for v2.0 | Solution Architect | v2.0 design |

---

### 15. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Solution Architect |  |  |  |
| Backend Engineering Lead (Team Identity) |  |  |  |
| Security Architect |  |  |  |
| Product Manager |  |  |  |
| Compliance Officer |  |  |  |
| QA Lead |  |  |  |

---

*This document is version controlled. Authorization model changes — adding ABAC, adopting an FGA layer, modifying claim shapes — require a new version with Solution Architect, Security Architect, and Product sign-off, and a public deprecation notice if any change affects customer-facing claims.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
