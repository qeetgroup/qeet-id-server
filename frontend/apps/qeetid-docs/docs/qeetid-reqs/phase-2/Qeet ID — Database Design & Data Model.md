# Qeet ID — Database Design & Data Model

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Database Design & Data Model |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Database Architect + Backend Lead |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the data layer of Qeet ID — the choice of database technologies, the logical data model and entity-relationship descriptions, the schema design principles, the indexing and partitioning strategy, the read-replica strategy, the migration approach, the data-retention and deletion policies, the backup and recovery design, the caching layer, and the event-sourcing approach for audit logs.

The audience is the Database Architect, every backend engineering team that owns one or more entities, the Solution Architect, DevOps Lead, SRE Lead, and Compliance Officer.

This document depends on [Microservices Decomposition](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md) (which service owns which data), [Multi-Tenancy Architecture](Qeet ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md) (how rows are isolated per tenant), and [Authorization Engine Design](Qeet ID%20%E2%80%94%20Authorization%20Engine%20Design.md) (RBAC table shapes).

---

### 3. Database Technology Choices

| Tier | Technology | Use | ADR |
| --- | --- | --- | --- |
| Primary OLTP | PostgreSQL 16 on Amazon Aurora | All authoritative state — users, tenants, roles, sessions, tokens, audit metadata, billing | ADR-004 |
| Cache & ephemeral store | Redis 7 on AWS ElastiCache (cluster mode) | Sessions hot path, rate-limit counters, JWKS cache, permission cache, revocation bloom filter | ADR-005 |
| Event streaming | Apache Kafka on AWS MSK | Audit event log, cross-service domain events, webhook fan-out | ADR-006 |
| Object storage | Amazon S3 | Audit log cold tier, backups, user data exports (GDPR portability), profile pictures, branding assets | ADR-003 |
| Secrets / key store | AWS KMS + HashiCorp Vault | Signing keys (envelope-wrapped), data-encryption keys, secrets | ADR-014 |
| Search index | Amazon OpenSearch | Audit log search in admin dashboard | — |

All technology choices are cloud-portable (NFR PO-04..PO-06): PostgreSQL, Redis, Kafka, and S3-compatible object stores exist on GCP and Azure. The migration path is one of the cost-optimisation paths preserved by ADR-001.

---

### 4. Schema Design Principles

**DP-01 — Every tenant table has `tenant_id NOT NULL` as the leading column of its primary indexes.** Tenant scoping is the universal first dimension. The exception list is small (the platform-internal `tenants` table itself, `signing_keys`, `plan_definitions`, and `migrations_history`).

**DP-02 — UUID v7 primary keys.** Sortable, opaque, globally unique across shards. v7 has the time prefix so B-tree inserts cluster (vs v4 which scatters).

**DP-03 — Row-level security (RLS) on tenant tables.** Belt-and-braces with application-layer scoping. Documented per table.

**DP-04 — Soft delete is *not* the default.** Default is hard delete with a tombstone in the audit log. Soft delete is used only where regulatory or operational requirements demand recovery (e.g., user accounts retained 30 days post-deletion before hard delete per Compliance §4.4).

**DP-05 — Audit columns on every row.** `created_at`, `updated_at` (ISO 8601 UTC) on every table. `created_by_actor_id` and `updated_by_actor_id` (UUID; nullable for system writes) on every table that holds customer-modifiable state.

**DP-06 — Encrypted PII fields stored as `{ciphertext, nonce, dek_id, enc_version}` JSONB.** Email and phone columns store a separate deterministic hash for indexed lookup (e.g. `email_hash = HMAC-SHA256(lowercase(email))`).

**DP-07 — JSONB only for genuinely schemaless data.** Custom metadata, OIDC claims store, SAML attribute snapshots. Not used as a lazy way to avoid declaring a column.

**DP-08 — Versioned schema migrations.** Forward-only. Online (zero-downtime). Backward-compatible during deploy windows.

**DP-09 — Foreign keys enforced where they don't impede sharding.** Within a shard, foreign keys enforce referential integrity. Cross-shard references (rare) are application-enforced.

**DP-10 — No `SELECT *` in service code.** Explicit column projection — protects against schema additions changing row size, exposes column-add costs to reviewers.

---

### 5. Logical Data Model

The model below summarises every entity the platform persists at MVP. Detailed column lists for the most architectural-significant tables follow.

### 5.1 Entity Inventory

| Entity | Owning Service | Storage | Approx Rows (24m) |
| --- | --- | --- | --- |
| `tenants` | Tenant | Postgres | 100K |
| `tenant_configurations` | Tenant | Postgres | 100K |
| `tenant_branding` | Tenant | Postgres + S3 (assets) | 100K |
| `tenant_admins` | Tenant | Postgres | 500K |
| `users` | User | Postgres | 100M |
| `user_profiles` | User | Postgres | 100M |
| `user_metadata` | User | Postgres (JSONB) | 100M |
| `email_verifications` | User | Postgres | bounded; cleaned daily |
| `phone_verifications` | User | Postgres | bounded; cleaned daily |
| `password_credentials` | User (MFA secrets in MFA Svc) | Postgres | 100M (one per user max) |
| `mfa_factors` | MFA | Postgres | 100M |
| `passkey_credentials` | MFA | Postgres | 200M (avg 2 per user) |
| `totp_seeds` | MFA | Postgres (field-encrypted) | 30M (≈30% adoption) |
| `backup_codes` | MFA | Postgres | hashed; small |
| `sessions` | Session | Postgres + Redis | 100M (90d retention) |
| `oauth_clients` (apps) | Token / Tenant | Postgres | 1M |
| `oauth_client_secrets` | Token | Postgres | 1M |
| `authorization_codes` | Token | Postgres (TTL 60s rows) | bounded; cleaned per minute |
| `refresh_tokens` | Token | Postgres | 1B (rotation creates new rows) |
| `signing_keys` | Token | Postgres + KMS-wrapped blobs | tens |
| `revocation_list` | Token | Postgres + Redis bloom | bounded |
| `roles` | RBAC | Postgres | 100M role-rows (≈1K per tenant avg) |
| `permissions` | RBAC | Postgres | 1B |
| `role_permissions` | RBAC | Postgres | 1B |
| `user_role_assignments` | RBAC | Postgres | 1B |
| `groups` | RBAC | Postgres | 10M |
| `group_role_assignments` | RBAC | Postgres | 10M |
| `user_group_membership` | RBAC | Postgres | 100M |
| `saml_connections` | SAML | Postgres | 200K |
| `saml_idp_metadata` | SAML | Postgres (XML blobs) | 200K |
| `saml_assertion_audit` | SAML | Postgres (90d) | 1B |
| `scim_endpoints` | SCIM | Postgres | 200K |
| `scim_provisioning_log` | SCIM | Postgres (12m) | 10B |
| `social_connections` | Social | Postgres | 50M |
| `api_keys` | Keys | Postgres + Redis | 500M (hashed) |
| `service_accounts` | Keys | Postgres | 5M |
| `webhook_subscriptions` | Webhook | Postgres | 1M |
| `webhook_deliveries` | Webhook | Postgres (90d) | 50B |
| `audit_log_hot` | Audit Ingestion | Postgres partitioned | 500B (12m hot) |
| `audit_log_hash_chain` | Audit Ingestion | Postgres + S3 | small |
| `subscriptions` | Billing | Postgres + Stripe ref | 500K |
| `mau_counters` | Billing | Postgres | 100K rolled monthly |
| `invoices` | Billing | Postgres + Stripe ref | 5M |
| `payment_methods` | Billing | Postgres (Stripe token only) | 500K |

### 5.2 Key Entity Schemas

The columns below are the architecturally significant ones for cross-service understanding. Migrations and full DDL live in each service's repository.

#### tenants

```
id                uuid           PK (UUID v7)
slug              text           UNIQUE NOT NULL
display_name      text           NOT NULL
plan              text           NOT NULL CHECK (plan IN ('free','growth','enterprise'))
data_region       text           NOT NULL
isolation_tier    text           NOT NULL DEFAULT 'l1'
shard_id          text           NULL
status            text           NOT NULL DEFAULT 'active'
deletion_scheduled_at  timestamptz NULL
created_at        timestamptz    NOT NULL DEFAULT now()
updated_at        timestamptz    NOT NULL DEFAULT now()
deleted_at        timestamptz    NULL
```

No RLS — the `tenants` table is platform-internal. Access is restricted at the application layer.

#### users

```
id                uuid              PK
tenant_id         uuid              NOT NULL
global_id         uuid              NOT NULL    -- stable across tenants for cross-tenant identity
email_ciphertext  bytea             NOT NULL    -- envelope-encrypted
email_nonce       bytea             NOT NULL
email_hash        bytea             NOT NULL    -- HMAC(lowercase(email)) for indexed lookup
email_verified    boolean           NOT NULL DEFAULT false
phone_ciphertext  bytea             NULL
phone_nonce       bytea             NULL
phone_hash        bytea             NULL
phone_verified    boolean           NOT NULL DEFAULT false
dek_id            uuid              NOT NULL
enc_version       smallint          NOT NULL DEFAULT 1
status            text              NOT NULL DEFAULT 'active'   -- active|suspended|pending_deletion|deleted
external_id       text              NULL                          -- from SCIM
created_at        timestamptz       NOT NULL DEFAULT now()
updated_at        timestamptz       NOT NULL DEFAULT now()
deleted_at        timestamptz       NULL

PRIMARY KEY (tenant_id, id)
UNIQUE INDEX users_tenant_email_hash_idx ON users(tenant_id, email_hash)
UNIQUE INDEX users_tenant_external_id_idx ON users(tenant_id, external_id) WHERE external_id IS NOT NULL
INDEX users_global_id_idx ON users(global_id)

RLS: tenant_id = current_setting('qeetify.current_tenant_id')::uuid
```

#### password_credentials

```
user_id           uuid              PK, FK users(id)
tenant_id         uuid              NOT NULL
password_hash     text              NOT NULL  -- Argon2id PHC string
pepper_version    smallint          NOT NULL DEFAULT 1
updated_at        timestamptz       NOT NULL DEFAULT now()

RLS as above
```

#### passkey_credentials

```
id                uuid              PK
tenant_id         uuid              NOT NULL
user_id           uuid              NOT NULL FK users
credential_id     bytea             NOT NULL
public_key_cose   bytea             NOT NULL
aaguid            bytea             NOT NULL
sign_count        bigint            NOT NULL DEFAULT 0
transports        text[]
backup_eligible   boolean           NOT NULL DEFAULT false
backup_state      boolean           NOT NULL DEFAULT false
attestation_format text             NULL
attestation_statement bytea         NULL
nickname          text              NULL
last_used_at      timestamptz       NULL
revoked_at        timestamptz       NULL
created_at        timestamptz       NOT NULL DEFAULT now()

PRIMARY KEY (tenant_id, id)
UNIQUE INDEX passkey_credentials_credential_id_idx ON passkey_credentials(credential_id)
RLS
```

#### sessions

```
id                uuid              PK
tenant_id         uuid              NOT NULL
user_id           uuid              NOT NULL FK users
client_id         text              NOT NULL FK oauth_clients
acr               text              NULL
amr               text[]            NULL
ip_address        inet              NULL
user_agent        text              NULL
device_fingerprint text             NULL
geo_country       text              NULL
geo_region        text              NULL
geo_city          text              NULL
created_at        timestamptz       NOT NULL DEFAULT now()
last_activity_at  timestamptz       NOT NULL DEFAULT now()
absolute_expires_at timestamptz     NOT NULL
idle_timeout_seconds integer        NOT NULL
revoked           boolean           NOT NULL DEFAULT false
revoked_reason    text              NULL
revoked_at        timestamptz       NULL

PRIMARY KEY (tenant_id, id)
INDEX sessions_user_active_idx ON sessions(tenant_id, user_id) WHERE revoked = false
INDEX sessions_absolute_expires_idx ON sessions(absolute_expires_at) WHERE revoked = false
RLS
```

Sessions also live in Redis under `session:{tenant_id}:{session_id}` keys for hot reads (≤ 5 ms p99).

#### oauth_clients

```
id                uuid              PK
client_id         text              NOT NULL UNIQUE  -- public identifier
tenant_id         uuid              NOT NULL
name              text              NOT NULL
type              text              NOT NULL  -- public|confidential
allowed_grant_types text[]          NOT NULL
allowed_redirect_uris text[]        NOT NULL
allowed_scopes    text[]            NOT NULL
token_endpoint_auth_method text     NOT NULL DEFAULT 'client_secret_post'
permissions_claim_mode text         NOT NULL DEFAULT 'full'  -- full|summary|none
access_token_ttl_seconds integer    NOT NULL DEFAULT 900
refresh_token_ttl_seconds integer   NOT NULL DEFAULT 2592000
require_pkce      boolean           NOT NULL DEFAULT true    -- always true for public; configurable for confidential
metadata          jsonb             NULL
created_at, updated_at
```

#### refresh_tokens

```
id                uuid              PK
tenant_id         uuid              NOT NULL
user_id           uuid              NULL    -- NULL for client_credentials
client_id         text              NOT NULL FK oauth_clients(client_id)
session_id        uuid              NULL    -- bound to session for user tokens
token_hash        bytea             NOT NULL  -- HMAC-SHA256
parent_id         uuid              NULL FK refresh_tokens(id)  -- rotation chain
issued_at         timestamptz       NOT NULL DEFAULT now()
expires_at        timestamptz       NOT NULL
used_at           timestamptz       NULL
revoked           boolean           NOT NULL DEFAULT false
revoked_reason    text              NULL
scopes            text[]            NOT NULL

PRIMARY KEY (tenant_id, id)
INDEX refresh_tokens_hash_idx ON refresh_tokens(token_hash)
INDEX refresh_tokens_session_idx ON refresh_tokens(tenant_id, session_id) WHERE revoked = false
RLS
```

The presence of `parent_id` is what enables the refresh-token reuse-chain walk (Auth Flow §10).

#### authorization_codes

```
id                uuid              PK
tenant_id         uuid              NOT NULL
code_hash         bytea             NOT NULL  -- HMAC-SHA256
client_id         text              NOT NULL
user_id           uuid              NOT NULL
redirect_uri      text              NOT NULL
scopes            text[]            NOT NULL
code_challenge    text              NOT NULL
code_challenge_method text          NOT NULL CHECK (code_challenge_method = 'S256')
nonce             text              NULL
acr_satisfied     text              NULL
created_at        timestamptz       NOT NULL DEFAULT now()
expires_at        timestamptz       NOT NULL  -- now() + 60s
consumed_at       timestamptz       NULL

PRIMARY KEY (tenant_id, id)
UNIQUE INDEX authorization_codes_hash_idx ON authorization_codes(code_hash)
RLS
```

Rows are deleted by a sweeper 5 minutes after `expires_at` (after the reuse-detect window has elapsed).

#### signing_keys

```
kid               text              PK
algorithm         text              NOT NULL  -- RS256|ES256|ES256_INTERNAL|...
purpose           text              NOT NULL  -- public_jwt|internal|magic_link
public_key_pem    text              NOT NULL
private_key_wrapped bytea           NOT NULL  -- wrapped by KMS KEK
status            text              NOT NULL  -- pending|current|previous|retired
activated_at      timestamptz       NULL
retired_at        timestamptz       NULL
created_at        timestamptz       NOT NULL DEFAULT now()
```

Platform-internal — no `tenant_id`. There is one platform signing key per algorithm at a time; per-tenant keys are not currently used (open decision: per-tenant JWKS for Enterprise tier — OQ-DB-01).

#### roles / permissions / role_permissions / user_role_assignments

(See [Authorization Engine Design](Qeet ID%20%E2%80%94%20Authorization%20Engine%20Design.md) §4 for canonical column lists.)

#### saml_connections

```
id                uuid              PK
tenant_id         uuid              NOT NULL
name              text              NOT NULL
sp_entity_id      text              NOT NULL
idp_entity_id     text              NOT NULL
idp_sso_url       text              NOT NULL
idp_slo_url       text              NULL
idp_certificate   text              NOT NULL  -- PEM
metadata_xml      text              NULL
attribute_mapping jsonb             NOT NULL
role_mapping      jsonb             NULL
allow_idp_initiated boolean         NOT NULL DEFAULT false
require_signed_authnrequest boolean NOT NULL DEFAULT true
sign_assertions   boolean           NOT NULL DEFAULT true
encrypt_assertions boolean          NOT NULL DEFAULT false
authentication_context text         NULL
clock_skew_seconds integer          NOT NULL DEFAULT 120
status            text              NOT NULL DEFAULT 'active'
created_at, updated_at

PRIMARY KEY (tenant_id, id)
RLS
```

#### scim_endpoints

```
id                uuid              PK
tenant_id         uuid              NOT NULL
name              text              NOT NULL
bearer_token_hash bytea             NOT NULL  -- HMAC-SHA256
group_mapping     jsonb             NOT NULL
include_inactive  boolean           NOT NULL DEFAULT false
status            text              NOT NULL DEFAULT 'active'
created_at, updated_at, last_sync_at
```

#### api_keys

```
id                uuid              PK
tenant_id         uuid              NOT NULL
prefix            text              NOT NULL  -- first 8 chars of raw key, for dashboard display
key_hash          bytea             NOT NULL  -- HMAC-SHA256
name              text              NOT NULL
environment       text              NOT NULL  -- live|test
scopes            text[]            NOT NULL
created_by        uuid              NULL
last_used_at      timestamptz       NULL
expires_at        timestamptz       NULL
revoked_at        timestamptz       NULL

PRIMARY KEY (tenant_id, id)
UNIQUE INDEX api_keys_key_hash_idx ON api_keys(key_hash)
RLS
```

#### webhook_subscriptions

```
id                uuid              PK
tenant_id         uuid              NOT NULL
url               text              NOT NULL
events            text[]            NOT NULL
signing_secret_ciphertext bytea     NOT NULL
signing_secret_nonce bytea          NOT NULL
dek_id            uuid              NOT NULL
enabled           boolean           NOT NULL DEFAULT true
created_at, updated_at

PRIMARY KEY (tenant_id, id)
RLS
```

#### audit_log_hot

Audit log is partitioned by `(tenant_id, date)` and kept for 12 months hot (NFR LG-08; Compliance AL-01..AL-12).

```
event_id          uuid              PK   -- UUID v7
tenant_id         uuid              NOT NULL
timestamp         timestamptz       NOT NULL
event_type        text              NOT NULL    -- e.g. audit.authentication.login_succeeded
actor_id          uuid              NULL
actor_type        text              NULL        -- user|service|system
target_id         uuid              NULL
target_type       text              NULL        -- user|role|app|session|tenant
ip_address        inet              NULL
user_agent        text              NULL
request_id        text              NULL
result            text              NOT NULL    -- success|failure|denied
metadata          jsonb             NULL        -- structured per event_type
hash_prev         bytea             NULL        -- previous event's hash in chain
hash_self         bytea             NOT NULL    -- HMAC of canonical event + hash_prev

PRIMARY KEY (event_id)
INDEX audit_log_tenant_time_idx ON audit_log_hot(tenant_id, timestamp DESC)
INDEX audit_log_target_idx ON audit_log_hot(tenant_id, target_type, target_id, timestamp DESC)

Partitioned by RANGE(tenant_id) sub-partitioned BY RANGE(timestamp) monthly.
```

#### subscriptions

```
id                uuid              PK
tenant_id         uuid              NOT NULL
stripe_subscription_id text         NOT NULL
plan              text              NOT NULL
status            text              NOT NULL   -- active|past_due|canceled|paused
current_period_start timestamptz    NOT NULL
current_period_end   timestamptz    NOT NULL
created_at, updated_at
```

---

### 6. Indexing Strategy

### 6.1 Principles

- **Tenant-first.** Every index on a tenant table has `tenant_id` as the leading column. There are no exceptions on tenant tables.
- **Sized for hot reads.** Indexes are chosen for the read pattern. Where a single composite supports two reads, prefer it.
- **Partial indexes for the common-filter case.** `WHERE revoked = false` indexes for tokens, sessions, API keys.
- **Hash columns over functional indexes.** `email_hash` column with a btree index is preferred over `EXPR INDEX (HMAC(email))` — the column is explicit, deterministic, and shareable across queries.
- **Cover lookups in JOIN paths.** For `users → role_assignments → roles`, the composite `(tenant_id, user_id)` on role_assignments and `(tenant_id, id)` on roles cover the path.

### 6.2 Hot Indexes (Examples)

| Table | Index | Purpose |
| --- | --- | --- |
| users | (tenant_id, email_hash) UNIQUE | Login lookup; SCIM lookup |
| users | (tenant_id, external_id) UNIQUE WHERE external_id NOT NULL | SCIM external mapping |
| refresh_tokens | (token_hash) | Refresh exchange |
| refresh_tokens | (tenant_id, session_id) WHERE revoked = false | Session revocation cascade |
| authorization_codes | (code_hash) UNIQUE | Code redemption |
| sessions | (tenant_id, user_id) WHERE revoked = false | User session list |
| api_keys | (key_hash) UNIQUE WHERE revoked_at IS NULL | API key validation |
| audit_log_hot | (tenant_id, timestamp DESC) | Dashboard audit query |
| passkey_credentials | (credential_id) UNIQUE | WebAuthn lookup |
| user_role_assignments | (tenant_id, user_id) | Permission composition |
| oauth_clients | (client_id) UNIQUE | Token endpoint |

---

### 7. Partitioning & Sharding Strategy

### 7.1 Partitioning

Three classes of table use native PostgreSQL declarative partitioning:

- **Audit log hot tier** — partition by `(tenant_id, month)`. Allows efficient retention drops (DROP PARTITION) and per-tenant scans.
- **Webhook deliveries** — partition by `month`. Old months get dropped at 90 days.
- **Scim provisioning log** — partition by `month`. 12-month retention.

### 7.2 Sharding

See [Multi-Tenancy Architecture](Qeet ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md) §6. Sharding applies at the **cluster** level: each shard is a separate Aurora cluster. Routing is at the application layer via a shard-aware connection pool keyed on `tenant_id`.

```
   Application Service
        │
        ▼
   Tenant-routing cache (Redis: tenant_id → shard_id, TTL 5m)
        │
        ▼
   Sharded connection pool (libraries: pgx-shard for Go, sequelize-sharded for Node)
        │
        ▼
   Aurora cluster shard_0   shard_1   shard_2   ...   shard_N
```

The Tenant Service is the source of truth for `tenant_id → shard_id`. A shard misrouting (rare) returns a 503 with a "tenant moved" hint, and the application invalidates the cache and retries.

### 7.3 Cross-Shard Queries

For platform reporting and capacity planning, cross-shard aggregations run as **batch jobs** in the background-workers tier, reading from each shard sequentially. They are not on any user-facing request path.

---

### 8. Read Replica Strategy

| Class | Pattern | Where |
| --- | --- | --- |
| Read-after-write critical (auth ceremonies, token issuance) | Primary only | Token Service, Auth Service |
| Hot-but-stale-OK reads (dashboard listings, audit search) | Replica with bounded staleness (NFR DI-02: ≤ 5s) | Admin BFF, Dev Portal BFF |
| Analytics (cross-tenant aggregations) | Replica or dedicated analytics replica | Background reporting |

Replica selection is a per-call decision via the application's DB client wrapper. By default, **writes and read-after-write code paths use the writer endpoint**; reads on display surfaces use the reader endpoint. Replica lag exceeding 5 s triggers SRE alert and the wrapper routes back to the primary for affected services.

Read replicas scale up to 10 per region per shard (NFR HS-08), each in a separate AZ.

---

### 9. Migration Strategy

### 9.1 Principles

- **Online only.** Every migration is non-blocking — Postgres-friendly patterns (NEW NULLable column + backfill + NOT NULL constraint with table validation; create index CONCURRENTLY).
- **Forward-only.** No "down" migrations in production. If a deploy needs to roll back, application code rolls back to a compatible version of the schema.
- **Tooling.** `dbmate` or `goose` for migration runner, integrated into CI/CD. Migrations applied as part of the deploy pipeline with explicit gating.
- **Multi-shard execution.** Migrations run against every shard in parallel; per-shard success tracked.

### 9.2 Pattern Catalog

| Change | Pattern |
| --- | --- |
| Add column | `ALTER TABLE ... ADD COLUMN ... NULL`; backfill in batches; `ALTER ... SET NOT NULL` after validation |
| Add index | `CREATE INDEX CONCURRENTLY` |
| Remove column | Stop writing → wait one release → `ALTER ... DROP COLUMN` |
| Rename column | Add new column → dual-write → backfill → switch reads → drop old |
| Change column type | Add new column → dual-write → backfill → switch reads → drop old |
| Add NOT NULL | Add column NULL → backfill → `ALTER ... SET NOT NULL` (10.x+: avoids table rewrite) |
| Add foreign key | `ALTER ... ADD CONSTRAINT ... NOT VALID` → `ALTER ... VALIDATE CONSTRAINT` |
| Drop table | Stop writing → wait one release → `DROP TABLE` |

### 9.3 Migration Audit

Every migration writes a row to `migrations_history` with checksum, applied-at, applied-by, shard. The compliance team can reproduce historical schema at any point.

---

### 10. Data Retention & Deletion Policies

Aligned to [Compliance Matrix §4.4](../phase-1/Qeet%20ID%20%E2%80%94%20Compliance%20Requirements%20Matrix.md) and NFR LG-07 to LG-09.

| Data class | Hot retention | Cold retention | Total | Mechanism |
| --- | --- | --- | --- | --- |
| User account records (active) | Duration of account | + 30d post-delete | per Compliance | Soft delete → hard delete at 30d |
| Session records | 90 days | — | 90 days | DROP PARTITION; Redis TTL |
| Authorization codes | 5 minutes | — | 5 minutes | Sweeper |
| Refresh tokens | Until exp or revoke + 7 days | — | + 7 days for reuse-detect | Sweeper |
| Audit logs (authentication) | 12 months Postgres | 0 months S3 (overlap) | 12 months | DROP PARTITION; S3 mirror keeps to 12m |
| Audit logs (administrative, security) | 12 months Postgres | 24 months S3 | 36 months (3 years) | DROP PARTITION; S3 Glacier transition |
| Billing records | 12 months Postgres | 6 years S3 | 7 years | Compliance / tax obligation |
| Webhook deliveries | 90 days | — | 90 days | DROP PARTITION |
| SCIM provisioning log | 12 months | — | 12 months | DROP PARTITION |
| User data exports (GDPR Art. 20) | 30 days S3 | — | 30 days | S3 lifecycle |
| Password breach lookups | Not stored | — | — | Stateless calls |

### 10.1 GDPR Right to Erasure

User deletion (NFR CN-04; Compliance G-06):

1. User account row marked `status = 'pending_deletion'`, `deleted_at = now()`.
2. PII fields (email, phone) replaced by deterministic pseudonyms (`deleted_user:{user_id}`).
3. Passkey credentials, TOTP seeds, password hashes deleted immediately.
4. User's session and refresh tokens revoked.
5. After 30 days: hard delete `users` row; backups containing the user roll off per backup retention.
6. Audit log entries for the user are **anonymised** (PII fields replaced by pseudonyms) but the events are retained — required for SOC 2 audit integrity.

The 30-day SLA is met because (a) live systems lose the data within an hour, and (b) the daily backup tier rolls off the live data within 30 days. Backups beyond that horizon never contained the data because the data was anonymised before they were taken.

---

### 11. Backup & Recovery

### 11.1 Backup Schedule

| Type | Cadence | Retention | Encryption |
| --- | --- | --- | --- |
| Continuous WAL streaming | Continuous (≤5s RPO) | 30 days | AES-256-GCM with KMS-managed keys |
| Daily snapshot | Daily | 30 days | Same |
| Weekly snapshot | Weekly | 90 days | Same |
| Monthly snapshot | Monthly | 12 months | Same |
| Yearly snapshot | Yearly | 7 years (billing only) | Same |

Source: NFR DR-03 / DR-04 / DR-05.

### 11.2 Cross-Region Backup

All backups are replicated to a secondary region (NFR DR-08). For us-east-1 primary, backups replicate to us-west-2. For eu-west-1, backups replicate to eu-central-1. The replica region is **backup-only** — not a hot site — at MVP.

### 11.3 Recovery Objectives

- **RTO for primary database failure within region:** ≤ 60 s (Aurora automated failover; NFR FO-04).
- **RTO for full regional disaster:** ≤ 4 h (NFR DR-01).
- **RPO for regional disaster:** ≤ 5 minutes (NFR DR-02).

### 11.4 Point-in-Time Recovery

NFR DR-10: data corruption recoverable to any moment within last 30 days via Aurora PITR. Tested quarterly.

### 11.5 Backup Verification

Weekly automated restore test into the validation environment (NFR DR-06). Test verifies the restored cluster passes consistency checks and that critical tables match production checksums. A failure pages the SRE on-call.

---

### 12. Caching Layer Design

### 12.1 Redis Usage Map

| Data class | Pattern | TTL | Source |
| --- | --- | --- | --- |
| Sessions (hot read) | Hash per session | Session idle/abs timeout | NFR CA — see IdP §6.2 |
| JWKS public keys | String per kid | 1 h (rotation event invalidates) | NFR CA-01 |
| OIDC discovery doc | String per tenant | 1 h | NFR CA-02 |
| Tenant configuration | Hash per tenant | 5 m | NFR CA-03 |
| RBAC role definitions | Hash per role | 5 m | NFR CA-04 |
| Effective permissions per user | Set | 5 m | NFR CA-05 |
| Rate-limit token buckets | Sliding window | Rolling | NFR CA-06 |
| Token revocation bloom filter | Bitmap | 1 h refresh | NFR CA-07 |
| API key validation | Hash per key prefix | 5 m | NFR CA-08 |
| SAML IdP metadata | String per connection | 24 h | NFR CA-09 |
| Tenant routing (shard_id) | String per tenant_id | 5 m | Multi-Tenancy §6 |
| User → tenant memberships | Set | 1 h | — |

### 12.2 Cache Key Conventions

```
   {service}:{class}:{tenant_id}:{entity_id}
   e.g.
   auth:session:org_acme:sess_8f3
   rbac:perms:org_acme:user_8f3
   token:jwks:_:kid_1a2b           (underscore for tenant when global)
```

Every key carries the tenant prefix. Property-based tests validate no key in production lacks a tenant component for tenant-scoped data classes.

### 12.3 Cache Failure Modes

- **Cache miss:** falls through to source-of-truth Postgres; populates cache on the way back. Degrades latency but not correctness.
- **Cache stale:** within TTL bound (5 min worst case). Acceptable for most data classes; not used for credential verification.
- **Cache unavailable:** circuit breaker after threshold; service operates in "Postgres-only" mode with latency warnings; alert fires.

---

### 13. Event Sourcing for Audit Logs

The audit log is built as an append-only event stream — Kafka topic + Postgres hot tier + S3 cold tier — with cryptographic hash chaining to make tamper evidence cryptographically verifiable.

### 13.1 Event Production

```
   Application Service
        │
        ▼
   Emit event to Kafka topic audit.{plane}.{verb}, partition key = tenant_id
        │
        ▼
   Audit Ingestion Service consumes
        │
        ▼
   1. Validate schema
   2. Compute hash_self = HMAC-SHA256(canonical_json(event) || hash_prev) where
      hash_prev = the previous event's hash_self in the per-tenant sequence
   3. INSERT into audit_log_hot
   4. Asynchronously mirror to S3 cold tier (1-minute window)
   5. Index into OpenSearch (search tier)
```

The `hash_prev`/`hash_self` chain means tampering with any event invalidates every subsequent hash. The chain head per tenant per day is **also** written into a separate immutable `audit_log_hash_chain` table — and the chain head is mirrored daily into S3 with versioning + object lock.

### 13.2 Tamper Evidence

To verify integrity, walk the chain from any starting hash forward — every link must verify. The chain heads are periodically published (internal: weekly) to a separate immutable store so they cannot be modified retroactively by an attacker who compromises the database.

### 13.3 Audit Search

OpenSearch indexes audit events with tenant-scoped indices. The admin dashboard queries by tenant; cross-tenant search is blocked at the index level.

### 13.4 Event Replay

Kafka retention on `audit.*` topics is 7 days (Microservices §6.3). A bug in Audit Ingestion that produced incorrect rows is fixable by:

1. Halt consumption.
2. Truncate the affected window in `audit_log_hot`.
3. Re-consume from Kafka offset.
4. Reverify hash chain.

For event reconstruction older than 7 days, the S3 cold tier is the source.

---

### 14. Performance Targets for Database Layer

| Operation | Target | NFR |
| --- | --- | --- |
| Indexed point read by tenant_id+key | p95 < 5 ms | implied by §4.4 latency budget |
| Refresh-token exchange (transaction) | p95 < 30 ms | PF-03 |
| Audit insert | p95 < 10 ms | implied by SL-08 |
| Replica lag | p95 < 5 s; p99 < 30 s | DI-02 |
| Aurora failover | < 60 s | FO-04 |

---

### 15. Open Decisions Carried From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OQ-DB-01 | Per-tenant JWKS for Enterprise tier (separate signing keys per Enterprise tenant)? | Security + Solution Architect | Phase 2 close |
| OQ-DB-02 | Database-per-service vs schema-per-service in the shared Aurora cluster | Database Architect | Phase 2 close |
| OQ-DB-03 | OpenSearch vs Elastic Cloud vs hosted self-managed for audit search | DevOps + SRE | Phase 2 close |
| OQ-DB-04 | Pepper rotation procedure — sweep all hashes vs background re-hash on login | Security Architect | Phase 2 close |
| OQ-DB-05 | Whether to expose `users.global_id` cross-tenant identity model in customer APIs at MVP | API Designer + Privacy | Phase 2 close |

---

### 16. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Database Architect |  |  |  |
| Backend Engineering Lead |  |  |  |
| Solution Architect |  |  |  |
| Security Architect |  |  |  |
| DevOps / SRE Lead |  |  |  |
| Compliance Officer |  |  |  |
| QA Lead |  |  |  |

---

*This document is version controlled. Database design changes that affect tenant scoping, encryption posture, retention, or backup posture require a Database Architect, Solution Architect, and Security Architect review. New entities require an owning service decision in the Microservices Catalog before they appear here.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
