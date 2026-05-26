# Qeetid — Improvements & New Features Punch List

> **Scope.** This file is a curated punch list of **improvements and new features that go *beyond* the existing v1.0 roadmap** captured in [documents/GAP-ANALYSIS.md](./documents/GAP-ANALYSIS.md), [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md), [documents/PROTOCOL-STATUS.md](./documents/PROTOCOL-STATUS.md) and [documents/FEATURE-MATRIX.md](./documents/FEATURE-MATRIX.md).
>
> Those four documents already enumerate must-have v1.0 work (passkeys, SAML, SCIM, OIDC code flow, billing, Argon2id, JWT rotation, GDPR export, social login, etc.) — read them first. **This file lists the additional improvements found by a code-level audit on 2026-05-26**: hardening gaps, code-quality issues, missing screens, modern competitive features, and developer/operational polish.
>
> **How to use.** Each section is ordered by priority (P0 → P3) so you can pick up items one-by-one in priority order. Every item has: *Why it matters*, *Where it lands* (concrete file/module), and (where relevant) a brief *Done when* criterion.
>
> **Legend.**
> - **P0** — security or correctness gap; do before pilot customers.
> - **P1** — competitive differentiator or compliance must-have for v1.0.
> - **P2** — UX/operational polish that should land before v1.1.
> - **P3** — nice-to-have, post-launch acceptable.

---

## Table of Contents

- [1. Backend — Security & Hardening](#1-backend--security--hardening)
- [2. Backend — Code Quality & Reliability](#2-backend--code-quality--reliability)
- [3. Backend — Database & Schema](#3-backend--database--schema)
- [4. Backend — New Features (Competitive Differentiators)](#4-backend--new-features-competitive-differentiators)
- [5. Backend — Protocol Extensions Beyond v1.0](#5-backend--protocol-extensions-beyond-v10)
- [6. Backend — Operations & Observability](#6-backend--operations--observability)
- [7. Frontend Admin — Polish on Existing Screens](#7-frontend-admin--polish-on-existing-screens)
- [8. Frontend Admin — Missing Screens & Flows](#8-frontend-admin--missing-screens--flows)
- [9. Frontend — Shared UI Library](#9-frontend--shared-ui-library)
- [10. Frontend — New Apps & Hosted Surfaces](#10-frontend--new-apps--hosted-surfaces)
- [11. Frontend — Marketing & Docs Site](#11-frontend--marketing--docs-site)
- [12. Developer Experience — SDKs, CLI, IaC](#12-developer-experience--sdks-cli-iac)
- [13. Testing, CI & Quality Gates](#13-testing-ci--quality-gates)
- [14. Suggested Implementation Sequence](#14-suggested-implementation-sequence)

---

## 1. Backend — Security & Hardening

### 1.1 — `[P0]` Add CSRF protection on cookie-bearing endpoints

- **Why:** State-changing `POST` endpoints (`/v1/auth/login`, `/v1/auth/refresh`, `/v1/recovery/password/confirm`, magic-link consume) have no CSRF token or `Origin`/`Referer` validation. If sessions move to cookies, this is an account-takeover vector.
- **Where:** Add `csrfMiddleware` in [backend/internal/platform/httpx/](./backend/internal/platform/httpx/) and wire it into the mutation routes registered from [backend/internal/http/router.go](./backend/internal/http/router.go).
- **Done when:** Cookie-auth requests require a double-submit token; `Origin` header is checked against tenant CORS allowlist.

### 1.2 — `[P0]` Standard security headers middleware

- **Why:** No HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy / strict CSP. Clickjacking, MIME-sniffing and injection are not mitigated at the HTTP layer.
- **Where:** New `SecurityHeaders()` middleware in [backend/internal/platform/httpx/](./backend/internal/platform/httpx/), mounted globally in [backend/internal/http/router.go](./backend/internal/http/router.go).
- **Done when:** All responses carry HSTS (max-age=31536000; includeSubDomains; preload), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, default CSP with per-app overrides.

### 1.3 — `[P0]` Sensitive-data redaction in logs

- **Why:** Structured logger may surface emails, phone numbers, tokens, password-reset codes if an error path embeds them. SOC 2 audit will flag this.
- **Where:** Add a `slog.Handler` wrapper in [backend/internal/platform/logger/handler.go](./backend/internal/platform/logger/handler.go) that masks `password`, `secret`, `token`, `refresh_token`, `code`, `email` (last-4 only), `phone` (last-4 only).
- **Done when:** Unit test asserts each known PII field is masked across log levels.

### 1.4 — `[P1]` Tamper-evident audit log (hash chain)

- **Why:** `audit.events` is append-only but a privileged admin or SQL injection can `DELETE` rows undetected. Compliance auditors expect cryptographic integrity.
- **Where:** New migration adding `prev_hash CHAR(64)` and `row_hash CHAR(64)` columns. Update [backend/internal/audit/audit.go](./backend/internal/audit/audit.go) `Record(...)` to compute `sha256(prev_hash || canonical_json(row))`. Verifier CLI walks the chain.
- **Done when:** Verifier detects any row deletion, mutation or reordering.

### 1.5 — `[P1]` Wire `audit.Record` into every mutating module

- **Why:** Only a couple of modules (tenant, user) emit audit events. RBAC, MFA, principal/service-principal, webhook, group, OIDC client, recovery, branding, policy mutations are silent.
- **Where:** Add `audit.Record(ctx, tx, ...)` inside the same transaction as the mutation in [backend/internal/rbac/](./backend/internal/rbac/), [backend/internal/mfa/](./backend/internal/mfa/), [backend/internal/principal/](./backend/internal/principal/), [backend/internal/webhook/](./backend/internal/webhook/), [backend/internal/group/](./backend/internal/group/), [backend/internal/oidc/](./backend/internal/oidc/), [backend/internal/recovery/](./backend/internal/recovery/), [backend/internal/branding/](./backend/internal/branding/), [backend/internal/policy/](./backend/internal/policy/).
- **Done when:** Grep `audit.Record` shows it called from every `service.go` Create/Update/Delete/Rotate/Revoke method.

### 1.6 — `[P1]` Per-tenant / per-user / per-client rate-limit tiers

- **Why:** Current limiter is per-IP only. Noisy free tenants exhaust shared quota; enterprise tenants get throttled at the same rate as everyone else.
- **Where:** Extend [backend/internal/platform/ratelimit/limiter.go](./backend/internal/platform/ratelimit/limiter.go) to accept a composite key `(scope, tier, id)`. Tier comes from `tenant.plan`. Add per-account login-fail counter (precursor to lockout, GAP-ANALYSIS P1-4).
- **Done when:** Different buckets for per-IP, per-tenant, per-user, per-api-key; `Retry-After` header populated; metrics labelled by scope.

### 1.7 — `[P1]` Enforce JWT `kid` header everywhere

- **Why:** Without `kid` enforcement, JWKS rotation will silently break tokens issued with the previous key.
- **Where:** [backend/internal/platform/tokens/jwt.go](./backend/internal/platform/tokens/jwt.go) — make `kid` mandatory in both issuance and verification paths; reject tokens with missing/unknown `kid`.
- **Done when:** A token signed by a retired key still verifies during the 24h grace window; a token without `kid` is rejected with `invalid_token`.

### 1.8 — `[P1]` Token-theft detection: alert user instead of silent revoke

- **Why:** Refresh-token reuse currently revokes the session silently — the user never learns their token was reused (a strong theft signal).
- **Where:** [backend/internal/auth/service.go](./backend/internal/auth/service.go) refresh handler — on reuse-detection, emit `audit.Record("token_reuse_detected", ...)`, enqueue an outbox event for an email/webhook notification, then revoke.
- **Done when:** Reuse triggers an email and a webhook event in addition to revocation.

### 1.9 — `[P1]` Encrypt MFA TOTP secrets at rest (AES-256-GCM)

- **Why:** [backend/migrations/0010_mfa.up.sql](./backend/migrations/0010_mfa.up.sql) stores `secret TEXT` plaintext. A read-only DB leak compromises every TOTP factor.
- **Where:** New `crypto` helper in [backend/internal/platform/](./backend/internal/platform/) (AES-256-GCM with envelope key from KMS). Migration adds `secret_nonce BYTEA`. Update [backend/internal/mfa/mfa.go](./backend/internal/mfa/mfa.go) to encrypt/decrypt around enrollment and verification.
- **Done when:** New enrollments store ciphertext; existing plaintext rows are re-encrypted by a one-shot migration script.

### 1.10 — `[P1]` Email-enumeration audit on signup / invite / recovery

- **Why:** Recovery already returns constant-time generic 200; signup and invite-accept may still leak which emails exist (different error codes, different latencies).
- **Where:** Audit [backend/internal/auth/service.go](./backend/internal/auth/service.go) `Signup`, [backend/internal/invite/](./backend/internal/invite/) accept, and verification endpoints. Normalise responses and constant-time compare.
- **Done when:** Identical body + timing for "exists" vs "does not exist".

### 1.11 — `[P2]` Per-call API-key audit logging

- **Why:** Today only `last_used_at` is updated; admins cannot see which endpoint a key called when triaging a leak.
- **Where:** Middleware around the api-key auth in [backend/internal/apikey/](./backend/internal/apikey/) emits `audit.events` rows asynchronously (sampled if volume is high).
- **Done when:** Audit Log Viewer in admin filters by `actor_type=api_key` and shows endpoint, method, status.

### 1.12 — `[P2]` TOTP replay-prevention `used_codes` cache

- **Why:** Same 6-digit code is accepted multiple times inside the 30s window because the verifier doesn't track used codes.
- **Where:** New `auth.mfa_totp_used_codes` table or Redis set keyed `(user_id, code_hash)`; check in [backend/internal/mfa/mfa.go](./backend/internal/mfa/mfa.go).
- **Done when:** Replay test fails (second submission of the same code returns `code_already_used`).

### 1.13 — `[P2]` API-key format & hash upgrade

- **Why:** Roadmap spec calls for `qf_live_…` / `qf_test_…` prefixes and HMAC-SHA256 hashing; current implementation uses `qk_<prefix>.<secret>` + bcrypt. bcrypt is unnecessarily slow for API-key lookup (hot path).
- **Where:** [backend/internal/apikey/](./backend/internal/apikey/) — switch to HMAC-SHA256 with a server-side pepper; rename prefix; gate by env (test vs live).
- **Done when:** Lookup latency drops by ~10× and key format matches spec.

### 1.14 — `[P3]` Automated key/secret rotation

- **Why:** OIDC client secrets, webhook signing secrets, API keys all support manual rotation; nothing automates it on a schedule.
- **Where:** Cron in [backend/cmd/server/main.go](./backend/cmd/server/main.go) or a separate `cmd/rotator/` binary; rotation policy fields per tenant.

---

## 2. Backend — Code Quality & Reliability

### 2.1 — `[P1]` Test coverage — currently effectively zero

- **Why:** No `*_test.go` files in `backend/internal/`. SOC 2 expects >80% coverage on critical paths (auth, tokens, audit, crypto).
- **Where:** Start with [backend/internal/auth/](./backend/internal/auth/) (login, refresh, signup, reuse-detection), [backend/internal/platform/tokens/](./backend/internal/platform/tokens/) (sign/verify, kid handling), [backend/internal/platform/totp/](./backend/internal/platform/totp/) (drift, replay), [backend/internal/audit/](./backend/internal/audit/) (hash-chain integrity), [backend/internal/rbac/](./backend/internal/rbac/) (effective-permission union).
- **Done when:** `make test` runs ≥200 cases; CI fails below a coverage threshold.

### 2.2 — `[P1]` Pagination subquery is non-scaling

- **Why:** Cursor pagination in user/repository fetches `created_at` via a subselect per call; this degrades on tenants with >1M users.
- **Where:** [backend/internal/user/repository.go](./backend/internal/user/repository.go) — use a composite cursor `(created_at, id)` encoded into a single opaque token; remove subquery; rely on a covering index.
- **Done when:** EXPLAIN shows index-only scan; p99 latency on a 10M-row tenant <50ms.

### 2.3 — `[P1]` Don't swallow JSON unmarshal errors on user metadata

- **Why:** Metadata column failures are silently ignored. Bad JSON = lost data without telemetry.
- **Where:** [backend/internal/user/repository.go](./backend/internal/user/repository.go) — log + emit metric on unmarshal failure; surface as 500 if metadata is required.

### 2.4 — `[P1]` Granular `/healthz` vs `/readyz`

- **Why:** Both endpoints in [backend/cmd/server/main.go](./backend/cmd/server/main.go) return a flat 200; Kubernetes cannot distinguish liveness from readiness, so it kills healthy pods or routes traffic to unready ones.
- **Where:** Split into:
  - `/healthz` — process alive (no checks).
  - `/readyz` — DB ping, outbox dispatcher heartbeat, JWKS cache freshness.
  - `/health/diag` — verbose JSON for operators.

### 2.5 — `[P1]` Graceful shutdown audit + in-flight tracking

- **Why:** Shutdown drops in-flight requests without metric or audit event; debugging "what was dropped during the deploy" is impossible.
- **Where:** [backend/cmd/server/main.go](./backend/cmd/server/main.go) — wrap server with in-flight counter; emit `system.shutdown_initiated` audit event; wait for outbox drain.

### 2.6 — `[P2]` Background-job framework instead of ad-hoc goroutines

- **Why:** GDPR purge, webhook retries, bulk import, analytics rollups are all long-running; today they live as one-off goroutines or are not implemented at all.
- **Where:** New `backend/internal/platform/jobs/` package — a thin worker over the outbox or a dedicated `platform.jobs` table; idempotent execution, retry policy, dead-letter queue.

### 2.7 — `[P2]` Soft-delete consistency across schemas

- **Why:** `user.users.deleted_at` exists but related rows (`external_identities`, verification rows) don't filter on parent deletion. Listing endpoints may leak deleted users' data.
- **Where:** Audit every `SELECT` in [backend/internal/user/](./backend/internal/user/) — add `WHERE deleted_at IS NULL` or join filter; consider a `users_active` view.

### 2.8 — `[P3]` Replace ad-hoc context propagation with typed keys

- **Why:** Several handlers fetch tenant ID from headers, request paths, and JWT claims inconsistently. Risk of cross-tenant bug.
- **Where:** Centralise a `httpx.TenantFromContext(ctx)` helper and require all repos to take it; lint that bans direct header access in repo files.

---

## 3. Backend — Database & Schema

### 3.1 — `[P1]` Missing indexes on hot query paths

- **Why:** Several common admin/UI queries will full-scan as tenants grow.
- **Where:** New migration `0023_indexes.up.sql` adding:
  - `audit.events (actor_user_id, created_at DESC)` — "what did user X do" filter.
  - `auth.sessions (tenant_id) WHERE revoked_at IS NULL` — active-session counts.
  - `auth.password_resets (expires_at)` — janitor cleanup.
  - `auth.magic_links (expires_at)` — same.
  - `tenant.webhook_deliveries (subscription_id, next_retry_at) WHERE delivered_at IS NULL` — dispatcher hot path.

### 3.2 — `[P2]` Partition `audit.events` and `tenant.webhook_deliveries` by month

- **Why:** Unbounded growth on append-only tables. Range queries by `created_at` already cluster naturally; partitioning + monthly archival to S3/Glacier keeps the working set small.
- **Where:** Migration to convert to `PARTITION BY RANGE (created_at)`; cron job to detach old partitions and copy to object storage.

### 3.3 — `[P2]` Audit retention policy table

- **Why:** GDPR / SOC 2 retention is per-tenant per-category; nothing enforces it today.
- **Where:** New `compliance.retention_policies` table; janitor job reads policy and purges/archives accordingly.

### 3.4 — `[P3]` Read-replica routing for analytics queries

- **Why:** Future analytics + audit-search workloads should not contend with hot OLTP.
- **Where:** Extend [backend/internal/platform/db/](./backend/internal/platform/db/) to expose a `ReadOnly()` pool; route audit-search and dashboard-aggregate queries to it.

---

## 4. Backend — New Features (Competitive Differentiators)

### 4.1 — `[P1]` Step-up authentication (ACR / risk-based MFA)

- **Why:** Enterprise customers ask for "force re-MFA if user is performing a privileged action / session is >30 min old / from a new device". Auth0 and Clerk both ship this.
- **Where:** New module `backend/internal/stepup/` with an HTTP middleware `RequireACR(level)`. Login flow attaches `acr` and `amr` claims; `/v1/auth/stepup/challenge` issues a challenge token.
- **Done when:** Admin can mark routes (or applications) as requiring `acr=urn:qeetid:acr:2`, and the gateway prompts MFA when current session is below it.

### 4.2 — `[P1]` Device trust & fingerprinting

- **Why:** "Sign in from new device" emails, trusted-device lists, phishing-resistant MFA all hang off this.
- **Where:** New module `backend/internal/device/` with `auth.devices` table; fingerprint = hash of (UA family, IP ASN, TLS JA3, optional cookie). Session links to device. Login emits `new_device` outbox event.
- **Done when:** User sees a "Trusted devices" tab listing each device + last seen; can revoke individually.

### 4.3 — `[P1]` Passwordless-by-default upgrade flow

- **Why:** Passkeys are the long-term direction. After any successful magic-link or social login, prompt the user to register a passkey before issuing the long-lived session.
- **Where:** Extend [backend/internal/recovery/](./backend/internal/recovery/) magic-link confirm and the social callback in [backend/internal/social/](./backend/internal/social/) to return an `upgrade_to_passkey=true` flag the frontend uses to start the WebAuthn ceremony.

### 4.4 — `[P1]` Account recovery via trusted contacts

- **Why:** Reduces support load. Apple, Google and 1Password all ship variants.
- **Where:** New tables `user.trusted_contacts`, `user.recovery_approvals`. Endpoints `POST /v1/recovery/contacts`, `POST /v1/recovery/request`, `POST /v1/recovery/approve/{code}`.

### 4.5 — `[P1]` Impersonation with sticky audit trail

- **Why:** Support engineers debug customer issues by signing in as the user; today there's no first-class flow, no audit, no banner — high risk.
- **Where:** New endpoint `POST /v1/admin/users/{id}/impersonate` (requires `support.impersonate` permission); issues a session with `act` claim. Audit event records initiator + target.
- **Done when:** Frontend shows sticky red banner; impersonation auto-expires after 30 min; audit row recorded.

### 4.6 — `[P2]` Risk scoring on login (velocity / ASN / Tor / geo)

- **Why:** Surface a per-login `risk_score 0-100` and feed it into the step-up logic. Reduces account-takeover incidents materially.
- **Where:** New module `backend/internal/risk/`; integrate MaxMind GeoIP2 + a Tor exit-node feed; emit `auth.login_risk` audit event.
- **Done when:** Dashboard shows risk histogram; high-risk logins force MFA challenge.

### 4.7 — `[P2]` Anomaly events (impossible-travel, velocity, credential-stuffing)

- **Why:** Differentiator for security-conscious mid-market customers. Webhookable.
- **Where:** New module `backend/internal/anomaly/`; reads recent `auth.sessions` + login events; emits `security.anomaly_detected` outbox events.

### 4.8 — `[P2]` Customer-facing analytics endpoints

- **Why:** Today the dashboard charts are mocked. Real analytics enables in-app dashboards without forcing customers to ship logs to Datadog.
- **Where:** New module `backend/internal/analytics/`. Endpoints `GET /v1/tenants/{id}/analytics/logins`, `/mfa-adoption`, `/active-users`, `/failed-logins`. Backed by hourly snapshots in a `analytics.*` schema.

### 4.9 — `[P2]` Continuous breached-password monitoring

- **Why:** HIBP at signup catches initial breaches; users whose password leaks *after* signup are silently vulnerable. Re-check periodically and prompt rotation.
- **Where:** Nightly job in [backend/internal/platform/jobs/](./backend/internal/platform/jobs/) calls HIBP k-anon API for active password hashes; emits `auth.password_breached` event.

### 4.10 — `[P2]` Just-in-time admin / break-glass tickets

- **Why:** Standing admin access is a SOC 2 red flag. Break-glass pattern is a strong control.
- **Where:** New module `backend/internal/breakglass/`; ticket grants 30-min elevated role, auto-revokes, audit-logged with justification text.

### 4.11 — `[P2]` Tenant-level feature flags / kill switch

- **Why:** Need to disable passkey ceremony for one tenant in production if a zero-day lands, without redeploying.
- **Where:** New module `backend/internal/featureflags/`; backed by `tenant.feature_flags` table; checked at handler entry by middleware.

### 4.12 — `[P3]` Workflow engine for post-login actions

- **Why:** "Block login if user hasn't accepted ToS v3", "force MFA enrollment after first login", "send to compliance training". These are bespoke flows that customers reimplement on top of auth.
- **Where:** New module `backend/internal/postlogin/` — a small DAG runner with built-in steps (require_acr, require_consent, redirect_to).

### 4.13 — `[P3]` Trusted-contact / passkey synchronisation across tenants

- **Why:** Multi-org users (consultants) want a single passkey across all tenants they belong to.
- **Where:** Decouple `auth.passkey_credentials` from tenant; index by global user identity.

### 4.14 — `[P3]` AES-encrypted user metadata fields (BYOK)

- **Why:** Some customers want field-level encryption of PII columns with a key they control.
- **Where:** Add a per-tenant KEK reference; envelope-encrypt specific columns (email, phone) on write.

---

## 5. Backend — Protocol Extensions Beyond v1.0

These are post-v1.0 per the roadmap but worth scoping now:

| Item | Priority | Where | Notes |
|---|---|---|---|
| OAuth Device Authorization Grant (RFC 8628) | P2 | new module `backend/internal/devicecode/` | Required for CLI / TV / kiosk apps. |
| Token Exchange (RFC 8693) | P2 | extend [oidc package](./backend/internal/oidc/) token endpoint | Enables downscoping + delegation patterns. |
| OIDC RP-Initiated Logout 1.0 | P2 | [oidc package](./backend/internal/oidc/) | `/oidc/logout` with `id_token_hint` + `post_logout_redirect_uri`. |
| OIDC Back-Channel Logout 1.0 | P3 | [oidc package](./backend/internal/oidc/) | Required for true SLO with downstream RPs. |
| PAR (Pushed Authorization Requests, RFC 9126) | P3 | [oidc package](./backend/internal/oidc/) | FAPI prerequisite. |
| DPoP (RFC 9449) | P3 | [tokens package](./backend/internal/platform/tokens/) + middleware | Sender-constrained tokens; defends against bearer theft. |
| CIBA (Client-Initiated Backchannel Authentication) | P3 | new module | Push-based MFA for out-of-band approval (banking UX). |
| Step-Up Authentication Challenge (RFC 9470) | P3 | extends 4.1 above | Standardised `insufficient_user_authentication` error. |
| Rich Authorization Requests (RFC 9396) | P3 | [oidc package](./backend/internal/oidc/) | Fine-grained consent (transaction-specific scopes). |
| OpenID4VC / DID issuance | P3 | new module | Verifiable Credentials issuer; differentiator for identity-wallet use cases. |
| gRPC API alongside REST | P3 | new `backend/internal/grpc/` | Internal services + high-throughput integrations. |
| MCP server for AI agents | P3 | new `backend/cmd/qeetid-mcp/` | Lets Claude/agents read/write users, roles, audit. Aligned with the platform's AI-search direction. |

---

## 6. Backend — Operations & Observability

### 6.1 — `[P1]` Structured-log shipping target

- **Why:** Today logs go to stdout only. SOC 2 wants centralised, immutable storage.
- **Where:** Add a `LOG_SINK` config to [backend/internal/config/config.go](./backend/internal/config/config.go); ship via OTel Collector to Loki/CloudWatch/Datadog.

### 6.2 — `[P1]` Outbox dispatcher metrics + dead-letter queue

- **Why:** [backend/internal/platform/outbox/](./backend/internal/platform/outbox/) has retry logic but no DLQ visibility; webhook failures pile up silently.
- **Where:** Promote a `platform.outbox_dead_letter` table after N attempts; expose `GET /v1/admin/outbox/dlq` for ops.

### 6.3 — `[P2]` In-process feature-flag service

- **Why:** Beyond kill-switch (4.11) — progressive rollouts for new auth factors.
- **Where:** Wrap an OpenFeature SDK; default provider is the `tenant.feature_flags` JSON store.

### 6.4 — `[P2]` Sandbox tenants

- **Why:** Customers want to test integrations against a non-prod tenant without paying. SDKs/docs assume one exists.
- **Where:** `tenant.environment` enum (`live` / `sandbox`); sandbox tenants reset every 7 days; quota-limited.

### 6.5 — `[P2]` Tenant export/import (backup + migration)

- **Why:** Customers want to back up their tenant + move between regions; engineers want repeatable end-to-end tests.
- **Where:** New `POST /v1/tenants/{id}/export` (JSON snapshot) + `POST /v1/tenants/import`.

### 6.6 — `[P3]` Redis cache for hot RBAC / branding / JWKS

- **Why:** Permission checks and branding lookups are on every request; DB hit is unnecessary.
- **Where:** [backend/internal/platform/](./backend/internal/platform/) — small cache helper with TTL + invalidation on mutation.

### 6.7 — `[P3]` Health page / status-page integration

- **Why:** Customers want a public uptime URL.
- **Where:** Emit `incident.opened` / `incident.resolved` outbox events that push to Statuspage / Better Stack.

### 6.8 — `[P3]` On-call runbook URLs embedded in logs

- **Why:** Faster MTTR if every error log carries a runbook link.
- **Where:** Adopt a `runbook` slog attribute convention; document in [SECURITY.md](./SECURITY.md) and a new `OPERATIONS.md`.

---

## 7. Frontend Admin — Polish on Existing Screens

These items target the screens already implemented (sign-in/up, dashboard, branding, audit logs, API keys, OAuth clients, webhooks, roles, tenant settings, MFA TOTP enrollment, GDPR admin, groups, invitations).

### 7.1 — `[P1]` Wire dashboard to real APIs (currently mocked)

- **Where:** [frontend/apps/qeetid-admin/src/routes/_app/dashboard.tsx](./frontend/apps/qeetid-admin/src/routes/_app/dashboard.tsx) — replace fixture data with the analytics endpoints (depends on §4.8).
- **Done when:** Login chart, MFA adoption, failed-logins all read live data.

### 7.2 — ~~Wire admin sign-in to `/v1/auth/login`~~ ✅ Already done

- `useLogin()` in [lib/auth.ts](./frontend/apps/qeetid-admin/src/lib/auth.ts) calls `POST /v1/auth/login` (with `anonymous: true` so failed credentials don't trigger the refresh-token loop), persists access/refresh/tenant/user tokens, and navigates to `/dashboard`. Loading state + error message are surfaced via the existing [signin-form.tsx](./frontend/apps/qeetid-admin/src/features/auth/components/signin-form.tsx) props. Remaining polish: forgot-password route (covered as a small follow-up).

### 7.3 — `[P1]` Universal empty / error / loading states

- **Where:** Most index screens (`users.tsx`, `groups.tsx`, audit log, sessions, webhooks, roles) lack proper empty/error/skeleton handling. Add reusable `<DataState>` wrapper in the shared UI lib (see §9.1).

### 7.4 — `[P1]` Detail-page routes for entities

- **Where:** Add `/users/$userId`, `/roles/$roleId`, `/webhooks/$id`, `/applications/$clientId`, `/groups/$groupId`. Today inline sheet/modals carry all detail — blocks deep-linking and bookmarking.

### 7.5 — `[P1]` Accessibility audit (WCAG 2.1 AA)

- **Where:** Add `@axe-core/react` in dev; address findings across [frontend/packages/qeetid-ui/](./frontend/packages/qeetid-ui/) primitives (focus traps in modal/sheet/dialog, ARIA on data tables, contrast on muted text).

### 7.6 — `[P2]` Success-toast coverage on every mutation

- **Where:** Centralise via a TanStack Query `MutationCache.onSuccess` handler in [frontend/apps/qeetid-admin/src/integrations/tanstack-query/root-provider.tsx](./frontend/apps/qeetid-admin/src/integrations/tanstack-query/root-provider.tsx) so every mutation gets a toast unless opted out.

### 7.7 — `[P2]` Pagination & "X of Y" headers on every table

- **Where:** Build a `<PaginationBar>` primitive (see §9.1) and roll into audit logs, users, groups, sessions, webhooks.

### 7.8 — `[P2]` Saved filters + URL-driven state

- **Where:** Audit log filter UI ([frontend/apps/qeetid-admin/src/routes/_app/security/audit-logs.tsx](./frontend/apps/qeetid-admin/src/routes/_app/security/audit-logs.tsx)) should serialise to URL query params so filters survive refresh/bookmarks and can be saved per-user.

### 7.9 — `[P2]` Bulk actions on user/group tables

- **Where:** Selection state + bulk-action toolbar in [frontend/apps/qeetid-admin/src/routes/_app/users.tsx](./frontend/apps/qeetid-admin/src/routes/_app/users.tsx) and `groups.tsx`. Backend endpoint per action (delete N, role-assign N) — pairs with bulk import (GAP-ANALYSIS P1-10).

### 7.10 — `[P2]` Audit log CSV/JSON export

- **Where:** Add export button in [security/audit-logs.tsx](./frontend/apps/qeetid-admin/src/routes/_app/security/audit-logs.tsx); backend streams NDJSON.

### 7.11 — `[P2]` Optimistic updates for toggles & deletes

- **Where:** Use TanStack Query `onMutate` for delete-row / toggle-active actions across users, webhooks, API keys, roles.

### 7.12 — ~~Surface dark-mode toggle in the header~~ ✅ Already done

- Toggle is wired into [frontend/apps/qeetid-admin/src/routes/_app.tsx:70](./frontend/apps/qeetid-admin/src/routes/_app.tsx#L70). `ThemeProvider` is mounted at root with an inline no-flash bootstrap script ([__root.tsx:19](./frontend/apps/qeetid-admin/src/routes/__root.tsx#L19)).

### 7.13 — `[P3]` Mobile / responsive pass

- **Where:** Tables in [users.tsx](./frontend/apps/qeetid-admin/src/routes/_app/users.tsx), audit logs, sessions, webhooks use fixed-width columns; add card layout breakpoint for <768px.

---

## 8. Frontend Admin — Missing Screens & Flows

### 8.1 — `[P0]` Impersonation banner

- **Why:** Critical safety feature when §4.5 ships.
- **Where:** Global sticky banner in [frontend/apps/qeetid-admin/src/routes/_app.tsx](./frontend/apps/qeetid-admin/src/routes/_app.tsx). Read `act` claim from token; show "Acting as alice@acme.com — exit".

### 8.2 — `[P1]` End-user self-service portal ("My Account")

- **Why:** Today the admin is for tenant owners; end users have no surface to manage their MFA, sessions, social linkages, passkeys, personal-data download, account deletion.
- **Where:** New routes under `/account/*` in the admin app (or a separate app — see §10.1). Screens: profile, security (password / MFA / passkeys), connected accounts (Google, GitHub, …), trusted devices, session list, data export, delete account.

### 8.3 — `[P1]` Session / device manager (end-user-facing)

- **Where:** [frontend/apps/qeetid-admin/src/routes/_app/security/sessions.tsx](./frontend/apps/qeetid-admin/src/routes/_app/security/sessions.tsx) is currently admin-facing & mocked. Build a real "your sessions" page for end users that integrates §4.2 device trust.

### 8.4 — `[P1]` SSO discovery on sign-in (email-domain → IdP)

- **Where:** Sign-in page detects email domain → calls `GET /v1/sso/discovery?email=…` → redirects to IdP. Backend endpoint to add.

### 8.5 — `[P1]` Bulk user import UI

- **Where:** New route `/users/import` with CSV/NDJSON drop-zone, preview, validation, then triggers the bulk-import API (GAP-ANALYSIS P1-10).

### 8.6 — `[P1]` Passkey enrollment prompt after login

- **Where:** Modal/banner that fires on first login post-passkey-ceremony (§4.3); integrates with the WebAuthn ceremony from the roadmap.

### 8.7 — `[P1]` Notifications inbox (bell icon)

- **Where:** Header in [_app.tsx](./frontend/apps/qeetid-admin/src/routes/_app.tsx); reads from a new `notifications` outbox + endpoint. Sources: anomaly alerts, quota warnings, compliance reminders, webhook delivery failures.

### 8.8 — `[P2]` Multi-tenant org switcher

- **Where:** Top-left org-name pill opens a popover with org list + "Create workspace" CTA. Today `useTenantId()` is hard-coded.

### 8.9 — `[P2]` Onboarding wizard / first-run checklist

- **Where:** Dashboard renders a "Getting started" card with steps (set branding, invite team, configure SSO, enable MFA, add first webhook) until each is completed.

### 8.10 — `[P2]` Search-everything command palette (cmd-K)

- **Where:** New `<CommandPalette>` in shared UI; indexes routes + recent users + roles + API keys + audit events.

### 8.11 — `[P2]` Magic-link landing page

- **Where:** Public route `/magic` that handles both "open in same browser" and "open in different browser/device" paths (fallback to OTP / QR).

### 8.12 — `[P2]` Hosted auth pages per tenant

- **Where:** New app `frontend/apps/qeetid-auth/` serving `auth.qeetid.com/{tenant}/sign-in` etc., reading branding settings from the backend. Required for proper SaaS white-labelling.

### 8.13 — `[P2]` Activity / event feed (real-time)

- **Where:** New route `/activity`; SSE or WebSocket-fed list of recent audit events.

### 8.14 — `[P2]` SAML setup wizard (5-step)

- **Where:** When backend SAML lands ([GAP-ANALYSIS P0-5](./documents/GAP-ANALYSIS.md)), build a stepper UI: paste IdP metadata → map attributes → test → enable.

### 8.15 — `[P3]` In-app product tour / coachmarks

- **Where:** Driver.js or shepherd.js for new tenants; trigger first-time only.

### 8.16 — `[P3]` In-app changelog / "What's new"

- **Where:** Header dropdown reading from [frontend/apps/qeetid-docs/content/docs/changelog.mdx](./frontend/apps/qeetid-docs/content/docs/changelog.mdx).

### 8.17 — `[P3]` Saved reports / scheduled exports

- **Where:** Reports module that lets users save filter combinations + schedule weekly CSV emails.

---

## 9. Frontend — Shared UI Library

### 9.1 — `[P1]` Missing primitives the admin app reimplements

Add these to [frontend/packages/qeetid-ui/](./frontend/packages/qeetid-ui/) and export from `src/index.ts`:

| Component | Used where | Why |
|---|---|---|
| `<DataTable>` (TanStack Table wrapper) | every index screen | All tables today are bespoke — column resize, sort, virtualization don't reuse. |
| `<DataState>` (empty / loading / error union) | every list screen | Unifies the 3 missing states (§7.3). |
| `<PaginationBar>` | every paged table | §7.7. |
| `<CopyableSecret>` | API keys, webhooks, OAuth clients | Reveal once + copy button, with countdown. |
| `<OTPInput>` (6-digit) | MFA TOTP enrollment, email-OTP login | Today rebuilt per page. |
| `<PasswordStrengthMeter>` | sign-up + change-password | Visual zxcvbn score. |
| `<TimeSince>` | every list with timestamps | "5 min ago" with tooltip = absolute time. |
| `<StatusPill>` | sessions, deliveries, jobs | Consistent color + label. |
| `<ColorPicker>` | branding | Currently inline. |
| `<LogoUploader>` | branding | Drag-drop + crop. |
| `<CodeBlock>` (syntax-highlighted, copyable) | webhooks, docs embeds | Shiki + copy. |
| `<JSONTree>` | webhook delivery body, audit event detail | Collapsible payload viewer. |
| `<CommandPalette>` | §8.10 | Cmd-K. |
| `<TimezonePicker>` | user prefs | Self-service portal. |
| `<CountryPicker>` | address forms | Future GDPR forms. |

### 9.2 — `[P2]` Storybook for the UI library

- **Where:** Add `frontend/packages/qeetid-ui/.storybook/` + stories for every component. Chromatic for visual regression in CI.

---

## 10. Frontend — New Apps & Hosted Surfaces

### 10.1 — `[P1]` `qeetid-account/` — end-user portal

- **Why:** Standalone app dedicated to end-user self-service (see §8.2). Separates the admin and end-user mental models cleanly.
- **Where:** `frontend/apps/qeetid-account/` — Vite + TanStack Router. Shares UI lib.

### 10.2 — `[P2]` `qeetid-auth/` — hosted auth pages

- **Where:** See §8.12.

### 10.3 — `[P2]` `qeetid-cli/` — developer CLI

- **Where:** `apps/qeetid-cli/` (or `backend/cmd/qeetid/`). Subcommands: `login`, `tenants list`, `users create`, `apikey create`, `webhooks tail`, `migrations run`.

### 10.4 — `[P3]` Embeddable drop-in `<QeetidAuth />` widget

- **Why:** Customers building non-React apps want a script tag instead of an SDK.
- **Where:** New package `frontend/packages/qeetid-embed/` — distributed as `<script src="https://cdn.qeetid.com/v1/embed.js">`.

---

## 11. Frontend — Marketing & Docs Site

### 11.1 — `[P1]` Docs i18n scaffolding (10 languages on roadmap)

- **Where:** Configure fumadocs i18n in [frontend/apps/qeetid-docs/](./frontend/apps/qeetid-docs/); add `content/docs/{locale}/` structure; even shipping only English at launch leaves the door open.

### 11.2 — `[P1]` Live SEO audit + structured data

- **Where:** Add `robots.txt`, dynamic `sitemap.xml`, dynamic OG-image generator, Schema.org `Organization` + `Product` JSON-LD in [frontend/apps/qeetid-web/src/app/layout.tsx](./frontend/apps/qeetid-web/src/app/layout.tsx).

### 11.3 — `[P2]` Interactive pricing calculator

- **Where:** [frontend/apps/qeetid-web/src/app/(marketing)/pricing/](./frontend/apps/qeetid-web/src/app/\(marketing\)/pricing/) — MAU slider + plan calculator.

### 11.4 — `[P2]` Live demo / sandbox in browser

- **Where:** Hosted demo tenant + "Try the dashboard" button → preloaded read-only admin.

### 11.5 — `[P2]` Comparison pages (vs Auth0 / Clerk / WorkOS / Stytch / Cognito)

- **Where:** Marketing site sub-routes; standard B2B SaaS conversion play.

### 11.6 — `[P2]` Case-study + customer-logo blocks

- **Where:** Marketing site components (gated on real customers).

### 11.7 — `[P2]` "Try It Now" in API docs

- **Where:** Embed Scalar/Stoplight Elements alongside existing docs at [frontend/apps/qeetid-docs/content/docs/api/](./frontend/apps/qeetid-docs/content/docs/api/) — depends on OpenAPI completion.

### 11.8 — `[P2]` Docs versioning sidebar

- **Where:** fumadocs supports versioned trees; set up v1 root now to avoid breaking links later.

### 11.9 — `[P3]` Engineering blog

- **Where:** New `frontend/apps/qeetid-web/src/app/(blog)/` route or a separate Ghost/MDX route on the marketing site.

### 11.10 — `[P3]` "Run this code" cloud sandbox links

- **Where:** StackBlitz / CodeSandbox embed buttons in quickstarts.

---

## 12. Developer Experience — SDKs, CLI, IaC

### 12.1 — `[P1]` Official SDK packages

Roadmap names six SDKs; the missing ones blocking developer adoption:

| SDK | Where | Notes |
|---|---|---|
| `@qeetid/sdk-node` | new `frontend/packages/sdk-node/` (or separate repo) | Server-side fetch client + typed responses; auto-generate from OpenAPI. |
| `@qeetid/sdk-react` | new `frontend/packages/sdk-react/` | `<QeetidProvider>`, `useSession()`, `useSignIn()`, `<SignedIn>` / `<SignedOut>`. |
| `@qeetid/sdk-next` | new `frontend/packages/sdk-next/` | Server Actions + middleware helpers. |
| `qeetid-python` | new repo | PyPI publish. |
| `qeetid-go` | new repo | Go module. |
| `qeetid-flutter` | new repo | pub.dev. |

- **Done when:** Quickstarts reference real packages, not aspirational ones.

### 12.2 — `[P1]` CI auto-generate SDK clients from OpenAPI

- **Why:** Hand-maintained SDKs drift; Speakeasy/Stainless can publish on every PR.
- **Where:** GitHub Actions step in [.github/workflows/](./.github/workflows/) once it exists.

### 12.3 — `[P1]` Complete OpenAPI specification

- **Where:** [backend/api/openapi.yaml](./backend/api/openapi.yaml) — adopt the `swaggest/openapi3` or `kin-openapi` generator with handler annotations, or maintain by hand with a contract-test job in CI.

### 12.4 — `[P2]` Postman / Insomnia collection generation

- **Where:** Once OpenAPI is complete, `openapi-to-postmanv2` in CI.

### 12.5 — `[P2]` Terraform provider

- **Why:** Ops teams want to declare tenants, roles, applications, webhooks in code.
- **Where:** New repo `terraform-provider-qeetid/`. Resources: `qeetid_tenant`, `qeetid_user`, `qeetid_role`, `qeetid_oidc_client`, `qeetid_webhook`, `qeetid_api_key`.

### 12.6 — `[P2]` Pulumi provider

- **Where:** Mirror the Terraform schema.

### 12.7 — `[P3]` Migration guides (Firebase, Auth0, Cognito)

- **Where:** New docs pages + accompanying bulk-import format docs. Pairs with the bulk-import API.

### 12.8 — `[P3]` MCP server for AI agents

- **Where:** `backend/cmd/qeetid-mcp/`. Exposes tools to read users/roles/audit and (with audit-logged consent) execute mutations. Aligns with the platform's existing AI-search direction.

---

## 13. Testing, CI & Quality Gates

### 13.1 — `[P0]` GitHub Actions workflow

- **Why:** Repository has no `.github/workflows/`. Already P0-10 in GAP-ANALYSIS — reaffirmed here.
- **Where:** Jobs: `golangci-lint`, `go test`, `pnpm typecheck`, `pnpm lint`, `pnpm build`, migration smoke (apply up + down on a throwaway Postgres), container build, OpenAPI lint.

### 13.2 — `[P1]` E2E Playwright suite (sign-in, sign-up, MFA enroll, admin CRUD)

- **Where:** New `frontend/apps/qeetid-admin/e2e/` (or top-level `e2e/`). Run against a docker-compose stack in CI.

### 13.3 — `[P1]` Backend unit tests (see §2.1)

### 13.4 — `[P1]` Frontend component tests (Vitest + Testing Library)

- **Where:** Tests next to each component in [frontend/apps/qeetid-admin/src/](./frontend/apps/qeetid-admin/src/) and the shared lib.

### 13.5 — `[P1]` Error reporting — Sentry / similar

- **Where:** Frontend SDK init in each app's entry; backend wired via OTel exporter.

### 13.6 — `[P1]` Accessibility tests in CI (axe-core / Playwright + axe)

- **Where:** Step in CI; fail on serious violations.

### 13.7 — `[P2]` Visual-regression tests (Chromatic / Percy)

- **Where:** On Storybook stories from §9.2.

### 13.8 — `[P2]` Contract tests for the OpenAPI spec

- **Where:** Spectral-lint + `oasdiff` to detect breaking changes between PRs.

### 13.9 — `[P3]` Web Vitals + Lighthouse CI

- **Where:** GitHub Action runs Lighthouse on every PR for marketing/docs/admin.

---

## 14. Suggested Implementation Sequence

A reasonable 12-week pickup that **layers on top of** the existing GAP-ANALYSIS sprint plan. If you only have engineering bandwidth for one track in parallel with the v1.0 punch list, prioritise security hardening + audit gaps first.

| Week | Focus | Items |
|---|---|---|
| 1 | Security headers + CSRF + log redaction | §1.1, §1.2, §1.3 |
| 2 | Audit completeness + hash chain | §1.4, §1.5 |
| 3 | Test scaffolding + CI | §2.1, §13.1, §13.2, §13.5 |
| 4 | Rate-limit tiers + JWT `kid` enforcement + TOTP encryption | §1.6, §1.7, §1.9 |
| 5 | DB indexes + readiness probes + outbox DLQ | §3.1, §2.4, §6.2 |
| 6 | Impersonation + sticky banner | §4.5, §8.1 |
| 7 | Self-service portal (My Account) | §8.2, §10.1 |
| 8 | Device trust + new-device alerts | §4.2 |
| 9 | Step-up auth + risk scoring | §4.1, §4.6 |
| 10 | Shared-UI primitives + Storybook | §9.1, §9.2 |
| 11 | Detail-page routes + bulk actions + audit export | §7.4, §7.9, §7.10 |
| 12 | SDK packages (Node + React) + OpenAPI completion + Terraform provider | §12.1, §12.3, §12.5 |

Then continue with the protocol extensions (§5), analytics (§4.8), hosted auth (§8.12, §10.2), and observability polish (§6) as bandwidth allows.

---

## Cross-references

- v1.0 launch blockers and roadmap — [documents/GAP-ANALYSIS.md](./documents/GAP-ANALYSIS.md)
- Feature implementation status — [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md)
- Protocol-by-protocol conformance — [documents/PROTOCOL-STATUS.md](./documents/PROTOCOL-STATUS.md)
- Feature matrix (quick reference) — [documents/FEATURE-MATRIX.md](./documents/FEATURE-MATRIX.md)
- Project conventions and don'ts — [CLAUDE.md](./CLAUDE.md)
- Contributor guide — [CONTRIBUTING.md](./CONTRIBUTING.md)

> **Document maintenance.** When an item ships, strike through its line (or move it to a "Done" section) and add the PR link. Re-prioritise quarterly.
