# Qeet ID — Launch-Readiness Status

> **Purpose.** A single, evidence-based reconciliation of the **PRD** and **TAD** against the **actual code** —
> answering: _when can Qeet ID launch to real users and enterprises with no hidden bugs or gaps, and what must
> happen first?_
>
> **Compiled:** 2026-07-17 (research audit + a same-day remediation pass — see [§5](#5-remediation-log-2026-07-17)).
> **Method:** 7 parallel code/doc audits, then direct build/boot/verify against a live local stack.
> **Sources of truth:** `Product_Requirement_Document.md` (v4.1, 43 modules), `Technical_Architecture_Document.md`
> (v2.1), `ROADMAP.md` (the designated shipped-vs-pending ledger — Qeet ID has **no** `AS-BUILT-NOTES.md`), and a
> direct read of the source tree (`internal/` — contexts + `internal/platform/`, `cmd/`, `apps/`, `qeet-sdks/qeet-id-*`).
>
> **Legend:** ✅ shipped/verified · 🟡 partial / polish · ⏳ external-ops (not code) · 🔭 future / post-GA.

---

## 0. TL;DR — the verdict

**Qeet ID is code-complete for its GA feature set and technically sound.** The backend compiles and vets clean
and *boots and serves* (verified live), the API surface is broad and real (no feature stubs), all three SDKs are
production-quality, and the console + hosted login + marketing site are built and wired to the real API.
**Everything remaining to launch is external-ops (KMS, DNS, pentest, conformance, billing keys) or i18n/a11y
polish — not missing features or code bugs.**

**Remediation pass (2026-07-17):** every code-side gap the audit found was fixed and verified the same day — a
real NATS event broker (B-2), a public audit-verify endpoint (B-10), two SDK bug
fixes (B-4/B-5), Go↔Node SDK parity (B-6), dedicated tests for all 8 previously-untested modules (B-9), the
agent kill-switch confirmed already-correct + a regression test (B-3), performance benchmarks run and CI-wired,
and the version/GA + migration-count documentation reconciled. Only two cosmetic items remain open (B-7 import
style, B-8 clearly-labeled "coming soon" UI). Details in [§5](#5-remediation-log-2026-07-17).

**Recommended launch dates (reasoning in [§9](#9-launch-date-recommendation)):**

| Tier | Audience | Recommended date | Confidence |
|---|---|---|---|
| **Tier 1 — Public / OSS / Developer & SMB** | self-hosters, startups, indie devs, Qeet Group internal | **Tue 2026-08-18** | High |
| **Tier 2 — Enterprise GA** | mid-market & enterprise buyers | **Tue 2026-09-29** | Medium-High |
| **Tier 3 — Regulated / compliance-gated** | customers requiring SOC 2 Type II / ISO 27001 | **~2027-02 (Q1)** | Medium |

**Do not** launch enterprise before the external penetration test signs off zero-critical. **Do not** launch on a
Friday or into the mid-Dec–early-Jan enterprise change-freeze. **Nothing has been publicly launched yet** — the
product is pre-1.0 with no `1.0.0` tag.

---

## 1. Snapshot — what the code actually is (verified 2026-07-17)

| Dimension | Reality |
|---|---|
| Backend | Go 1.25 modular monolith, `chi` v5, `pgx` v5. **`go build ./...` ✅ · `go vet ./...` ✅ · unit suite: 54 packages OK · integration suite (testcontainers): green.** |
| Code volume | ~202 Go files, ~37.8k non-test LOC + ~13.3k test LOC. **80 backend test files** (+ new integration + regression tests this pass). |
| Domains | 5 bounded contexts (`access`, `developer`, `federation`, `identity`, `operations`) → ~40 modules. **No dead/empty packages.** |
| API surface | ~325 route registrations, **5 split OpenAPI 3.1 specs**, 100% route-coverage enforced by a `chi.Walk` CI test. |
| Data model | **82 migration pairs**, highest = `0083_copilot_conversations`. Embedded via `//go:embed`, auto-applied on boot. |
| Runtime | Beyond the server: `cmd/worker` (6 background workers), `cmd/scheduler` (3 advisory-locked cron jobs), `cmd/migrate`, `cmd/seed`. |
| Frontends | `login` (Next.js 16, en-only) on `@qeetrix/ui`. The **`console`** (TanStack Router + Vite, **96 route files**, 8 locales) now lives in `qeet-consoles/qeet-id-console`, and the marketing **`website`** (Next.js 16, 25 marketing pages incl. pricing/compare/legal) in `qeet-websites/qeet-id-website`. |
| SDKs | `qeet-id-{go,node,react}` — all **v0.1.0, production-quality, zero real stubs**; Go/Node now at resource parity. |
| Deployment | **Reference path:** EC2 + Caddy (auto-TLS) + AWS RDS + `docker compose` in `ap-south-2`, image → GHCR → SSH. **Staged (not live):** Helm/K8s/Terraform/observability under `deploy/base/`. Not yet serving production (pre-1.0). |
| CI/CD | `go vet`, golangci-lint, **govulncheck**, race + testcontainers integration tests, migration smoke, frontend build/typecheck/test, **gitleaks**, **CodeQL**, and a nightly **perf** workflow. |

**Bottom line:** the "~90% complete" figure in the workspace guide is accurate for *code*. The last 10% is ops,
third-party engagements, and polish.

### 1a. Live boot + smoke test (run 2026-07-17, local)

A real end-to-end local bring-up, not just a compile:

| Step | Result |
|---|---|
| Postgres (`:5001`) via `docker compose` | ✅ healthy |
| `make dev` → `go run ./cmd/api` | ✅ boots in ~2s, listens `:4001` |
| Auto-migrations on boot (embedded) | ✅ applied — **89 tables** created, no errors |
| `/healthz`, `/readyz`, `/metrics` | ✅ 200 (Prometheus `build_info` present) |
| `/.well-known/openid-configuration` | ✅ 200 — full discovery (`actor_types` user/service/agent, PKCE S256, device-auth, CIBA) |
| `/.well-known/jwks.json` | ✅ 200 — ES256 P-256 key with `kid` |
| `/v1/users` without auth | ✅ **401** (auth/tenant guard enforced) |
| `/v1/credentials/verify` (public VC verify) | ✅ mounted & public |
| `/v1/audit/verify` (public chain verify) | ✅ **200** `{chain_valid, rows_checked}` — added this pass (B-10) |
| `/v1/tenants/{id}/audit/verify` without auth | ✅ **401** — per-tenant verify is authed by design (public variant above) |

Dev boot correctly warns-and-continues on ephemeral keys and disables CSRF **only** in `SERVICE_ENV=dev` — the
secure-by-default posture is intact. **The server genuinely runs and serves.**

---

## 2. What is IMPLEMENTED ✅ (feature-complete, in code, wired)

Grouped by area. Every item is backed by real Go code + routes + (mostly) tests.

### Authentication & credentials
- ✅ Password auth — **Argon2id** (OWASP params t=3/m=64MiB/p=4), timing-safe, bcrypt→Argon2id rehash-on-login, global email uniqueness, enumeration-safe flows.
- ✅ **Passkeys / WebAuthn** full FIDO2 lifecycle (`go-webauthn`) — platform/roaming/synced credentials, usernameless + conditional-UI, per-credential mgmt, sign-count clone detection.
- ✅ Magic links & Email/SMS OTP — single-use, TTL-bound, SHA-256-hashed, rate-limited.
- ✅ **MFA** — TOTP (RFC 6238), recovery codes (bcrypt), email/SMS OTP factors, WebAuthn-as-2FA, **step-up MFA** (`RequireRecentMFA`), per-tenant policy, trusted devices.
- ✅ Per-account lockout, breached-password check (HIBP k-anonymity, fail-open).
- ✅ Self-service registration + per-tenant registration policy; **passkey-first signup** (password-optional) on direct + hosted paths.

### Sessions & tokens
- ✅ Access (15m) + refresh (30d), **always-on refresh rotation + token-family theft detection**.
- ✅ Session listing / per-session + "revoke all others" / concurrent-session limits / RP-initiated logout.
- ✅ **ES256 (P-256) JWT signing** with `kid`, retired-key grace window (zero-downtime rotation), alg-confusion guard, `alg=none` rejection.

### Authorization
- ✅ **RBAC** (`resource.action`, wildcards, system + custom roles, nested groups, Redis-cached effective perms), `/v1/check` + bulk, **explainable `?explain=true`** grant-path trace.
- ✅ **ReBAC** (Zanzibar relation-tuples, recursive userset + cycle guard, `0060`/`0078`) with `?explain=true`. Recursive group→resource resolution verified live under load.
- ✅ **ABAC** policy engine (`0080`) — attribute-condition rules (13 operators, deny-overrides).
- ✅ **AuthZEN** PDP facade over RBAC/ReBAC.

### Federation & enterprise SSO
- ✅ **OIDC/OAuth2 provider** — discovery, Dynamic Client Registration (RFC 7591), Auth Code + **PKCE (S256 only)**, `client_credentials`, **Device Grant (RFC 8628)**, **CIBA**, userinfo, JWKS, **introspection (7662)**, **revocation (7009)**, RP-initiated logout.
- ✅ **RFC 8693 Token Exchange** — on-behalf-of delegation, `act` chain (multi-hop), scope downscoping.
- ✅ **SAML 2.0 SP _and_ IdP** (RSA-SHA256, metadata, multi-SP per tenant, JIT provisioning).
- ✅ **SCIM 2.0** (Users + Groups + PatchOp, per-tenant bearer tokens, in-transaction RBAC propagation).
- ✅ **LDAP/AD** (LDAPS/STARTTLS, connection CRUD + test-bind); **Social login** (any OIDC-discovery provider, account linking/merge).
- ✅ Domain-based SSO routing (DNS-TXT, `0056`), self-serve **Admin Portal** links, **inbound migration adapters** (`POST /users/bulk/import?source=auth0|cognito|azure_b2c`).

### Developer & AI-agent platform
- ✅ API keys (`qid_live_`/`qid_test_`, bcrypt-hashed, scoped, rotatable) + service principals (`client_credentials`).
- ✅ **AI-agent identities** (`0061`) — `POST /v1/agents/token`, ephemeral `actor_type=agent` tokens (TTL 60s–3600s), `act` authorizing-human, per-issuance audit; **lifecycle state machine** (`0065`) + **immediate tenant-wide kill-switch** (`POST /agents/kill-all`, enforced per-request — see B-3); **sponsor** (`0072`) + **shadow-AI discovery** (`0073`).
- ✅ **MCP resource-server enforcement** via `/oauth/introspect` (surfaces `actor_type`/`agent_id`/`act.sub`).
- ✅ **Secrets vault** (per-tenant AES-256-GCM, scope-gated reveal) + **third-party OAuth token vault** (`0071`).
- ✅ **W3C Verifiable Credentials** (JWT-VC, `0062`) — issue, **public** verify, revoke.
- ✅ **Webhooks** — HMAC-SHA256 signed, exponential-backoff retry, **DLQ + one-click retry**.
- ✅ **Auth Hooks** (`0059`) — synchronous post-login allow/deny + custom claims (fail-open).

### Operations, audit & compliance
- ✅ **Tamper-evident audit** — append-only **SHA-256 hash-chained** log; **public unauthenticated `GET /v1/audit/verify`** (platform chain, `{chain_valid, rows_checked}`) + authed per-tenant `GET /v1/tenants/{id}/audit/verify`; GDPR erasure pseudonymizes (preserves chain).
- ✅ **Audit intelligence / anomaly detection** (behavioral baselining) + free-text audit search (`0079`).
- ✅ **SIEM streaming** (`0058`) — Splunk HEC / Datadog / webhook sinks, high-watermark cursor, DLQ.
- ✅ **GDPR** export/erasure worker + **SOC2/ISO compliance-evidence generation** (`0081`).
- ✅ **Billing** — plans, checkouts, **Stripe + Razorpay** (webhook signature verify) — _code-complete_ (needs env keys; see [§3](#3-what-is-pending-before-launch--the-real-ga-checklist)).
- ✅ Email templates, retention auto-purge, in-app notification inbox, analytics (MAU/DAU/method-mix), per-tenant rate-limit overrides.
- ✅ **Adaptive/risk-based MFA** (`0077`) — impossible-travel + device-reputation signals _(caveat in [§4](#4-partial--honest-caveats))_.
- ✅ Bot detection (`0053`), security-events feed (`0052`), trusted devices (`0054`), IP allow/deny CIDR.

### Platform
- ✅ **Secure-by-default boot-gate** — refuses to start on weak JWT secret / CSRF-off / dev-trust-headers / missing origins (bypass only via audited `DISABLE_BOOT_GATE`).
- ✅ **App-layer tenant isolation** — per-query `WHERE tenant_id = $1` predicates + the router-level `EnforceTenantScope` guard (rejects any `{tenantID}` path that isn't the caller's own tenant).
- ✅ Redis token-bucket rate limiting (per IP/tenant/user/API-key); transactional **outbox + DLQ + redrive** with a **real NATS publisher** (opt-in via `NATS_URL` — see B-2).
- ✅ Observability — Prometheus `/metrics`, OTel tracing (OTLP), `/healthz` + `/readyz`, redacting structured logs.
- ✅ Real **SMTP + Twilio** delivery (log fallback), **AWS KMS** DEK envelope encryption wired for vaults.

### Frontends & SDKs
- ✅ **Admin console** — 96 route files (users, orgs, groups, RBAC/ABAC/ReBAC, OIDC/SAML/SCIM/LDAP/social connections, API keys/webhooks/agents/vault, security, settings); real API client.
- ✅ **Hosted login** — password/passkey/social/magic-link/OTP/TOTP/step-up/consent/device-grant.
- ✅ **Marketing website** — home, features, pricing, compare (auth0/clerk/workos/stytch), customers, blog, careers, security, status, legal (privacy/terms/DPA/subprocessors).
- ✅ **SDKs** — `qeet-id-node` (41 services) and `qeet-id-go` (now at parity, 41 services) + `qeet-id-react` (browser flows + **exclusive passkey/WebAuthn** ceremony). Correct JWKS ES256 verify, constant-time webhook HMAC, alg-confusion guards.

---

## 3. What is PENDING before launch ⏳ (the real GA checklist)

**Every remaining gate is external-ops or polish — no code items remain** (all code-side gaps were closed in the
[remediation pass](#5-remediation-log-2026-07-17)). Reconciled from PRD §12.2 + ROADMAP `:101–104` + verification.

| # | Item | Type | Blocks | Notes |
|---|---|---|---|---|
| 1 | **AWS KMS BYOK go-live** | ⏳ ops | Tier 1 | KeyProvider + envelope encryption coded, wired & tested — needs a **live CMK provisioned**. Derived-key vault works meanwhile. |
| 2 | **OpenID OP conformance run + SAML/SCIM interop** (Entra/Okta/Google) | ⏳ ops | Tier 2 | Conformance is CI-guarded at the contract level; needs a formal run against a deployed instance. Cert within 90 days of GA per PRD. |
| 3 | **Email deliverability** — SPF/DKIM/DMARC + bounce/complaint | ⏳ ops | Tier 1 | Gates production OTP / magic-link / verification email. SMTP code is real; DNS + reputation are external. |
| 4 | **RDS PITR / backups + DR drill** | ⏳ ops | Tier 1 (backups), Tier 2 (drill) | Enable PITR; run the DR runbook once (target RTO < 30s / RPO < 5m). |
| 5 | **External penetration test — zero-critical gate** | ⏳ ops | **Tier 2 (hard gate)** | PRD makes "zero critical findings" a GA prerequisite. Engage a firm ~6 weeks before Tier 2. **The single biggest schedule driver.** |
| 6 | **Billing go-live** — Stripe + Razorpay production keys | ⏳ ops | Tier 1 (if paid at launch) | Checkout code complete & webhook-verified; needs 5 env keys + one live validation. |
| 7 | _(removed)_ **RLS prod activation** | — | — | Postgres RLS was reverted on 2026-07-23 (never deployed; see B-1). Tenant isolation is app-layer only. |
| 8 | **i18n completion** | 🟡 polish | Tier 2 | Console `en` fully externalized; **7 other locales ~53%**; `login` app en-only; emails not localized. Needs human translation + retrofit. |
| 9 | **a11y — WCAG 2.2 AA legacy screens** | 🟡 polish | Tier 2 | Gate wired via Biome `a11y`; new/critical flows compliant; **~70 older console screens** need retrofit. |
| 10 | **Managed-cloud infra** (multi-region/HA, K8s/Helm/Terraform go-live) | 🟡 ops | Managed offering only | Staged & "structurally validated", not the live path. Self-host single-node is production-viable today. |
| 11 | **Bug-bounty program** | ⏳ process | Tier 2 | Explicitly deferred "to launch alongside v1.0" (`SECURITY.md`). |

---

## 4. PARTIAL / honest caveats 🟡

Things that work but carry an asterisk (none are launch blockers for Tier 1):

- 🟡 **Adaptive risk — impossible-travel needs an upstream geo header.** The signal ships but requires a
  proxy-provided country header (e.g. Cloudflare `CF-IPCountry`); **no server-side GeoIP**. Off by default.
- 🟡 **CAEP/SSF is a pragmatic middle path, not full interop.** Real-time revocation via 10-min token TTL +
  hardened refresh check + `session.revoked` / `token.claims_change` webhooks. **No SSF transmitter**
  (`/.well-known/ssf-configuration`, SET format, stream-mgmt API absent). Don't market as "full CAEP parity."
- 🟡 **Nested org hierarchy not built.** Tenancy is a **flat `tenant_id`** model (matches Auth0/WorkOS/Stytch); no
  Instance→Org→Project hierarchy/delegation. Fine for GA; a named roadmap item.
- 🟡 **Auth-hook custom claims** flow into direct API-token/MFA login but **not yet** the hosted-login → OIDC
  ID-token pipeline.
- 🟡 **Invitation acceptance still requires a password** — the one path where "passkeys-first" isn't fully true.

---

## 5. Remediation log (2026-07-17)

The audit surfaced 10 findings (B-1…B-10). Status after the same-day remediation pass:

| # | Finding | Status |
|---|---|---|
| B-1 | Tenant isolation was app-layer only; no Postgres RLS (docs overclaimed) | ↩️ **Reverted (2026-07-23)** — RLS was added on 2026-07-17 but removed; isolation is app-layer only by design (docs corrected to match) |
| B-2 | Outbox published to logs only; no real broker | ✅ **Fixed** — NATS publisher wired + proven end-to-end |
| B-3 | (TAD claim) agent kill-switch is TTL-bounded | ✅ **Not a gap** — enforced per-request; verified live + regression test added |
| B-4 | SDK JWKS unknown-`kid` refetch amplification (Go+Node) | ✅ **Fixed** — 1-min refetch cooldown |
| B-5 | SDK React WebAuthn error misclassification | ✅ **Fixed** — `NotAllowedError`→cancelled, else failed |
| B-6 | Go↔Node SDK resource parity gap | ✅ **Fixed** — added bot-detection/risk-settings/token-vault to Go |
| B-7 | SDK TS `@/*` alias not used (React 28 `../../` imports) | 🟢 **Open** (cosmetic/style) |
| B-8 | Frontend "coming soon" surfaces (clearly labeled) | 🟢 **Open** (cosmetic; not deceptive) |
| B-9 | 8 backend modules without dedicated tests | ✅ **Fixed** — 12 integration tests, all 8 covered |
| B-10 | Audit `/verify` was authed-only, not the public endpoint docs claim | ✅ **Fixed** — public `/v1/audit/verify` added |

Plus: **version/GA story** and **migration-count** documentation reconciled; **performance benchmarks** run + CI-wired.
Full build/vet/unit (54 pkgs) + integration suites green after all changes.

### ↩️ B-1 — Postgres RLS defense-in-depth (added 2026-07-17, **reverted 2026-07-23**)
- **Finding:** 0 RLS policies; isolation was 100% application-layer (223 `WHERE tenant_id` predicates +
  `EnforceTenantScope`). PRD/TAD + workspace guide claimed DB-level RLS — untrue.
- **What was done (2026-07-17):** migration `0082_rls_tenant_isolation` added a least-privilege `qid_app` role +
  grants and `ENABLE`d RLS + a `tenant_isolation` policy on the tenant-scoped tables, with the pool stamping
  `app.tenant_id`/`app.bypass_rls` per checkout (a `rlsctx` package) and a `DB_MIGRATE_URL` (owner) vs `DB_URL`
  (app role) split.
- **Reverted (2026-07-23):** the product has not been deployed anywhere, and the two-role / two-URL setup was not
  wanted. Migration `0082` and the `rlsctx` package were deleted, the pool's GUC stamping removed, `0083` stripped
  of its RLS/role blocks (keeping the copilot tables), and `DB_MIGRATE_URL` collapsed back to a single `DB_URL`.
  `EnforceTenantScope` (the cross-tenant `{tenantID}` guard, QID-18) was **kept**. Tenant isolation is therefore
  app-layer only — the per-query `tenant_id` predicates + `EnforceTenantScope` — as it was before this pass.

### ✅ B-2 — Real NATS event broker for the outbox
- **Finding:** durable outbox + dispatcher + DLQ existed, but the only wired `Publisher` was `LogPublisher` — no
  cross-product event fan-out.
- **Fix (opt-in):** `NATSPublisher` + `NewPublisher(natsURL)` factory (`internal/platform/events/outbox/nats.go`, official
  `nats.go`). Subject = event topic, payload = event JSON, type in a `Qeet-Event-Type` header; `Publish` flushes
  synchronously so failures return to the dispatcher (retry + DLQ own durability). Wired into `cmd/api` +
  `cmd/worker` via `NATS_URL`; blank = log-only path (unchanged).
- **Verified live:** unit test (publish→subscribe with header) + end-to-end — created a group via the API →
  dispatcher published → an independent subscriber received `group.events` / `Qeet-Event-Type: group.created`.

### ✅ B-3 — Agent kill-switch enforcement (NOT a gap — verified)
- The TAD's "checked only at re-mint, valid until TTL" was **stale**. `RequireAuth` consults `AgentStatus` (a
  fresh `SELECT status FROM auth.agents`) on **every** agent-token request, wired in production
  (`main.go: verifier.AgentStatus = agentService.AgentStatus`). A non-`active`/unknown agent is denied 401 within
  one request.
- **Proven live:** minted an agent token (200) → `kill-all` → same token reused → **401 "agent suspended"**.
- **Hardening:** added regression test `TestRequireAuth_AgentStatusEnforced` so a refactor can't silently
  reintroduce a latency gap.

### ✅ B-4 — SDK JWKS unknown-`kid` refetch amplification (Go + Node)
- A token with an unknown `kid` forced a JWKS refetch per request (amplification vector). **Fix:** cache-miss
  refreshes rate-limited to one per 1-minute cooldown; first fetch always allowed; a rotated-in key is still
  picked up within the window; Node de-dupes concurrent refreshes. Verified: Go build/vet/tests, Node full suite (204).

### ✅ B-5 — SDK React WebAuthn error misclassification
- Every ceremony exception was labeled `"cancelled"`. **Fix:** a classifier maps only `NotAllowedError`
  (user-cancel/timeout, deliberately conflated by the spec) to `"cancelled"`; every other DOMException →
  `"failed"`. Verified: React typecheck + tests (28).

### ✅ B-6 — Go↔Node SDK resource parity
- `qeet-id-go` lacked **bot-detection, risk-settings, token-vault**. **Fix:** added all three as idiomatic Go
  resources (matching backend JSON types — incl. `float64` scores/thresholds) and registered them on the client.
  Verified: Go build/vet/tests.

### ✅ B-9 — Dedicated tests for all 8 previously-untested modules
- Added 12 real Postgres-backed integration tests (testcontainers, also CI): **recovery** (5 — reset round-trip +
  single-use, weak/invalid, expired, enumeration-safety, magic-link), **organizations/groups/invitations/
  verification** (`identity_modules_test.go`), **notifications/service-accounts** (`ops_dev_modules_test.go`),
  **ratelimits** (`ratelimits_test.go` — defaults, override, cross-tenant 403). Full integration suite green.

### ✅ B-10 — Public audit-verify endpoint
- The only chain-verify was authed/tenant-scoped; the PRD/TAD advertise a **public** verify as the "provable
  audit" differentiator. **Fix:** added `GET /v1/audit/verify` (public, no auth) verifying the platform chain and
  returning only `{chain_valid, rows_checked}` (no tenant scope, no row IDs, no leak); per-tenant verify stays
  authed. Documented in `operations.yaml` (`security: []`); OpenAPI coverage test green. **Verified live** (200
  without auth; tenant verify still 401).

### 🟢 Open (cosmetic, non-blocking)
- **B-7** — TS SDKs don't use the `@/*` alias (React has 28 deep `../../` imports). Style only; adopt `@/*` to
  match workspace convention.
- **B-8** — three clearly-labeled "coming soon" console surfaces (`developer/bots.tsx`, `authorization/versions.tsx`
  server-side rollback, `authorization/assistant.tsx`). None wired to fake data; hide behind a flag or keep the copy.

### Documentation reconciled
- ✅ **Version/GA story** — confirmed nothing was launched and there is no `1.0.0` tag. Canonical = **pre-1.0, not
  yet GA**. `CHANGELOG.md`'s premature `1.0.0 (2026-06-22)` → relabeled `[Unreleased]`; workspace guide's "GA
  (2026-05-27)" → "pre-1.0, not yet launched"; README/SECURITY/ROADMAP already consistent.
- ✅ **Migration-count drift** — `ROADMAP.md` header + `qeet-id/CLAUDE.md` said `0001–0064` → corrected (now
  through `0082`).
- 🟡 **`GAP-ANALYSIS.md` / `MERGE-BLUEPRINT.md` lag the code** (describe `0077`–`0081` work as unshipped). Treat
  **this STATUS.md + ROADMAP.md** as ground truth; Qeet ID has no `AS-BUILT-NOTES.md`.

---

## 6. FUTURE — post-GA roadmap 🔭 (not launch-blocking)

Sequenced across the PRD's phases through H1 2028:

- **Phase A (H2 2026):** end-user self-service portal, full device registry + MDM posture, flow-builder alpha, FGA
  permissions index, discovery-first SDK bootstrap, deeper audit intelligence.
- **Phase B (H1 2027):** entitlements/access-certification, SCIM joiner/mover/leaver engine, full consent/privacy,
  user impersonation, white-label/ISV Platform API, **full CAEP/SSF (receiver + transmitter)**, general-purpose
  ABAC engine, management CLI, Rust SDK, **SOC 2 / ISO 27001 engagements**.
- **Phase C (H2 2027):** IDV/KYC connectors, enterprise app catalog, communications infra, connector marketplace,
  **Identity Graph & Relationship Intelligence**.
- **Phase D (H1 2028):** FAPI 2.0 (PAR/JAR/DPoP/mTLS), DID methods + EUDI wallet, OID4VCI/OID4VP,
  Merkle-checkpoint externally-verifiable audit, FIPS/air-gapped mode, SPIFFE/WIMSE JWT-SVID, mobile admin app.
- **Tracked / unscheduled:** nested org hierarchy, device-bound agent credentials (TPM/enclave + RFC 8705 mTLS),
  NL-to-query audit search, broader published perf matrix (login/user-CRUD/soak).
- **Explicit non-goals:** full IGA (SoD/role-mining), PAM session-recording.

---

## 7. Deployment / "server up and running" readiness

- ✅ **Deploy path proven:** distroless nonroot image → GHCR → EC2 + Caddy (auto-HTTPS) + AWS RDS via
  `docker compose`, with a `/readyz` health-gate in the deploy workflow; migrations auto-apply on boot. (Proven by
  the pipeline + the local boot in [§1a](#1a-live-boot--smoke-test-run-2026-07-17-local); **not yet serving
  production** — pre-1.0.)
- ✅ **Secure-by-default boot-gate** blocks an insecure prod start.
- ⏳ **Before prod go-live:** provision the live KMS CMK (#1), email DNS (#3), RDS PITR (#4), billing keys if
  selling (#6), mount `jwt_signing_key.pem` / SAML keys (deploy runbook), and put a WAF/CDN (Cloudflare/AWS Shield)
  at the edge (also supplies the geo header for adaptive risk).
- 🟡 **Rotate the JWT signing key set every 90 days** (self-hoster expectation, `SECURITY.md`).
- 🟡 **Scaling later:** Helm/K8s/Terraform are staged; validate (`helm lint`, `terraform validate`) before first use.
- **Performance (measured, dev machine):** OIDC discovery/JWKS **p95 ≈ 3.2 ms** (SLO < 20 ms); RBAC + recursive
  ReBAC `/check` **p95 ≈ 11.9 ms** (SLO < 30 ms). Nightly `perf.yml` gates discovery; `make bench` runs the suite.

---

## 8. Launch-readiness by audience

| Audience | Ready? | Verdict |
|---|---|---|
| **Qeet Group internal** (products delegate to it) | ✅ Yes | Ship. Real NATS fan-out (B-2) wired — set `NATS_URL` when products consume Qeet ID events. |
| **OSS self-hosters / indie devs** | ✅ after #1,#3,#4 | Fully usable; no feature gaps. |
| **Startups / SMB (paid)** | ✅ after #1,#3,#4,#6 | Add billing keys; i18n/a11y can trail. |
| **Mid-market / Enterprise** | 🟡 after Tier-2 gates | Needs pentest zero-critical (#5), conformance (#2), i18n/a11y (#8/#9). All code is done. |
| **Regulated (finance/health/gov)** | 🔴 not yet | Needs SOC 2 Type II / ISO 27001 (observation window) → Tier 3. |

---

## 9. Launch-date recommendation

**Today is 2026-07-17 (Fri); nothing is publicly launched yet** (pre-1.0, no `1.0.0` tag; `api.id.qeet.in` is the
intended target host). Dates are for the *first announced, supported* launches; mid-week chosen deliberately.

### 🟢 Tier 1 — Public / OSS / Developer & SMB → **Tuesday, 2026-08-18** _(good)_
~4.5 weeks out. Enough to close the fast external-ops gates: **KMS CMK (#1), email DNS (#3), RDS PITR (#4), billing
keys (#6)**, plus a self-run OIDC conformance dry-run. No code features are missing for this audience. **The
earliest date to launch "without gaps" for real (non-regulated) users.**

### 🟠 Tier 2 — Enterprise GA → **Tuesday, 2026-09-29** _(recommended headline "enterprise-ready" launch)_
~10.5 weeks out. Critical path = the **external penetration test**: engage a firm by **~2026-08-25** for ~3–4 weeks
of testing + critical remediation before this date. In parallel: **OIDC/SAML/SCIM conformance certification** (#2),
**i18n + a11y** (#8/#9), and a **DR drill** (#4). End-of-Q3 lands before Q4 budget
cycles and clear of the year-end freeze. _If the pentest slips, move to the next Tuesday rather than ship unproven._

### 🔵 Tier 3 — Regulated / compliance-gated → **~2027-02 (Q1)** _(when you need SOC 2 / ISO)_
SOC 2 Type II needs a **3–6 month observation window** that can only start once controls run in production (~Tier-2
launch). Target a compliance-badged launch **early Q1 2027 (e.g. Tue 2027-02-16)**. An audit-calendar effort, not code.

### Dates to avoid
- ❌ Any **Friday** or day before a public holiday (India `ap-south-2` + target-market calendars).
- ❌ **Mid-December → early January** for the enterprise tier (change-freeze season).
- ❌ Enterprise launch **before** pentest zero-critical sign-off (PRD hard gate) — non-negotiable.

---

## 10. Pre-launch action checklist

### ✅ Done in the 2026-07-17 remediation pass
- [x] NATS broker (B-2) · public audit-verify (B-10)  _(RLS B-1 was added then reverted 2026-07-23 — see §5)_
- [x] SDK fixes: JWKS throttle (B-4), React WebAuthn (B-5), Go↔Node parity (B-6)
- [x] Agent kill-switch verified + regression test (B-3)
- [x] Dedicated tests for all 8 modules (B-9) · performance benchmarks run + CI-wired (`perf.yml`, `make bench`)
- [x] Version/GA story + migration-count docs reconciled

### ☐ Before Tier 1 (2026-08-18) — external-ops
1. ☐ Provision live AWS KMS CMK; enable BYOK (#1).
2. ☐ Configure email SPF/DKIM/DMARC + bounce handling (#3).
3. ☐ Enable RDS PITR/backups (#4).
4. ☐ Set Stripe + Razorpay production keys; run one live checkout (#6, if selling at launch).
5. ☐ Self-run an OIDC OP conformance dry-run; fix any edge cases.

### ☐ Before Tier 2 (2026-09-29)
6. ☐ **Engage a pentest firm by ~2026-08-25; remediate all criticals** (#5).
7. ☐ Formal OIDC + SAML + SCIM conformance/interop certification (#2).
8. ~~RLS prod activation~~ — removed; Postgres RLS was reverted on 2026-07-23 (tenant isolation is app-layer only).
9. ☐ Complete i18n (7 locales + login app + emails) and a11y legacy-screen retrofit (#8/#9).
10. ☐ Run a DR drill; record RTO/RPO (#4).
11. ☐ Launch the bug-bounty program (#11).
12. ☐ (Optional polish) B-7 `@/*` SDK alias; B-8 flag the "coming soon" console surfaces; broaden the perf matrix.

### ☐ Before Tier 3 (Q1 2027)
13. ☐ Start SOC 2 Type II observation window; begin ISO 27001 engagement.

---

## Appendix — methodology & confidence

Compiled from **7 parallel audits** (full PRD read, full TAD read, backend catalog, gap/bug/stub scan, frontend
audit, ROADMAP/CHANGELOG/GAP-ANALYSIS review, SDK exploration), then a same-day **remediation pass** with direct
verification: `go build`/`go vet` ✅, unit suite (54 packages) ✅, all three SDKs build/typecheck/test ✅, a real
**local boot + HTTP smoke test** ([§1a](#1a-live-boot--smoke-test-run-2026-07-17-local)), a **login → authed
tenant-scoped read** flow, an **agent kill-switch
end-to-end proof**, a **NATS publish→subscribe end-to-end proof**, the **full testcontainers integration suite**,
and **k6 performance benchmarks**.

**Not run:** external load tests at scale, the deployed EC2 stack, and the third-party gates by nature (pentest,
formal conformance, KMS/DNS/billing go-live). Confidence is **high** on what exists in the code, that it
boots/serves, that NATS/agent-revocation work, and on the GA gate list; **medium** on the exact enterprise date
(gated by the pentest calendar). Re-verify any "shipped" claim contradicted by `GAP-ANALYSIS.md`/`MERGE-BLUEPRINT.md`
before external publication — those two docs pre-date the `0077`–`0082` work.
