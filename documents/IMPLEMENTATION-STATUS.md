# Qeetid — Implementation Status Report

**Repository under review:** [qeet-identity](../) (this workspace)
**Requirements source:** [qeetgroup/qeetid · qeetid-reqs](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs) — Phase 1 (Discovery), Phase 2 (System Design), Phase 3 (UI/UX Design)
**Status as of:** 2026-05-25
**Target release:** v1.0 "Foundation" — Month 15 MVP

This document maps the **268 features across 12 product categories** specified in the Qeetid roadmap against what is **actually implemented in this codebase today**. Companion documents:

- [FEATURE-MATRIX.md](./FEATURE-MATRIX.md) — quick-reference status table
- [PROTOCOL-STATUS.md](./PROTOCOL-STATUS.md) — protocol-by-protocol conformance status
- [GAP-ANALYSIS.md](./GAP-ANALYSIS.md) — prioritized list of remaining work

**Legend:**
- ✅ **Implemented** — code complete, happy-path covered, ready for hardening/QA
- 🟡 **Partial** — data model + some logic exists; key pieces (e.g. ceremony, external integration) outstanding
- 🔴 **Not implemented** — feature absent or stubbed (`501 Not Implemented`)
- ⚪ **Out of scope for v1.0** — deferred per roadmap to v1.5/v2.0/v3.0

---

## 1. Executive Summary

### Overall Posture

| Area | Required (Must-Have, v1.0) | Implemented | Partial | Not Started |
|------|---------------------------:|------------:|--------:|------------:|
| Qeetid Auth (Authentication) | 14 | 7 | 4 | 3 |
| Qeetid ID (Identity Management) | 12 | 9 | 2 | 1 |
| Qeetid Access (RBAC/ABAC) | 9 | 7 | 1 | 1 |
| Qeetid Connect (Federation) | 16 | 2 | 4 | 10 |
| Qeetid Guard (Security) | 8 | 2 | 2 | 4 |
| Qeetid Keys (M2M Auth) | 8 | 6 | 1 | 1 |
| Developer Experience (SDKs/API) | 12 | 2 | 3 | 7 |
| Admin Dashboard | 17 | 1 | 1 | 15 |
| Developer Portal | 10 | 4 | 1 | 5 |
| Billing & Subscriptions | 11 | 0 | 0 | 11 |
| Infrastructure & Operations | 12 | 1 | 2 | 9 |
| Compliance & Trust | 11 | 0 | 2 | 9 |
| **TOTAL (Must-Haves only)** | **140** | **41 (29%)** | **23 (16%)** | **76 (55%)** |

### What we have

- A **Go monolith backend** (chi + pgx + PostgreSQL) with 19 internal modules covering core identity, auth, RBAC, MFA, API keys, audit, GDPR, webhooks, OIDC scaffolding, and tenant administration. See [backend/internal/](../backend/internal/).
- A **3-app pnpm/Turborepo frontend** — admin dashboard ([qeetid-admin](../frontend/apps/qeetid-admin/)), marketing site ([qeetid-web](../frontend/apps/qeetid-web/)), and docs site ([qeetid-docs](../frontend/apps/qeetid-docs/)) — plus a shared [@qeetid/ui](../frontend/packages/qeetid-ui/) shadcn-style component library.
- A **production-shaped database schema** ([backend/migrations/](../backend/migrations/)) across `tenant`, `user`, `auth`, `rbac`, `audit`, `platform` schemas — 21 numbered migrations, 30+ tables.
- An **OpenAPI 3.x baseline** at [backend/api/openapi.yaml](../backend/api/openapi.yaml).
- A **transactional outbox** at [backend/internal/platform/outbox/outbox.go](../backend/internal/platform/outbox/outbox.go) with webhook dispatcher.

### What we do NOT have yet (Must-Have v1.0 gaps)

- **WebAuthn / Passkey ceremony** — registration/login endpoints return 501. Storage and listing endpoints exist.
- **Social login OAuth exchange** — provider config + identity-linking storage exist; `start` and `callback` return 501.
- **OAuth 2.0 / OIDC Authorization Code flow** — discovery, JWKS, client registration, userinfo are in; the `/authorize` and `/token` (code grant) endpoints are not.
- **SAML 2.0 (SP & IdP)** — no code, no migration, not wired into router.
- **SCIM 2.0** — no code, no endpoints; covered by user/group internal APIs only.
- **Admin dashboard screens** — only `/dashboard` and `/sign-in`/`/sign-up` exist; the remaining ~38 routes are catch-all "Coming soon" placeholders.
- **Billing / Stripe integration** — entirely absent.
- **CAPTCHA / bot detection / WAF integration / HaveIBeenPwned** — not implemented.
- **Webhook signature verification example, retry UI, delivery-history UI** — backend exists, no UI.
- **Email & SMS providers** — `Sender` interface is a `LogSender` (logs to stdout); SendGrid/Twilio not wired.
- **JWT signing in production mode (RS256/ES256 + JWKS rotation)** — current issuer uses HS256 with a single static key; the JWKS endpoint exists but is not backed by a rotated key set.
- **SDKs (React, Next.js, Node, Python, Flutter, Go)** — none.
- **Compliance certifications** (SOC 2, FIDO2 cert, OpenID Foundation Basic OP) — not initiated in codebase.

### What is on track and ahead of plan

- **Argon2id/bcrypt password hashing** — bcrypt cost 12 implemented at [backend/internal/platform/password/hasher.go](../backend/internal/platform/password/hasher.go). (Roadmap calls for Argon2id; bcrypt is acceptable but should be reconsidered.)
- **TOTP MFA** with recovery codes (RFC 6238) — implemented at [backend/internal/mfa/mfa.go](../backend/internal/mfa/mfa.go).
- **Magic link + email OTP** — implemented at [backend/internal/recovery/recovery.go](../backend/internal/recovery/recovery.go) and [backend/internal/verification/verification.go](../backend/internal/verification/verification.go).
- **Outbox-based event publishing** — already in place per the Phase 2 architecture spec.
- **Rate limiting** — token-bucket per-IP at [backend/internal/platform/ratelimit/limiter.go](../backend/internal/platform/ratelimit/limiter.go), mounted on `/v1/auth/login` and `/v1/auth/refresh`.
- **Documentation site (qeetid-docs)** — 32 MDX files already authored, AI search integrated. Far more complete than the underlying APIs they describe.
- **Shared UI library** — 20 production-quality shadcn-style primitives ready, including the full Sidebar system the admin dashboard navigation will need.

---

## 2. Qeetid Auth — Authentication

Reference: [Feature Prioritization roadmap §Authentication Suite](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-1) and [Protocol Requirements §WebAuthn/FIDO2, §OAuth/OIDC, §Magic Links, §TOTP](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-1).

| Feature (Must-Have v1.0) | Status | Implementation | Notes / Gaps |
|---|---|---|---|
| Email + password sign-in | ✅ | [backend/internal/auth/service.go](../backend/internal/auth/service.go), [backend/internal/auth/http.go](../backend/internal/auth/http.go) | Endpoints: `POST /v1/auth/login`, `/refresh`, `/logout`, `/me`, sessions list/revoke. |
| Argon2id password hashing | 🟡 | [backend/internal/platform/password/hasher.go](../backend/internal/platform/password/hasher.go) | Uses **bcrypt cost=12** — roadmap requires **Argon2id**. Should migrate to `golang.org/x/crypto/argon2` with the recommended parameters. |
| Social login — Google | 🟡 | [backend/internal/social/social.go](../backend/internal/social/social.go) | Provider config + linked-identity tables exist. `/v1/social/{provider}/start` and `/callback` return **501**. |
| Social login — GitHub | 🟡 | Same | Same — provider model is generic but exchange flow missing. |
| Social login — Microsoft | 🟡 | Same | Same. |
| Social login — Apple | 🟡 | Same | Same — needs Apple-specific OIDC variant (JWT client assertion). |
| Magic links | ✅ | [backend/internal/recovery/recovery.go](../backend/internal/recovery/recovery.go) | `POST /v1/recovery/magic-link/start` and `/consume`. 15-min TTL, one-time use, hash-stored token. |
| Email OTP | ✅ | [backend/internal/verification/verification.go](../backend/internal/verification/verification.go) | 6-digit code, 10-min TTL, single-use, SHA-256 hashed. |
| Passkeys — WebAuthn registration | 🔴 | [backend/internal/passkey/passkey.go](../backend/internal/passkey/passkey.go) | `register/begin`, `register/finish` return **501**. Storage table `auth.passkey_credentials` exists. Needs `github.com/go-webauthn/webauthn` integration. |
| Passkeys — WebAuthn login | 🔴 | Same | `login/begin`, `login/finish` return **501**. |
| Passkeys — cross-device QR / Hybrid Transport | 🔴 | — | Requires upstream WebAuthn ceremony first. |
| MFA — TOTP | ✅ | [backend/internal/mfa/mfa.go](../backend/internal/mfa/mfa.go), [backend/internal/platform/totp/totp.go](../backend/internal/platform/totp/totp.go) | RFC 6238, 6-digit, 30s window, ±1 period skew. Includes provisioning URL. |
| MFA — SMS OTP | 🟡 | [backend/internal/verification/verification.go](../backend/internal/verification/verification.go) | Phone-verification flow exists; not wired into MFA step-up at login. Provider is `LogSender` (no real SMS). |
| MFA — Email OTP | 🟡 | [backend/internal/verification/verification.go](../backend/internal/verification/verification.go) | Same — not wired into MFA step-up. |
| MFA — backup / recovery codes | ✅ | [backend/internal/mfa/mfa.go](../backend/internal/mfa/mfa.go) | 10 × 10-digit, bcrypt-hashed, one-time use. |
| Account lockout, brute-force protection | 🟡 | [backend/internal/platform/ratelimit/limiter.go](../backend/internal/platform/ratelimit/limiter.go) | Per-IP rate limit on `/login` and `/refresh`. No **per-account lockout** with exponential backoff or PasswordHIBP check — both roadmap requirements. |
| Session management w/ configurable timeouts | ✅ | [backend/internal/auth/service.go](../backend/internal/auth/service.go), `auth.sessions` table | Session list + revoke endpoints. Configurable max age via tenant policy. |
| Refresh token rotation | ✅ | [backend/internal/auth/service.go](../backend/internal/auth/service.go) | Single-use refresh; reuse triggers session revocation (token-theft detection). Matches RFC 9700. |

**Module assessment:** Core password + magic-link + TOTP path is **production-shaped**. The two biggest v1.0 gaps are **passkeys** and **social OAuth exchange** — both are at "storage-ready, ceremony missing" status.

---

## 3. Qeetid ID — Identity Management

| Feature (Must-Have v1.0) | Status | Implementation | Notes / Gaps |
|---|---|---|---|
| Multi-tenancy with org isolation | ✅ | [backend/internal/tenant/](../backend/internal/tenant/), schema `tenant` | Tenant CRUD + soft-delete + plan/region fields. Every user/role/audit row carries `tenant_id`. |
| User profile management | ✅ | [backend/internal/user/](../backend/internal/user/) | CRUD, soft-delete, metadata, password endpoint. |
| User invitation | ✅ | [backend/internal/invite/](../backend/internal/invite/) | `POST /v1/invites`, accept flow creates user + assigns role atomically. Email auto-verified on accept. |
| Self-service signup | ✅ | [backend/internal/auth/service.go](../backend/internal/auth/service.go), [backend/internal/auth/http.go](../backend/internal/auth/http.go) | `POST /v1/auth/signup` public, rate-limited. Body is `{email, password, display_name?}` — no workspace details required. In one tx: auto-creates a **personal tenant** (slug `personal-<12hex>`, name `"Jane's workspace"`) + user + owner role with all permissions + role assignment + session. Email is **globally unique** (migration `0022_global_email`). User can rename their workspace or create more from the admin UI after sign-in. |
| Email verification | ✅ | [backend/internal/verification/](../backend/internal/verification/) | 6-digit code flow; sets `email_verified_at`. |
| Phone verification | ✅ | [backend/internal/verification/](../backend/internal/verification/) | Same flow for phone. |
| Password reset | ✅ | [backend/internal/recovery/](../backend/internal/recovery/) | Non-leaking start (always success); token-based confirm; revokes all sessions on reset. |
| Account deletion (self-service) | 🟡 | [backend/internal/gdpr/gdpr.go](../backend/internal/gdpr/gdpr.go) | `POST /v1/gdpr/requests` is admin-scoped; needs a self-service endpoint with 30-day grace + reauthentication. |
| GDPR data export | 🔴 | — | No export endpoint. Roadmap requires JSON/CSV download of all user data within 72 h. |
| GDPR right-to-erasure | 🟡 | [backend/internal/gdpr/gdpr.go](../backend/internal/gdpr/gdpr.go) | Request intake + grace period + status tracking implemented. **The background `Run()` purge job that actually redacts PII is scaffolded but not implemented.** Audit-trail preservation rules not encoded. |
| Consent management | 🔴 | — | No consent records table, no consent UI, no consent receipts. |
| User groups / hierarchies | ✅ | [backend/internal/group/group.go](../backend/internal/group/group.go) | Parent-child groups, member CRUD. Group-level permission grants not yet wired into RBAC effective-permissions calculation. |

**Module assessment:** Identity primitives are solid. Two compliance-driven gaps — **GDPR data export** and **consent management** — must close before SOC 2 / GDPR sign-off.

---

## 4. Qeetid Access — RBAC / ABAC

| Feature (Must-Have v1.0) | Status | Implementation | Notes / Gaps |
|---|---|---|---|
| Predefined roles | ✅ | Seed at startup of [backend/internal/rbac/rbac.go](../backend/internal/rbac/rbac.go) | Default permissions: `tenant.read/write`, `user.read/write`, `role.read/write`, `audit.read`. |
| Custom roles per tenant | ✅ | `rbac.roles`, [backend/internal/rbac/rbac.go](../backend/internal/rbac/rbac.go) | `POST /v1/tenants/{id}/roles`. |
| Role-permission binding | ✅ | `rbac.role_permissions` | Grant/revoke endpoints. |
| User-role assignment | ✅ | `rbac.user_roles` | Assign / unassign with `granted_by` tracking. |
| Effective permission resolution | ✅ | [backend/internal/rbac/rbac.go](../backend/internal/rbac/rbac.go) | UNION across roles. `GET /v1/users/{id}/tenants/{t}/permissions`. |
| Permission check API | ✅ | `GET /v1/check?user_id=&tenant_id=&permission=` | Designed as auth hot-path. |
| Permission audit logging | ✅ | [backend/internal/audit/audit.go](../backend/internal/audit/audit.go) | All RBAC mutations recorded in `audit.events`. |
| Group-based permission inheritance | 🟡 | [backend/internal/group/](../backend/internal/group/) | Groups exist; permission grants on groups not yet computed into user-effective permissions. |
| Hierarchical role inheritance | 🔴 | — | Roles are flat. No "role-of-role" relationship. |
| ABAC / fine-grained authorization | ⚪ | — | Deferred to **v1.5** per roadmap. Policy table exists ([backend/internal/policy/policy.go](../backend/internal/policy/policy.go)) but stores tenant-wide security settings, not attribute-based access policies. |

**Module assessment:** RBAC is **production-ready**. ABAC is correctly deferred. Group inheritance is the one open item before v1.0.

---

## 5. Qeetid Connect — Enterprise Federation

| Feature (Must-Have v1.0) | Status | Implementation | Notes / Gaps |
|---|---|---|---|
| OAuth 2.0 Authorization Code + PKCE | 🟡 | [backend/internal/oidc/oidc.go](../backend/internal/oidc/oidc.go) | Client registration + JWKS + userinfo + discovery work. `/oauth/authorize` and the code-grant branch of `/oauth/token` are **not implemented**. PKCE S256 validation logic missing. |
| OAuth 2.0 Client Credentials | ✅ | [backend/internal/principal/principal.go](../backend/internal/principal/principal.go) | `POST /v1/oauth/token` with service principal grant. |
| OAuth 2.0 Refresh Token | ✅ | [backend/internal/auth/service.go](../backend/internal/auth/service.go) | Rotation + reuse detection. |
| OAuth 2.0 Token Introspection (RFC 7662) | 🔴 | — | `/oauth/introspect` not implemented. |
| OAuth 2.0 Token Revocation (RFC 7009) | 🟡 | [backend/internal/auth/](../backend/internal/auth/) | Session revoke + refresh-token reuse-revoke exist but no `/oauth/revoke` endpoint that accepts an opaque token from any client. |
| OpenID Connect Core 1.0 | 🟡 | [backend/internal/oidc/oidc.go](../backend/internal/oidc/oidc.go) | Discovery + JWKS + userinfo endpoints in place. ID token issuance through the authorization code flow not yet wired. |
| OIDC Discovery 1.0 | ✅ | `GET /.well-known/openid-configuration` | Returns full metadata document. |
| OIDC Dynamic Client Registration 1.0 | ✅ | `POST /v1/oidc/clients` | Client lifecycle endpoints. |
| OIDC Foundation Basic OP certification | 🔴 | — | Certification not initiated. Required before production launch per roadmap. |
| SAML 2.0 — Service Provider | 🔴 | — | No SAML code, no `saml` schema, no metadata endpoint. |
| SAML 2.0 — Identity Provider | 🔴 | — | Same. |
| SAML 2.0 — Single Logout | 🔴 | — | Same. |
| SCIM 2.0 — `/Users` resource | 🔴 | — | No `/scim/v2/*` endpoints. Internal user CRUD exists but SCIM schema not exposed. |
| SCIM 2.0 — `/Groups` resource | 🔴 | — | Same. |
| SCIM 2.0 — `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | 🔴 | — | Same. |
| JIT provisioning (SAML + OIDC) | 🔴 | — | Depends on SAML/OIDC code flows. |
| Integration guides — Entra ID / Okta / Google Workspace | 🟡 | [frontend/apps/qeetid-docs/content/docs/authentication/sso.mdx](../frontend/apps/qeetid-docs/content/docs/authentication/sso.mdx) | Docs page exists; underlying SSO not implemented. |
| LDAP federation | ⚪ | — | Deferred to **v1.5**. |

**Module assessment:** This is the **biggest implementation gap relative to the v1.0 roadmap**. Federation is the explicit competitive wedge vs Auth0/Okta — and it's mostly absent. **10 of 16 must-haves not started.**

---

## 6. Qeetid Guard — Security

| Feature (Must-Have v1.0) | Status | Implementation | Notes / Gaps |
|---|---|---|---|
| Rate limiting per endpoint and client | 🟡 | [backend/internal/platform/ratelimit/limiter.go](../backend/internal/platform/ratelimit/limiter.go) | Per-IP token bucket on login/refresh only. Per-client and per-tenant tiers not implemented. |
| Brute force detection + exponential backoff | 🔴 | — | No per-account counter, no exponential backoff schedule. |
| Bot detection (UA, honeypot, signatures) | 🔴 | — | No detection. |
| CAPTCHA integration (hCaptcha / reCAPTCHA) | 🔴 | — | Not integrated. |
| New device alerts | 🔴 | — | Sessions table stores IP/UA; no diffing or notification. |
| DDoS protection | 🔴 | — | Expected at edge (Cloudflare/Shield). Not configured here. |
| WAF with OWASP Top 10 rules | 🔴 | — | Expected at edge. Not configured here. |
| Credential stuffing protection (HaveIBeenPwned) | 🔴 | — | Not integrated. |
| Security event webhooks | ✅ | [backend/internal/webhook/webhook.go](../backend/internal/webhook/webhook.go) | Events published to `audit.events` + outbox; webhook dispatcher delivers to subscribers with HMAC signing + retry. |
| IP allowlist / denylist | ✅ | [backend/internal/policy/policy.go](../backend/internal/policy/policy.go) | Per-tenant CIDR list; `Allowed()` method. Enforcement wiring at request entry not yet connected. |

**Module assessment:** Most Guard features are explicit gaps. Of the 8 must-haves, only **rate limit (partial)** and **security webhooks (full)** exist. The remaining six depend on either edge config (Cloudflare WAF, Shield) or third-party integration (hCaptcha, HIBP).

---

## 7. Qeetid Keys — Machine-to-Machine

| Feature (Must-Have v1.0) | Status | Implementation | Notes / Gaps |
|---|---|---|---|
| OAuth 2.0 Client Credentials | ✅ | [backend/internal/principal/principal.go](../backend/internal/principal/principal.go) | Full grant flow. |
| API key creation with scoping + expiry | ✅ | [backend/internal/apikey/apikey.go](../backend/internal/apikey/apikey.go) | `POST /v1/api-keys` returns plaintext once, stores bcrypt hash. Scopes + optional `expires_at`. |
| API key rotation with overlap window | 🟡 | Same | Multiple active keys per service-principal works; explicit "rotation flow" (create-new, sunset-old) is left to clients. |
| Environment separation (test vs live) | 🟡 | Key format prefix in [backend/internal/apikey/apikey.go](../backend/internal/apikey/apikey.go) | Format is `qk_<prefix>.<secret>`. Roadmap specifies `qf_live_…` / `qf_test_…` — a renaming + environment-aware validation is needed. |
| Service account management | ✅ | [backend/internal/principal/principal.go](../backend/internal/principal/principal.go) | Create / list / disable. |
| API key revocation (< 60 s) | ✅ | [backend/internal/apikey/apikey.go](../backend/internal/apikey/apikey.go) | Sets `revoked_at`; checked on every request. |
| API key usage logging | ✅ | [backend/internal/apikey/apikey.go](../backend/internal/apikey/apikey.go) | `last_used_at` updated async. Per-call audit event not yet emitted. |
| API key leak detection (secret scanning) | 🔴 | — | No GitHub/GitLab scanning integration. |

**Module assessment:** **6 of 8 must-haves complete**. The two gaps (env prefix naming and leak-detection program) are small-scope items.

---

## 8. Developer Experience — SDKs, API, Webhooks

| Feature (Must-Have v1.0) | Status | Implementation | Notes / Gaps |
|---|---|---|---|
| React SDK | 🔴 | — | Not present in monorepo. |
| Next.js SDK | 🔴 | — | Not present. |
| Node.js SDK | 🔴 | — | Not present. |
| Python SDK | 🔴 | — | Not present. |
| Flutter SDK | 🔴 | — | Not present. |
| Go SDK | 🔴 | — | Not present. |
| REST API documentation | ✅ | [frontend/apps/qeetid-docs/content/docs/api/](../frontend/apps/qeetid-docs/content/docs/api/) | 7 MDX pages: index, errors, pagination, users, roles, sessions, tenants. |
| OpenAPI / Swagger specification | 🟡 | [backend/api/openapi.yaml](../backend/api/openapi.yaml) | File exists at ~2.4 KB — small relative to the 80+ routes mounted in [router.go](../backend/internal/http/router.go). Needs completion. |
| Quickstart guides per SDK | 🟡 | [frontend/apps/qeetid-docs/content/docs/quickstart.mdx](../frontend/apps/qeetid-docs/content/docs/quickstart.mdx) | A generic quickstart is authored. Per-SDK guides exist as stubs at [docs/sdks/*.mdx](../frontend/apps/qeetid-docs/content/docs/sdks/). |
| Interactive API explorer | 🔴 | — | No Swagger UI / Redoc / Stoplight mounted. |
| Webhook configuration UI | 🔴 | — | Admin dashboard route is a placeholder; backend CRUD exists. |
| Webhook delivery retry with exponential backoff | ✅ | [backend/internal/webhook/webhook.go](../backend/internal/webhook/webhook.go) | `tenant.webhook_deliveries` with `next_retry_at` + attempt count. |
| Webhook signature verification (HMAC) | ✅ | [backend/internal/webhook/webhook.go](../backend/internal/webhook/webhook.go) | Per-subscription secret, HMAC-SHA256 in `X-Signature`. |
| Sandbox / test environment | 🔴 | — | No environment separation in tenant model beyond an unused `region` field. |
| Postman collection | 🔴 | — | Not present. |
| Code examples (6+ languages) | 🟡 | [frontend/apps/qeetid-docs/](../frontend/apps/qeetid-docs/) | MDX docs include code blocks; depth varies. |
| Migration guides (Firebase, Auth0, Cognito) | 🔴 | — | Not present. |
| Bulk user import API | 🔴 | — | No bulk endpoint; SCIM bulk also missing. |

**Module assessment:** The **docs experience is ahead** of the underlying APIs — docs reference SDKs that don't exist yet and endpoints that aren't implemented. This is **acceptable for a discovery/marketing phase** but will be confusing to early adopters.

---

## 9. Admin Dashboard

Reference: [Admin Dashboard Design Specification](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-3) (25+ screens). See also [frontend/apps/qeetid-admin/src/config/navigation.tsx](../frontend/apps/qeetid-admin/src/config/navigation.tsx) where the planned nav tree is already encoded.

| Screen (per Phase 3 spec) | Status | Implementation |
|---|---|---|
| Sign-in / Sign-up | ✅ | [src/routes/_auth/sign-in.tsx](../frontend/apps/qeetid-admin/src/routes/_auth/sign-in.tsx), [src/routes/_auth/sign-up.tsx](../frontend/apps/qeetid-admin/src/routes/_auth/sign-up.tsx) — form UI present. Not wired to backend `/v1/auth/login` yet (uses TanStack Form locally). |
| Organization Overview / Home | ✅ | [src/routes/_app/dashboard.tsx](../frontend/apps/qeetid-admin/src/routes/_app/dashboard.tsx) — KPI cards, login activity chart, login methods pie, MFA adoption, failed logins. **All data is mocked**, not API-backed. |
| Users Index | 🔴 | Placeholder via `/_app/$` catch-all. |
| User Detail | 🔴 | Same. |
| Roles Index | ✅ | [src/routes/_app/access/roles.tsx](../frontend/apps/qeetid-admin/src/routes/_app/access/roles.tsx) — roles list + create + per-role permission grant/revoke against `/v1/permissions` and `/v1/roles/{id}/permissions/{permId}`. |
| Role Editor | 🔴 | Same. |
| SSO Connections (SAML/OIDC) Index | 🟡 | OIDC half done at [src/routes/_app/auth/connections/oidc.tsx](../frontend/apps/qeetid-admin/src/routes/_app/auth/connections/oidc.tsx). SAML pending (backend P0-5). |
| SAML Setup Wizard (5-step) | 🔴 | Same. |
| SCIM Configuration | 🔴 | Same. |
| Audit Log Viewer | ✅ | [src/routes/_app/security/audit-logs.tsx](../frontend/apps/qeetid-admin/src/routes/_app/security/audit-logs.tsx) — paginated table with action / resource-type / actor filters wired to `GET /v1/tenants/{id}/audit`. |
| MFA Policy Configuration | 🔴 | Same. Backend `/policy` endpoints exist. |
| Password Policy | 🔴 | Same. |
| Security Events Dashboard | 🔴 | Same. |
| Applications (OAuth clients) Index | ✅ | [src/routes/_app/auth/connections/oidc.tsx](../frontend/apps/qeetid-admin/src/routes/_app/auth/connections/oidc.tsx) — list + register (public / confidential, redirect URIs, scopes) + delete. Client secret revealed once for confidential clients. |
| Application Detail | 🟡 | Inline in the list table for now; per-app detail page deferred. |
| Webhooks Index & Detail | ✅ | [src/routes/_app/developer/webhooks.tsx](../frontend/apps/qeetid-admin/src/routes/_app/developer/webhooks.tsx) — list, create (with event-picker), test, disable. Delivery-history detail tab still TBD. |
| API Keys Management | ✅ | [src/routes/_app/auth/api/keys.tsx](../frontend/apps/qeetid-admin/src/routes/_app/auth/api/keys.tsx) — list, create (with one-time raw-secret reveal + copy), scopes / expiry inputs, revoke. |
| Branding & Customization | ✅ | [src/routes/_app/settings/branding.tsx](../frontend/apps/qeetid-admin/src/routes/_app/settings/branding.tsx) — GET / PUT `/v1/tenants/{id}/branding` with logo, primary/secondary color pickers, custom domain, email-from identity, and live sign-in card preview. |
| Custom Domain Setup (4-step) | 🔴 | Same. |
| Email Template Editor | 🔴 | Same. |
| Team & Admin Roles | 🔴 | Same. |
| Tenant Profile Settings | ✅ | [src/routes/_app/settings/workspace/general.tsx](../frontend/apps/qeetid-admin/src/routes/_app/settings/workspace/general.tsx) — name / plan / region / status editor against `PATCH /v1/tenants/{id}`. Slug is shown as immutable. |
| Billing Dashboard | 🔴 | Same. No backend either. |
| Plan Upgrade Flow | 🔴 | Same. |
| Compliance Documents | 🔴 | Same. |
| Usage Analytics | 🔴 | Same. |

**Module assessment:** Frontend has the **scaffolding** (router, layout, sidebar with full nav tree, theme provider, shadcn UI library) but **content is missing for ~38 of ~40 routes**. The dashboard chart layout is polished and indicates the UI direction.

---

## 10. Developer Portal & Marketing

Reference: [Phase 3 Developer Portal Design Specification](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-3).

| Feature | Status | Implementation |
|---|---|---|
| Landing / marketing site | ✅ | [frontend/apps/qeetid-web/](../frontend/apps/qeetid-web/) — pages: `/`, `/features`, `/pricing`, `/security`, `/customers`, `/contact`. |
| Marketing sections (hero, features, integrations, testimonials, CTA) | ✅ | [src/components/marketing/sections/](../frontend/apps/qeetid-web/src/components/marketing/sections/) — 8 sections. |
| Docs landing + full-text search | ✅ | [frontend/apps/qeetid-docs/](../frontend/apps/qeetid-docs/) — Fumadocs + Flexsearch + AI search. |
| Public GitHub repos per SDK | 🔴 | — | No SDK repos exist yet. |
| Status page | 🔴 | — | Not implemented (typically external — Statuspage/Better Stack). |
| Public roadmap | 🔴 | — | Not published. |
| Public changelog | 🟡 | [frontend/apps/qeetid-docs/content/docs/changelog.mdx](../frontend/apps/qeetid-docs/content/docs/changelog.mdx) | File present, content TBD. |
| Security Trust Center | 🟡 | [frontend/apps/qeetid-web/src/app/(marketing)/security/](../frontend/apps/qeetid-web/src/app/(marketing)/security/) | Page exists; needs SOC 2/GDPR doc downloads + sub-processor list. |
| Community forum / Discord | 🔴 | — | External link; not in code. |

**Module assessment:** Marketing + docs are **far ahead of the backend**. This is a sensible bet for a pre-launch product (drives signups / waitlist) — just make sure feature claims on the marketing pages stay aligned with what actually ships.

---

## 11. Billing & Subscriptions

| Feature (Must-Have v1.0) | Status | Implementation |
|---|---|---|
| Free / Growth / Enterprise tier plumbing | 🔴 | Backend `tenant.plan` field exists (`tenant.tenants`) but no enforcement. |
| Stripe payments + subscriptions | 🔴 | No Stripe client, no webhook handler. |
| Public pricing calculator | 🟡 | [frontend/apps/qeetid-web/src/app/(marketing)/pricing/](../frontend/apps/qeetid-web/src/app/(marketing)/pricing/) — static page; no interactive calculator. |
| Real-time MAU counter | 🔴 | — |
| MAU threshold alerts (80% / 100%) | 🔴 | — |
| Self-service upgrade | 🔴 | — |
| Invoice history + payment method | 🔴 | — |
| Tax handling via Stripe Tax | 🔴 | — |
| Custom enterprise invoicing | 🔴 | — |
| Billing dashboard | 🔴 | — |
| Pricing page | ✅ | Static marketing pricing page exists. |

**Module assessment:** **Entirely unstarted** — appropriate if the product is still pre-revenue, but it is a v1.0 must-have per roadmap.

---

## 12. Infrastructure & Operations

| Feature (Must-Have v1.0) | Status | Implementation |
|---|---|---|
| 99.9% uptime SLA | ⚪ | Process / SLA contract, not code. |
| Multi-AZ redundancy | ⚪ | Deployment-config concern. Not in this repo. |
| Auto-scaling | ⚪ | Same. |
| EU / US data residency | 🟡 | `tenant.region` column exists; no actual partitioning. |
| Multi-region active-active | ⚪ | Deferred to **v1.5**. |
| Disaster recovery (RTO < 4 h, RPO 5 min) | ⚪ | Operational. |
| Daily backups (30-day retention) | ⚪ | Operational. |
| CDN integration | ✅ | Next.js apps deploy-ready behind CloudFront/Vercel CDN. |
| Secrets management (Vault / KMS) | 🟡 | [backend/internal/config/config.go](../backend/internal/config/config.go) reads from environment. No Vault/KMS adapter. |
| Monitoring (Datadog / Grafana) | 🔴 | No exporter / OTel collector wiring. |
| Centralized logging (ELK / Loki) | 🟡 | [backend/internal/platform/logger/handler.go](../backend/internal/platform/logger/handler.go) — structured slog. No shipping. |
| Distributed tracing (OpenTelemetry) | 🔴 | Not instrumented. Roadmap NFR TR-01 to TR-06 requires 100% trace coverage. |
| Incident response runbooks | 🔴 | Not in repo. |
| Containerization | ✅ | [backend/Dockerfile](../backend/Dockerfile), [backend/docker-compose.yml](../backend/docker-compose.yml). |
| CI/CD | 🔴 | No `.github/workflows/` in repo. |
| Database migrations | ✅ | [backend/migrations/](../backend/migrations/) — 21 numbered migrations. |
| Zero-downtime deployments | ⚪ | Process. |

**Module assessment:** **Local dev story is good** (Docker Compose, migrations, structured logging). **Production-grade observability and CI/CD are absent.**

---

## 13. Compliance & Trust

| Feature (Must-Have v1.0) | Status | Implementation |
|---|---|---|
| SOC 2 Type I certification | 🔴 | Not initiated. |
| GDPR — DSAR / data export | 🔴 | No export endpoint. |
| GDPR — right-to-erasure | 🟡 | [backend/internal/gdpr/](../backend/internal/gdpr/) — request layer ✅, purge runner scaffolded only. |
| GDPR — DPA template | 🔴 | Not in repo. |
| GDPR — consent records | 🔴 | Not implemented. |
| FIDO Alliance FIDO2 certification | 🔴 | Pre-req (passkey ceremony) missing. |
| OpenID Foundation Basic OP certification | 🔴 | Pre-req (auth code flow) missing. |
| Published sub-processor list | 🔴 | Not in repo. |
| PCI DSS compliance (Stripe-handled) | 🔴 | Stripe not integrated. |
| Bug bounty program | 🔴 | Not in repo / not published. |
| Vulnerability disclosure policy | 🔴 | No `SECURITY.md` at repo root. |
| Annual penetration test | ⚪ | Process. |
| Security advisory mailing list | 🔴 | Not set up. |
| Tamper-evident audit logs | 🟡 | `audit.events` is append-only; no hash-chain / cryptographic seal. |
| 12-month audit log retention | ⚪ | DB retention policy. |
| Field-level PII encryption | 🔴 | Not implemented. |
| Encryption at rest (AES-256) | ⚪ | DB / disk-level. |
| Encryption in transit (TLS 1.2+) | ⚪ | Edge / LB concern. |
| Argon2id password hashing | 🟡 | bcrypt cost=12 used; should migrate to Argon2id. |
| RS256 / ES256 JWT signing | 🟡 | Codebase supports asymmetric algs ([backend/internal/platform/tokens/jwt.go](../backend/internal/platform/tokens/jwt.go)) but production config uses HS256 with static key. |

**Module assessment:** Compliance is a **launch-blocker cluster** that needs early attention given the typical 6–12 month certification lead time.

---

## 14. Data Layer Status

Reference: [Phase 2 Database Design & Data Model](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-2).

The schemas and tables present in [backend/migrations/](../backend/migrations/) are:

| Schema | Tables | Status |
|---|---|---|
| `platform` | `outbox` | ✅ |
| `tenant` | `tenants`, `invites`, `branding`, `security_policies`, `webhook_subscriptions`, `webhook_deliveries`, `social_providers`, `groups`, `group_members` | ✅ |
| `"user"` | `users`, `email_verifications`, `phone_verifications`, `external_identities`, `purge_requests` | ✅ |
| `auth` | `password_credentials`, `sessions`, `refresh_tokens`, `password_resets`, `magic_links`, `mfa_totp`, `mfa_recovery_codes`, `passkey_credentials`, `api_keys`, `service_principals`, `oidc_clients` | ✅ |
| `rbac` | `permissions`, `roles`, `role_permissions`, `user_roles` | ✅ |
| `audit` | `events` | ✅ |
| **Missing for SAML** | `saml.*` — IdP metadata, SP metadata, assertion replay cache | 🔴 |
| **Missing for SCIM** | `scim.*` if separate from `user.*` mapping with `externalId` | 🔴 |
| **Missing for Billing** | `billing.*` — subscriptions, invoices, payment methods | 🔴 |
| **Missing for Consent** | `compliance.consents` or `user.consents` | 🔴 |

---

## 15. Protocol Conformance Snapshot

| Protocol | Status | Where |
|---|---|---|
| OAuth 2.0 Auth Code + PKCE | 🟡 | Discovery + JWKS done; `/authorize` + code-grant `/token` missing |
| OAuth 2.0 Client Credentials | ✅ | [backend/internal/principal/](../backend/internal/principal/) |
| OAuth 2.0 Refresh Token | ✅ | [backend/internal/auth/](../backend/internal/auth/) |
| OAuth 2.0 Token Introspection (RFC 7662) | 🔴 | — |
| OAuth 2.0 Token Revocation (RFC 7009) | 🟡 | session/refresh revoke only |
| OIDC Core 1.0 | 🟡 | userinfo + jwks ✅; ID token issuance ❌ |
| OIDC Discovery 1.0 | ✅ | [backend/internal/oidc/](../backend/internal/oidc/) |
| OIDC Dynamic Client Registration 1.0 | ✅ | Same |
| SAML 2.0 (SP + IdP) | 🔴 | — |
| SCIM 2.0 | 🔴 | — |
| WebAuthn Level 2 / FIDO2 | 🔴 | Ceremony missing |
| TOTP RFC 6238 | ✅ | [backend/internal/platform/totp/](../backend/internal/platform/totp/) |
| HOTP RFC 4226 | ⚪ | Not separately required (TOTP covers MVP). |
| JWT RFC 7519 / JWS RFC 7515 | 🟡 | Asymmetric support exists, HS256 in default config |
| PKCE RFC 7636 | 🔴 | No validation logic until `/authorize` ships |
| Magic Links (internal) | ✅ | [backend/internal/recovery/](../backend/internal/recovery/) |
| SMS OTP | 🟡 | Code flow ✅, MFA step-up wiring ❌, real SMS provider ❌ |
| Client Credentials + API Keys | ✅ | Both ✅ |
| DPoP RFC 9449 | ⚪ | Post-launch (3 months). |
| PAR RFC 9126 | ⚪ | Post-launch. |
| RAR RFC 9396 | ⚪ | v2.0. |
| Device Authorization RFC 8628 | ⚪ | Post-launch (6 months). |
| LDAP | ⚪ | v1.5. |

See [PROTOCOL-STATUS.md](./PROTOCOL-STATUS.md) for protocol-level detail.

---

## 16. Frontend Tech & Coverage

| Layer | Status | Reference |
|---|---|---|
| Monorepo (pnpm + Turbo) | ✅ | [frontend/package.json](../frontend/package.json), [frontend/pnpm-workspace.yaml](../frontend/pnpm-workspace.yaml) |
| Shared UI library (shadcn-style) | ✅ | [frontend/packages/qeetid-ui/](../frontend/packages/qeetid-ui/) — 20 components incl. full Sidebar system |
| Admin app — routing + layout | ✅ | [frontend/apps/qeetid-admin/src/routes/](../frontend/apps/qeetid-admin/src/routes/) — TanStack Router file-based |
| Admin app — navigation tree | ✅ | [src/config/navigation.tsx](../frontend/apps/qeetid-admin/src/config/navigation.tsx) — full nav structure defined |
| Admin app — screens implemented | 🟡 | Only `/dashboard` + `/sign-in` + `/sign-up`; 38 other routes are catch-all placeholders |
| Marketing site (Next.js) | ✅ | [frontend/apps/qeetid-web/](../frontend/apps/qeetid-web/) — all marketing pages |
| Docs site (Next.js + fumadocs) | ✅ | [frontend/apps/qeetid-docs/](../frontend/apps/qeetid-docs/) — 32 MDX pages, AI search |
| Embeddable Auth UI (white-label drop-in) | 🔴 | Phase 3 deliverable; not in code |
| Accessibility (WCAG 2.1 AA) | 🟡 | shadcn primitives are largely accessible; no formal audit |
| i18n / l10n | 🔴 | No i18n framework wired into any app |

---

## 17. Critical Path Before v1.0 Launch

In order of dependency / blocking severity, these are the items that must close before Month 15:

1. **WebAuthn passkey ceremony** — biggest UX differentiator. Integrate `github.com/go-webauthn/webauthn` into [backend/internal/passkey/](../backend/internal/passkey/).
2. **Social OAuth `/start` and `/callback`** — pick library (`golang.org/x/oauth2`) and wire Google + GitHub + Microsoft + Apple at [backend/internal/social/](../backend/internal/social/).
3. **OAuth Authorization Code + OIDC ID token issuance** — `/oauth/authorize`, PKCE validation, code storage with 60-second TTL, ID token signing.
4. **SAML 2.0 — SP + IdP** — new module + library (`crewjam/saml`). Highest enterprise-blocking item.
5. **SCIM 2.0** — `/scim/v2/Users` and `/scim/v2/Groups` with PATCH semantics; tie into existing user/group repos.
6. **Admin dashboard screens** — at minimum Users, Roles, Audit Log, Applications (OAuth clients), Webhooks, API Keys, Branding, Tenant Profile.
7. **Production JWT signing (RS256/ES256) + JWKS rotation** — replace HS256 default in [backend/internal/platform/tokens/jwt.go](../backend/internal/platform/tokens/jwt.go).
8. **Argon2id migration** for new passwords; keep bcrypt verifier for rolling rehash.
9. **Email + SMS providers** — wire SendGrid + Twilio behind the `Sender` interface.
10. **GDPR data export + consent records** — required for SOC 2 / GDPR sign-off.
11. **Stripe billing integration** — at minimum the free→growth tier flow.
12. **OpenAPI completion + Redoc / Swagger UI mount** — basic table-stakes for a developer-platform launch.
13. **CI/CD** — GitHub Actions for lint / test / build / migrate.
14. **OTel tracing + Prometheus metrics + structured log shipping**.
15. **SDK alpha for Node.js + React** — the two most-requested in the roadmap.

---

## 18. Document Status

**Author:** generated 2026-05-25 via repo analysis + Phase 1/2/3 requirement docs.
**Sources:**
- [qeetgroup/qeetid/qeetid-reqs](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs)
- This repository's [backend/](../backend/), [frontend/](../frontend/), and [backend/migrations/](../backend/migrations/).

**Update cadence:** Recommended weekly during the implementation push to v1.0.
