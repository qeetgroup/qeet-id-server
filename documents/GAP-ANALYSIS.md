# Qeetid — Gap Analysis & v1.0 Punch List

Prioritized list of work required to move from current state to **v1.0 "Foundation"** launch readiness. Each item links to the relevant requirement and the current code location (where partial work exists).

For full context see [IMPLEMENTATION-STATUS.md](./IMPLEMENTATION-STATUS.md), [FEATURE-MATRIX.md](./FEATURE-MATRIX.md), [PROTOCOL-STATUS.md](./PROTOCOL-STATUS.md).

---

## Priority Tiers

- **P0 — Launch blocker.** Without this, v1.0 cannot ship. Enterprise sales, compliance certs, or core security are blocked.
- **P1 — Launch differentiator.** Roadmap calls it MVP-must; missing it materially weakens the launch story (passkeys, social login, dashboard usability).
- **P2 — Catch-up.** Should be in v1.0 per roadmap but won't block production if delayed by a few weeks.
- **P3 — Polish / post-launch acceptable.** Roadmap places in v1.0 but pragmatically can slide to v1.1.

---

## P0 — Launch Blockers (close before any pilot customer goes live)

### P0-1 — Replace HS256 default with RS256/ES256 + JWKS rotation

- **Why:** OIDC Foundation Basic OP certification requires asymmetric signing; resource servers cannot verify HS256 without shared secret; static key set has no rotation story.
- **Where:** [backend/internal/platform/tokens/jwt.go](../backend/internal/platform/tokens/jwt.go), [backend/internal/oidc/oidc.go](../backend/internal/oidc/oidc.go).
- **Done when:** Two active RS256 (or ES256) keys, 90-day rotation, `kid` in every JWT header, `/jwks.json` reflects current key set, retired keys retained 24h.

### P0-2 — Migrate password hashing from bcrypt to Argon2id

- **Why:** Compliance Requirements Matrix names Argon2id explicitly; Phase 1 Protocol Requirements §JWT and §M2M assume Argon2id storage.
- **Where:** [backend/internal/platform/password/hasher.go](../backend/internal/platform/password/hasher.go).
- **How:** Add Argon2id hasher; keep bcrypt verifier for legacy hashes; on successful bcrypt login, rehash to Argon2id (transparent rolling rehash).
- **Done when:** All new password writes are Argon2id; legacy bcrypt verification retained; no behavioral change to clients.

### P0-3 — Implement WebAuthn passkey ceremonies

- **Why:** Roadmap names "passkeys-first UX" as the primary v1.0 differentiator. FIDO Alliance FIDO2 Server Certification is a launch prerequisite.
- **Where:** [backend/internal/passkey/passkey.go](../backend/internal/passkey/passkey.go) (currently returns 501 for all four endpoints).
- **Library:** `github.com/go-webauthn/webauthn`.
- **Done when:** `/v1/passkeys/register/begin`, `/register/finish`, `/login/begin`, `/login/finish` all functional; conditional-UI autofill works in admin sign-in; FIDO MDS3 attestation verification in place.

### P0-4 — Implement OAuth 2.0 Authorization Code + OIDC ID-token issuance

- **Why:** OIDC Foundation Basic OP certification + every meaningful SSO flow needs `/authorize` + code-grant `/token`.
- **Where:** new endpoints under [backend/internal/oidc/](../backend/internal/oidc/). Schema migration for `auth.authorization_codes` table.
- **Done when:** `GET /oauth/authorize` (with PKCE S256 validation, exact redirect URI match, state validation, iss param), `POST /oauth/token` code-grant branch returning ID token + access token + refresh token, `/userinfo` returns full claim set per scope.

### P0-5 — Implement SAML 2.0 SP (then IdP)

- **Why:** Enterprise customers (the entire Qeetid Connect product line) cannot federate without it. Roadmap lists 3 SAML must-haves at v1.0.
- **Where:** new module `backend/internal/saml/`, new schema `saml` for replay cache + IdP certs.
- **Library:** `github.com/crewjam/saml`.
- **Done when:** SP-initiated SSO from Entra ID, Okta, Google Workspace works end-to-end. SP metadata endpoint `/saml/metadata` serves valid XML. Single Logout (SP-init + IdP-init) works.

### P0-6 — Implement SCIM 2.0 User + Group endpoints

- **Why:** SCIM provisioning is the enterprise "auto-deprovision when HR fires someone" hard requirement. The whole `Qeetid Connect` value prop rests on it.
- **Where:** new module `backend/internal/scim/` that wraps existing user/group repos.
- **Done when:** `/scim/v2/Users`, `/scim/v2/Users/{id}`, `/scim/v2/Groups`, `/scim/v2/Groups/{id}`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/ResourceTypes`, `/scim/v2/Schemas` all functional with PATCH semantics for the 8 lifecycle operations. Okta SCIM validator passes. Deprovisioning terminates sessions within 60s.

### P0-7 — Real email + SMS providers wired in

- **Why:** Magic links, OTP codes, password resets, invites all rely on the `Sender` interface which is currently `LogSender`. Nothing leaves the server.
- **Where:** [backend/internal/platform/notifier/notifier.go](../backend/internal/platform/notifier/notifier.go).
- **Done when:** SendGrid (or AWS SES) wired for email, Twilio (or AWS SNS) for SMS, with envar-based config. Templates rendered per tenant branding.

### P0-8 — GDPR data export + complete the erasure runner

- **Why:** GDPR mandatory at launch (Compliance Requirements Matrix). The 30-day-grace erasure scheduler exists at [backend/internal/gdpr/gdpr.go](../backend/internal/gdpr/gdpr.go) but the actual purge `Run()` is a no-op.
- **Done when:** `POST /v1/users/{id}/export` returns JSON+CSV of all user-owned data within 72 h SLA; `Run()` redacts PII per spec while preserving audit-trail references.

### P0-9 — Production observability: OTel tracing + Prometheus metrics + log shipping

- **Why:** SOC 2 audit + NFR §Observability TR-01 to TR-06 require 100% trace coverage on customer-facing requests; AL-01 to AL-05 alert classes need backing metrics.
- **Where:** new middleware in [backend/internal/platform/httpx/](../backend/internal/platform/httpx/). Add OTel SDK, Prom client.
- **Done when:** Every HTTP request emits a trace, key business metrics (logins, MFA challenges, token issuance, webhook deliveries) emit counters/histograms, logs ship to Loki/CloudWatch.

### P0-10 — CI/CD pipeline

- **Why:** Releases must be hands-off (NFR OP-01 to OP-08).
- **Done when:** GitHub Actions workflow: `go test ./...`, `golangci-lint`, container image build, migration smoke test, frontend build. Required on every PR to `main`.

---

## P1 — Launch Differentiators

### P1-1 — Social login OAuth `/start` and `/callback`

- **Where:** [backend/internal/social/social.go](../backend/internal/social/social.go) (currently 501).
- **Library:** `golang.org/x/oauth2`.
- **Providers:** Google, GitHub, Microsoft, Apple — all four are v1.0 must-haves.
- **Done when:** End-to-end social signup creates a user, links external identity in `user.external_identities`, issues Qeetid session.

### P1-2 — Admin Dashboard — implement the 8 most-needed screens

Priority order based on actual operator workflow:

1. **Users** index + detail — list/search/edit; drives every other workflow.
2. **Audit Log Viewer** — required for compliance demos.
3. **API Keys Management** — every dev-portal user needs this.
4. **Applications (OAuth clients)** index + detail — required for any integration setup.
5. **Roles & permissions** editor — required for any enterprise pilot.
6. **Branding** editor with live preview.
7. **Webhooks** index + delivery history.
8. **Tenant Profile** settings — surface the existing `/v1/tenants/{id}` PATCH.

The scaffolding (router, layout, sidebar, shadcn UI, navigation tree) is already in place at [frontend/apps/qeetid-admin/](../frontend/apps/qeetid-admin/). Each screen is mostly forms + tables against existing backend endpoints.

### P1-3 — OAuth 2.0 Token Introspection + Revocation public endpoints

- `POST /oauth/introspect` (RFC 7662) — backend has all data, needs the endpoint shim.
- `POST /oauth/revoke` (RFC 7009) — same.

### P1-4 — Per-account lockout & exponential backoff

- **Where:** new logic alongside [backend/internal/auth/service.go](../backend/internal/auth/service.go).
- **Done when:** Five consecutive failed password attempts → temporary lock per Phase 1 spec; backoff exposed via `Retry-After`.

### P1-5 — HaveIBeenPwned password check on registration + reset

- **Where:** [backend/internal/recovery/recovery.go](../backend/internal/recovery/recovery.go), [backend/internal/user/](../backend/internal/user/).
- **Done when:** k-anonymous HIBP API call before accepting a new password.

### P1-6 — CAPTCHA on signup + login (hCaptcha primary)

- **Done when:** Config option per tenant; backend verifies hCaptcha response token; frontend renders widget on `/sign-in`, `/sign-up`, and recovery flows.

### P1-7 — Email-OTP / SMS-OTP wired into MFA step-up at login

- **Where:** [backend/internal/mfa/mfa.go](../backend/internal/mfa/mfa.go).
- **Done when:** Login flow detects MFA-enabled user, branches to OTP challenge, accepts code, issues session.

### P1-8 — Webhook configuration UI in admin dashboard

- **Where:** new route in [frontend/apps/qeetid-admin/](../frontend/apps/qeetid-admin/). Backend already has `POST/GET/DELETE /v1/webhooks` and `tenant.webhook_deliveries` history.
- **Done when:** Subscribe, view deliveries, replay a delivery, rotate signing secret.

### P1-9 — Stripe billing — minimum viable subscription flow

- **Where:** new module `backend/internal/billing/`, new migration `billing.*`.
- **Done when:** Free→Growth upgrade via Stripe Checkout; MAU metering on dashboard; webhook handler updates `tenant.plan`.

### P1-10 — Bulk user import API

- **Done when:** `POST /v1/users/bulk` accepting newline-delimited JSON; preserves prior password hashes (Firebase, Auth0, Cognito formats); rate-limited.

---

## P2 — Catch-up

| Item | Where | Notes |
|---|---|---|
| Complete OpenAPI spec | [backend/api/openapi.yaml](../backend/api/openapi.yaml) | Currently ~2.4 KB; needs all 80+ endpoints documented. |
| Mount Swagger UI / Redoc | new docs route | Use generated spec. |
| Postman collection | docs or `/tools/` | Generate from OpenAPI. |
| Per-tenant + per-client rate limits | [backend/internal/platform/ratelimit/](../backend/internal/platform/ratelimit/) | Today is per-IP only. |
| Group-based permission inheritance | [backend/internal/group/](../backend/internal/group/) + [backend/internal/rbac/](../backend/internal/rbac/) | Roll up group memberships into effective-permission query. |
| New-device email alert | [backend/internal/auth/service.go](../backend/internal/auth/service.go) | Diff session IP/UA against history, send email. |
| Tamper-evident audit log (hash chain) | [backend/internal/audit/audit.go](../backend/internal/audit/audit.go) | Add `prev_hash` column; cryptographic seal. |
| Consent records | new module | DPIA/GDPR Article 7. |
| Per-call API-key audit events | [backend/internal/apikey/](../backend/internal/apikey/) | Emit `audit.events` row per usage. |
| API key prefix rename (`qf_live_` / `qf_test_`) | [backend/internal/apikey/](../backend/internal/apikey/) | Plus env separation enforcement. |
| Custom domain support | [backend/internal/branding/](../backend/internal/branding/) + new ACM/Let's-Encrypt automation | Roadmap H2 (admin dashboard). |
| Email template editor | new admin route | Backend stores templates in `tenant.branding.settings`. |

---

## P3 — Polish / Post-launch acceptable

| Item | Notes |
|---|---|
| SDKs — Node.js, React, Python first (others can follow) | Code-gen from OpenAPI feasible. |
| Migration guides (Firebase, Auth0, Cognito) | Pure docs work. |
| Status page (Statuspage / Better Stack) | External service. |
| Public roadmap page | Marketing site. |
| Public changelog | [docs/changelog.mdx](../frontend/apps/qeetid-docs/content/docs/changelog.mdx) already exists. |
| Bug bounty (HackerOne / Intigriti) | Process + page. |
| Security advisory list | Mailing list + SECURITY.md. |
| i18n on hosted auth pages | Roadmap requires 10 languages at launch — substantial work, but no v1.0 customer truly blocks on this. |
| WCAG 2.1 AA formal audit | shadcn primitives are largely compliant; needs verification. |
| AES-256 encryption of MFA TOTP secret at rest | [backend/internal/mfa/mfa.go](../backend/internal/mfa/mfa.go) — currently plaintext. |
| TOTP replay-prevention `used_codes` cache | [backend/internal/platform/totp/](../backend/internal/platform/totp/) |
| Email-enumeration hardening audit | Confirm `/login`, `/recovery/password/start`, `/invite/accept` all return constant-time generic responses. |
| TLS 1.3 enforcement | Edge config (Cloudflare). |

---

## P3 — Already deferred to v1.5 / v2.0 per roadmap

These should NOT be worked on for v1.0:

- ABAC / fine-grained authorization → v1.5
- LDAP federation → v1.5
- ML-based bot detection → v1.5
- Multi-region active-active → v1.5
- HIPAA BAA → v1.5
- DPoP (RFC 9449) → 3 months post-launch
- PAR (RFC 9126) → 3 months post-launch
- Device Authorization Grant (RFC 8628) → 6 months post-launch
- SCIM Bulk Operations → 6 months post-launch
- OIDC Back-Channel + Front-Channel Logout → 6 months post-launch
- FAPI 2.0 → v2.0
- RAR (RFC 9396) → v2.0
- ISO 27001 → v2.0
- On-premise deployment → v2.0
- 99.99% uptime SLA → v2.0
- SPIFFE / SPIRE → v2.0
- FedRAMP → v3.0

---

## Suggested Sprint Sequencing (12 weeks to v1.0 freeze)

| Weeks | Focus | Items |
|---|---|---|
| 1–2 | Hardening foundation | P0-1, P0-2, P0-7, P0-10 |
| 3–4 | Passkey + Social login | P0-3, P1-1 |
| 5–6 | OAuth/OIDC code flow | P0-4, P1-3, plus dashboard "Applications" screen |
| 7–8 | SAML SP (then IdP) | P0-5, plus dashboard "SSO connections" |
| 9 | SCIM | P0-6 |
| 10 | GDPR completion + observability | P0-8, P0-9 |
| 11 | Admin dashboard (8 screens) | P1-2 |
| 12 | Billing + bug-bash + cert prep | P1-9, P1-4..P1-8 |

Certifications (FIDO2, OIDC Basic OP, SOC 2 Type I) should kick off in parallel from week 1 — they each take 8–12 weeks of audit-firm wall-clock time.

---

## Document Status

Generated 2026-05-25. Update as items close.
