# Qeetid — Feature Implementation Matrix

Quick-reference table mapping every **v1.0 Must-Have feature** from [qeetid-reqs/phase-1/Qeetid — Feature Prioritization & Product Roadmap.md](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-1) to this codebase.

For module-level context and gap analysis, see:
- [IMPLEMENTATION-STATUS.md](./IMPLEMENTATION-STATUS.md)
- [PROTOCOL-STATUS.md](./PROTOCOL-STATUS.md)
- [GAP-ANALYSIS.md](./GAP-ANALYSIS.md)

**Legend:** ✅ done · 🟡 partial · 🔴 not started · ⚪ out of v1.0 scope

---

## A. Qeetid Auth (Authentication) — 14 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| A1 | Email + password sign-in | ✅ | [backend/internal/auth/service.go](../backend/internal/auth/service.go) |
| A2 | Argon2id password hashing | 🟡 | [backend/internal/platform/password/hasher.go](../backend/internal/platform/password/hasher.go) (bcrypt cost 12 — migrate to Argon2id) |
| A3 | Social login — Google | 🟡 | [backend/internal/social/social.go](../backend/internal/social/social.go) (501 on `/start`) |
| A4 | Social login — GitHub | 🟡 | Same |
| A5 | Social login — Microsoft | 🟡 | Same |
| A6 | Social login — Apple | 🟡 | Same |
| A7 | Magic links | ✅ | [backend/internal/recovery/recovery.go](../backend/internal/recovery/recovery.go) |
| A8 | Email OTP | ✅ | [backend/internal/verification/verification.go](../backend/internal/verification/verification.go) |
| A9 | Passkeys (WebAuthn/FIDO2) — register | 🔴 | [backend/internal/passkey/passkey.go](../backend/internal/passkey/passkey.go) (501) |
| A10 | Passkeys — login | 🔴 | Same |
| A11 | Cross-device passkey via QR (Hybrid) | 🔴 | — |
| A12 | MFA — TOTP | ✅ | [backend/internal/mfa/mfa.go](../backend/internal/mfa/mfa.go) |
| A13 | MFA — SMS OTP | 🟡 | Verification flow exists; not wired to MFA step-up |
| A14 | MFA — Email OTP | 🟡 | Same |
| A15 | MFA — backup / recovery codes | ✅ | [backend/internal/mfa/mfa.go](../backend/internal/mfa/mfa.go) |
| A16 | Account lockout, brute-force protection | 🟡 | [backend/internal/platform/ratelimit/limiter.go](../backend/internal/platform/ratelimit/limiter.go) (per-IP only) |
| A17 | Session management w/ timeouts | ✅ | [backend/internal/auth/](../backend/internal/auth/) |
| A18 | Refresh-token rotation + reuse detection | ✅ | [backend/internal/auth/service.go](../backend/internal/auth/service.go) |

---

## B. Qeetid ID (Identity Management) — 12 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| B1 | Multi-tenancy with org isolation | ✅ | [backend/internal/tenant/](../backend/internal/tenant/) |
| B2 | User profile management | ✅ | [backend/internal/user/](../backend/internal/user/) |
| B3 | User invitation | ✅ | [backend/internal/invite/](../backend/internal/invite/) |
| B4 | Self-service signup (org signup, signup user becomes tenant owner) | ✅ | [backend/internal/auth/service.go](../backend/internal/auth/service.go), [http.go](../backend/internal/auth/http.go) — `POST /v1/auth/signup`. Creates tenant + user + system `owner` role + assignment atomically; auto-login. |
| B5 | Email verification | ✅ | [backend/internal/verification/](../backend/internal/verification/) |
| B6 | Phone verification | ✅ | Same |
| B7 | Password reset (token + email) | ✅ | [backend/internal/recovery/](../backend/internal/recovery/) |
| B8 | Account deletion (self-service, 30-day grace) | 🟡 | [backend/internal/gdpr/](../backend/internal/gdpr/) (admin-scoped) |
| B9 | GDPR data export (JSON/CSV) | 🔴 | — |
| B10 | GDPR right-to-erasure | 🟡 | Request intake ✅; purge runner scaffolded |
| B11 | Consent management | 🔴 | No consent records table |
| B12 | User groups / hierarchies | ✅ | [backend/internal/group/](../backend/internal/group/) |

---

## C. Qeetid Access (RBAC / ABAC) — 9 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| C1 | Predefined roles | ✅ | [backend/internal/rbac/rbac.go](../backend/internal/rbac/rbac.go) seeds |
| C2 | Custom roles per tenant | ✅ | Same |
| C3 | Role-permission binding | ✅ | Same |
| C4 | User-role assignment | ✅ | Same |
| C5 | Effective permission resolution | ✅ | Same |
| C6 | Permission-check API | ✅ | `GET /v1/check` |
| C7 | Permission audit logging | ✅ | [backend/internal/audit/](../backend/internal/audit/) |
| C8 | Group-based permission inheritance | 🟡 | Group model ✅, inheritance ❌ |
| C9 | Hierarchical role inheritance | 🔴 | Roles are flat |

---

## D. Qeetid Connect (Federation) — 16 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| D1 | OAuth 2.0 Authorization Code + PKCE | 🟡 | [backend/internal/oidc/](../backend/internal/oidc/) — `/authorize` missing |
| D2 | OAuth 2.0 Client Credentials | ✅ | [backend/internal/principal/](../backend/internal/principal/) |
| D3 | OAuth 2.0 Refresh Token | ✅ | [backend/internal/auth/](../backend/internal/auth/) |
| D4 | OAuth 2.0 Token Introspection (RFC 7662) | 🔴 | — |
| D5 | OAuth 2.0 Token Revocation (RFC 7009) | 🟡 | session/refresh only |
| D6 | OIDC Core 1.0 (ID token via code flow) | 🟡 | userinfo ✅, ID token ❌ |
| D7 | OIDC Discovery 1.0 | ✅ | [backend/internal/oidc/](../backend/internal/oidc/) |
| D8 | OIDC Dynamic Client Registration | ✅ | Same |
| D9 | OIDC Foundation Basic OP certification | 🔴 | Not initiated |
| D10 | SAML 2.0 — SP | 🔴 | — |
| D11 | SAML 2.0 — IdP | 🔴 | — |
| D12 | SAML 2.0 — SLO | 🔴 | — |
| D13 | SCIM 2.0 — Users | 🔴 | — |
| D14 | SCIM 2.0 — Groups | 🔴 | — |
| D15 | SCIM 2.0 — Service config / Schemas | 🔴 | — |
| D16 | JIT provisioning (SAML + OIDC) | 🔴 | — |
| D17 | Integration guides (Entra ID / Okta / Google) | 🟡 | [docs/authentication/sso.mdx](../frontend/apps/qeetid-docs/content/docs/authentication/sso.mdx) |

---

## E. Qeetid Guard (Security) — 8 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| E1 | Rate limiting per endpoint + client | 🟡 | [backend/internal/platform/ratelimit/](../backend/internal/platform/ratelimit/) (per-IP only) |
| E2 | Brute-force detection + exponential backoff | 🔴 | — |
| E3 | Bot detection (UA, honeypot, signatures) | 🔴 | — |
| E4 | CAPTCHA integration (hCaptcha / reCAPTCHA) | 🔴 | — |
| E5 | New-device alerts | 🔴 | — |
| E6 | DDoS protection (edge) | 🔴 | Expected at Cloudflare/Shield |
| E7 | WAF (OWASP Top 10) | 🔴 | Expected at edge |
| E8 | Credential-stuffing protection (HIBP) | 🔴 | — |
| E9 | Security event webhooks | ✅ | [backend/internal/webhook/](../backend/internal/webhook/) |
| E10 | IP allowlist / denylist | 🟡 | [backend/internal/policy/](../backend/internal/policy/) (enforcement wiring missing) |

---

## F. Qeetid Keys (Machine-to-Machine) — 8 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| F1 | OAuth 2.0 Client Credentials grant | ✅ | [backend/internal/principal/](../backend/internal/principal/) |
| F2 | API key creation with scoping + expiry | ✅ | [backend/internal/apikey/](../backend/internal/apikey/) |
| F3 | API key rotation with overlap window | 🟡 | Multiple keys supported; explicit rotation flow not exposed |
| F4 | Environment separation (test vs live) | 🟡 | Single prefix `qk_…` — needs `qf_live_…` / `qf_test_…` |
| F5 | Service account management | ✅ | [backend/internal/principal/](../backend/internal/principal/) |
| F6 | API key revocation (< 60 s) | ✅ | [backend/internal/apikey/](../backend/internal/apikey/) |
| F7 | API key usage logging (per-call audit) | 🟡 | `last_used_at` ✅; per-call event ❌ |
| F8 | API key leak detection (secret scanning) | 🔴 | — |

---

## G. Developer Experience — 12 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| G1 | React SDK | 🔴 | — |
| G2 | Next.js SDK | 🔴 | — |
| G3 | Node.js SDK | 🔴 | — |
| G4 | Python SDK | 🔴 | — |
| G5 | Flutter SDK | 🔴 | — |
| G6 | Go SDK | 🔴 | — |
| G7 | REST API documentation | ✅ | [frontend/apps/qeetid-docs/content/docs/api/](../frontend/apps/qeetid-docs/content/docs/api/) |
| G8 | OpenAPI / Swagger specification | 🟡 | [backend/api/openapi.yaml](../backend/api/openapi.yaml) (minimal) |
| G9 | Quickstart guides per SDK | 🟡 | [docs/sdks/](../frontend/apps/qeetid-docs/content/docs/sdks/) (stubs) |
| G10 | Interactive API explorer | 🔴 | — |
| G11 | Webhook configuration UI | 🔴 | — |
| G12 | Webhook delivery retry (exp backoff) | ✅ | [backend/internal/webhook/](../backend/internal/webhook/) |
| G13 | Webhook signature verification (HMAC) | ✅ | Same |
| G14 | Sandbox / test environment | 🔴 | — |
| G15 | Postman collection | 🔴 | — |
| G16 | Code examples (6+ languages) | 🟡 | Inline in docs |
| G17 | Migration guides (Firebase, Auth0, Cognito) | 🔴 | — |
| G18 | Bulk user import API | 🔴 | — |

---

## H. Admin Dashboard — 17 must-haves (screens)

| # | Screen | Status | File / Location |
|---|---|:-:|---|
| H1 | Organization Overview / Home | ✅ | [src/routes/_app/dashboard.tsx](../frontend/apps/qeetid-admin/src/routes/_app/dashboard.tsx) (mocked data) |
| H2 | Users — list + create (search / edit pending) | 🟡 | [src/routes/_app/users.tsx](../frontend/apps/qeetid-admin/src/routes/_app/users.tsx) |
| H3 | Roles & permissions | 🔴 | Same |
| H4 | Applications (OAuth clients) | 🔴 | Same |
| H5 | SSO connection configuration | 🔴 | Same |
| H6 | SCIM provisioning configuration | 🔴 | Same |
| H7 | MFA policy + password policy | 🔴 | Same |
| H8 | Branding customization | ✅ | [src/routes/_app/settings/branding.tsx](../frontend/apps/qeetid-admin/src/routes/_app/settings/branding.tsx) — full form + live preview |
| H9 | Email template customization | 🔴 | Same |
| H10 | Audit log viewer | ✅ | [src/routes/_app/security/audit-logs.tsx](../frontend/apps/qeetid-admin/src/routes/_app/security/audit-logs.tsx) — paginated + filters |
| H11 | Webhook configuration | ✅ | [src/routes/_app/developer/webhooks.tsx](../frontend/apps/qeetid-admin/src/routes/_app/developer/webhooks.tsx) — list + create + test + disable |
| H12 | API key management | ✅ | [src/routes/_app/auth/api/keys.tsx](../frontend/apps/qeetid-admin/src/routes/_app/auth/api/keys.tsx) — list + create with one-time secret reveal + revoke |
| H13 | Team & admin management | 🟡 | Invitations live at [src/routes/_app/invitations.tsx](../frontend/apps/qeetid-admin/src/routes/_app/invitations.tsx); members tab pending |
| H14 | Usage / analytics dashboard | 🔴 | Same |
| H15 | Billing dashboard with plan management | 🔴 | Same |
| H16 | Compliance documents library | 🔴 | Same |
| H17 | Sign-in / sign-up screens | ✅ | [src/routes/_auth/](../frontend/apps/qeetid-admin/src/routes/_auth/) |

---

## I. Developer Portal — 10 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| I1 | Landing page with quickstart entry | ✅ | [frontend/apps/qeetid-docs/](../frontend/apps/qeetid-docs/) home |
| I2 | Full-text documentation search | ✅ | Flexsearch + AI search (OpenRouter) |
| I3 | Community forum / Discord | 🔴 | External |
| I4 | Public GitHub repos per SDK | 🔴 | SDKs don't exist yet |
| I5 | Status page | 🔴 | External |
| I6 | Public roadmap | 🔴 | — |
| I7 | Public changelog | 🟡 | [docs/changelog.mdx](../frontend/apps/qeetid-docs/content/docs/changelog.mdx) (placeholder) |
| I8 | Security Trust Center | 🟡 | [web/security/](../frontend/apps/qeetid-web/src/app/(marketing)/security/) (needs doc downloads) |
| I9 | Marketing site | ✅ | [frontend/apps/qeetid-web/](../frontend/apps/qeetid-web/) |
| I10 | Pricing page | ✅ | [web/pricing/](../frontend/apps/qeetid-web/src/app/(marketing)/pricing/) |

---

## J. Billing & Subscriptions — 11 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| J1 | Free tier (≤ 10K MAU, no CC) | 🔴 | `tenant.plan` field exists but no enforcement |
| J2 | Growth plan (per-MAU pricing) | 🔴 | — |
| J3 | Enterprise plan (custom contracts) | 🔴 | — |
| J4 | Stripe integration (payments + subs) | 🔴 | — |
| J5 | Public pricing calculator (interactive) | 🟡 | Static page only |
| J6 | Real-time MAU counter | 🔴 | — |
| J7 | MAU threshold alerts (80% / 100%) | 🔴 | — |
| J8 | Self-service upgrade | 🔴 | — |
| J9 | Invoice history + payment method | 🔴 | — |
| J10 | Tax handling (VAT, GST) via Stripe Tax | 🔴 | — |
| J11 | Custom invoicing for Enterprise | 🔴 | — |

---

## K. Infrastructure & Operations — 12 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| K1 | 99.9% uptime SLA | ⚪ | Operational |
| K2 | Multi-AZ redundancy | ⚪ | Deployment-level |
| K3 | EU / US data residency | 🟡 | `tenant.region` column; no partitioning |
| K4 | Disaster recovery (RTO < 4h, RPO 5min) | ⚪ | Operational |
| K5 | Automated daily backups (30-day retention) | ⚪ | DB-level |
| K6 | Auto-scaling | ⚪ | K8s/ECS-level |
| K7 | CDN integration | ✅ | Next.js apps |
| K8 | Secrets management (Vault / KMS) | 🟡 | Env-based; no Vault/KMS adapter |
| K9 | Monitoring & alerting (Datadog / Grafana) | 🔴 | No OTel exporter |
| K10 | Centralized logging (ELK / Loki) | 🟡 | structured slog; no shipping |
| K11 | Incident response runbooks | 🔴 | Not in repo |
| K12 | 24/7 on-call | ⚪ | Operational |

---

## L. Compliance & Trust — 11 must-haves

| # | Feature | Status | File / Location |
|---|---|:-:|---|
| L1 | SOC 2 Type I | 🔴 | Not initiated |
| L2 | GDPR compliance from Day 1 | 🟡 | Erasure request layer ✅; export ❌; consent ❌ |
| L3 | FIDO Alliance FIDO2 certification | 🔴 | Passkey ceremony missing |
| L4 | OpenID Foundation certification (Basic OP) | 🔴 | Code flow missing |
| L5 | DPA template (public) | 🔴 | Not in repo |
| L6 | Published sub-processor list | 🔴 | — |
| L7 | PCI DSS (Stripe-handled) | 🔴 | Stripe not integrated |
| L8 | Bug bounty program | 🔴 | Not published |
| L9 | Vulnerability disclosure policy | 🔴 | No SECURITY.md |
| L10 | Annual penetration test | ⚪ | Process |
| L11 | Security advisory mailing list | 🔴 | Not set up |

---

## Summary

| Category | ✅ | 🟡 | 🔴 | ⚪ | Total |
|---|---:|---:|---:|---:|---:|
| A. Auth | 7 | 7 | 3 | 0 | 18 (incl. 4 sub-items) |
| B. Identity | 8 | 3 | 2 | 0 | 13 |
| C. Access | 7 | 1 | 1 | 0 | 9 |
| D. Federation | 4 | 3 | 9 | 0 | 16 |
| E. Guard | 1 | 2 | 7 | 0 | 10 |
| F. Keys | 4 | 3 | 1 | 0 | 8 |
| G. DX | 4 | 4 | 10 | 0 | 18 |
| H. Admin Dashboard | 2 | 0 | 15 | 0 | 17 |
| I. Dev Portal | 4 | 2 | 4 | 0 | 10 |
| J. Billing | 0 | 1 | 10 | 0 | 11 |
| K. Infra/Ops | 1 | 2 | 3 | 6 | 12 |
| L. Compliance | 0 | 1 | 9 | 1 | 11 |
| **TOTAL** | **42 (26%)** | **29 (18%)** | **74 (45%)** | **7 (4%)** | **163** |

(Counts diverge slightly from the 140 must-have headline because some headline items expand into sub-features — e.g. "social login" is one roadmap line but four protocol implementations.)
