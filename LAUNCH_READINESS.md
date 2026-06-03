# Qeet ID — Launch Readiness, Pending Work & Roadmap

> **What this is.** A complete, end‑to‑end / layer‑by‑layer / domain‑by‑domain audit of Qeet ID (backend + 3 frontends), the full punch‑list of everything still pending before a **proper, hardened GA**, a sequenced plan to make Qeet ID a first‑class identity **provider**, a **quantum‑secure** roadmap, the production‑readiness gates, and where the product can differentiate against today's identity platforms.
>
> **Audited:** 2026‑06‑02 · branch `develop` · graphify graph commit `53459009` **and** a direct read of the source. **Target launch:** **July 2026** (timeline relaxed from June 5 — so the plan below assumes we do everything properly, with no "ship as beta / cut corners" compromises).
>
> **Method:** static audit of `backend/internal/*` (32 domains, 40 migration pairs) + `frontend/apps/*` (3 apps) + router/OpenAPI wiring + the existing graph report, plus current (2025–2026) web research on identity‑platform gaps and post‑quantum cryptography (sources in §14). Claims that come from code link the file:line.

---

## 0. Verdict (July timeline)

**Qeet ID is much further along than its own docs admit.** The `CHANGELOG.md` "Known gaps" list is **stale** — it still claims passkeys/social return `501`, SAML/SCIM are "not implemented," and billing is "absent." None of that is true: passkey, social OAuth, SAML 2.0 (SP), SCIM 2.0, OIDC `/authorize`+`/token`+`/userinfo`+JWKS, a secrets vault, IP allow‑lists, LDAP, retention, and an internal billing model are all **implemented and wired** (`backend/internal/http/router.go`).

So this is **not** a "build the features" project — it's a **"finish the provider story + harden for production + verify everything"** project. With a July runway, the right goal is a **clean, conformance‑tested, properly‑secured GA**, not a flag‑hidden beta. This document is the master list to get there. Nothing in §3 is hand‑wavy — every blocker has a file reference and a definition of done.

**The three things that most define the gap:**
1. 🔴 **Tokens are signed HS256 (symmetric)** → JWKS can't expose a verifiable public key → external apps can't verify Qeet‑issued tokens → **Qeet ID can't act as an OIDC provider yet** (`backend/internal/platform/tokens/jwt.go:87`).
2. 🔴 **OIDC `/authorize` ships no hosted login/consent UI** — it requires a pre‑authenticated user with a pre‑existing consent row (`backend/internal/oidc/oidc.go:115`).
3. 🔴 **Email & SMS don't send** — `LogSender` only (`backend/internal/platform/notifier/notifier.go`).

---

## 1. What's actually DONE (the real baseline)

**Backend** (Go modular monolith; `go.mod` = 1.25.0; chi v5; pgx v5; 40 migration pairs; outbox + hash‑chained audit):

- **Auth & sessions** — login / refresh / logout, session list + per‑session revoke, **refresh‑token rotation with reuse/theft detection** (`backend/test/integration/flows_test.go` `TestAuthSignupLoginRefreshReuse`).
- **Tenancy** — multi‑tenant by `tenant_id` everywhere; tenant‑less signup → create‑workspace‑as‑owner → `POST /v1/auth/switch-tenant` re‑mints a tenant‑scoped token.
- **RBAC + ABAC `policy` + per‑tenant `authpolicy`** (password rules + allowed login methods).
- **MFA** — TOTP + bcrypt‑hashed recovery codes.
- **Passkeys / WebAuthn** — registration + login ceremonies (`TestPasskeyBeginCeremonies`).
- **Social login** — generic OIDC‑discovery providers per tenant (`TestSocialOIDCLoginFlow`).
- **OIDC provider endpoints** — `/oauth/authorize`, `/oauth/token-code`, `/oauth/userinfo`, discovery, JWKS, dynamic client registration, consent‑grant listing, auth‑code + PKCE, refresh rotation (`TestOIDCRefreshTokenRotateReuse`). *(Gaps in §3.)*
- **SAML 2.0 (SP side)** — metadata, SSO redirect, ACS, code exchange + admin CRUD (`backend/internal/saml/saml.go`).
- **SCIM 2.0** — `ServiceProviderConfig`, `ResourceTypes`, `Schemas`, **Users** CRUD+PATCH, per‑tenant bearer + token rotate/revoke (`backend/internal/scim/scim.go:284`).
- **LDAP** bind login + connection CRUD/test.
- **API keys** (`qk_…`, shown once) + **machine/service principals** via `client_credentials`.
- **Webhooks** — HMAC‑signed, persisted‑before‑send outbox, retries (`backend/internal/webhook/webhook.go`).
- **Audit** — append‑only, hash‑chained, deterministic canonicalization (unit‑tested).
- **Secrets vault** — per‑tenant AES‑256‑GCM, audited reveal (`backend/internal/secret/secret.go`).
- **GDPR export/erasure, retention auto‑purge, IP allow/deny, branding, email‑template overrides, invites, verification, groups, analytics, internal billing**.
- **Platform** — CSRF (cookie‑bearing; bearer bypass), security headers, in‑flight tracking, per‑IP/tenant/user/api‑key rate limiting, keyset paging, redacting logger, health `/healthz` `/readyz`.
- **CI** — `ci.yml` + CodeQL; multi‑stage **distroless** Docker image.

**Frontend:**
- **`qeetid-admin`** (Vite + TanStack Router, React 19) — ~**70 real route files** (the IAM control plane is largely complete); catch‑all `_app/$.tsx` renders "Coming soon" for any nav target without a screen.
- **`qeetid-web`** (Next.js 16) — **marketing site** (not the end‑user login app).
- **`qeetid-docs`** (Next.js + fumadocs) — ~32 MDX pages + AI search.
- **`@qeetrix/ui`** wired into admin (85 files) + web (29 files).

---

## 2. Severity legend

| Tag | Meaning |
| :-- | :-- |
| 🔴 **P0** | Must ship for a proper public‑provider GA. |
| 🟠 **P1** | Required for a credible GA / operability; in scope for July. |
| 🟡 **P2** | Quality, DX, and competitive features; some in July, rest fast‑follow. |
| 🟣 **FUTURE** | Strategic (full PQC token signing, ReBAC, NHI/agents) — deliberately post‑GA. |

---

## 3. Master gap inventory

### 3.1 🔴 P0 — provider completeness & core security

| # | Gap | Evidence | Definition of done |
| :-- | :-- | :-- | :-- |
| P0‑1 | **HS256 symmetric token signing.** | `tokens/jwt.go:87` | RS256/ES256 asymmetric signing; **public** JWK at `/.well-known/jwks.json`; keep the existing `kid`/primary/retired/grace machinery but make **algorithm a property of the key**; documented operational key‑rotation runbook (generate → publish → promote → retire). |
| P0‑2 | **No hosted login + consent UI** for OIDC. | `oidc/oidc.go:115‑117` | A Qeet‑hosted login page + scope‑consent screen; consent persisted on approve; supports the full redirect → authenticate → consent → code flow for a third‑party RP. |
| P0‑3 | **Email & SMS are `LogSender`.** | `platform/notifier/notifier.go` | Real providers behind the `Sender` interface (SMTP/SendGrid/SES; Twilio/SNS); config vars added; **deliverability**: dedicated sending domain, SPF/DKIM/DMARC, bounce/complaint handling, retry/queue. |
| P0‑4 | **Insecure dev defaults not gated for prod.** `JWT_SECRET=please-change-me`; `.env.example` ships `CSRF_DISABLED=true`, `AUTH_DEV_TRUST_HEADERS=true`. | `backend/.env.example`, `internal/config/config.go` | Boot refuses in non‑dev if `JWT_SECRET` is default/weak, `CSRF_DISABLED`/`AUTH_DEV_TRUST_HEADERS` set, `ALLOWED_ORIGINS` empty, or `WEBAUTHN_RP_*` unset. |
| P0‑5 | **bcrypt, not Argon2id.** | `platform/password/hasher.go` | Argon2id (tuned params) + verify‑old‑bcrypt‑then‑rehash‑on‑login migration path. |
| P0‑6 | **Secrets‑vault key derived from `JWT_SECRET`.** | `secret/secret.go:4‑6` | Key sourced from real KMS (AWS/GCP KMS or Vault), envelope encryption, independent rotation. |
| P0‑7 | **No OAuth token revocation (RFC 7009) or introspection (RFC 7662).** | none found in `oidc`/`principal` | Add `/oauth/revoke` + `/oauth/introspect` (or signed/JWKS verification path) so RPs and resource servers can validate/kill tokens. |
| P0‑8 | **No per‑account brute‑force / lockout.** Only an IP rate limiter (5 r/s burst 20). | `internal/http/router.go:142`; nothing in `auth`/`recovery` | Per‑account failed‑attempt throttling + temporary lockout + alerting; protects against credential stuffing (a top real‑world attack, §10). |
| P0‑9 | **No conformance runs / RP‑initiated logout.** | `oidc/oidc.go` | Pass OpenID Foundation Basic+Config OP; add `end_session`/RP‑initiated logout, `prompt`/`max_age`/`nonce`/`at_hash`; SCIM 2.0 and SAML interop verified against Entra ID / Okta / Google Workspace. |

### 3.2 🟠 P1 — credible GA & operability

| # | Gap | Evidence | Done means |
| :-- | :-- | :-- | :-- |
| P1‑1 | **Rate limiting is in‑memory per process.** | `platform/ratelimit/limiter.go` ("Swap for Redis…") | Shared store (Redis) so limits hold across replicas before scaling >1 instance. |
| P1‑2 | **No observability** — 0 OTel/Prometheus imports, no `/metrics`. | grep | OTel traces + Prometheus metrics + RED/USE dashboards; deepen `/readyz` (DB + outbox lag); security‑event logging/alerts (failed logins, lockouts, key rotations). |
| P1‑3 | **SDKs documented but not shipped.** 11 docs pages teach `@qeetid/sdk` / `pip install qeetid`; no package in `frontend/packages/`. | `qeetid-docs` | Ship a real TS SDK (+ Python), generated from the OpenAPI; or relabel docs honestly until shipped. |
| P1‑4 | **Single `openapi.yaml`** for 32 domains. | `backend/api/` (1 spec + postman) | Verify it covers every mounted route; it's the source of truth for SDK generation + conformance. |
| P1‑5 | **SAML is SP‑only — no IdP issuance.** | `saml/saml.go:2‑3` | Add SAML **IdP** side (sign assertions with the asymmetric key) so Qeet can be an SSO **source** for downstream apps (part of "be a provider"). |
| P1‑6 | **SCIM exposes Users, not Groups.** | `scim/scim.go:284‑294` (Users only) | Add `/scim/v2/Groups` CRUD+PATCH + membership; the CHANGELOG promised Users **+ Groups**. |
| P1‑7 | **No IaC / deploy manifests / DR.** Only Dockerfile + local compose. | `find` (no k8s/helm/tf) | Deployment target (k8s/Helm or chosen PaaS), DB backups + PITR, documented restore/DR drill, **zero‑downtime migration** process (40 paired migrations exist; need a rollout playbook). |
| P1‑8 | **Token storage / XSS exposure review.** Tokens returned in JSON body (`refresh_token`, `session_id`). | `auth/http.go:91‑92` | Confirm the frontend does **not** put tokens in `localStorage`; offer an HttpOnly‑cookie session mode; document the chosen token model + CSP. |
| P1‑9 | **Test coverage holes on high‑blast‑radius paths.** No unit tests for `rbac` decision logic, `policy`, `gdpr` erasure, `mfa`, `recovery`, `verification`, `oidc`, `passkey`, `social`. | test‑file census | Unit suites for the **authZ decision matrix** and **GDPR erasure correctness** first; then the rest. (Integration tests cover several happy paths already.) |
| P1‑10 | **MFA breadth.** TOTP + recovery codes only. | `mfa/mfa.go` | Add WebAuthn‑as‑second‑factor, step‑up/adaptive MFA, and (once P0‑3 lands) email/SMS OTP factor. |
| P1‑11 | **Billing has no payment processor.** Internal model only. | `billing/billing.go:1‑3` | If charging at GA: integrate Stripe/PSP (checkout, webhooks, dunning, MAU metering). If invoice‑only at GA: label it so. |
| P1‑12 | **Email/UI localization (i18n).** | — | At minimum templatized, locale‑aware transactional emails; admin/login i18n scaffold. |
| P1‑13 | **Accessibility (WCAG 2.2 AA).** | — | a11y audit of admin + the new hosted login/consent (keyboard, contrast, ARIA, screen‑reader). |
| P1‑14 | **Go version drift.** Dockerfile `FROM golang:1.26-alpine`; `go.mod` = 1.25.0; `EXPOSE 4000` vs compose `:4001`. | `backend/Dockerfile`, `backend/go.mod` | Pin a single Go version + consistent port; reproducible builds. |

### 3.3 🟡 P2 — quality & competitive features

- **Breached‑password check** (HaveIBeenPwned k‑anonymity) at signup/reset — none today.
- **Anomaly detection** — impossible‑travel, new‑device/new‑geo alerts, suspicious‑login emails.
- **Passkey account‑recovery flow** — the industry's unsolved UX (recovery codes + verified fallback + device re‑enrollment).
- **Trusted devices / device management** UI.
- **Bulk user import + password‑hash importer** (bcrypt/argon2/scrypt/PBKDF2) — the migration wedge against incumbents (§10).
- **Per‑tenant rate‑limit configuration** UI — the admin "Per‑tenant rate limits coming soon" (`qeetid-admin/.../security/rate-limits.tsx:115`).
- **Data residency / multi‑region** routing per tenant.
- **Tenant offboarding / full export & delete.**
- **Sweep the admin catch‑all** (`_app/$.tsx`) — build or hide every nav target that currently falls through to "Coming soon."

### 3.4 🟣 FUTURE — strategic (see §9, §10)

- Full **PQC token signing (ML‑DSA / hybrid)**; **PQC passkeys** as authenticators ship.
- **ReBAC / Zanzibar‑style** relationship authorization.
- **Non‑human / AI‑agent identity** as first‑class principals.

---

## 4. Backend domain‑by‑domain matrix

Status: ✅ done & wired · ⚠️ has a P0/P1 gap · 🧪 needs tests.

| Domain | Status | Notes / pending |
| :-- | :-- | :-- |
| `auth` | ✅ | Login/refresh/logout, session revoke, rotation+theft. Add per‑account lockout (P0‑8); confirm token‑storage model (P1‑8). |
| `tenant` | ✅ 🧪 | Add isolation‑invariant tests. |
| `user` | ✅ | CRUD/profile/metadata; bulk import (P2). |
| `rbac` | ⚠️ 🧪 | **AuthZ decision logic untested** — highest risk (P1‑9). |
| `policy` (ABAC) | ⚠️ 🧪 | Decision‑matrix tests needed. |
| `authpolicy` | ✅ | Password rules + login methods. |
| `mfa` | ⚠️ | TOTP+recovery only; breadth (P1‑10); tests. |
| `passkey` | ✅ 🧪 | Negative‑path tests; PQC‑authenticator readiness (§9). |
| `social` | ✅ | Generic OIDC providers — seed of "custom connector" (§8‑B). |
| `oidc` | ⚠️ | **P0‑1/2/7/9**: asymmetric signing, hosted login/consent, revoke/introspect, conformance + logout. |
| `saml` | ⚠️ | **SP only — add IdP issuance** (P1‑5). |
| `scim` | ⚠️ | Users complete; **add Groups** (P1‑6). |
| `ldap` | ✅ | Bind login + CRUD + test‑bind. |
| `apikey` | ✅ 🧪 | Add tests. |
| `principal` | ✅ | Machine identities — foundation for NHI/agents (§10). |
| `webhook` | ✅ | HMAC + outbox + retries. Strong. |
| `audit` | ✅ | Hash‑chained, verifier‑tested. |
| `secret` | ⚠️ | AES‑GCM but **key from JWT secret → KMS** (P0‑6). |
| `gdpr` | ⚠️ 🧪 | **Erasure correctness untested** — compliance risk (P1‑9). |
| `retention` | ✅ | Auto‑purge soft‑deleted users. |
| `ipallow` | ✅ | CIDR allow/deny + check. |
| `branding` | ✅ 🧪 | Tests. |
| `emailtemplate` | ✅ | Needs real sender to matter (P0‑3). |
| `invite` | ✅ | Needs real sender (P0‑3). |
| `verification` | ⚠️ 🧪 | Needs sender; tests. |
| `recovery` | ⚠️ 🧪 | Needs sender; add lockout/anti‑enumeration; tests. |
| `group` | ✅ | Audited membership (integration‑tested). |
| `billing` | ⚠️ | Internal model; no PSP (P1‑11). |
| `analytics` | ✅ | Overview/KPIs. |
| `platform/*` | ⚠️ | notifier (P0‑3), tokens (P0‑1), ratelimit (P1‑1), observability (P1‑2). |
| `http` | ✅ | Clean public/authed split, layered limiters, CSRF/CORS/headers. |
| `config` | ⚠️ | Prod‑safety gates (P0‑4); version pinning (P1‑14). |

---

## 5. Frontend, app by app

| App | State | Pending |
| :-- | :-- | :-- |
| **`qeetid-admin`** | ~70 screens; control plane largely complete. | Sweep the catch‑all (P2); build per‑tenant rate‑limit UI; add admin UIs for **JWKS/key rotation**, **consent/grants**, **provider/connection** management, lockout settings; a11y (P1‑13). |
| **`qeetid-web`** | Marketing only — **not** the login app. | Decide the home for the **hosted login + consent** surface (P0‑2): here, in admin, or a dedicated minimal `login` app. This is the visible face of "Sign in with Qeet ID." |
| **`qeetid-docs`** | ~32 MDX + AI search. | Reconcile **SDK docs with reality** (P1‑3); add provider‑setup, JWKS, revocation, and migration guides; i18n. |

---

## 6. End‑to‑end flow walkthrough (where each flow breaks today)

| Flow | Verdict | Break point |
| :-- | :-- | :-- |
| Sign up → create workspace → owner | ✅ | Tested (`TestTenantCreateWithOwner`). |
| Password login → access/refresh → rotation → reuse detect | ✅ | Tested; add per‑account lockout (P0‑8). |
| Switch workspace | ✅ | `POST /v1/auth/switch-tenant`. |
| Email verify / magic link / reset / invite email | 🔴 | `LogSender` — never delivered (P0‑3). |
| MFA (TOTP) | ✅ | TOTP only (P1‑10). |
| Passkey register + passwordless login | ✅ | Set `WEBAUTHN_RP_*` in prod (empty by default, P0‑4). |
| Social login (external OIDC) | ✅ | Provider needs OIDC discovery. |
| **"Sign in with Qeet ID" (OIDC auth‑code+PKCE)** | 🔴 | No hosted login/consent (P0‑2); HS256 ID token unverifiable via JWKS (P0‑1); no revoke/introspect (P0‑7). |
| SAML SSO (Qeet as SP) / SCIM Users / LDAP | ✅ | SAML IdP side + SCIM Groups pending (P1‑5/6); run interop (P0‑9). |
| Machine‑to‑machine (`client_credentials`) | ✅ | Same JWKS caveat for consumers verifying tokens (P0‑1). |
| Admin control plane | ✅ | Catch‑all stub for unbuilt nav items (P2). |
| API‑key auth + rate limiting | ✅* | Per‑process limits weaken under multi‑replica (P1‑1). |
| Audit + webhook delivery | ✅ | Strong. |
| GDPR export / erasure | ⚠️ | Works, **erasure untested** (P1‑9). |

---

## 7. Cross‑cutting production readiness (the "don't miss anything" section)

**Security hardening** — asymmetric signing + key rotation (P0‑1); Argon2id (P0‑5); KMS (P0‑6); brute‑force/lockout (P0‑8); revoke/introspect (P0‑7); prod‑config gates (P0‑4); token‑storage/CSP review (P1‑8); breached‑password (P2); secret‑scanning + Dependabot/CodeQL (CodeQL present); a documented **threat model** + an external **penetration test** before GA; `SECURITY.md` disclosure process exists — keep it live.

**Scale & reliability** — Redis‑backed limits (P1‑1); load/soak test to a target RPS; connection‑pool tuning (`DB_MIN/MAX_CONNS`); graceful shutdown + draining (in‑flight tracker exists); outbox/webhook DLQ + replay verified; multi‑replica behind LB.

**Observability** — OTel traces, Prometheus metrics, `/metrics`, dashboards + alerts; deep `/readyz`; structured security‑event audit (P1‑2).

**Operations** — IaC/Helm or PaaS; DB backups + PITR + a tested restore; **zero‑downtime migration** runbook; key‑rotation runbook; incident runbooks + on‑call; staging that mirrors prod.

**Compliance** — GDPR DPA + RoPA + DPIA; verified erasure (P1‑9); data‑retention config (exists); SOC 2 readiness (Type I → II); cookie/consent + privacy policy; Trust Center; data‑residency story (P2).

**Developer experience** — shipped SDKs (P1‑3); complete + validated OpenAPI (P1‑4); quickstarts that match reality; sandbox tenant; clear error vocabulary (exists).

**Quality gates** — RBAC/policy + GDPR erasure unit tests (P1‑9); OIDC/SCIM/SAML conformance (P0‑9); a11y (P1‑13); i18n (P1‑12); CI gating on lint + typecheck + unit + integration (CI exists).

---

## 8. "Bring your own provider" — three phases, sequenced (you chose all three)

With a July runway, **Phase A is in launch scope** (no longer deferred).

### 8‑A 🔴 Qeet ID as a first‑class OIDC/OAuth2 **+ SAML IdP** *(launch)*
This is "Sign in with Qeet ID." It is exactly P0‑1, P0‑2, P0‑7, P0‑9 **+ P1‑5 (SAML IdP issuance)**:
- Asymmetric signing + public JWKS so RPs can verify ID tokens.
- Hosted login + consent UI so the auth‑code flow runs for external apps.
- Token revocation + introspection.
- OpenID Foundation conformance + RP‑initiated logout.
- SAML IdP side (sign + issue assertions) so Qeet is also an SSO source.
*DoD:* a developer registers a client, redirects users to a Qeet‑hosted login, gets consent, verifies the ID token against your JWKS, and can revoke it — the literal definition of being a provider.

### 8‑B 🟠 Custom / bring‑your‑own external connector *(fast‑follow)*
Promote the existing generic‑OIDC `social` connector to a first‑class **"Custom Provider"**: arbitrary OIDC **and** SAML connectors per tenant, claim/attribute mapping UI, JIT provisioning + role mapping, "test connection" probe. Most plumbing exists.

### 8‑C 🟡 Pluggable provider SDK / plugin framework *(later)*
A stable provider interface (`Start`/`Callback`/`MapClaims`/`Refresh`) + registry so new provider **types** can be added without forking core; ship reference plugins.

---

## 9. 🟣 Quantum‑secure roadmap

**Why for identity:** tokens and stored secrets are long‑lived; under **"Harvest Now, Decrypt Later"** adversaries store today's ciphertext to decrypt once a quantum computer exists. US/UK/EU/AU guidance assumes this is happening now.

**Standards (finalized Aug 13 2024):** **FIPS 203 ML‑KEM** (key exchange) · **FIPS 204 ML‑DSA** (signatures — the JWT/SAML/webhook‑signing successor) · **FIPS 205 SLH‑DSA** (hash‑based backup). FN‑DSA/Falcon pending.

**Deadlines pulling this forward (NSA CNSA 2.0 / NSM‑10):** software/firmware signing prefers PQC by 2025, **exclusive by 2030**; OS by 2027/2033; **all US national‑security systems quantum‑resistant by 2035**. Relevant the moment you pursue public‑sector/regulated buyers.

**Roadmap for Qeet ID:**
1. **Crypto‑agility — in launch (free side effect of P0‑1).** Once tokens are asymmetric with a `kid` key registry, adding an algorithm is "register a key type," not a rewrite. Make algorithm a key property.
2. **Hybrid PQC TLS — in launch (cheap, real).** Terminate TLS with **X25519MLKEM768** (default in Go 1.24+ `crypto/tls`; OpenSSL 3.5+; Chrome/Edge/Firefox; ~⅓ of Cloudflare human HTTPS already hybrid in early 2025). Blunts HNDL on data‑in‑transit, no client change. **Market this as "quantum‑ready," which is true today.**
3. **PQC token signing — track drafts (FUTURE).** IETF `draft-ietf-cose-dilithium` (ML‑DSA in JOSE) + `draft-ietf-jose-pq-composite-sigs` (PQ/T hybrid). Plan a hybrid (classical+ML‑DSA) JWT mode behind crypto‑agility once a JOSE `alg` stabilizes. Caveat: ML‑DSA keys/sigs are much larger — measure token/JWKS bloat.
4. **PQC passkeys — track FIDO (FUTURE).** IANA added PQC algorithms to **COSE** on 2025‑04‑24; `draft-vitap-ml-dsa-webauthn` is active; FIDO is scoping PQC WebAuthn (authenticator timelines ~mid‑2026). Keep the WebAuthn credential‑algorithm list **configurable** so PQC authenticators drop in.
5. **PQC‑ready data at rest.** When moving the vault to KMS (P0‑6), prefer a KMS/HSM with an ML‑KEM (hybrid) roadmap.

> **Honest framing:** ship **hybrid TLS + crypto‑agility** now and call it **"quantum‑ready"**; keep ML‑DSA token signing + PQC passkeys as roadmap. Don't claim present‑tense "quantum‑secure" — the JOSE codepoints and FIDO authenticators are still stabilizing through 2026.

---

## 10. Differentiation — still‑unsolved problems you can win on

Bold = Qeet already has a structural edge.

- **MAU pricing cliffs & lock‑in** — Auth0 B2C per‑MAU ≈doubled; SSO behind Enterprise quotes; a cited bill jumped ~15×. → **Self‑host + internal billing + "no SSO tax."**
- **Painful migration / password‑hash import.** → Ship the **bcrypt→Argon2id importer + bulk import** (P2) as a headline.
- **Centralization / breach risk** — Okta's Oct‑2023 support breach hit ~all customers. → **Self‑hostable, tenant‑isolated, hash‑chained audit** as trust signals.
- **Non‑human / AI‑agent identity (the #1 emerging 2026 gap)** — NHIs outnumber humans ~45–90:1; ~97% over‑privileged; MS/Okta/Google racing to model agents as principals. → **`principal` + `apikey` + scopes are a head start** — extend to short‑lived, scoped, attributable agent identities.
- **Fine‑grained authZ (ReBAC/Zanzibar)** — most bolt on OpenFGA. → Native relationship‑based authZ is a credible roadmap.
- **Passkey recovery** remains unsolved UX‑wide → a clean recovery flow (P2) is a wedge.
- **Magic‑link/OTP deliverability, SCIM brittleness, revocation latency, data residency** — recurring complaints; your **outbox + audit + multi‑tenant** spine makes fast revocation + per‑region routing achievable.

*(These double as the "why Qeet" marketing/docs narrative.)*

---

## 11. Phased plan to a July GA (~6 weeks from 2026‑06‑02)

Six parallel workstreams; milestones gate the launch. Dates are targets — adjust to the exact July date.

| Workstream | Wk 1 (Jun 2–8) | Wk 2 (Jun 9–15) | Wk 3 (Jun 16–22) | Wk 4 (Jun 23–29) | Wk 5 (Jun 30–Jul 6) | Wk 6 (Jul 7–13) → **GA** |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| **A. Provider / OIDC** | P0‑1 asymmetric signing + JWKS + key‑rotation runbook | P0‑2 hosted login + consent UI | P0‑7 revoke/introspect; P1‑5 SAML IdP | P0‑9 OIDC conformance + `end_session` | SCIM Groups (P1‑6); interop (Entra/Okta/Google) | Conformance sign‑off |
| **B. Security hardening** | P0‑4 config gates; P0‑5 Argon2id+rehash | P0‑8 lockout/anti‑stuffing | P0‑6 KMS vault | P1‑8 token‑storage/CSP; threat model | **External pen test** | Pen‑test fixes |
| **C. Comms / email** | P0‑3 provider wiring | Deliverability (SPF/DKIM/DMARC, bounces) | Wire verify/reset/magic/invite/MFA‑OTP | Localized templates (P1‑12) | — | Deliverability soak |
| **D. Platform / ops** | P1‑14 version pin | P1‑1 Redis limits | P1‑2 OTel+Prometheus+`/readyz` | P1‑7 IaC/Helm + backups/PITR | Zero‑downtime migration + DR drill; load test | Staging→prod cutover rehearsal |
| **E. Quality / tests** | P1‑9 RBAC/policy tests | P1‑9 GDPR erasure tests | mfa/recovery/verification/oidc/passkey tests | a11y audit (P1‑13) | Full regression + integration | Green CI gate |
| **F. SDK / docs / FE** | P1‑4 validate OpenAPI | P1‑3 generate TS SDK | Python SDK; reconcile docs | FE: JWKS/consent/provider/lockout admin UIs | Sweep catch‑all (P2); per‑tenant rate‑limit UI | Docs/quickstart parity |

**Cross‑cutting, in launch scope:** hybrid PQC TLS + crypto‑agility (§9.1–9.2), GDPR DPA/RoPA, Trust Center, billing decision (PSP vs invoice‑only, P1‑11).
**Deferred to fast‑follow:** P2 competitive features (breached‑pw, anomaly detection, passkey recovery, bulk import, data residency), 8‑B/8‑C, full PQC token signing + PQC passkeys.

---

## 12. Go‑live definition of done (launch checklist)

**Security & identity**
- [ ] Tokens signed RS256/ES256; JWKS serves verifiable public keys; rotation runbook tested.
- [ ] Hosted login + consent UI complete; full third‑party auth‑code+PKCE flow demoed end‑to‑end.
- [ ] `/oauth/revoke` + `/oauth/introspect`; RP‑initiated logout (`end_session`).
- [ ] OpenID Foundation Basic+Config OP conformance passed; SCIM + SAML interop verified.
- [ ] Argon2id + rehash‑on‑login; KMS‑backed vault; per‑account lockout live.
- [ ] Prod boot refuses insecure defaults; CSRF/dev‑trust off; `WEBAUTHN_RP_*` + `ALLOWED_ORIGINS` set.
- [ ] External penetration test completed; criticals/highs fixed.

**Comms**
- [ ] Email + SMS deliver in prod; SPF/DKIM/DMARC pass; bounce/complaint handling; all auth emails fire.

**Platform / ops**
- [ ] Redis‑backed limits; OTel + Prometheus dashboards + alerts; deep `/readyz`.
- [ ] IaC/Helm; DB backups + PITR + restore drill; zero‑downtime migration rehearsed; DR runbook.
- [ ] Load test meets target RPS/latency; graceful shutdown verified.

**Quality / compliance / DX**
- [ ] RBAC/policy + GDPR erasure unit tests; full regression green in CI.
- [ ] a11y (WCAG 2.2 AA) on admin + hosted login; transactional emails localized.
- [ ] GDPR DPA/RoPA/DPIA; Trust Center + privacy/cookie policy; SOC 2 readiness underway.
- [ ] TS (+ Python) SDK shipped; OpenAPI validated against routes; quickstarts match reality.

**Provider story**
- [ ] 8‑A delivered (OIDC + SAML IdP). 8‑B/8‑C roadmapped with owners/dates.

**Quantum**
- [ ] Hybrid PQC TLS enabled; algorithm‑agile key registry in place; "quantum‑ready" claim documented (not "quantum‑secure").

---

## 13. Quick reference — file map for the blockers

| Item | File |
| :-- | :-- |
| JWT signing (HS256) | `backend/internal/platform/tokens/jwt.go:87` |
| OIDC authorize / no consent UI | `backend/internal/oidc/oidc.go:115` |
| Email/SMS LogSender | `backend/internal/platform/notifier/notifier.go` |
| Password (bcrypt) | `backend/internal/platform/password/hasher.go` |
| Secrets vault key | `backend/internal/secret/secret.go:4` |
| Rate limiter (in‑memory) | `backend/internal/platform/ratelimit/limiter.go` |
| Dev config defaults | `backend/.env.example`, `backend/internal/config/config.go` |
| SAML SP‑only | `backend/internal/saml/saml.go:2` |
| SCIM (Users, no Groups) | `backend/internal/scim/scim.go:284` |
| Token in response body | `backend/internal/auth/http.go:91` |
| Router / mounts | `backend/internal/http/router.go` |
| Dockerfile / Go version | `backend/Dockerfile` |

---

## 14. Sources (web research, 2025–2026)

**Identity‑platform gaps & incidents**
- Logto — *2025 Auth0 pricing & alternatives*: https://blog.logto.io/auth0-pricing-explain
- SSOJet — *Auth0 support after Okta (2025)*: https://ssojet.com/blog/auth0-support-after-okta
- SuperTokens — *Okta alternatives*: https://supertokens.com/blog/okta-alternatives
- Okta SEC 8‑K (FY2024, breach disclosure): https://www.sec.gov/Archives/edgar/data/0001660134/000166013424000107/okta-62420248xkex991.htm

**Non‑human / AI‑agent identity**
- IBM — *What is non‑human identity*: https://www.ibm.com/think/topics/non-human-identity
- Aembit — *IAM for Agentic AI (2026)*: https://aembit.io/blog/iam-agentic-ai/
- SailPoint — *Agentic AI and the future of IAM*: https://www.sailpoint.com/blog/agentic-ai-and-the-future-of-iam
- CSA — *Non‑human identity governance vacuum*: https://labs.cloudsecurityalliance.org/research/csa-whitepaper-nonhuman-identity-agentic-ai-governance-v1-cs/

**Post‑quantum cryptography**
- NIST — *First 3 finalized PQC standards (FIPS 203/204/205)*: https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
- Wikipedia — *Harvest now, decrypt later*: https://en.wikipedia.org/wiki/Harvest_now,_decrypt_later
- postquantum.com — *NSA CNSA 2.0 timeline & requirements*: https://postquantum.com/cnsa-2-0/complete-guide/
- Cloudflare — *PQC support (X25519MLKEM768 adoption)*: https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-support/
- inside.java — *Post‑quantum hybrid key exchange for TLS 1.3 (Go)*: https://inside.java/2026/02/17/tls-post-quantum-hybrid-key-exchange/
- IETF — *ML‑DSA for JOSE and COSE* (`draft-ietf-cose-dilithium`): https://www.ietf.org/archive/id/draft-ietf-cose-dilithium-04.html
- IETF — *PQ/T hybrid composite signatures for JOSE/COSE* (`draft-ietf-jose-pq-composite-sigs`): https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/
- IETF — *ML‑DSA for WebAuthn* (`draft-vitap-ml-dsa-webauthn`): https://datatracker.ietf.org/doc/draft-vitap-ml-dsa-webauthn/
- Wultra — *Passkeys & FIDO2 became quantum‑safe (COSE PQC codepoints, Apr 2025)*: https://www.wultra.com/blog/passkeys-and-fido2-quietly-became-quantum-safe-heres-what-changed

---

*Generated from a static audit of branch `develop` (graph commit `53459009`). If code moves, run `graphify update .` in `qeet-id/` and re‑verify the §13 file:line references before acting.*
