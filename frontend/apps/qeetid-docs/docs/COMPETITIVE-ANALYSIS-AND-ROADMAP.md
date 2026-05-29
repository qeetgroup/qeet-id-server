# Qeet ID — Platform Analysis, Competitive Comparison & Improvement Roadmap

> **Purpose of this document.** This is the single source of truth for *where Qeet ID stands today*, *how it compares to every major identity platform on the market*, and *what we will build next, in order*. It is written for future developers: read it before planning a sprint so you understand both the gap and the rationale. Each roadmap item has a target window so you can see what was meant to ship when.
>
> This is an **internal engineering planning document**, not public end-user docs. It lives under `qeetid-docs` so it ships with the docs app and stays close to the team.

| | |
|---|---|
| **Document owner** | Platform / Architecture |
| **Created** | 2026-05-29 |
| **Last updated** | 2026-05-29 |
| **Status** | Living document — update the changelog at the bottom on every material change |
| **Scope** | Backend (Go), Frontend (admin / web / docs), Infra, Docs |


> ⚠️ **Doc-staleness warning discovered during this analysis.** The root [`README.md`](../../../../README.md) and [`CHANGELOG.md`](../../../../CHANGELOG.md) claim "OAuth 2.0 Authorization Code grant + OIDC ID-token issuance not yet wired" and reference a `documents/` folder that **no longer exists**. The code disagrees: the Authorization Code + PKCE flow and ID-token issuance **are implemented** (`backend/internal/oidc/oidc.go`). Treat the root README's status table as out of date; **this document supersedes it**. First roadmap chore: reconcile the README.

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [What Qeet ID is](#2-what-qeet-id-is)
3. [Current state — verified inventory](#3-current-state--verified-inventory)
4. [The competitive landscape](#4-the-competitive-landscape)
5. [Feature gap matrix](#5-feature-gap-matrix-qeet-id-vs-the-field)
6. [What we missed — prioritised backlog](#6-what-we-missed--prioritised-backlog)
7. [The roadmap (dated, phase-by-phase)](#7-the-roadmap-dated-phase-by-phase)
8. [Frontend → backend → docs: per-area improvement plan](#8-frontend--backend--docs-per-area-improvement-plan)
9. [How to keep this document alive](#9-how-to-keep-this-document-alive)
10. [Sources](#10-sources)
11. [Changelog](#11-changelog-of-this-document)

---

## 1. Executive summary

Qeet ID is a **developer-first, open-source, passkeys-first identity platform** positioned as an affordable, self-hostable alternative to Auth0 / Okta / Clerk / WorkOS. Architecturally it is a **Go modular monolith + PostgreSQL** backend with a **pnpm/Turborepo** frontend (admin dashboard, marketing site, fumadocs docs site) and a shared UI library.

**Where we are strong (production-grade today):**

- Email/password auth with refresh-token rotation **and reuse/theft detection**
- Passwordless magic links + email/phone OTP plumbing
- TOTP MFA with recovery codes
- Multi-tenant RBAC with an effective-permissions + `check` API
- API keys & service principals (OAuth `client_credentials`)
- **OIDC provider**: discovery, dynamic client registration, **Authorization Code + PKCE**, ID-token issuance, userinfo
- **Hash-chained, tamper-evident audit log** (a genuine differentiator vs many competitors)
- Webhooks with HMAC signing, exponential-backoff retry, and a dead-letter queue
- Transactional outbox; per-tenant branding & security policy storage; GDPR erasure with a grace-period purge worker

**Where we are behind the market (the gaps this doc is about):**

| Gap | Market expectation | Qeet ID today |
|---|---|---|
| **Enterprise SSO (SAML 2.0)** | Table stakes for B2B | ❌ Not implemented |
| **SCIM 2.0 directory sync** | Table stakes for B2B | ❌ Not implemented |
| **WebAuthn / passkey ceremony** | Table stakes in 2026 | 🟡 Storage ready, ceremony returns **501** |
| **Social login (Google/GitHub/…)** | Table stakes | 🟡 Config + linking ready, exchange returns **501** |
| **Real email/SMS delivery** | Required for prod | ❌ `LogSender` to stdout only |
| **RS256/ES256 + JWKS rotation** | Required for prod OIDC | 🟡 HS256, empty JWKS |
| **Attack protection** (bot detection, breached-password, brute-force, adaptive/risk MFA) | Auth0/WorkOS-grade | ❌ None (admin has stub UIs) |
| **Hosted/embeddable login UI + client SDKs** | Clerk/WorkOS killer feature | ❌ Referenced in docs, not in repo |
| **Extensibility (Actions/Hooks)** | Auth0 Actions / Zitadel Actions v2 | ❌ None |
| **Fine-grained authz (ReBAC/Zanzibar)** | WorkOS FGA / Auth0 FGA / Ory Keto | ❌ Only role-based; group RBAC not wired |
| **Admin self-serve SSO/SCIM portal** | WorkOS/Stytch/Frontegg killer feature | ❌ None |

**Honest maturity read:** core CIAM scaffolding is ~70% complete and well-architected; **enterprise (B2B) readiness is the biggest hole**, and **developer-integration surface (SDKs + hosted UI) is the second**. The roadmap in §7 attacks production-hardening first, then enterprise, then security intelligence, then DX/extensibility, then advanced authorization and agentic identity.

---

## 2. What Qeet ID is

```
qeet-identity/
├── backend/            Go modular monolith — chi + pgx + PostgreSQL, 23 domain modules, 25 migrations
├── frontend/           pnpm + Turborepo
│   ├── apps/qeetid-admin   Admin dashboard (Vite 8 + TanStack Router/Query/Form/Table, React 19)
│   ├── apps/qeetid-web     Marketing site (Next.js 16) — incl. /compare/{auth0,clerk,stytch,workos}
│   └── apps/qeetid-docs    Docs site (Next.js 16 + fumadocs + AI search) — 38 MDX pages
│   └── packages/qeetid-ui  Shared UI (36 components)
└── docker-compose.yml  Postgres + backend (+ opt-in frontend)
```

**Tech stack:** Go 1.25, chi/v5, pgx/v5, golang-jwt/v5, golang.org/x/crypto (bcrypt). React 19 everywhere; Next.js 16; Vite 8; Tailwind 4; Turborepo 2.9; pnpm 9.15.

**Positioning vs the market:** open-source + self-hostable (like Keycloak / FusionAuth / Zitadel / Ory) **but** aiming for the polished DX and B2B/multi-tenant model of Clerk / WorkOS / Stytch. The closest architectural peer is **Zitadel** (Go, multi-tenant, OSS).

---

## 3. Current state — verified inventory

> Legend: ✅ implemented & wired · 🟡 partial / stubbed / not enforced · ❌ absent. All entries below were verified against source on the analysed commit (file references included). This is more accurate than the root README.

### 3.1 Backend — implemented (✅)

| Domain | Endpoints / capability | Notes |
|---|---|---|
| **Auth core** | signup, login, refresh, logout, list/revoke sessions, `me` | Refresh-token **rotation + reuse/theft detection** → full session revoke. `internal/auth/` |
| **Recovery** | forgot/reset password, magic-link start/consume | Enumeration-safe (timing floor). `internal/recovery/` |
| **Verification** | email & phone OTP start/confirm | 6-digit, 10-min TTL. **Sends via `LogSender` only.** `internal/verification/` |
| **Users** | CRUD + set-password + soft-delete | Global email uniqueness (migration 0022). `internal/user/` |
| **Tenants** | CRUD + soft-delete | Personal tenant auto-created on signup. `internal/tenant/` |
| **RBAC** | permissions, roles, grant/revoke, assign/unassign, effective perms, `GET /v1/check` | Single-call authz check. `internal/rbac/` |
| **Groups** | CRUD, nested via `parent_id` | **No group-level permission resolution yet.** `internal/group/` |
| **Invites** | create/list/accept/revoke | 14-day token. `internal/invite/` |
| **MFA** | TOTP enroll/confirm/verify/disable + recovery codes | RFC 6238, 10 bcrypt-hashed recovery codes. `internal/mfa/` |
| **API keys** | create/list/revoke, scoped, expirable | bcrypt-hashed secret, bearer middleware. `internal/apikey/` |
| **Service principals** | create/list/disable + `POST /v1/oauth/token` (`client_credentials`) | `internal/principal/` |
| **OIDC provider** | discovery, JWKS, client registration, **`/authorize` + `/token-code` (Auth Code + PKCE S256)**, ID-token, userinfo | **HS256 signing, JWKS empty.** `internal/oidc/oidc.go:110,156,252,364,394` |
| **Audit** | list (cursor) + **`/verify` hash-chain integrity** | SHA-256 append-only chain (migration 0023). Differentiator. `internal/audit/` |
| **Analytics** | tenant overview KPIs + trends | MAU/DAU, login/MFA/failed trends, method mix. `internal/analytics/` |
| **GDPR** | erasure request/cancel/list + async purge worker | 30-day grace, PII → `[REDACTED]`. `internal/gdpr/` |
| **Webhooks** | subscription CRUD + events + delivery | HMAC-SHA256, exp-backoff retry, DLQ. `internal/webhook/` |
| **Branding** | per-tenant logo/colors/custom domain/email sender | `internal/branding/` |
| **Policy** | per-tenant IP allow/deny, password rules, MFA mode, session age | **Stored but not enforced in request path (no middleware).** `internal/policy/` |
| **Platform** | outbox + DLQ admin, in-memory rate limiter, CSRF, security headers, health/ready | `internal/platform/` |

### 3.2 Backend — partial / stubbed (🟡)

| Capability | State | Evidence |
|---|---|---|
| **WebAuthn / passkeys** | Storage, list, delete work. **Ceremony (register/login begin/finish) returns HTTP 501.** Pending a `go-webauthn` integration. | `internal/passkey/passkey.go:4,112` |
| **Social OAuth** | Provider config upsert + identity linking/unlinking work. **`/start` + `/callback` return 501.** | `internal/social/social.go:4,203,211` |
| **OIDC completeness** | Auth Code + PKCE done; **refresh-token grant, token introspection, token revocation, RP-initiated logout, and a consent screen are missing.** | `internal/oidc/` |
| **JWT signing** | HS256 with static secret; **no RS256/ES256, no JWKS rotation** → external RPs cannot verify. | `oidc.go:443,450` |
| **Rate limiting** | In-memory token bucket → **single-process only**; not distributed. | `internal/platform/ratelimit/` |
| **Email/SMS** | `LogSender` writes to stdout; pluggable boundary exists but **no real provider**. | `internal/platform/notifier/` |
| **Outbox publisher** | `LogPublisher` only; **no Kafka/queue**. | `internal/platform/outbox/` |
| **Policy enforcement** | Tables + API exist; **enforcement middleware not wired**. | `internal/policy/` |

### 3.3 Backend — absent (❌)

SAML 2.0 (SP/IdP) · SCIM 2.0 · LDAP/AD federation · adaptive/risk-based MFA · bot detection · breached-password detection · brute-force / suspicious-IP throttling · device authorization flow · CIBA · token exchange (RFC 8693) · DPoP · fine-grained / relationship-based authz (ReBAC) · group-level RBAC resolution · Actions/Hooks extensibility engine · hosted/embeddable login UI · first-party client SDKs (in-repo) · custom registration forms / progressive profiling · account-linking flows · Stripe billing · S3/object storage · Redis · password hashing upgrade (still bcrypt cost 12, not Argon2id) · AI-agent / MCP identity.

### 3.4 Frontend — current state

- **`qeetid-admin`** (~62 routes): **~55% are real, API-integrated screens** (users, tenants, groups, roles/permissions, OIDC clients, API keys, machine identities, webhooks, audit logs, sessions, rate limits, GDPR, branding, domains, billing UI, TOTP, passkey config, dashboard/analytics). **~45% are stub/mock/config-only**: SAML, SCIM, LDAP, passwordless config, magic-link config, SMS/email MFA, recovery-codes preview, tokens, secrets, bot/anomaly/IP-allowlist threat screens, SOC2/ISO27001/retention compliance pages, email-template editor (no save), "bots"/automation builder. Route tree: `apps/qeetid-admin/src/routes/`, nav: `src/config/navigation.tsx`.
- **`qeetid-web`**: complete marketing site incl. competitor comparison pages (`/compare/auth0`, `/clerk`, `/stytch`, `/workos`) — `src/components/marketing/comparison-page.tsx`.
- **`qeetid-docs`**: 38 MDX pages + AI search (OpenRouter) + OG image gen + Flexsearch. Covers auth methods, API reference, RBAC, MFA, sessions, audit, webhooks, multi-tenancy, SDKs.
- **`qeetid-ui`**: 36 production-ready components.
- **No end-user auth UI in the repo**: the docs reference `@qeetid/react`, `@qeetid/sdk`, `@qeetid/nextjs`, `@qeetid/react-native`, Go/Python SDKs and a hosted account portal, but **none of those packages exist in this monorepo yet** — they are documented-but-unbuilt. This is a major gap (see §6).

---

## 4. The competitive landscape

Two cohorts matter for Qeet ID: **commercial CIAM leaders** (set the feature bar and DX expectations) and **open-source / self-hostable** platforms (our direct positioning peers).

### 4.1 Commercial leaders

**Auth0 (Okta)** — the incumbent. Differentiators: **Actions/Flows** (versioned Node.js extensibility hooks at every pipeline stage), **Adaptive MFA** (risk-scored step-up on untrusted IP / new device / impossible travel), and a full **Attack Protection** suite (ML **Bot Detection**, **Breached Password Detection**, **Brute-Force Protection**, **Suspicious IP Throttling**). Plus **Organizations** (B2B), **Universal Login** (hosted, customizable), huge social/enterprise connection catalog, account linking, and **Auth0 FGA** (relationship-based authz / OpenFGA). Enterprise SSO + SCIM are gated behind expensive tiers — a wedge Qeet ID can exploit.

**Clerk** — best-in-class **developer experience for React/Next**. Killer feature: **drop-in prebuilt components** — `<SignIn/>`, `<SignUp/>`, `<UserProfile/>`, `<UserButton/>`, `<OrganizationSwitcher/>`, `<OrganizationProfile/>`, `<CreateOrganization/>`, `<OrganizationList/>` — plus hooks (`useUser`, `useSession`, `useSignIn`, `useOrgSwitcher`). **Organizations** with roles/permissions **embedded in the session** (no extra authz round-trip). Hosted account portal, device management, passkeys, magic links. SCIM reached GA in April 2026.

**WorkOS** — the **enterprise-readiness** play. **Single-API SSO** (SAML + OIDC across Okta/Azure AD/Google/OneLogin/Ping/…), **Directory Sync / SCIM** (bidirectional, real-time events), and the standout **embeddable, white-labeled Admin Portal** that lets *customer* IT teams self-configure SSO/SCIM without a support ticket. Plus **Audit Logs** (CSV/SIEM export), **RBAC + FGA** (Warrant acquisition), **Radar** (fraud), **Vault** (encryption keys), and **AuthKit** (hosted UI). Free to 1M MAU; ~$125/connection for SSO/SCIM.

**Stytch** — headless-first, strong **B2B Organizations/Members** model (native, not bolted on), SSO + SCIM + RBAC + MFA, passkeys/biometrics, embeddable Admin Portal, device fingerprinting/fraud, M2M.

**Frontegg / Descope** — B2B self-service admin portal (Frontegg) and **drag-and-drop auth flow builders** (Descope) with strong passwordless. Both emphasize no-code flow customization.

**Supabase Auth / AWS Cognito / Firebase Auth / Google Identity Platform** — bundled-with-platform auth. Cheap/free, broad social, but weaker on enterprise SSO/SCIM and B2B org modeling. Relevant because many of Qeet ID's target developers default to these.

### 4.2 Open-source / self-hostable peers (our direct lane)

**Keycloak** — the most **feature-complete OSS**: OIDC, **SAML 2.0**, **LDAP/AD federation**, SCIM, fine-grained authz, Kerberos. Weaknesses: clunky customization, no official support, dated DX. Qeet ID's wedge: modern DX + clean multi-tenancy.

**FusionAuth** — polished self-host DX. Notable: **Tenants + Applications**, **per-app Themes**, **Lambdas** (custom logic in OIDC/SAML/SCIM flows), **Connectors** (federation), **Entity Management** + **FGA by Permify**, breached-password detection, **custom registration forms**, advanced OAuth scopes, SCIM, threat detection, WebAuthn, MFA policies, FIPS crypto, self-service account management.

**Zitadel** — **closest architectural peer** (Go, multi-tenant, OSS, cloud-native). Ships SSO, MFA, **Passkeys**, OIDC, **SAML**, **SCIM**, first-class **Organizations** multi-tenancy, **Actions v2** (instance-wide external-endpoint hooks in any language), a forkable **Next.js Login UI v2**, and resource-based **User v2 / Session v2 APIs**, with a Projects + Grants authorization model. **Study Zitadel closely — it is the blueprint for several roadmap items.**

**Ory** (Kratos/Hydra/Oathkeeper/Keto) — API-first, headless, no admin GUI. Strong standards: **OAuth 2.0 device authorization flow**, SMS login, token-chain revocation, and **Keto** (Google-Zanzibar **relationship-based authorization**). For deep backend teams.

**SuperTokens / Logto** — lighter OSS. SuperTokens ships self-hosted prebuilt login UI; Logto offers a modern console and broader compliance-cert coverage than Keycloak. Both lack heavy enterprise federation.

### 4.3 Where the market is heading (2026 trends to design for)

- **Passkeys are table stakes** — ~75% consumer awareness; "a CIAM vendor without native WebAuthn/passkeys is selling yesterday's product." (We're at 501.)
- **AI-agent / non-human identity** — 10–30% of auth volume is becoming agent traffic. The settling stack: **OAuth 2.1 + Dynamic Client Registration + MCP**, scoped agent credentials, tokens carrying `sub=agent, act=human`, human-in-the-loop consent.
- **Fine-grained authorization** (ReBAC/Zanzibar) for "who can do what to which resource," with consent-time scope approval.
- **Device authorization flow & step-up auth** as first-class.
- **Compliance posture** (SOC 2 / ISO 27001) as a sales gate.

---

## 5. Feature gap matrix (Qeet ID vs the field)

✅ full · 🟡 partial/stub · ❌ none. Competitor columns are representative of their flagship offering.

| Capability | **Qeet ID** | Auth0 | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Email/password + sessions | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Refresh rotation + theft detection | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ |
| Magic links | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ |
| Email/SMS OTP **delivery** | 🟡 | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ |
| TOTP MFA + recovery codes | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **WebAuthn / passkeys** | 🟡 501 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Social login** | 🟡 501 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Enterprise SSO (SAML 2.0)** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| **SCIM 2.0 provisioning** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| LDAP/AD federation | ❌ | ✅ | 🟡 | ✅ | 🟡 | ✅ | ✅ | 🟡 | 🟡 |
| OIDC provider (Auth Code+PKCE) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| OIDC refresh/introspect/revoke/logout | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **RS256/ES256 + JWKS rotation** | 🟡 HS256 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `client_credentials` / M2M | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Device authorization flow | ❌ | ✅ | ❌ | 🟡 | ❌ | ✅ | ✅ | 🟡 | ✅ |
| Multi-tenant / Organizations | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |
| RBAC | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| Group-level RBAC | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Fine-grained / ReBAC authz** | ❌ | ✅ FGA | 🟡 | ✅ | ✅ | ✅ | ✅ Permify | 🟡 | ✅ Keto |
| **Adaptive / risk-based MFA** | ❌ | ✅ | 🟡 | 🟡 | ✅ | 🟡 | ✅ | 🟡 | 🟡 |
| **Bot detection** | ❌ | ✅ | 🟡 | ✅ Radar | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Breached-password detection** | ❌ | ✅ | ✅ | 🟡 | ✅ | 🟡 | ✅ | 🟡 | 🟡 |
| Brute-force / suspicious-IP throttle | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Hash-chained tamper-evident audit** | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | ❌ | 🟡 | 🟡 | ❌ |
| Audit export (CSV/SIEM) | 🟡 | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |
| Webhooks + DLQ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |
| **Extensibility (Actions/Hooks)** | ❌ | ✅ | 🟡 | 🟡 | 🟡 | 🟡 SPI | ✅ Lambdas | ✅ v2 | 🟡 |
| **Hosted / embeddable login UI** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| **First-party client SDKs (built)** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Self-serve SSO/SCIM admin portal** | ❌ | 🟡 | 🟡 | ✅ | ✅ | ❌ | 🟡 | 🟡 | ❌ |
| Custom registration / progressive profiling | ❌ | ✅ | ✅ | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | ✅ |
| Account linking | 🟡 | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ |
| GDPR erasure / data export | ✅ | ✅ | ✅ | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | 🟡 |
| Branding / theming | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| Billing integration (Stripe) | ❌ | n/a | ✅ | n/a | 🟡 | ❌ | ❌ | ❌ | ❌ |
| **AI-agent / MCP identity** | ❌ | 🟡 | ❌ | 🟡 | 🟡 | ❌ | ❌ | 🟡 | ✅ |
| Distributed rate limiting (Redis) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SOC2 / ISO27001 posture | ❌ | ✅ | ✅ | ✅ | ✅ | n/a | ✅ | ✅ | ✅ |

**Reading the matrix:** Qeet ID already matches the field on core auth, OIDC Auth-Code, multi-tenancy, RBAC, and *beats* most on tamper-evident audit. The concentrated red is: **enterprise federation (SAML/SCIM/LDAP), attack protection, fine-grained authz, extensibility, and the integration surface (SDKs + hosted UI + self-serve portal).**

---

## 6. What we missed — prioritised backlog

Grouped by theme. Each item: **why it matters**, **effort** (S ≤1wk, M 1–3wk, L 3–6wk, XL >6wk), and **area** (BE/FE/Docs/Infra). These feed the dated roadmap in §7.

### Theme A — Production hardening (do first; unblocks everything)
1. **Finish WebAuthn/passkey ceremony** (integrate `go-webauthn`, wire 4 endpoints). *Table stakes; storage already done.* **M · BE+FE+Docs**
2. **Finish social OAuth** `/start` + `/callback` for Google/GitHub/Microsoft/Apple. *Table stakes.* **M · BE+FE+Docs**
3. **RS256/ES256 signing + JWKS rotation** (publish real keys at `/.well-known/jwks.json`, kid-based 90-day rotation). *Without this, external RPs can't verify our tokens.* **M · BE**
4. **Real email/SMS providers** (SES/SendGrid + Twilio behind the `Sender` interface). *Nothing passwordless actually delivers today.* **S–M · BE+Infra**
5. **Argon2id password hashing** with bcrypt-compat verification + lazy rehash-on-login. **S–M · BE**
6. **Wire policy enforcement** (IP allow/deny + MFA-required + session-age middleware actually in the request path). **S · BE**
7. **Distributed rate limiting via Redis** (replace in-memory token bucket). *Single-process today = prod blocker.* **M · BE+Infra**
8. **Reconcile root README/CHANGELOG** with reality and restore a `documents/` (or link this doc). **S · Docs**

### Theme B — Enterprise (B2B) readiness (biggest commercial gap)
9. **SAML 2.0** SP + IdP (ACS, metadata, signing/encryption, IdP-initiated). *Hard gate for enterprise deals.* **XL · BE+FE+Docs**
10. **SCIM 2.0** server (Users + Groups, provisioning/deprovisioning, filtering). **L–XL · BE+FE+Docs**
11. **Org-level SSO connections** (per-tenant SAML/OIDC IdP config) + domain-based routing. **L · BE+FE**
12. **WorkOS-style self-serve Admin Portal** (embeddable, white-labeled, lets customer IT configure SSO/SCIM). *This is WorkOS/Stytch's killer feature.* **L · FE+BE**
13. **LDAP/AD federation** connector. **L · BE**
14. **Audit log export** (CSV + SIEM/webhook streaming). **S–M · BE+FE**
15. **Group-level RBAC resolution** (groups grant roles/permissions transitively). **M · BE+FE**

### Theme C — Security intelligence (Auth0 Attack-Protection parity)
16. **Breached-password detection** (k-anonymity HIBP range API at signup/login/reset). **S–M · BE**
17. **Brute-force + suspicious-IP throttling** with lockout/notification. **M · BE**
18. **Bot detection** (risk signals; pluggable CAPTCHA/Turnstile). **L · BE+FE**
19. **Adaptive / risk-based MFA** (step-up on new device / new IP / impossible travel). **L · BE+FE**
20. **Step-up authentication** primitive (re-auth before sensitive actions; `acr`/`amr` claims). **M · BE+FE**
21. **Anomaly detection + security notifications** (new-device email, etc.). **M · BE**

### Theme D — Developer experience & extensibility (the Clerk/Zitadel lane)
22. **First-party client SDKs** — build the packages the docs already promise: `@qeetid/sdk` (TS), `@qeetid/react` (+ hooks/components), `@qeetid/nextjs`, plus Go & Python. **XL · FE/BE+Docs**
23. **Prebuilt UI components** — `<QeetidSignIn/>`, `<SignUp/>`, `<UserProfile/>`, `<UserButton/>`, `<OrganizationSwitcher/>`, etc. (Clerk's moat). **XL · FE**
24. **Hosted/embeddable login UI** (forkable Next.js app like Zitadel Login v2 / WorkOS AuthKit). **L–XL · FE+BE**
25. **Actions/Hooks extensibility engine** (run customer logic — external endpoint targets, Zitadel-Actions-v2 style — at pre/post auth, token mint, registration). **L · BE+FE**
26. **Custom registration forms / progressive profiling** + **account-linking** flows. **M · BE+FE**
27. **Complete OpenAPI spec** (currently ~3% coverage) → generate SDKs + Postman from it. **M · BE+Docs**
28. **CLI** (`qeetid` — login, tenant/app management, local dev tunnel). **M · BE/FE**

### Theme E — Advanced authorization & future
29. **Fine-grained / relationship-based authz** (Zanzibar-style; or embed OpenFGA). *WorkOS FGA / Auth0 FGA / Ory Keto parity.* **XL · BE+FE+Docs**
30. **OAuth 2.1 alignment** + **device authorization flow** + **token exchange (RFC 8693)** + **DPoP**. **L · BE**
31. **AI-agent / MCP identity** (Dynamic Client Registration for agents, scoped agent credentials, `sub=agent, act=human` tokens, human-in-the-loop consent). *Where the market is going in 2026.* **L–XL · BE+Docs**
32. **CIBA** (decoupled/back-channel auth). **L · BE**

### Theme F — Platform & ops
33. **Stripe billing** (enforce `tenant.plan`, metering, usage). **L · BE+FE**
34. **Kafka/queue outbox publisher** (swap `LogPublisher`) for event streaming at scale. **M · BE+Infra**
35. **S3/object storage** for branding assets (logos) + theme assets. **S · BE+Infra**
36. **SOC 2 / ISO 27001 posture** (turn admin compliance stubs into real evidence collection; data-retention automation). **L · BE+FE**
37. **Observability** (OpenTelemetry traces/metrics, structured audit→SIEM). **M · BE+Infra**

---

## 7. The roadmap (dated, phase-by-phase)

> Dates are **target windows** from the 2026-05-29 baseline, assuming a small team. They communicate *intent and ordering* to future devs — adjust as capacity changes, but preserve the **dependency order** (a phase's items unblock the next). Update actual ship dates in the changelog.

### Phase 0 — Production Hardening · **Jun 2026 → mid-Jul 2026**
*Goal: everything that exists actually works in production.*
- Backlog: **#1 passkeys, #2 social OAuth, #3 RS256/JWKS, #4 email/SMS, #5 Argon2id, #6 policy enforcement, #7 Redis rate limit, #8 README reconcile.**
- **Exit criteria:** passwordless flows deliver real messages; external RPs verify our JWTs via JWKS; passkeys + Google/GitHub login work end-to-end; rate limiting survives multi-replica deploy; README matches reality.

### Phase 1 — Enterprise (B2B) Readiness · **mid-Jul 2026 → end-Sep 2026 (Q3)**
*Goal: close the biggest commercial gap — win B2B deals.*
- Backlog: **#9 SAML 2.0, #10 SCIM 2.0, #11 org SSO connections, #12 self-serve Admin Portal, #14 audit export, #15 group RBAC.** (**#13 LDAP** stretch.)
- **Exit criteria:** a customer can self-configure SAML SSO + SCIM provisioning from an embeddable portal; group membership grants permissions; audit logs export to SIEM.

### Phase 2 — Security Intelligence · **Oct 2026 → Dec 2026 (Q4)**
*Goal: Auth0 Attack-Protection-grade defenses; turn the admin "threat" stubs real.*
- Backlog: **#16 breached-password, #17 brute-force/IP throttle, #18 bot detection, #19 adaptive MFA, #20 step-up, #21 anomaly + notifications.**
- **Exit criteria:** risk-scored logins trigger step-up; breached creds blocked; admin threat dashboards show real data.

### Phase 3 — Developer Experience & Extensibility · **Jan 2027 → Mar 2027 (Q1)**
*Goal: make Qeet ID as easy to adopt as Clerk; make it extensible like Zitadel/Auth0.*
- Backlog: **#27 OpenAPI completion (first — SDKs generate from it), #22 client SDKs, #23 prebuilt UI components, #24 hosted login UI, #25 Actions/Hooks, #26 custom registration/account-linking, #28 CLI.**
- **Exit criteria:** `npm i @qeetid/react` + `<QeetidSignIn/>` gives working auth in <15 min; customers run custom logic via Actions; a forkable hosted login page ships.

### Phase 4 — Advanced Authorization & Agentic Identity · **Apr 2027 → Jun 2027 (Q2)**
*Goal: get ahead of the 2026/27 market curve.*
- Backlog: **#29 fine-grained/ReBAC authz, #30 OAuth 2.1 + device flow + token exchange + DPoP, #31 AI-agent/MCP identity, #32 CIBA.**
- **Exit criteria:** ReBAC `check` API; device flow for CLI/TV; agents get scoped, auditable delegated tokens.

### Continuous track — Platform & Ops (runs alongside all phases)
- **#33 Stripe billing**, **#34 Kafka outbox**, **#35 S3 assets**, **#36 SOC2/ISO posture**, **#37 observability.** Pull each in when the matching phase needs it (e.g. billing with Phase 1 enterprise plans; observability throughout).

**One-glance timeline**

```
2026  Jun────Jul────Aug────Sep────Oct────Nov────Dec │ 2027  Jan────Feb────Mar────Apr────May────Jun
      │ Phase 0 │      Phase 1 (Enterprise)         │       Phase 3 (DX)        │  Phase 4 (Authz/Agent)
      │  Harden │  SAML·SCIM·Portal·OrgSSO·GroupRBAC │       Phase 2 (Security) overlaps Oct–Dec
      └─────────┴───────────────────────────────────┴──────────────────────────────────────────────
      Platform & Ops (billing, Kafka, S3, SOC2, OTel) ── continuous ──────────────────────────────►
```

---

## 8. Frontend → backend → docs: per-area improvement plan

The user goal is "improve all, frontend to backend to docs." For each major feature, all three layers must land together. Use this as the per-feature checklist.

| Feature | Backend | Frontend (admin / SDK / hosted UI) | Docs |
|---|---|---|---|
| **Passkeys** | Integrate `go-webauthn`, implement 4 ceremony endpoints, store attestation | Wire admin passkey screen to real API; add passkey flow to hosted login + React SDK | Flesh out `authentication/passkeys.mdx` with real ceremony + code samples |
| **Social login** | Implement `/start` + `/callback` per provider; encrypt secrets | Admin provider config → live; "Continue with Google/GitHub" buttons in login UI | `authentication/social-providers.mdx` with per-provider setup |
| **SAML/SCIM** | New `saml` + `scim` modules; metadata, ACS, SCIM Users/Groups | New real admin screens (replace stubs) + **embeddable Admin Portal** | New `authentication/saml.mdx`, `scim.mdx`, portal embedding guide |
| **RS256/JWKS** | Key mgmt, rotation job, populate JWKS | Admin "signing keys" screen | OIDC/JWKS doc + RP verification guide |
| **Attack protection** | breached-pwd, brute-force, bot, adaptive MFA engines | Turn `threats/*` + `mfa/*` stubs into real dashboards | New "Security / Attack Protection" doc section |
| **Fine-grained authz** | ReBAC store + `check`/`expand` API (or OpenFGA) | Policy/relationship builder UI (extend `access/policies`) | New `authorization/fga.mdx` |
| **Client SDKs** | Complete OpenAPI → codegen | Build `@qeetid/sdk`, `@qeetid/react`, `@qeetid/nextjs`, Go, Python packages | Make `sdks/*.mdx` match shipped packages (today they document unbuilt SDKs) |
| **Hosted login UI** | Login session API (Zitadel Session-v2 style) | Forkable Next.js login app + prebuilt components | "Hosted UI" + "Customization/Theming" guides |
| **Actions/Hooks** | Execution engine + external-endpoint targets | Admin Actions editor/registry | "Extensibility / Actions" doc |
| **Billing** | Stripe integration, plan enforcement, metering | Make billing screen real | Pricing/plan-limits doc |

**Docs-wide actions:** (a) keep this file current; (b) complete the **OpenAPI spec** (~3% → 100%) since it powers SDK codegen + Postman + API docs; (c) ensure every "✅ implemented" feature has a matching MDX page; (d) **mark documented-but-unbuilt SDKs as "coming soon"** until Phase 3 ships them, to avoid misleading integrators.

---

## 9. How to keep this document alive

- **On every feature merge** that changes status: flip the relevant ✅/🟡/❌ in §3 and §5, and check off the backlog item in §6.
- **At each phase boundary:** record the *actual* ship date in the changelog, and re-baseline future windows from the new "today."
- **Re-run the competitor scan quarterly** — this market moves fast (SCIM GA dates, agentic-identity standards, etc.). Update §4 and §5.
- **Treat §6 numbering as stable IDs** (e.g. "closes backlog #9") so PRs and issues can reference them.

---

## 10. Sources

Competitive research (accessed 2026-05-29):

- WorkOS — [WorkOS vs Auth0 vs Clerk for B2B SaaS 2026](https://workos.com/blog/workos-vs-auth0-vs-clerk-the-best-auth-platform-for-b2b-saas-in-2026), [Top SCIM providers 2025](https://workos.com/blog/top-scim-providers-2025), [Docs](https://workos.com/docs)
- Clerk — [Organizations / B2B](https://clerk.com/organizations), [Organizations overview](https://clerk.com/docs/guides/organizations/overview), [Embeddable UIs](https://clerk.com/articles/complete-guide-to-embeddable-uis-for-user-management)
- Auth0 — [Adaptive MFA](https://auth0.com/docs/secure/multi-factor-authentication/adaptive-mfa), [Attack Protection (PDF)](https://assets.ctfassets.net/2ntc334xpx65/2RwXAFDxr1amQzHyR1O682/83ec05a1fb186cc33c0f8776d807fe26/Auth0-Attack-Protection.pdf), [Bot Detection](https://auth0.com/blog/auth0-bot-detection-reduces-bot-attacks-by-79/), [June 2025 updates](https://auth0.com/blog/june-2025-in-auth0-new-foundations-secure-connections-and-smarter-protection/)
- Stytch / WorkOS alternatives — [SuperTokens: WorkOS alternatives](https://supertokens.com/blog/workos-alternatives), [Scalekit: Auth0 alternatives](https://www.scalekit.com/compare/auth0-alternatives)
- Open-source comparison — [SuperTokens: Ory vs Keycloak vs SuperTokens](https://supertokens.com/blog/ory-vs-keycloak-vs-supertokens), [Zitadel vs Keycloak](https://www.auth0alternatives.com/compare/zitadel/vs/keycloak), [FusionAuth: Keycloak alternatives](https://fusionauth.io/guides/keycloak-alternatives), [Logto: Top OSS IAM 2025](https://blog.logto.io/top-oss-iam-providers-2025)
- FusionAuth — [Premium features](https://fusionauth.io/docs/get-started/core-concepts/premium-features), [Tenants](https://fusionauth.io/docs/get-started/core-concepts/tenants), [Entity Management](https://fusionauth.io/docs/get-started/core-concepts/entity-management)
- Zitadel — [Actions v2](https://zitadel.com/docs/concepts/features/actions_v2), [Hosted Login UI](https://zitadel.com/docs/guides/integrate/login/hosted-login), [TypeScript Login](https://zitadel.com/blog/typescript-login), [Roadmap](https://zitadel.com/docs/product/roadmap)
- 2026 trends — [Ory: Top 5 CIAM trends 2026](https://www.ory.com/blog/top-5-ciam-trends-2026), [Frontegg: CIAM in the age of AI agents](https://frontegg.com/blog/the-role-of-ciam-in-the-age-of-ai-agents), [CIAM Compass: AI Agent Identity & MCP](https://guptadeepak.com/ciam-compass/guides/ai-agent-identity-mcp/)

Internal: source verified against branch `ms/signin-with-qeet` @ `bf778f4`; file references inline in §3.

---

## 11. Changelog of this document

| Date | Author | Change |
|---|---|---|
| 2026-05-29 | Platform (initial) | Created. Full verified inventory of backend/frontend, competitive comparison across 9+ platforms, gap matrix, prioritised backlog (#1–#37), and dated 5-phase roadmap (Phase 0 Jun 2026 → Phase 4 Q2 2027). Flagged stale root README/CHANGELOG. |
