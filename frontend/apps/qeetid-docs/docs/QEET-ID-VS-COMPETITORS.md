# Qeet ID vs. the Competition — What Our Platform Supports

> A single-page, honest comparison of **what Qeet ID supports today** against Auth0, Okta, Clerk, WorkOS, Stytch, the bundled clouds (Supabase / Cognito / Firebase), and the open-source field (Keycloak, FusionAuth, Zitadel, Ory).
>
> **Qeet ID in one line:** an open-source, self-hostable, **passkeys-first** identity platform with the developer experience of Clerk, the enterprise model of WorkOS, and a tamper-evident audit log nobody else ships — **without the "SSO tax."**

| | |
|---|---|
| **Created** | 2026-05-29 |
| **Last updated** | 2026-05-29 |
| **Companion docs** | [Competitive Analysis & Roadmap](./COMPETITIVE-ANALYSIS-AND-ROADMAP.md) · [Sprint plan](./sprints/README.md) |
| **Status** | Pre-1.0. This page marks each feature honestly — see the legend. |

---

## How to read this page

| Mark | Meaning for Qeet ID |
|------|--------------------|
| ✅ | **Supported today** — implemented and wired (verified in source). |
| 🟡 | **Partial** — present but stubbed, not enforced, or dev-only (e.g. returns `501`, stdout sender). |
| 🗓️ `S#` | **Planned** — scheduled in the [sprint plan](./sprints/README.md); the number is the sprint. |
| ❌ | Not built and not currently scheduled. |

For competitors: ✅ generally available · 🟡 limited/gated/add-on · ❌ not offered.

---

## 1. What Qeet ID supports **today** (✅ verified)

These work right now on a local/self-hosted deployment.

### Authentication
- ✅ **Email + password** — signup, login, logout (bcrypt cost 12; timing-attack floor; global email uniqueness).
- ✅ **Sessions** — list active sessions, revoke a session, `/me` current-user context.
- ✅ **Refresh-token rotation with theft detection** — reusing a rotated token revokes the whole session + audits it. *(Many competitors don't do reuse-detection.)*
- ✅ **Magic links** — passwordless email sign-in (single-use, TTL).
- ✅ **Password reset** — enumeration-safe; revokes all sessions on reset.
- ✅ **Email & phone OTP verification** — 6-digit, single-use, TTL *(delivery is dev-only today — see Partial)*.

### Multi-tenancy, users & access
- ✅ **Multi-tenant workspaces** — tenant CRUD, isolation, personal tenant auto-created on signup.
- ✅ **Users** — CRUD, cursor pagination, soft-delete, set-password.
- ✅ **Groups** — nested groups (CRUD).
- ✅ **RBAC** — permissions, custom roles, grant/revoke, assign to users, **effective-permissions** query, single-call **`/check`** authorization API.
- ✅ **Invitations** — create / accept / revoke (tokenized).

### Machine & protocol
- ✅ **API keys** — scoped, expirable, bcrypt-hashed, bearer middleware.
- ✅ **Service principals + OAuth `client_credentials`** (M2M tokens).
- ✅ **OIDC provider** — discovery, dynamic client registration, **Authorization Code + PKCE (S256)**, ID-token issuance, userinfo. *(Signed HS256 today — see Partial.)*

### Operations, security & compliance
- ✅ **Tamper-evident audit log** — append-only, **SHA-256 hash-chained**, with a `/verify` integrity endpoint. **A genuine differentiator.**
- ✅ **Webhooks** — event subscriptions, HMAC-SHA256 signing, exponential-backoff retry, **dead-letter queue**.
- ✅ **Transactional outbox** — reliable event publishing.
- ✅ **GDPR right-to-erasure** — request / cancel / grace-period async purge (PII → `[REDACTED]`, audit survives).
- ✅ **Analytics** — tenant KPIs + trends (MAU/DAU, login/MFA/failed-login, method mix).
- ✅ **Per-tenant branding** (logo, colors, custom domain) and **security-policy storage** (IP allow/deny, password rules, MFA mode, session age — *stored; enforcement is planned*).
- ✅ **MFA — TOTP** (RFC 6238) **+ recovery codes**.

### Admin & docs (frontend)
- ✅ **Admin dashboard** with ~34 real, API-wired screens (users, tenants, groups, roles/permissions, OIDC clients, API keys, machine identities, webhooks, audit logs, sessions, GDPR, branding, domains, dashboard/analytics).
- ✅ **Docs site** — 38 pages with AI search.

---

## 2. What's **partial** today (🟡) and when it lands

| Capability | Today | Becomes ✅ in |
|---|---|---|
| **WebAuthn / passkeys** | Storage + list/delete work; ceremony returns `501` | 🗓️ [Sprint 3](./sprints/sprint-3.md) (+ recovery) |
| **Social login** (Google/GitHub/MS/Apple) | Provider config + identity linking work; OAuth exchange returns `501` | 🗓️ [Sprint 11](./sprints/sprint-11.md) |
| **Real email / SMS delivery** | `LogSender` → stdout only | 🗓️ [Sprint 3](./sprints/sprint-3.md) |
| **RS256/ES256 + JWKS rotation** | HS256, empty JWKS (external RPs can't verify) | 🗓️ [Sprint 4](./sprints/sprint-4.md) |
| **OIDC completeness** | Auth Code + PKCE done; refresh/introspect/revoke/logout missing | 🗓️ [Sprint 4](./sprints/sprint-4.md) |
| **Group-level RBAC** | Groups exist; permissions are user-level only | 🗓️ [Sprint 2](./sprints/sprint-2.md) |
| **Policy enforcement** | IP/MFA/session-age stored but not enforced in the request path | 🗓️ [Sprint 10](./sprints/sprint-10.md) |
| **Distributed rate limiting** | In-memory token bucket (single-process) | 🗓️ [Sprint 15](./sprints/sprint-15.md) / Redis |
| **Argon2id passwords** | bcrypt cost 12 | 🗓️ [Sprint 9](./sprints/sprint-9.md) |

---

## 3. Qeet ID vs. competitors — support matrix

> Competitor columns reflect each vendor's flagship offering. Qeet ID column uses the legend above (✅ / 🟡 / 🗓️ S# / ❌).

### Core authentication

| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Email/password + sessions | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Refresh rotation **+ theft detection** | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ |
| Magic links | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ |
| Email/SMS OTP **delivery** | 🟡 S3 | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ |
| TOTP MFA + recovery codes | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Passkeys / WebAuthn** | 🟡 S3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Social login** | 🟡 S11 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Account linking / identity merge | 🗓️ S11 | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ |

### Protocols & tokens

| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| OIDC provider (Auth Code + PKCE) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RS256/ES256 + JWKS rotation | 🟡 S4 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Refresh / introspect / revoke / logout | 🗓️ S4 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `client_credentials` / M2M | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Device flow / token-exchange / CIBA | 🗓️ S7/S19 | ✅ | ❌ | 🟡 | 🟡 | ✅ | ✅ | 🟡 | ✅ |

### Enterprise (B2B)

| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **SAML 2.0 SSO** | 🗓️ S12 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| **SCIM 2.0 provisioning** | 🗓️ S13 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Org-level SSO connections | 🗓️ S13 | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |
| LDAP / AD federation | 🗓️ S14 | ✅ | 🟡 | ✅ | 🟡 | ✅ | ✅ | 🟡 | 🟡 |
| **Self-serve admin portal** | 🗓️ S14 | 🟡 | 🟡 | ✅ | ✅ | ❌ | 🟡 | 🟡 | ❌ |
| Multi-tenant / Organizations | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |

### Authorization

| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| RBAC | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| Group-level RBAC | 🗓️ S2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Fine-grained / ReBAC | 🗓️ S19 | ✅ FGA | 🟡 | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ Keto |
| **Explainable authz ("why?")** | 🗓️ S2 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 |

### Security & operations

| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Adaptive / risk-based MFA + step-up | 🗓️ S15 | ✅ | 🟡 | 🟡 | ✅ | 🟡 | ✅ | 🟡 | 🟡 |
| Bot detection | 🗓️ S15 | ✅ | 🟡 | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| Breached-password detection | 🗓️ S15 | ✅ | ✅ | 🟡 | ✅ | 🟡 | ✅ | 🟡 | 🟡 |
| Brute-force / IP throttling | 🟡 S15 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Tamper-evident (hash-chained) audit** | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | ❌ | 🟡 | 🟡 | ❌ |
| **Externally-verifiable audit (Merkle)** | 🗓️ S5 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Webhooks + DLQ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |
| GDPR erasure / data export | ✅ | ✅ | ✅ | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | 🟡 |

### Developer experience & extensibility

| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Prebuilt UI components | 🗓️ S17 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| Hosted / embeddable login UI | 🗓️ S17 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| First-party client SDKs | 🗓️ S16 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Actions / Hooks extensibility | 🗓️ S18 | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | ✅ | ✅ | 🟡 |
| AI-agent / MCP identity + delegation | 🗓️ S7 | 🟡 | ❌ | 🟡 | 🟡 | ❌ | ❌ | 🟡 | ✅ |
| **Built-in test mode / dev inbox** | 🗓️ S1 | 🟡 | 🟡 | ❌ | ❌ | ❌ | 🟡 | ❌ | ❌ |

### Business model

| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **Open source** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | 🟡 | ✅ | ✅ |
| **Self-hostable** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **No "SSO tax"** (SAML/SCIM not paywalled) | ✅* | ❌ | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | ✅ | ✅ |
| Data residency + BYOK | 🗓️ S20 | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | ✅ | 🟡 |
| Billing built-in | 🗓️ S20 | n/a | ✅ | n/a | 🟡 | ❌ | ❌ | ❌ | ❌ |

<sub>* Positioning commitment: enterprise SSO/SCIM are included, not gated behind premium tiers, once shipped ([Sprint 14](./sprints/sprint-14.md)).</sub>

---

## 4. Where Qeet ID is **different** (and aims to win)

Beyond matching the field, Qeet ID is building features that solve problems competitors **don't** — see the [sprint plan](./sprints/README.md) for the full catalog (D1–D14):

- **Tamper-evident audit you can prove to a third party** — hash-chained today (✅), externally-verifiable Merkle checkpoints next (🗓️ S5). No mainstream CIAM offers independent audit verification.
- **Explainable Authorization** — a `why was this allowed/denied?` decision trace (🗓️ S2). Every other RBAC system returns a bare boolean.
- **Built-in Test Mode + Dev Inbox** — capture OTPs/magic links and control the clock so testing auth takes seconds (🗓️ S1).
- **Resilient passwordless recovery** — a multi-factor recovery quorum that fixes the #1 unsolved passkey problem (🗓️ S3).
- **First-class AI-agent identity** — scoped, revocable, auditable delegation (`sub=agent, act=human`), MCP-native (🗓️ S7).
- **Zero-downtime universal importer** — migrate off Auth0/Cognito/Firebase **keeping existing password hashes** (no forced resets) (🗓️ S9).
- **Safe impersonation + tenant kill-switch** — guarded support mode and instant breach containment (🗓️ S8).
- **Time-Travel Identity** — "what could this user access on date Y?" for audits/incidents (🗓️ S19).
- **Break-glass admin recovery + auth canaries** — survive locking yourself out of your own IdP; know your auth is healthy before users do (🗓️ S18).
- **Open-source, self-hostable, no SSO tax** — the enterprise feature set without the enterprise paywall.

---

## 5. Honest bottom line

**Use Qeet ID today for:** password + magic-link auth, TOTP MFA, multi-tenant RBAC with a `check` API, API keys & M2M, an OIDC provider (Auth Code + PKCE), tamper-evident audit, webhooks, and GDPR erasure — all open-source and self-hosted.

**Not ready yet (scheduled):** passkeys & social login ceremonies, real email/SMS, RS256/JWKS, SAML/SCIM/LDAP, attack protection, client SDKs & hosted UI, fine-grained authz, billing. Every one of these has a sprint — see the [coverage matrix](./sprints/README.md#coverage-matrix--every-gap-mapped-to-a-sprint).

**Closest architectural peer:** Zitadel (open-source, Go, multi-tenant). **Biggest current gap vs. the field:** enterprise federation (SAML/SCIM) and the client-integration surface (SDKs + hosted UI). **Biggest edge:** verifiable audit, explainable authorization, and the developer/operations features in §4.

> This page mirrors the verified inventory in [COMPETITIVE-ANALYSIS-AND-ROADMAP.md](./COMPETITIVE-ANALYSIS-AND-ROADMAP.md). Keep both in sync: when a 🟡/🗓️ feature ships, flip it to ✅ here and in the roadmap matrix.
