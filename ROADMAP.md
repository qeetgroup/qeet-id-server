# Qeet ID — Roadmap

The full picture of **what's available today** and **what's planned next** — plus the internal
package structure that lands with future work. The [README](./README.md) links here.

**Legend:** ✅ shipped · 🟠 planned (high) · 🟡 planned (medium) · 🟢 planned (later) · ⏳ external ops (not code)
**Status:** pre-1.0, **July 2026 GA** target — reconciled against source on 2026-07-06 (migrations 0001–0064, `domains/`/`apps/`/`sdk/`). Every ✅ below is backed by real code; remaining gaps live in the 🔭 Planned section.
This file is the **single source of truth** for shipped-vs-pending status and the competitive matrix (see 🏁 Competitive position below) — it absorbed the retired `QEET-ID-STATUS.md` on 2026-07-06. The competitive backlog is distilled by the [`product-manager`](./.claude/agents/product-manager.md) agent into `qeet-files/qeet-id/FEATURE-PROPOSALS.md`.

---

## 🚢 Deployment (current → future)

**Current:** live on **EC2 + Docker Compose + Caddy (auto-TLS) + AWS RDS** (`ap-south-2`); image built/pushed to GHCR and shipped over SSH. Config lives in `deploy/` (`Caddyfile`, `docker-compose.yml`, runbook `README.md`).

**Future (in git history, restore when ready):**
- 🟡 **Kubernetes + Helm** — chart with Deployment/Service/Ingress/HPA/PDB + pre-upgrade migration Job + ExternalSecrets; per-env `values.yaml` for stage + prod
- 🟡 **AWS Terraform** — RDS, ECR, KMS CMK, Secrets Manager; root module + per-env `tfvars`
- 🟢 **Multi-env staging** — `environments/stage/` overlay; promote dev → stage → prod pipeline
- 🟢 **Observability stack** — Prometheus scrape rules, Grafana dashboard, OTel Collector config

---

## ✅ Shipped — available today

### 🔑 Authentication & sessions
- ✅ Email + password (Argon2id, OWASP params, per-account lockout, enumeration-safe)
- ✅ Passkeys / WebAuthn (FIDO2, resident credentials, cross-device)
- ✅ Magic links · email OTP · SMS OTP
- ✅ TOTP (RFC 6238) + 8 recovery codes · MFA step-up (per-operation elevation)
- ✅ Adaptive / risk-based MFA — per-tenant risk thresholds drive step-up / force-MFA (`0063_risk_settings`)
- ✅ Session management — refresh rotation + theft detection + silent revocation
- ✅ Breached-password detection (HIBP k-anonymity, env-gated) · password reset

### 🏢 Enterprise SSO & provisioning
- ✅ OIDC / OAuth 2.0 provider — discovery, JWKS, Auth Code + PKCE, `/userinfo`, refresh, revoke, introspect, logout, signing-key rotation, RFC 9728 PRM + RFC 8707 resource indicators (partial)
- ✅ Device Authorization Grant (RFC 8628) · Token Exchange (RFC 8693 — downscope + `act` delegation)
- ✅ SAML 2.0 — **SP and IdP** modes · SCIM 2.0 (users + groups + PatchOp) · LDAP / Active Directory
- ✅ Social login (Google, GitHub, Microsoft, Apple, custom) · account linking · SSO test-connection

### 🛡️ Authorization
- ✅ RBAC (roles, group-derived perms, single-call `/check`, **explainable `?explain=true` grant-path trace**) · per-tenant policy (IP allow/deny CIDR, password/login-method rules) *(this is tenant policy — not a general attribute-condition ABAC engine)*
- ✅ **ReBAC** (Zanzibar-style `relation_tuples`, recursive `/check` with cycle guard) *(grant-path trace is RBAC-only; ReBAC `/check` returns `{allowed}` today)*
- ✅ IP allow/deny (CIDR) · Auth Hooks / Actions (post-login **allow/deny**, HMAC-signed) *(custom-claim injection not yet implemented)*

### 🤖 Developer & AI-agent platform
- ✅ Scoped API keys (`qk_`, hashed, audited) · service accounts (`client_credentials` M2M)
- ✅ Secrets vault (AES-256-GCM, scoped `vault:<name>`, **real AWS KMS provider** wired + tested) · HMAC-SHA256 webhooks (backoff retry)
- ✅ **AI-agent identity** — ephemeral scoped revocable tokens (`actor_type=agent`) + tenant-wide **kill-switch** (`/agents/kill-all`)
- ✅ **MCP introspection** (`actor_type`/`agent_id`/`act` on `/oauth/introspect`) · token delegation (RFC 8693 `act`)
- ✅ **W3C Verifiable Credentials** (JWT-VC issue / verify / revoke) · analytics · SIEM streaming

### 👥 Identity & workspace
- ✅ Multi-tenant organisations (isolated, per-tenant branding, custom domains)
- ✅ Users (CRUD, sessions, recycle bin: soft-delete → restore/purge) · nested groups (SCIM sync) · invitations *(bulk CSV import is not built — only single-user create; see 🔭 Planned / issue #173)*
- ✅ Domain verification (DNS TXT) · per-tenant email templates · org switcher + branding preview

### 📜 Compliance & billing
- ✅ SHA-256 hash-chained audit log (`/verify` integrity walk) · GDPR erasure + grace-period purge · retention auto-purge
- ✅ Multi-currency billing (ISO-4217) · card payments — Stripe (global) + Razorpay (India), webhook-verified (env-gated)
- 🟡 Data export endpoint **not built**; SOC 2 / ISO 27001 compliance screens are **static templates**, not generated evidence

### 🧰 Platform & delivery
- ✅ 3 React frontends (admin console ~80 screens, hosted login, marketing site) · **6 SDK packages** (TS server + browser, React w/ full `<SignIn/>`/`<OrgSwitcher/>`/… component suite, Next.js, Go, Python) · per-tenant rate-limit overrides (`0064`)
- ✅ Transactional outbox **+ DLQ** · webhook dispatcher (HMAC, backoff retry) · Prometheus/OTel observability · `config.Validate()` boot-gate *(webhooks don't yet ride the outbox/DLQ — retry is unbounded)*
- ✅ Docker Compose + Caddy (auto-TLS) on EC2 deploy · CI gates: arch fitness R1/R2, 100% OpenAPI route coverage, **CodeQL** *(Helm/Terraform/kustomize are in git history, not the tree — see 🚢 Deployment above; govulncheck/gitleaks are not wired)*

---

## 🔭 Planned — not yet available

### Product roadmap
| Feature | Priority | Notes |
|---|---|---|
| CIBA grant (Client-Initiated Backchannel Auth) | 🟠 | Push/email async consent for elevated tokens |
| Data export endpoint | 🟠 | GDPR erasure ships; a user/tenant data-export endpoint is not built (was listed shipped in error) |
| Bulk user import (CSV) | 🟡 | Only single-user `POST /users` ships; the console import screen has no backend endpoint (issue #173, was listed shipped in error) |
| ReBAC grant-path trace | 🟡 | RBAC `/check` explains "why"; ReBAC `/check` returns `{allowed}` only |
| Auth-hook custom claims | 🟡 | Hooks gate allow/deny today; token claim-injection not implemented |
| Webhook DLQ | 🟡 | Webhook retry is unbounded; wire onto the platform outbox/DLQ or add a give-up + dead state |
| i18n — remaining coverage | 🟡 | 8 console catalogs (en+7) exist w/ partial namespaces; remaining screens + locale-aware emails + login app pending |
| WCAG 2.2 AA — a11y gate + legacy screens | 🟡 | ⚠️ the a11y eslint globs point at renamed `qeetid-admin`/`qeetid-login` dirs (gate matches 0 files today); fix globs, then audit ~70 older screens |
| SOC 2 / ISO 27001 evidence generation | 🟡 | Compliance screens are static templates; generated evidence pending |
| Adaptive-MFA depth | 🟢 | Threshold engine ships (`0063`); richer signals (impossible-travel, device reputation) pending |

### 🤖 AI-agent identity & governance
*Surfaced by the `product-manager` agent from live competitive research (Auth0 / Okta / WorkOS / Descope / Microsoft Entra).*

| Feature | Priority | What it adds |
|---|---|---|
| **Token Vault** | 🟠 | Per-tenant encrypted store for third-party OAuth refresh tokens, so agents call Slack/GitHub/Google on a user's behalf without handling tokens |
| **MCP AS compliance (finish)** | 🟠 | RFC 9728 PRM + RFC 8707 are **live but shallow** (resource validated, not bound into token audience); add audience-binding + RFC 9207 `iss` |
| **Agent lifecycle state machine** | 🟠 | `active`/`suspended`/`decommissioned` states + sponsor auto-transfer; *bulk kill-switch (`/agents/kill-all`) + single-agent revoke already ship* |
| **Agent-as-Principal** | 🟡 | First-class non-human OIDC principal (`sub_type=agent`, separate `sub` namespace, discovery metadata) |
| **Shadow-AI discovery** | 🟡 | Flag OAuth clients holding live grants but not registered as managed principals |
| **Agent sponsor model** | 🟡 | Every agent tied to a named human owner; auto-transfer on offboarding (no orphaned agents) |
| **AuthZEN PDP/PEP** | 🟡 | OpenID AuthZEN-standard `/evaluation` endpoint + COAZ MCP-tool profile over the existing authz engine |
| **SSF / CAEP events** | 🟡 | Real-time `session-revoked` / `token-claims-change` signals pushed to downstream gateways |
| **Device-bound agent credentials** | 🟢 | TPM/enclave-attested keys + RFC 8705 mTLS — non-exportable, non-replayable M2M creds |

### 🧰 Developer experience
| Feature | Priority | What it adds |
|---|---|---|
| `qeetid` management CLI | 🟡 | Single Go binary over the Management API: `migrate`, `keys rotate`, `agents suspend`, `audit export` — `--json` for CI/agents |
| FGA Permissions Index | 🟡 | Pre-computed ReBAC flattening for sub-ms authz in RAG/AI workloads |
| Rust SDK | 🟢 | Async crate scoped to machine identity (client credentials, JWKS, token exchange) |
| SCIM agent extension | 🟢 | `Agent`/`AgenticApplication` resource types (watch `draft-abbey-scim-agent-extension`) |

### ⏳ External ops hardening (not code)
- AWS **KMS BYOK go-live** (provider **implemented, wired & tested** — needs a live KMS key/CMK provisioned) · **OpenID conformance** run against a deployed instance
- Email **deliverability** (SPF/DKIM/DMARC + bounce handling) · **RDS PITR** / backups · external **penetration test**
- Billing **go-live** (Stripe/Razorpay env keys) · managed-cloud infrastructure (multi-region, autoscaling)

---

## 🏁 Competitive position

> **Qeet ID in one line:** an open-source, self-hostable, **passkeys-first** identity platform with the developer experience of Clerk, the enterprise model of WorkOS, and a tamper-evident audit log nobody else ships — **without the "SSO tax."**
>
> *(This matrix was merged in from the retired `QEET-ID-STATUS.md` on 2026-07-06 — ROADMAP.md is now the single source for both shipped/pending status and competitive positioning.)* Competitor columns reflect each vendor's flagship offering as of the prior analysis (2026-05) and may have shifted; the Qeet ID column is current as of 2026-07-06. ✅ generally available · 🟡 limited/gated/add-on · ⏳ planned · ❌ not offered.

### Core authentication
| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Email/password + sessions | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Refresh rotation **+ theft detection** | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ |
| Magic links | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ |
| Email/SMS OTP | ✅¹ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ |
| TOTP MFA + recovery codes | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Passkeys / WebAuthn** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **WebAuthn as 2nd factor + step-up** | ✅ | ✅ | 🟡 | 🟡 | ✅ | 🟡 | ✅ | 🟡 | 🟡 |
| **Social login** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Account linking / identity merge | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Per-account lockout / brute-force | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

<sub>¹ Senders wired; production deliverability needs a sending domain (SPF/DKIM/DMARC).</sub>

### Protocols & tokens
| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| OIDC provider (Auth Code + PKCE) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **ES256/RS256 + JWKS rotation** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Refresh / introspect / revoke / logout | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Hosted login + consent | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| `client_credentials` / M2M | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Device Authorization Grant (RFC 8628) | ✅ | ✅ | ❌ | 🟡 | 🟡 | ✅ | ✅ | 🟡 | ✅ |
| **Token Exchange (RFC 8693) + delegation** | ✅ | ✅ | ❌ | 🟡 | 🟡 | ✅ | ✅ | 🟡 | ✅ |
| MCP AS metadata (RFC 9728 + 8707) | 🟡⁴ | ⏳ | ❌ | 🟡 | ❌ | ❌ | ❌ | ❌ | 🟡 |
| CIBA (backchannel) | ⏳ | ✅ | ❌ | 🟡 | 🟡 | ✅ | 🟡 | 🟡 | 🟡 |

<sub>⁴ RFC 9728 Protected Resource Metadata + RFC 8707 resource indicators are advertised and validated, but the `resource` is not yet bound into the token audience (shallow); RFC 9207 `iss` pending.</sub>

### Enterprise (B2B)
| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **SAML 2.0 — SP (consume IdP)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| **SAML 2.0 — IdP (be an SSO source)** | ✅ | ✅ | 🟡 | ✅ | 🟡 | ✅ | ✅ | ✅ | ❌ |
| **SCIM 2.0 — Users + Groups** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Org-level SSO connections (per tenant) | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |
| Domain verification / SSO-by-domain | ✅ | ✅ | ✅ | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | ❌ |
| LDAP / AD federation | ✅ | ✅ | 🟡 | ✅ | 🟡 | ✅ | ✅ | 🟡 | 🟡 |
| Multi-tenant / Organizations | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |
| Self-serve SSO/SCIM admin UI | ✅ | 🟡 | 🟡 | ✅ | ✅ | ❌ | 🟡 | 🟡 | ❌ |

### Authorization
| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| RBAC + single-call `/check` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| ABAC / policy | 🟡⁵ | 🟡 | ❌ | 🟡 | 🟡 | ✅ | ✅ | 🟡 | ✅ |
| Group-level RBAC | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Fine-grained / ReBAC (Zanzibar)** | ✅ | ✅ FGA | 🟡 | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ Keto |
| **Explainable authz ("why?")** | ✅⁶ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 |

<sub>⁵ Per-tenant IP allow/deny (CIDR) + password/login-method policy, not a general attribute-condition engine. ⁶ Explainable trace is on **RBAC** `/check` (`?explain=true`); the ReBAC `/check` returns `{allowed}` only.</sub>

### Security & operations
| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **Tamper-evident (hash-chained) audit** | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | ❌ | 🟡 | 🟡 | ❌ |
| **Externally-verifiable audit (Merkle)** | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Webhooks (HMAC, backoff retry) | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |
| **SIEM streaming (push to sinks)** | ✅ | 🟡 | ✅ | 🟡 | 🟡 | ❌ | 🟡 | 🟡 | ❌ |
| GDPR erasure | ✅ | ✅ | ✅ | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | 🟡 |
| Data export | ⏳ | ✅ | ✅ | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | 🟡 |
| Distributed rate limiting (Redis) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Metrics + distributed tracing (OTel) | ✅ | ✅ | 🟡 | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ |
| Adaptive / risk-based MFA | 🟡³ | ✅ | 🟡 | 🟡 | ✅ | 🟡 | ✅ | 🟡 | 🟡 |
| **Bot detection** | ✅ | ✅ | 🟡 | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| Breached-password detection | ✅ | ✅ | ✅ | 🟡 | ✅ | 🟡 | ✅ | 🟡 | 🟡 |
| Secrets vault / BYOK (KMS) | ✅⁷ | ✅ | ❌ | 🟡 | 🟡 | 🟡 | 🟡 | ✅ | 🟡 |

<sub>³ A threshold-based risk engine ships (`0063_risk_settings` → step-up/force-MFA by risk level); richer signals (impossible-travel, device reputation) are the follow-up. ⁷ AES-256-GCM vault + a wired, tested AWS KMS provider; only provisioning a live CMK (BYOK rollout) is external ops.</sub>

### Developer experience & delivery
| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| First-party client SDKs | ✅ (TS×2/React/Next/Go/Python) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Hosted login UI | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| Prebuilt React components | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| i18n + WCAG 2.2 AA (scaffolded) | 🟡 | ✅ | ✅ | ✅ | 🟡 | ✅ | 🟡 | 🟡 | 🟡 |
| OpenAPI spec (100% route coverage) | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| IaC / deploy | 🟡⁸ | n/a | n/a | n/a | n/a | 🟡 | 🟡 | ✅ | 🟡 |
| **Actions / Hooks extensibility** | ✅ | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | ✅ | ✅ | 🟡 |
| **AI-agent / MCP identity + delegation** | ✅ | 🟡 | ❌ | 🟡 | 🟡 | ❌ | ❌ | 🟡 | ✅ |
| **Verifiable Credentials (W3C JWT-VC)** | ✅ | ❌ | ❌ | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ |

<sub>⁸ Ships as Docker Compose + Caddy on EC2 + a DR runbook; a Helm chart + Terraform live in git history (see 🚢 Deployment above), not the current tree.</sub>

### Business model
| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **Open source** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | 🟡 | ✅ | ✅ |
| **Self-hostable** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **No "SSO tax"** (SAML/SCIM not paywalled) | ✅ | ❌ | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | ✅ | ✅ |
| Data residency + BYOK | 🟡 | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | ✅ | 🟡 |
| Billing built-in (multi-currency + cards) | 🟡² | n/a | ✅ | n/a | 🟡 | ❌ | ❌ | ❌ | ❌ |

<sub>² Stripe + Razorpay checkout code complete & webhook-verified; go-live needs env keys.</sub>

**Where Qeet ID wins:** both an OIDC **and** SAML IdP with SCIM Users+Groups (open-source, not paywalled); tamper-evident hash-chained audit with `/verify`; a full agentic-identity stack (AI-agent identities + RFC 8693 delegation + MCP introspection + token vaulting + W3C VCs); ReBAC + explainable RBAC authz; and security-on-by-default (theft detection, lockout, prod boot-gate, bot detection). **Closest peer:** Zitadel. **Remaining gaps vs. the field:** CIBA, data export, ReBAC grant-path explainability, richer adaptive-MFA signals, and KMS BYOK go-live (ops).

<details><summary>Competitive research sources (2025–2026)</summary>

- Logto — *2025 Auth0 pricing & alternatives*: https://blog.logto.io/auth0-pricing-explain
- SSOJet — *Auth0 support after Okta (2025)*: https://ssojet.com/blog/auth0-support-after-okta
- SuperTokens — *Okta alternatives*: https://supertokens.com/blog/okta-alternatives
- Okta SEC 8-K (FY2024 breach disclosure): https://www.sec.gov/Archives/edgar/data/0001660134/000166013424000107/okta-62420248xkex991.htm
- IBM — *What is non-human identity*: https://www.ibm.com/think/topics/non-human-identity
- NIST — *First 3 finalized PQC standards (FIPS 203/204/205)*: https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
- Cloudflare — *PQC support (X25519MLKEM768)*: https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-support/
- IETF — *ML-DSA for JOSE/COSE* (`draft-ietf-cose-dilithium`): https://www.ietf.org/archive/id/draft-ietf-cose-dilithium-04.html
- IETF — *ML-DSA for WebAuthn* (`draft-vitap-ml-dsa-webauthn`): https://datatracker.ietf.org/doc/draft-vitap-ml-dsa-webauthn/

</details>

---

## 🧱 Internal structure — planned packages & directories

Placeholder directories were removed so the tree only contains real code; the intent is recorded here.
**Create the directory the day code lands in it.**

### Platform (infrastructure)
| Planned package | Purpose | Notes |
|---|---|---|
| `platform/api/grpc` | gRPC server setup, interceptors | Pairs with `api/protobuf/`. REST-first today. |
| `platform/api/openapi` | OpenAPI loading/validation helpers | Specs live in `api/openapi/`; coverage guard in `platform/api/rest`. |
| `platform/cache/memory` | In-process LRU/TTL cache | e.g. WebAuthn challenge sessions, TOTP replay window. |
| `platform/database/repositories` | Shared repository base types/helpers | Generic paginator, `Transactor`, bulk insert. |
| `platform/events/publisher` | Unified `Publisher` interface | Over outbox/Kafka/NATS. Outbox exists at `platform/events/outbox`. |
| `platform/events/subscriber` | In-process/durable event consumers | Fan-out bus. |
| `platform/events/schemas` | Canonical event schema definitions | Shared producer/consumer types. |
| `platform/messaging/kafka` | Kafka producer/consumer wrappers | For cross-service streaming. |
| `platform/messaging/nats` | NATS JetStream wrappers | Lightweight alternative to Kafka. |
| `platform/messaging/queues` | Generic async job queue | DB-backed (outbox) or in-process. |
| `platform/observability/alerts` | Prometheus alert-rule generation | Runtime rules in git history. |
| `platform/observability/dashboards` | Grafana dashboard generation | Runtime dashboards in git history. |
| `platform/scheduler` | Cron-style maintenance scheduler | Session cleanup, retention purge, outbox sweep. |
| `platform/security/kms` | AWS KMS / envelope-encryption client | Used when `SECRETS_PROVIDER=aws-kms` (powers KMS BYOK above). |
| `platform/security/secrets` | Promoted per-tenant vault client | Real impl today: `domains/developer/credentials/secrets`. |
| `platform/security/signing` | Unified `Signer`/`Verifier` | Webhook HMAC, SAML XML-Dsig, JWT today live in their packages. |
| `platform/storage` | Object/blob storage client | S3-compatible: avatars, audit exports. |
| `platform/tenancy` | Tenancy primitives + ctx propagation | Today enforced via raw `tenant_id` per query. |
| `platform/testing` | Lightweight unit-test helpers | Integration helpers live in `tests/fixtures/`. |

### Domains (business contexts)
| Planned domain | Context | Purpose |
|---|---|---|
| `access/sessions` | access | First-class session entity (today folded into auth). |
| `access/passwords` | access | Password lifecycle/history as its own concern. |
| `access/devices` | access | Device registry (pairs with device-bound agent creds above). |
| `access/trusted-devices` | access | Remembered/trusted device management. |
| `access/lockout` | access | Lockout as a dedicated package (today in auth + migration 0041). |
| `identity/memberships` | identity | Membership entity distinct from RBAC user_roles. |
| `identity/profiles` | identity | Extended user profile data. |
| `federation/oauth2` | federation | Generic OAuth2 (beyond OIDC/social). |
| `federation/provisioning` | federation | Provisioning beyond SCIM. |
| `developer/bots` | developer | Bot identities distinct from agents. |
| `developer/integrations` | developer | Third-party integration registry. |
| `operations/subscriptions` | operations | Subscriptions split from billing. |
| `operations/invoices` | operations | Invoices split from billing. |
| `operations/exports` | operations | Data-export jobs (GDPR/analytics). |
| `operations/log-streaming` | operations | Real-time log streaming (SIEM is `operations/siem`). |

### API surfaces
| Planned | Purpose |
|---|---|
| `api/protobuf/` | gRPC `.proto` service definitions (REST-first today). |
| `api/contracts/` | Consumer-driven contract tests (Pact-style) for SDKs/frontends. |
