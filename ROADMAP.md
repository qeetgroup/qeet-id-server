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
- ✅ Passkeys / WebAuthn (FIDO2, resident credentials, cross-device) · **passkey-first signup** — a passkey can found a new account directly, no password required (`/signup/passkey/*` tenant-less, `/register/passkey/*` hosted signup UI; password stays available as an alternative)
- ✅ Magic links · email OTP · SMS OTP
- ✅ TOTP (RFC 6238) + 8 recovery codes · MFA step-up (per-operation elevation)
- ✅ Adaptive / risk-based MFA — per-tenant risk thresholds drive step-up / force-MFA (`0063_risk_settings`), extended with two additive, independently-togglable signals on top of the base bot-score engine (`0077_adaptive_risk`, off by default): **impossible travel** (a login from a new country sooner than a configurable minimum plausible travel time after the last one — geo comes from a trusted upstream proxy header, e.g. Cloudflare's `CF-IPCountry`; no signal configured = the check never fires, fail-open) and **device reputation** (a login from a browser+OS combination never seen before for that user)
- ✅ Session management — refresh rotation + theft detection + silent revocation, plus a pragmatic, CAEP/SSF-*shaped* real-time revocation path (not full protocol interop): a 10-minute access-token TTL bounds how long a revoked-but-unexpired token stays usable (access tokens are stateless JWTs — no per-request DB check); `POST /auth/refresh` now also rejects a suspended or soft-deleted user's still-valid refresh token (previously only the session's own `revoked_at` was checked — a plain status change never touched `auth.sessions`); and two signals ride the existing webhook dispatcher so a subscribed tenant reacts immediately instead of waiting out the TTL — `session.revoked` (logout, explicit session revoke, and refresh-token-reuse theft detection) and `token.claims_change` (a direct role grant/revoke). Both are opt-in via the webhook's own `events` filter, no new settings surface
- ✅ Breached-password detection (HIBP k-anonymity, env-gated) · password reset

### 🏢 Enterprise SSO & provisioning
- ✅ OIDC / OAuth 2.0 provider — discovery, JWKS, Auth Code + PKCE, `/userinfo`, refresh, revoke, introspect, logout, signing-key rotation, RFC 9728 PRM + **RFC 8707 resource indicators bound into the token audience** across authorization_code, refresh_token (preserved across rotation, or switched via an explicit `resource`), and token-exchange · RFC 9207 `iss` on the authorize redirect (success and error) *(device grant doesn't collect a resource indicator yet)*
- ✅ Device Authorization Grant (RFC 8628) · Token Exchange (RFC 8693 — downscope + `act` delegation) · **CIBA** (poll mode — a client resolves the user via `login_hint`, no browser redirect; async consent via an in-app notification + `/oauth/bc-authorize/{pending,decision}`)
- ✅ SAML 2.0 — **SP and IdP** modes · SCIM 2.0 (users + groups + PatchOp) · LDAP / Active Directory
- ✅ **Self-serve Admin Portal** — a tenant admin generates a capability-scoped (`saml`/`scim`), time-limited link (`POST /tenants/{id}/admin-portal/links`) their *own* IT admin follows to configure the SAML connection and/or roll the SCIM token directly — no Qeet ID account, no console login. Possession of the link is the sole credential (hashed at rest, revocable, not single-use); the hosted page at `{LoginBaseURL}/admin-portal/{token}` renders on the tenant's brand. Closes the gap against WorkOS's Admin Portal, the category leader for this pattern
- ✅ Social login (Google, GitHub, Microsoft, Apple, custom) · account linking · SSO test-connection

### 🛡️ Authorization
- ✅ RBAC (roles, group-derived perms, single-call `/check`, **explainable `?explain=true` grant-path trace**) · per-tenant policy (IP allow/deny CIDR, password/login-method rules) *(this is tenant policy — not a general attribute-condition ABAC engine)*
- ✅ **ReBAC** (Zanzibar-style `relation_tuples`, recursive `/check` with cycle guard, **`?explain=true` grant-path trace** — root-to-leaf chain of tuples, mirrors RBAC's explain shape)
- ✅ IP allow/deny (CIDR) · Auth Hooks / Actions (post-login **allow/deny + custom-claim injection**, HMAC-signed) *(claims flow into the direct API-token login path, incl. MFA; the hosted-login SSO cookie → OIDC ID-token path doesn't carry them yet)*

### 🤖 Developer & AI-agent platform
- ✅ Scoped API keys (`qk_`, hashed, audited) · service accounts (`client_credentials` M2M)
- ✅ Secrets vault (AES-256-GCM, scoped `vault:<name>`, **real AWS KMS provider** wired + tested) · **Token Vault** — per-tenant encrypted store for third-party OAuth tokens (any registered provider — Slack/GitHub/Google/custom), a standard authorization-code connect ceremony, and a `GetAccessToken` API that transparently refreshes and never exposes the raw refresh token to the caller — an agent holding an RFC 8693-delegated token reaches the delegating user's own connected account · HMAC-SHA256 webhooks (backoff retry + dead-letter give-up after `maxDeliveryAttempts`)
- ✅ **AI-agent identity** — ephemeral scoped revocable tokens (`actor_type=agent`) + tenant-wide **kill-switch** (`/agents/kill-all`) + **lifecycle state machine** (`active`/`suspended`/`decommissioned`, `0065_agent_lifecycle`) + **sponsor model** (every agent requires a named human owner who's an actual tenant member; `TransferSponsor` reassigns everything an offboarding sponsor owned in one call)
- ✅ **MCP introspection** (`actor_type`/`agent_id`/`act` on `/oauth/introspect`) · token delegation (RFC 8693 `act`) · **Agent-as-Principal** — first-class non-human principal self-described via `actor_type`+`agent_id` claims (not a `sub`-prefix convention, which would break RFC 8693 token exchange's subject-token UUID parsing), advertised via discovery's `actor_types_supported` · **Shadow-AI discovery** — flags OIDC clients that picked up a machine grant type (`client_credentials`/token-exchange) without going through the agents/service-accounts registry, ranked by live refresh-token count; `.../oidc/clients/{id}/review` acknowledges one
- ✅ **AuthZEN PDP/PEP** — OpenID AuthZEN-standard `POST /tenants/{id}/access/v1/evaluation`, a spec-shaped facade routing to the existing RBAC/ReBAC engines (`resource.type="permission"` → RBAC; anything else → ReBAC using `"type:id"`/relation), with `context.explain` returning the same grant-path trace as each engine's own `?explain=true` — lets an external policy-enforcement point (e.g. an MCP tool-call gateway) speak one standard protocol instead of Qeet ID's bespoke `/check` shape
- ✅ **Agent Governance** — everything above is packaged as one named console surface (`/developer/agents`, renamed from "AI Agents"), not scattered settings: agent create/suspend/kill-all, a sponsor-transfer tool (search-select the departing/new sponsor, previews the affected count before confirming), and a Shadow-AI review queue (acknowledge unmanaged machine-grant clients). Token Vault and CIBA are governed by the same primitives but remain API-only — no console UI (documented, not built) — since neither has an admin-facing workflow distinct from their API contract yet
- ✅ **W3C Verifiable Credentials** (JWT-VC issue / verify / revoke) · analytics · SIEM streaming

### 👥 Identity & workspace
- ✅ Multi-tenant organisations (isolated, per-tenant branding, custom domains)
- ✅ Users (CRUD, sessions, recycle bin: soft-delete → restore/purge) · nested groups (SCIM sync) · invitations · bulk import (console parses CSV/NDJSON client-side, posts to `POST /users/bulk`; per-row partial-success reporting) · **IdP migration import** (`POST /users/bulk/import?source=auth0|cognito|azure_b2c` — converts that vendor's own export file, no portable password carried over)
- ✅ Domain verification (DNS TXT) · per-tenant email templates · org switcher + branding preview

### 📜 Compliance & billing
- ✅ SHA-256 hash-chained audit log (`/verify` integrity walk) · **audit intelligence** — a background sweep builds a rolling behavioral baseline per `(tenant, actor)` (action types, hour-of-day, IPs) and flags deviations (first-time action, unusual hour, new IP) as a transparent, weighted-novelty score with named reasons — not a black-box model; per-tenant threshold + cold-start guard, console screen at Security & Compliance → Audit Intelligence · GDPR erasure + grace-period purge · retention auto-purge
- ✅ GDPR data export — async job (`user.export_requests`), payload covers profile/sessions/passkeys/roles/MFA status, `/gdpr/export` + `/gdpr/export/{id}` download
- ✅ Multi-currency billing (ISO-4217) · card payments — Stripe (global) + Razorpay (India), webhook-verified (env-gated)
- 🟡 SOC 2 / ISO 27001 compliance screens are **static templates**, not generated evidence

### 🧰 Platform & delivery
- ✅ 3 React frontends (admin console ~80 screens, hosted login, marketing site) · **6 SDK packages** (TS server + browser, React w/ full `<SignIn/>`/`<OrgSwitcher/>`/… component suite, Next.js, Go, Python) · per-tenant rate-limit overrides (`0064`)
- ✅ Transactional outbox **+ DLQ** · webhook dispatcher (HMAC, backoff retry, own dead-letter `dead_at` state — not yet unified with the platform outbox's DLQ, but no longer unbounded) · Prometheus/OTel observability · `config.Validate()` boot-gate
- ✅ Docker Compose + Caddy (auto-TLS) on EC2 deploy · CI gates: arch fitness R1/R2, 100% OpenAPI route coverage, **CodeQL**, `golangci-lint`, `govulncheck`, `gitleaks`, gated integration suite (testcontainers), frontend pnpm lint/typecheck/build/test *(Helm/Terraform/kustomize are in git history, not the tree — see 🚢 Deployment above; coverage-floor enforcement, Spectral spec-lint, Postman/Newman contract tests are not wired)*

---

## 🔭 Planned — not yet available

### Product roadmap
| Feature | Priority | Notes |
|---|---|---|
| Auth-hook claims in the OIDC ID-token path | 🟢 | Custom claims already flow into direct API-token login (incl. MFA); threading them through the hosted-login cookie → OIDC authorize/ID-token pipeline is separate, larger work |
| i18n — remaining coverage | 🟡 | 8 console catalogs (en+7) exist w/ partial namespaces; remaining screens + locale-aware emails + login app pending |
| WCAG 2.2 AA — a11y gate + legacy screens | 🟡 | Gate fixed (`eslint.config.mjs` globs updated from `qeetid-admin`/`qeetid-login` → `console`/`login` + `qeetid-web` → `website`; also split plugin registration to avoid Next.js flat-config conflict); 6 newly-exposed violations resolved. ~70 older console screens still carry hardcoded English — not a11y violations per se, but gating them incrementally remains the backlog |
| SOC 2 / ISO 27001 evidence generation | 🟡 | Compliance screens are static templates; generated evidence pending |
| Published performance benchmarks (p95/p99) | 🟡 | `tests/performance/` k6 scripts now cover the authz hot path too (`authz.js` — RBAC `/check` + ReBAC recursive group-membership `/check`), not just auth/CRUD; still no externally-published numbers or CI wiring — pending representative post-GA traffic, not an engineering blocker |
| Audit free-text search | ✅ | `GET /audit?q=` — PostgreSQL `websearch_to_tsquery('simple', ...)` over a generated `search_vector` column on `audit.events` (action, resource_type, actor_type, user_agent, metadata); GIN-indexed (migration 0079). Console filter bar adds a Search input above the exact-match filters; exported pages pass `q` through. Supports quoted phrases, `-exclusions`, OR |

### 🤖 AI-agent identity & governance
*Surfaced by the `product-manager` agent from live competitive research (Auth0 / Okta / WorkOS / Descope / Microsoft Entra).*

| Feature | Priority | What it adds |
|---|---|---|
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
| MCP AS metadata (RFC 9728 + 8707) | ✅⁴ | ⏳ | ❌ | 🟡 | ❌ | ❌ | ❌ | ❌ | 🟡 |
| CIBA (backchannel) | ✅ | ✅ | ❌ | 🟡 | 🟡 | ✅ | 🟡 | 🟡 | 🟡 |

<sub>⁴ RFC 9728 Protected Resource Metadata + RFC 8707 resource indicators are advertised, validated, and bound into the token audience across authorization_code/refresh_token/token-exchange; RFC 9207 `iss` ships on the authorize redirect. Device grant doesn't collect a resource indicator yet.</sub>

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
| Self-serve SSO/SCIM admin UI | ✅⁹ | 🟡 | 🟡 | ✅ | ✅ | ❌ | 🟡 | 🟡 | ❌ |

### Authorization
| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| RBAC + single-call `/check` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| ABAC / policy | 🟡⁵ | 🟡 | ❌ | 🟡 | 🟡 | ✅ | ✅ | 🟡 | ✅ |
| Group-level RBAC | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Fine-grained / ReBAC (Zanzibar)** | ✅ | ✅ FGA | 🟡 | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ Keto |
| **Explainable authz ("why?")** | ✅⁶ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 |

<sub>⁵ Per-tenant IP allow/deny (CIDR) + password/login-method policy, not a general attribute-condition engine. ⁶ `?explain=true` returns a full grant-path trace on **both** RBAC and ReBAC `/check`. ⁹ Both a logged-in tenant admin's own self-serve console screens *and* a WorkOS-style Admin Portal link an external IT admin can use with no Qeet ID account at all.</sub>

### Security & operations
| Capability | **Qeet ID** | Auth0/Okta | Clerk | WorkOS | Stytch | Keycloak | FusionAuth | Zitadel | Ory |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **Tamper-evident (hash-chained) audit** | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | ❌ | 🟡 | 🟡 | ❌ |
| **Externally-verifiable audit (Merkle)** | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Webhooks (HMAC, backoff retry) | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |
| **SIEM streaming (push to sinks)** | ✅ | 🟡 | ✅ | 🟡 | 🟡 | ❌ | 🟡 | 🟡 | ❌ |
| GDPR erasure | ✅ | ✅ | ✅ | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | 🟡 |
| Data export | ✅ | ✅ | ✅ | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | 🟡 |
| Distributed rate limiting (Redis) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Metrics + distributed tracing (OTel) | ✅ | ✅ | 🟡 | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ |
| Adaptive / risk-based MFA | ✅³ | ✅ | 🟡 | 🟡 | ✅ | 🟡 | ✅ | 🟡 | 🟡 |
| **Bot detection** | ✅ | ✅ | 🟡 | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| Breached-password detection | ✅ | ✅ | ✅ | 🟡 | ✅ | 🟡 | ✅ | 🟡 | 🟡 |
| Secrets vault / BYOK (KMS) | ✅⁷ | ✅ | ❌ | 🟡 | 🟡 | 🟡 | 🟡 | ✅ | 🟡 |

<sub>³ A threshold-based risk engine ships (`0063_risk_settings` → step-up/force-MFA by risk level), extended with impossible-travel and device-reputation signals (`0077_adaptive_risk`) — both additive, independently-togglable, and off by default; impossible travel also needs a trusted upstream proxy to supply a country header (external ops, not a code gap — no server-side GeoIP lookup exists or is needed). ⁷ AES-256-GCM vault + a wired, tested AWS KMS provider; only provisioning a live CMK (BYOK rollout) is external ops.</sub>

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

**Where Qeet ID wins:** both an OIDC **and** SAML IdP with SCIM Users+Groups (open-source, not paywalled); tamper-evident hash-chained audit with `/verify`; a full agentic-identity stack (AI-agent identities + RFC 8693 delegation + MCP introspection + token vaulting + W3C VCs); ReBAC **and** RBAC both explainable (`?explain=true` on both `/check` endpoints — no other researched platform, including OpenFGA/SpiceDB, ships ReBAC explainability at all); and security-on-by-default (theft detection, lockout, prod boot-gate, bot detection). **Closest peer:** Zitadel. **Remaining gaps vs. the field:** KMS BYOK go-live (ops).

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

