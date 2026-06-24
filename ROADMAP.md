# Qeet ID — Roadmap

The full picture of **what's available today** and **what's planned next** — plus the internal
package structure that lands with future work. The [README](./README.md) links here.

**Legend:** ✅ shipped · 🟠 planned (high) · 🟡 planned (medium) · 🟢 planned (later) · ⏳ external ops (not code)
**Status:** pre-1.0, feature-complete for the **July 2026 GA** — every ✅ below has working Go code (no stubs).
The golden status inventory is the internal `QEET-ID-STATUS.md` (in the qeet-files PRD hub); the competitive
backlog is distilled by the [`product-manager`](./.claude/agents/product-manager.md) agent.

---

## 🚢 Deployment (current → future)

**Current:** EC2 + Docker Compose + AWS RDS — see [deploy/prod/deploy.md](./deploy/prod/deploy.md).

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
- ✅ Session management — refresh rotation + theft detection + silent revocation
- ✅ Breached-password detection (HIBP k-anonymity, env-gated) · password reset

### 🏢 Enterprise SSO & provisioning
- ✅ OIDC / OAuth 2.0 provider — discovery, JWKS, Auth Code + PKCE, `/userinfo`, refresh, revoke, introspect, logout
- ✅ Device Authorization Grant (RFC 8628) · Token Exchange (RFC 8693 — downscope + `act` delegation)
- ✅ SAML 2.0 — **SP and IdP** modes · SCIM 2.0 (users + groups + PatchOp) · LDAP / Active Directory
- ✅ Social login (Google, GitHub, Microsoft, Apple, custom) · account linking · SSO test-connection

### 🛡️ Authorization
- ✅ RBAC · ABAC policy engine (explainable results)
- ✅ **ReBAC** (Zanzibar-style `relation_tuples`, recursive `/check` with cycle guard + grant-path trace)
- ✅ IP allow/deny (CIDR) · Auth Hooks / Actions (post-login allow/deny + custom claims)

### 🤖 Developer & AI-agent platform
- ✅ Scoped API keys (`qk_`, hashed, audited) · service accounts (`client_credentials` M2M)
- ✅ Secrets vault (AES-256-GCM, scoped `vault:<name>`) · HMAC-SHA256 webhooks (backoff retry + DLQ)
- ✅ **AI-agent identity** — ephemeral scoped revocable tokens (`actor_type=agent`)
- ✅ **MCP introspection** (`actor_type`/`agent_id`/`act` on `/oauth/introspect`) · token delegation (RFC 8693 `act`)
- ✅ **W3C Verifiable Credentials** (JWT-VC issue / verify / revoke) · analytics · SIEM streaming

### 👥 Identity & workspace
- ✅ Multi-tenant organisations (isolated, per-tenant branding, custom domains)
- ✅ Users (CRUD, bulk import, sessions, recycle bin) · nested groups (SCIM sync) · invitations
- ✅ Domain verification (DNS TXT) · per-tenant email templates · org switcher + branding preview

### 📜 Compliance & billing
- ✅ SHA-256 hash-chained audit log (`/verify` integrity walk) · GDPR erasure + grace-period purge
- ✅ Data export · retention auto-purge · SOC 2 / ISO 27001 / GDPR evidence reporting
- ✅ Multi-currency billing (ISO-4217) · card payments — Stripe (global) + Razorpay (India), webhook-verified (env-gated)

### 🧰 Platform & delivery
- ✅ 3 React frontends (admin console, hosted login, marketing site) · 5 SDKs (TS, React, Next.js, Go, Python)
- ✅ Transactional outbox + webhook dispatcher (DLQ) · Prometheus/OTel observability · `config.Validate()` boot-gate
- ✅ Helm + Compose + Terraform + kustomize deploy · CI gates (arch fitness R1/R2, 100% OpenAPI coverage, govulncheck, gitleaks)

---

## 🔭 Planned — not yet available

### Product roadmap
| Feature | Priority | Notes |
|---|---|---|
| CIBA grant (Client-Initiated Backchannel Auth) | 🟠 | Push/email async consent for elevated tokens |
| Prebuilt `<SignIn/>` / `<OrgSwitcher/>` SDK components | 🟡 | `<UserButton/>` already ships in `@qeetid/react` |
| i18n locale catalogs | 🟡 | Scaffold + login done; non-English catalogs + remaining screens pending |
| WCAG 2.2 AA — remaining legacy screens | 🟡 | New screens + lint gate done; expanding to ~70 older admin screens |
| Adaptive / risk-based MFA | 🟡 | Threat-scoring exists; adaptive rule engine pending |

### 🤖 AI-agent identity & governance
*Surfaced by the `product-manager` agent from live competitive research (Auth0 / Okta / WorkOS / Descope / Microsoft Entra).*

| Feature | Priority | What it adds |
|---|---|---|
| **Token Vault** | 🟠 | Per-tenant encrypted store for third-party OAuth refresh tokens, so agents call Slack/GitHub/Google on a user's behalf without handling tokens |
| **MCP AS compliance** | 🟠 | RFC 9728 Protected Resource Metadata + RFC 8707 Resource Indicators (mandated by the MCP 2026-07 spec) |
| **Agent lifecycle + kill switch** | 🟠 | `active`/`suspended`/`decommissioned` state machine with instant authz denial + bulk kill-switch API |
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
- AWS **KMS BYOK** (`KeyProvider` interface ready — needs a real key) · **OpenID conformance** run against a deployed instance
- Email **deliverability** (SPF/DKIM/DMARC + bounce handling) · **RDS PITR** / backups · external **penetration test**
- Billing **go-live** (Stripe/Razorpay env keys) · managed-cloud infrastructure (multi-region, autoscaling)

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
| `platform/observability/alerts` | Prometheus alert-rule generation | Runtime rules in git history (deploy/base/observability/). |
| `platform/observability/dashboards` | Grafana dashboard generation | Runtime dashboards in git history (deploy/base/observability/). |
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
