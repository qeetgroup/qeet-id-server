# Subsystem Map — qeet-id-server

**Level:** L2 — repository (lightweight L3 navigation + L4 pointers)
**Status:** active · **Evidence state:** verified
**Last verified:** 2026-08-28
**Verification scope:** every filename below was confirmed to exist. Purpose lines are quoted from
the package's own doc comment where one exists, and marked `no package doc` where none does.
Dependency lines come from the actual import graph. Test mappings come from each integration test's
imports.

---

## What this file is — and is not

This is a **navigation layer**. Its only job is to answer:

> *"Where should I inspect next?"*

It does **not** re-explain architecture already covered in [context.md](context.md), and it does
**not** document individual functions or types. **Source code and tests are the deepest truth in
this repository** — this file points at them and stops.

### File-naming convention — read this before looking for a file

**The convention is `<domain>.go`, not layered file names.** Domain logic, persistence and HTTP
handlers usually live in one file named after the package. Additional files split by **feature**,
not by layer.

Only four packages use `service.go` / `repository.go` naming, and sixteen have a dedicated
`http.go`. **Do not assume a `service.go` or `repository.go` exists** — check the L4 pointers below.

Every leaf package additionally carries `queries.sql` + `sqlc.yaml` + a generated `dbgen/`
(`db.go`, `models.go`, `queries.sql.go`). **`dbgen/` is sqlc output and is never hand-edited.**

### Relative weight

Hand-written Go, excluding generated `dbgen/`:

```text
operations  10.9k  ████████████
access       9.6k  ███████████
federation   9.6k  ███████████
platform     7.6k  ████████
identity     4.8k  █████
developer    4.0k  ████
bootstrap    1.5k  ██
```

Roughly 30–35% of each bounded context's raw line count is generated code.

---

## access — authentication

**Purpose** — *"handles login, refresh, logout, and session storage. Access & ID tokens are signed
with ES256 (asymmetric) and verifiable via the public JWKS."*
**Path** `internal/access/authentication/`
**Key dependencies** `platform/http/{errs,httpx}` · `platform/crypto/{tokens,encryption,hibp}` ·
`platform/events/outbox` · **`identity/users`** and **`operations/audit`** (cross-context)
**Security** **Critical** — sessions, lockout, trusted device

**L4 pointers**

```text
service.go          Service, its policies and the shared sign-in types
password.go         password sign-in and password changes
issue.go            session issuing, the login hook
refresh.go          refresh-token rotation and reuse
sessions.go         sign-out and session listing
mfachallenge.go     the second-factor step of a sign-in
http.go             HTTP handlers
loginsession.go     hosted SSO session cookie  qe_ls; sign-out ends the app grants it started
trusteddevice.go    MFA-skip cookie            qe_td
lockout.go          per-account lockout
service_test.go     unit
```

**Tests** `service_test.go` · integration: `flows_test.go`, `revocation_signals_test.go`

---

## access — authorization

**Purpose** — RBAC *"models permissions, per-tenant roles, role→permission bindings, and user
assignments. The Check endpoint is the hot path callers use to authorize an action."*
**Path** `internal/access/authorization/{rbac,abac,rebac,authzen,policy,authpolicy}/`
**Key dependencies** `platform/http/{errs,httpx}` · **`operations/audit`** (cross-context)
**Security** **Critical** — every access decision

**L4 pointers**

```text
rbac/rbac.go          roles, permissions, bindings
rbac/service.go       decision service
rbac/enforce.go       router middleware — consumes bootstrap/permissions.go
rbac/http.go          /check, /roles, /permissions
abac/abac.go          13 operators, deny-overrides, fail-closed
rebac/rebac.go        Zanzibar relation tuples, recursive check
decide/decide.go      one decision across all three: tenant, ABAC deny, then any allow
authzen/authzen.go    OpenID AuthZEN PDP/PEP facade
policy/policy.go      tenant security policy
authpolicy/authpolicy.go   password rules, permitted login methods
```

**Tests** `rbac/enforce_test.go`, `abac/abac_test.go`, `rebac/rebac_test.go` · integration:
`authz_test.go`

> `authzen/` has **no unit test**. Coverage is integration-only.

---

## access — mfa, passkeys, recovery

**Purpose** — MFA: *"TOTP enrollment and verification plus a small set of recovery codes. Recovery
codes are bcrypt-hashed."* Passkeys: *"implements WebAuthn passkey registration and login on top of
go-webauthn."* Recovery: *"forgot-password and magic-link login. Both are stateless tokens."*
**Path** `internal/access/{mfa,passkeys,recovery}/`
**Key dependencies** `platform/crypto/password` · `platform/crypto/totp` · `platform/messaging/{notifier,emailtmpl}` ·
`platform/http/{errs,httpx}` · **`operations/audit`**
**Security** **Critical** — second factors and account recovery

**L4 pointers**

```text
mfa/totp.go          TOTP and recovery codes
mfa/otp.go           SMS and email codes
mfa/stepup.go        step-up of a session
mfa/push.go          push approval — pairs with the qeet-id-auth mobile app
passkeys/passkey.go  WebAuthn registration + login ceremonies (single file)
recovery/http.go     handlers
recovery/recovery.go forgot-password, magic link
```

**Tests** `mfa/mfa_test.go`, `passkeys/login_decode_test.go` · integration:
`passkey_ceremony_test.go` (uses `virtualwebauthn`), `recovery_test.go`

> `recovery/` has **no unit test** — integration-only.

---

## access — risk & threat

**Purpose** — *"records and surfaces security anomalies … detection-agnostic."*
**Path** `internal/access/{threat/risk,threat/bot,threat/threat,risk/ipallow}/`
**Key dependencies** `platform/http/{errs,httpx}` · **`operations/audit`**
**Security** **High** — adaptive MFA and access gating

**L4 pointers**

```text
threat/risk/risk.go       adaptive risk scoring
threat/risk/history.go    login-context history
threat/bot/bot.go         bot-detection telemetry
threat/threat/threat.go   security-event surface
risk/ipallow/ipallow.go   CIDR allow/deny
```

**Tests** `threat/risk/risk_test.go`, `risk/ipallow/ipallow_test.go` · integration: `risk_test.go`

> Two different packages are named `risk`: `access/risk/ipallow` and `access/threat/risk`. They are
> unrelated. Adaptive risk is **off by default**.

---

## identity

**Purpose** — tenants, users, groups, invitations, verification. Invitations: *"lets a tenant admin
invite an email address into a tenant with a pre-assigned role … the invite is consumed in the same
transaction."*
**Path** `internal/identity/{tenant,users,groups,invitations,verification,domainverify}/`
**Key dependencies** `platform/http/{errs,httpx,paging}` — **the only `http/paging` consumer** ·
`platform/database/postgres/{dbutil,pgxerr}` · `platform/messaging/{notifier,emailtmpl}` ·
`platform/events/outbox` · **`access/authentication`**, **`operations/audit`**
**Security** **High** — tenant and user lifecycle

**L4 pointers**

```text
tenant/domain.go · tenant/http.go · tenant/repository.go
tenant/branding/branding.go
users/domain.go · users/http.go · users/repository.go
users/bulk.go             bulk import
users/import_adapters.go  Auth0 / Cognito / Azure B2C migration
users/user360.go
groups/group.go · invitations/{http.go,invite.go}
verification/{http.go,verification.go} · domainverify/domainverify.go
```

**Tests** `users/{repository,bulk,import_adapters}_test.go`, `domainverify/domainverify_test.go` ·
integration: `identity_modules_test.go`, `flows_test.go`

> **`identity/users` and `identity/tenant` have no package doc comment**, and `tenant`, `groups`,
> `invitations` and `verification` have **no unit tests** — integration-only.

---

## federation

**Purpose** — *"implements Qeet's OpenID Connect provider role: the OAuth2/OIDC grants
(authorization_code+PKCE, refresh, client_credentials, token-exchange, device, CIBA) plus discovery,
JWKS, and userinfo endpoints."*
**Path** `internal/federation/{oidc,saml,scim,ldap,social,adminportal}/`
**Key dependencies** `platform/http/{errs,codes,httpx}` · `platform/crypto/tokens` ·
**`access/authentication`**, **`identity/users`**, **`operations/audit`**
**Security** **Critical** — parses untrusted external input (SAML XML, SCIM, LDAP)

**L4 pointers**

```text
oidc/token.go           token grants (code, refresh, token exchange)
oidc/authorize.go       authorization and consent
oidc/discovery.go       discovery and JWKS
oidc/http*.go           HTTP handlers
oidc/device.go          RFC 8628 device grant
oidc/ciba.go            CIBA (poll mode)
oidc/clients_admin.go   OAuth client administration
saml/saml.go            SP role — consume a customer IdP
saml/idp.go             IdP role — serve a customer SP
scim/scim.go · scim/groups.go
ldap/ldap.go
social/social.go · apple.go · github.go · platform.go · oauthclient.go
adminportal/adminportal.go   capability-scoped, time-limited SSO/SCIM config links
```

**Tests** `oidc/{oidc,jwks}_test.go`, `saml/{saml,idp}_test.go`, `scim/{scim,groups_integration}_test.go`,
`ldap/ldap_test.go`, `social/social_test.go`, `adminportal/adminportal_test.go` · integration:
`device_test.go`, `device_admin_test.go`, `clients_admin_test.go`, `signing_keys_test.go`,
`adminportal_test.go`

> Notably imports **no** `platform/database/*` or `events/outbox` directly.

---

## developer

**Purpose** — service principals: *"non-human callers that authenticate via client_credentials grant
and receive a short-lived service JWT scoped to a single tenant."* Agents: *"non-human AI-agent
identities … tokens (`actor_type="agent"`) that are re-minted rather than refreshed."*
**Path** `internal/developer/{agents,api-keys,principal,auth-hooks,webhooks,credentials}/`
**Key dependencies** `platform/http/{errs,httpx}` · `platform/crypto/{tokens,encryption}` ·
**`operations/audit`**
**Security** **Critical** — machine credentials and other systems' secrets

**L4 pointers**

```text
agents/agent.go              lifecycle, sponsor, kill switch, ephemeral tokens
api-keys/apikey.go           qk_ keys — "<prefix>.<secret>", bcrypt hash stored
principal/principal.go       client_credentials, /v1/oauth/token
auth-hooks/authhook.go       post-login hooks — DEFAULT FAIL-OPEN (ADR-0011)
webhooks/webhook.go          HMAC-SHA256 delivery (timestamp + body) + dead-letter
webhooks/events.go           event catalogue, delivery envelope, outbox relay
credentials/secrets/secret.go · keyprovider.go · kms.go
credentials/tokenvault/tokenvault.go
credentials/vc/vc.go         W3C JWT-VC
```

**Tests** `agents/agent_test.go`, `api-keys/apikey_test.go`, `webhooks/webhook_test.go`,
`credentials/secrets/{secret,kms}_test.go` · integration: `agent_test.go`, `ops_dev_modules_test.go`

> **No bounded context imports `developer`.** It is a leaf. `principal/` has no unit test.

---

## operations

**Purpose** — audit: *"records actor-visible mutations to `audit.events`. Each write happens inside
the caller's `pgx.Tx`, so the row commits atomically with the business write. Every row carries a
SHA-256 hash chaining to the previous row in the same tenant; tampering (delete, edit, reorder)
breaks the chain and is caught by `Verifier.Verify`."*
**Path** `internal/operations/{audit,billing,gdpr,analytics,retention,siem,activity,notifications,entitlements,ratelimits,search,sales,email,qeetai}/`
**Key dependencies** `platform/http/{errs,httpx}` · `platform/ai` (+`openai`, `anthropic`) — **sole
consumer** · `platform/cache/ratelimit`
**Security** **Critical** for `audit/`; **High** for `billing/`, `gdpr/`, `siem/`

**L4 pointers**

```text
audit/audit.go        hash-chained writes
audit/verifier.go     /verify chain-integrity walk
audit/http.go
audit/anomaly/anomaly.go   behavioural baselines
billing/{billing,payments,tax}.go
gdpr/{gdpr,evidence}.go    erasure, export, SOC2/ISO evidence
retention/retention.go · siem/siem.go · analytics/analytics.go
activity/{domain,http,hub}.go   SSE feed
qeetai/{qeetai,orchestrator,sse,tools,providercfg,http}.go
entitlements/ · ratelimits/ · search/ · notifications/ · sales/ · email/
```

**Tests** `audit/audit_test.go`, `billing/{billing,payments,tax}_test.go`, `gdpr/evidence_test.go`,
`qeetai/http_test.go` · integration: `audit_anomaly_test.go`, `ratelimits_test.go`,
`ops_dev_modules_test.go`

> **`operations/audit` is a de-facto shared kernel** — all four other bounded contexts import it.
> `operations` uses `pgxpool` directly rather than the `platform/database` helpers.

---

## platform — shared kernel

**Purpose** — pure infrastructure. `errs`: *"defines the canonical, transport-agnostic error
vocabulary … Each error carries a stable machine code; the transport layer maps that code to an HTTP
status, so these errors are reusable across HTTP, gRPC, CLI, jobs, and event consumers."*
**Path** `internal/platform/`
**Key dependencies** **none inside this repository** — R1 forbids importing any bounded context,
`cmd/*` or `bootstrap`
**Security** **Critical** — `http/httpx` (tenant scope, CSRF), `crypto/` (signing, hashing),
`config` (the boot gate)

**L4 pointers**

```text
http/httpx/auth.go        RequireAuth · RequireTenant · EnforceTenantScope   ← tenant boundary
http/httpx/csrf.go        double-submit, HMAC-keyed
http/httpx/middleware.go · response.go · ctx.go · timing.go
http/errs/                ~50 files, one per domain
http/httpx/error_status_*.go   ~40 files, 1:1 mirror of errs/
crypto/tokens/jwt.go      ES256, RFC 7638 kid, rotation
crypto/password/          Argon2id hashing and strength rules
crypto/envelope/          AES-256-GCM encryption under the data key
crypto/totp/              TOTP codes
crypto/hibp/              breached-password k-anonymity
config/config.go          81 env vars + Config.Validate() boot gate
database/postgres/pool.go     "owns the single pgx pool shared by every module"
database/migrations/runner.go //go:embed *.sql
events/outbox/{outbox,nats}.go
worker/worker.go · cache/ratelimit/ · messaging/ · observability/ · ai/
```

**Tests** `http/httpx/{auth,csrf,middleware}_test.go`, `crypto/tokens/jwt_test.go`,
`config/config_test.go`, `events/outbox/{outbox,nats}_test.go`, `worker/worker_test.go` — 24 unit
tests, the densest coverage in the repository

> The `errs/` ↔ `error_status_*.go` pairing is 1:1 by domain. A new error domain needs a file in
> **both**.

---

## bootstrap — composition root

**Purpose** — the only package that wires anything. `no package doc comment on any of its six files`.
**Path** `internal/bootstrap/`
**Key dependencies** **everything** — this is the one package allowed to import every context and all
of platform
**Security** **Critical** — middleware order and the route tree are load-bearing for tenant isolation

**L4 pointers**

```text
dependencies.go   645 lines — constructs every service and repository
router.go         347 lines — middleware chain, route tree, all mounts
permissions.go    216 lines — "METHOD /chi/route/pattern" → required permission
app.go            131 lines — assembly
lifecycle.go       88 lines — startup / graceful shutdown
server.go          30 lines — HTTP server
```

`permissions.go` documents its own contract: *"the authorization policy table consumed by
`rbac.Enforce` … Only end-user principals are gated (API keys / service principals bypass — see
`rbac.Enforce`); routes absent here are ungated (public, self-service, or tenant-create)."*

**Tests** `permissions_test.go` and `openapi_coverage_test.go` walk the production router: every
authenticated route needs an explicit policy, and every route must be in the OpenAPI spec.

---

## Cross-context imports — the unguarded seam

No test enforces R1, R2 or cross-context imports.

**Status:** verified · **Evidence:** import-graph scan — 38 import statements across 8 pairs

```text
operations/audit       ← access(9) · federation(8) · identity(5) · developer(5)
access/authentication  ← federation(6) · identity(2)
identity/users         ← federation(2) · access(1)
```

- **`operations/audit` is imported by all four other contexts** — a shared kernel in practice, not by
  design.
- `access ↔ identity` is bidirectional at package granularity (`access/authentication` → `identity/users`,
  `identity/tenant` → `access/authentication`) without forming a Go import cycle.
- **Nothing imports `developer`.**

Prefer interfaces declared by the consumer over importing another context's concrete types, so the
extraction seam described in [context.md](context.md) survives.

---

## Where to go next

| You need | Read |
|---|---|
| How the repository works | [context.md](context.md) |
| A file path, fast | [architecture-map.md](architecture-map.md) |
| What you may and may not change | [boundaries.md](boundaries.md) |
| Steps for a specific change | [workflows.md](workflows.md) |
| **Actual behaviour** | **the source and its tests** |
