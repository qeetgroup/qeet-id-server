# Subsystem Map — qeet-id-server

**Level:** L2 — repository (lightweight L3 navigation + L4 pointers)
**Status:** active · **Evidence state:** verified
**Last verified:** 2026-11-15
**Verification scope:** every filename below was confirmed against `c2454fec`. Purpose lines come
from package comments where present; dependency lines were checked against the import graph and test
mappings against the current colocated and integration-tagged tests.

---

## What this file is — and is not

This is a **navigation layer**. Its only job is to answer:

> _"Where should I inspect next?"_

It does **not** re-explain architecture already covered in [context.md](context.md), and it does
**not** document individual functions or types. **Source code and tests are the deepest truth in
this repository** — this file points at them and stops.

### File-naming convention — read this before looking for a file

**Every domain package has the same shape.** `<package>.go` holds the package doc, the Service and
`New`; `http.go` the routes and handlers (59 packages); `errors.go` its error codes; then one file per
topic, split by **feature**, not by layer (`register.go`, `login.go`, …). Tests sit beside the file
they test: `foo_test.go` (no database) and `foo_db_test.go` (PostgreSQL, `//go:build integration`).
Only three packages (rbac, organization, user) also have a `service.go` or `repository.go`: don't add one elsewhere. Check the L4 pointers below.

Every leaf package additionally carries `queries.sql` (an entry in the root `sqlc.yaml`) + a generated `dbgen/`
(`db.go`, `models.go`, `queries.sql.go`). **`dbgen/` is sqlc output and is never hand-edited.**

### Relative weight

Hand-written Go, excluding generated `dbgen/`:

```text
federation  41.1k  █████████████████
access      35.6k  ███████████████
platform    24.9k  ██████████
operations  24.8k  ██████████
identity    15.9k  ██████
developer    9.3k  ████
bootstrap    5.4k  ██
```

The figures include colocated tests and exclude generated `dbgen/`; they are navigation weights,
not complexity or coverage measurements. Generated `dbgen/` is about 15% of the repository's Go
line count on this revision.

---

## access — authentication

**Purpose** — _"handles login, refresh, logout, and session storage. Access & ID tokens are signed
ES256 or RS256, by the signing key's type, and verifiable via the public JWKS."_
**Path** `internal/access/authentication/`
**Key dependencies** `platform/http/{errs,httpx}` · `platform/crypto/{tokens,encryption,hibp}` ·
`platform/events/outbox` · **`identity/user`** and **`operations/audit`** (cross-context)
**Security** **Critical** — sessions, lockout, trusted device

**L4 pointers**

```text
authentication.go   Service, its policies and the shared sign-in types
signup.go           self-service sign-up
password.go         password sign-in and password changes
issue.go            session issuing, the login hook
refresh.go          refresh-token rotation and reuse
sessions.go         sign-out and session listing
mfachallenge.go     the second-factor step of a sign-in
http.go             Handler and routes; http_<flow>.go its handlers: signup, login,
                    loginsession, mfa, sessions, password, trusteddevice
loginsession.go     hosted SSO session cookie  qe_ls; sign-out ends the app grants it started
trusteddevice.go    MFA-skip cookie            qe_td
lockout.go          per-account lockout
```

**Tests** beside each file (`refresh_test.go`, `mfachallenge_db_test.go`, …; `TestMain` in
`authentication_db_test.go`)

---

## access — authorization

**Purpose** — RBAC _"models permissions, per-organization roles, role→permission bindings, and user
assignments. The Check endpoint is the hot path callers use to authorize an action."_
**Path** `internal/access/authorization/{rbac,abac,rebac,decide,decisionlog,authzen}/`, `internal/access/authpolicy/`
**Key dependencies** `platform/http/{errs,httpx}` · **`operations/audit`** (cross-context)
**Security** **Critical** — every access decision

**L4 pointers**

```text
rbac/rbac.go          roles, permissions, bindings
rbac/service.go       decision service
rbac/enforce.go       router middleware — consumes bootstrap RoutePolicies()
rbac/holds.go         Holds, CallerHolds: whether a caller holds one permission
rbac/importroles.go   ImportRoles: a bulk user import giving a role, with role.write and seats
rbac/http.go          /check, /roles, /permissions
abac/abac.go          Service; operators.go the 13 operators, condition.go and relations.go
                      the role and relation leaves, evaluate.go deny-overrides, fail-closed
abac/policies.go · versions.go · validate.go · attributes.go   policy storage, history, checks
rebac/rebac.go        Service; tuples.go Zanzibar relation tuples, check.go and graph.go
                      the recursive check, objects.go object listing
decide/decide.go      one decision across all three: organization, ABAC deny, then any allow
authzen/authzen.go    OpenID AuthZEN PDP/PEP facade
decisionlog/decisionlog.go   the decisions check, AuthZEN and evaluate answer, kept 30 days
authpolicy/authpolicy.go       authentication policy: password rules (password.go),
                               permitted login methods (methods.go), lockout (lockout.go)
authpolicy/securitypolicy.go   organization security policy: sessions, second factor, step-up
```

**Tests** `rbac/enforce_test.go`, `abac/{abac,operators,evaluate}_test.go`, `rebac/{check,graph}_test.go` · integration:
`rbac/enforce_db_test.go`, `abac/abac_db_test.go`, `decide/decide_db_test.go`

`authzen/` now has a direct package test as well as wider authorization coverage.

---

## access — mfa, passkeys, recovery

**Purpose** — MFA: _"TOTP enrollment and verification plus a small set of recovery codes. Recovery
codes are Argon2id-hashed."_ Passkeys: _"implements WebAuthn passkey registration and login on top of
go-webauthn."_ Recovery: _"forgot-password and magic-link login. Both are stateless tokens."_
**Path** `internal/access/{mfa,passkey,recovery}/`
**Key dependencies** `platform/crypto/password` · `platform/crypto/totp` · `platform/messaging/{notifier,emailtmpl}` ·
`platform/http/{errs,httpx}` · **`operations/audit`**
**Security** **Critical** — second factors and account recovery

**L4 pointers**

```text
mfa/totp.go          TOTP and recovery codes
mfa/otp.go           SMS and email codes
mfa/stepup.go        step-up of a session
mfa/push.go          push approval — pairs with Qeet ID on the phone (the native qeet-id-ios and qeet-id-android);
                     pushdevices.go the paired devices, pushchallenge.go a request's life, pushadmin.go admin views
mfa/pushnative.go    delivery by platform: APNs (APNS_*), FCM (FCM_SERVICE_ACCOUNT); the app also lists waiting requests (devices/{id}/pending)
passkeys/passkey.go  Service; webauthn.go the relying party, register.go · login.go · signup.go ·
                     mfa.go the ceremonies, credentials.go stored passkeys, http.go handlers
recovery/http.go     handlers
recovery/recovery.go forgot-password, magic link
```

**Tests** `mfa/{totp,stepup,push}_test.go`, `passkey/http_test.go` · integration:
`passkey/{register,signup}_db_test.go` (use `virtualwebauthn`), `recovery/recovery_db_test.go`

`recovery/` has direct package tests and database-backed recovery flow coverage.

---

## access — risk & threat

**Purpose** — _"records and surfaces security anomalies … detection-agnostic."_
**Path** `internal/access/{threat,threat/risk,threat/bot,ipallow}/`
**Key dependencies** `platform/http/{errs,httpx}` · **`operations/audit`**
**Security** **High** — adaptive MFA and access gating

**L4 pointers**

```text
threat/risk/risk.go       adaptive risk scoring
threat/risk/history.go    login-context history
threat/bot/bot.go         bot-detection telemetry
threat/threat.go         security-event surface
ipallow/ipallow.go        CIDR allow/deny
*/http.go                 each package's handlers
```

**Tests** `threat/risk/risk_test.go`, `ipallow/ipallow_test.go` · integration: `risk_test.go`

> `access/ipallow` is the organization's IP rules, not risk scoring; adaptive risk (`access/threat/risk`)
> is **off by default**.

---

## identity

**Purpose** — organizations, users, groups, invitations, verification. Invitations: _"lets an organization admin
invite an email address into an organization with a pre-assigned role … the invite is consumed in the same
transaction."_
**Path** `internal/identity/{organization,user,group,invite,verification,domainverify}/`
**Key dependencies** `platform/http/{errs,httpx,paging}` — **the only `http/paging` consumer** ·
`platform/database/postgres` · `platform/messaging/{notifier,emailtmpl}` ·
`platform/events/outbox` · **`access/authentication`**, **`operations/audit`**
**Security** **High** — organization and user lifecycle

**L4 pointers**

```text
organization/organization.go · organization/http.go · organization/repository.go · organization/selection.go
organization/branding/branding.go · branding/http.go · branding/logo.go
user/user.go · user/http.go · user/repository.go
users/endsignins.go       ending every way a person is signed in
users/accounts.go         an administrator's changes to accounts, each in a transaction it owns
users/list.go · users/suspension.go · users/signins.go   lists whose SQL is built from their filters
users/bulk.go             bulk import
users/import_adapters.go  Auth0 / Cognito / Azure B2C migration
users/user360.go
groups/{group,http,members,templates,import}.go
invitations/{invite,http,accept,inbox,seats,sender,passkey}.go
verification/{verification,http,codes,email,emailchange,phone}.go · domainverify/{domainverify,http,capture}.go
```

**Tests** `user/{repository,bulk,import_adapters}_test.go`, `domainverify/domainverify_test.go` ·
integration: `user/accounts_db_test.go`, `invite/invite_db_test.go`, `group/group_db_test.go`

Organization, groups, invitations and verification now all have direct package tests in addition to
wider flow coverage.

---

## federation

**Purpose** — _"implements Qeet's OpenID Connect provider role: the OAuth2/OIDC grants
(authorization_code+PKCE, refresh, client_credentials, token-exchange, device, CIBA) plus discovery,
JWKS, and userinfo endpoints."_
**Path** `internal/federation/{oidc,saml,scim,ldap,social,adminportal,directory,oidcsso,ssosync,identitylink,provision,oidcrp,logincode,oauthstate}/`
**Key dependencies** `platform/http/{errs,httpx}` · `platform/crypto/{codes,tokens}` ·
**`access/authentication`**, **`identity/user`**, **`operations/audit`**
**Security** **Critical** — parses untrusted external input (SAML XML, SCIM, LDAP)

**L4 pointers**

```text
oidc/authorization_code.go · refresh.go · token_exchange.go · client_credentials.go   one file per token grant
oidc/token.go · client_auth.go   what every grant shares: the response, ID tokens, client authentication
oidc/introspect.go      introspection and revocation (RFC 7662, RFC 7009)
oidc/authorize.go       authorization and consent
oidc/discovery.go       discovery and JWKS
oidc/http*.go           HTTP handlers; http_token.go is the one token endpoint and its error writer
oidc/poll.go            the device and CIBA polling step, shared
oidc/device.go          RFC 8628 device grant
oidc/ciba.go            CIBA (poll mode)
oidc/clients_admin.go   OAuth client administration
saml/saml.go · http.go  SP role — consume a customer IdP: the service, the routes
saml/connections.go · connections_admin.go · preflight.go   connections, their admin handlers, the offline check
saml/signin.go · acs.go · provisioning.go · login_code.go · sp_metadata.go   the SP-initiated sign-in, the ACS, the account it signs in, the one-time code, the SP's metadata
saml/certificates.go · metadata_import.go · metadata_refresh.go · encryption.go   IdP certificate rollover, metadata import and refresh, encrypted assertions
saml/idp.go             IdP role — serve a customer SP: signing key, registry service
saml/idp_sso.go · idp_authnrequest.go · idp_assertion.go · idp_metadata.go   SSO, the AuthnRequest, the signed assertion, the IdP's metadata
saml/idp_sp.go · idp_sp_admin.go · idp_attributes.go · idp_assignment.go   registered apps and their handlers, NameID and attributes per app, assigned people and groups
oidcsso/                an organization's own OpenID Connect provider as a sign-in connection
provision/              the one account-provisioning flow of SAML, LDAP, OIDC single sign-on and social sign-in
identitylink/           the checks on an account a federated sign-in would sign in (home, verified, administers)
ssosync/                a connection's sign-in keeps name, address and groups in step; IdP group mappings
oidcrp/                 the OpenID Connect relying party: discovery, JWKS, code exchange, ID-token checks
logincode/ · oauthstate/   the one-time login codes and the OAuth states of every federated sign-in
scim/scim.go · http.go · users.go · user_change.go · groups.go · group_patch.go · admin.go · tokens.go · discovery.go
ldap/ldap.go · http.go · connections.go · protocol.go · signin.go   (the shape of oidcsso/)
social/social.go · http.go · providers.go · identities.go · signin.go · provisioning.go · login_code.go · platform.go · apple.go · github.go · adapters.go
adminportal/adminportal.go · http.go · links.go · session.go · portal_context.go · portal_saml.go · portal_scim.go · portal_domains.go   capability-scoped, time-limited SSO/SCIM config links
directory/              one view of the SCIM and LDAP connections: http.go, events.go · sync_errors.go (their filtered lists' SQL stays inline), alerts.go, mapping_store.go
```

Every package's static SQL is in its `queries.sql`; a service method owns its transaction and writes
its audit row in it, with the `audit.Actor` the handler passes (`audit.ActorOf(r)`).

**Tests** beside the file they test: `foo_test.go`, and `foo_db_test.go` for the database ones
(`//go:build integration`); each package's `TestMain` and shared helpers are in `<package>_db_test.go`
(and `<package>_test.go`).

> Notably imports **no** `platform/database/*` or `events/outbox` directly.

---

## developer

**Purpose** — service principals: _"non-human callers that authenticate via client_credentials grant
and receive a short-lived service JWT scoped to a single organization."_ Agents: _"non-human AI-agent
identities … tokens (`actor_type="agent"`) that are re-minted rather than refreshed."_
**Path** `internal/developer/{agent,apikey,principal,authhook,webhook,credentials}/`
**Key dependencies** `platform/http/{errs,httpx}` · `platform/crypto/{tokens,encryption}` ·
**`operations/audit`**
**Security** **Critical** — machine credentials and other systems' secrets

**L4 pointers**

```text
agents/{agent,lifecycle,sponsors}.go   lifecycle, sponsor, kill switch, ephemeral tokens (client_credentials)
api-keys/apikey.go           qk_ keys — "<prefix>.<secret>", the secret's SHA-256 stored
principal/principal.go       client_credentials, served at oidc's /v1/oauth/token
rotation/rotation.go         rotating any of the three: request, scope check, overlap
auth-hooks/run.go            post-login hooks — DEFAULT FAIL-OPEN (ADR-0011); hooks.go manages them
webhooks/dispatcher.go       HMAC-SHA256 delivery (timestamp + body) + dead-letter
webhooks/{subscription,deliveries}.go   subscriptions, secret rotation, delivery history
webhooks/events.go           event catalogue, delivery envelope, outbox relay
credentials/secret/secret.go · keyprovider.go · kms.go   no change or read without its audit row
credentials/tokenvault/{providers,connect,tokens}.go       no token read without its audit row
credentials/vc/vc.go         W3C JWT-VC
```

**Tests** `agent/agent_test.go`, `apikey/apikey_test.go`, `webhook/dispatcher_test.go`,
`credentials/secret/{secret,kms}_test.go` · integration: `agent/agent_db_test.go`, `webhook/dispatcher_db_test.go`

**No bounded context imports `developer`.** It is a leaf. `principal/` has direct package tests.

---

## operations

**Purpose** — audit: _"records actor-visible mutations to `audit.events`. Each write happens inside
the caller's `pgx.Tx`, so the row commits atomically with the business write. Every row carries a
SHA-256 hash chaining to the previous row in the same organization; tampering (delete, edit, reorder)
breaks the chain and is caught by `Verifier.Verify`."_ Rows with no organization go on one of 16
platform chains (`chain_shard`, the writer's database connection's), so their writers don't
queue on one lock; each is a whole chain with its own tip, lock and checkpoint.
**Path** `internal/operations/{audit,billing,gdpr,compliance,analytics,retention,siem,activity,notification,entitlements,ratelimits,search,sales,email,qeetai,servicehealth}/`
**Key dependencies** `platform/http/{errs,httpx}` · `platform/ai` (+`openai`, `anthropic`) — **sole
consumer** · `platform/cache/ratelimit`
**Security** **Critical** for `audit/`; **High** for `billing/`, `gdpr/`, `siem/`

**L4 pointers**

```text
audit/audit.go        hash-chained writes
audit/verifier.go     /verify chain-integrity walk
audit/http.go · audit/list.go   the log's endpoints; its filtered list, the one dynamic query
audit/anomaly/anomaly.go   behavioural baselines
billing/{billing,payments,tax}.go
billing/subscription.go   a subscription's grants; PlanResolver, an organization's effective plan
gdpr/{gdpr,purge,export}.go    erasure and export requests and their sweeps
gdpr/erasure.go · gdpr/export_data.go   what erasure removes, what an export holds
compliance/{evidence,controls,owners,audits}.go   SOC 2 / ISO 27001 evidence runs, control owners, external audits
gdpr/organizationpurge.go        a deleted organization's data purged after 30 days
retention/retention.go · retention/sweeps.go   purge window, sweeps of every growing table
siem/forward.go · analytics/analytics.go
servicehealth/servicehealth.go   each component's state, operator-posted incidents
activity/{activity,stream,history,summary,related,rows,hub}.go   SSE feed and history
qeetai/{qeetai,orchestrator,sse,tools,providercfg,http}.go
entitlements/ · ratelimits/ · search/ · notifications/ · sales/ · email/
```

**Monthly active users** (the plans' `mau` allowance): `organization.monthly_active_users`, one row per
organization, calendar month (UTC) and person, written by `identity/user/active.go`'s
`RecordActive` in the same transaction as each sign-in (`access/authentication/issue.go`), session
renewal (`refresh.go`) and application code exchange or refresh-token grant
(`federation/oidc/authorization_code.go`, `refresh.go`). API keys, service principals and agents are never recorded. Reported
as `mau` by `GET /v1/organizations/{organizationID}/entitlements/usage`; nothing is refused above the allowance.
Kept 13 months by `retention/sweeps.go`. The analytics dashboard's MAU is a different figure: a
rolling 30 days of sign-ins from the audit log.

**Tests** `audit/verifier_test.go`, `billing/{billing,payments,tax}_test.go`, `compliance/{evidence,controls}_test.go`,
`qeetai/http_test.go` · integration: `audit/verify_all_db_test.go`, `ratelimits/ratelimits_db_test.go`

> **`operations/audit` is a de-facto shared kernel** — all four other bounded contexts import it.
> `operations` uses `pgxpool` directly rather than the `platform/database` helpers.

---

## platform — shared kernel

**Purpose** — pure infrastructure. `errs`: _"defines the canonical, transport-agnostic error
vocabulary … Each error carries a stable machine code; the transport layer maps that code to an HTTP
status, so these errors are reusable across HTTP, gRPC, CLI, jobs, and event consumers."_
**Path** `internal/platform/`
**Key dependencies** **none inside this repository** — R1 forbids importing any bounded context,
`cmd/*` or `bootstrap`
**Security** **Critical** — `http/httpx` (organization scope, CSRF), `crypto/` (signing, hashing),
`config` (the boot gate)

**L4 pointers**

```text
http/httpx/auth.go        RequireAuth · RequireOrganization · EnforceOrganizationScope   ← organization boundary
                          · AuthVerifier.Live: an admitted principal still live (open streams)
http/httpx/cors.go        CORS: which origins may read which responses
http/httpx/metricsguard.go  MetricsGuard: /metrics only with its token
http/httpx/csrf.go        double-submit, HMAC-keyed
http/httpx/middleware.go · response.go · ctx.go · timing.go
http/errs/                the Error type, the 15 kinds, and the errors several packages return
http/httpx/error_status.go     the kind → HTTP status table
crypto/tokens/{issue,verify,keys}.go   ES256 or RS256, RFC 7638 kid, rotation
crypto/password/          Argon2id hashing, strength rules, machine secrets' SHA-256
crypto/codes/             one-time codes and URL-safe tokens, and their stored SHA-256
crypto/envelope/          AES-256-GCM encryption under the data key, key ids for rotation
crypto/envelope/reseal/   moves stored values to the current key (secrets-reencrypt job)
crypto/totp/              TOTP codes
crypto/hibp/              breached-password k-anonymity
config/config.go · validate.go   111 env vars + Config.Validate() boot gate
database/postgres/pool.go     "owns the single pgx pool shared by every module"
database/postgres/querier.go  Querier: a pool, connection or transaction a helper runs on
database/migrations/runner.go //go:embed *.sql
events/outbox/{outbox,nats}.go
http/sse/                 Server-Sent Events writer, keep-alive
strutil/                  nullable-string pointers, truncation, comma lists
worker/worker.go · cache/ratelimit/ · messaging/ · observability/ · ai/
```

**Tests** `http/httpx/{auth,csrf,middleware}_test.go`, `crypto/tokens/{issue,verify,keys}_test.go`,
`config/{config,validate}_test.go`, `events/outbox/{outbox,nats}_test.go`, `worker/worker_test.go`; platform has
the repository's broadest direct infrastructure coverage.

> A package's own errors are in its `errors.go`; only errors several packages return are in `errs/`.

---

## bootstrap — composition root

**Purpose** — the only package that wires anything. `no package doc comment on any of its six files`.
**Path** `internal/bootstrap/`
**Key dependencies** **everything** — this is the one package allowed to import every context and all
of platform
**Security** **Critical** — middleware order and the route tree are load-bearing for organization isolation

**L4 pointers**

```text
dependencies.go   shared infrastructure, the order the contexts are built in, the workers
wire_<context>.go one per context (access, identity, federation, developer, operations): its
                  services, each built with every dependency it needs (a missing one stops
                  start-up), its handlers, its route permissions, user-only routes and
                  step-ups, its scheduled jobs
keys.go · mail.go · infra.go · sso.go · adapters.go — building blocks (keys, message chain, limits, SSO identity, adapters)
router.go         middleware chain, route tree, all mounts
permissions.go    RoutePolicies: "METHOD /chi/route/pattern" → route policy, from the contexts' tables
stepup.go         StepUpRoutes, from the contexts' tables
maintenance.go    MaintenanceJobs, in the order they are tried; the platform's own jobs
app.go            241 lines — assembly
lifecycle.go      196 lines — startup / graceful shutdown
server.go          37 lines — HTTP server
```

`permissions.go` documents its own contract: _"the authorization policy table consumed by
`rbac.Enforce` … Every authenticated route has a `RoutePolicy`; users, application-issued user
tokens, API keys, service principals and agents are each checked according to that policy. Routes
absent from the table are denied."_

**Tests** `permissions_test.go` and `openapi_coverage_test.go` walk the production router: every
authenticated route needs an explicit policy, and every route must be in the OpenAPI spec.

---

## Cross-context imports — enforced directions

`depguard` rules R1–R6 in `.golangci.yml` fix which context may import which (federation builds on
access and identity; operations and developer are leaves; the audit writer is `internal/platform/audit`).
The map and the reasons are in [context.md](context.md) and [AGENTS.md](../../AGENTS.md) rule 3.

---

## Where to go next

| You need                        | Read                                       |
| ------------------------------- | ------------------------------------------ |
| How the repository works        | [context.md](context.md)                   |
| A file path, fast               | [architecture-map.md](architecture-map.md) |
| What you may and may not change | [boundaries.md](boundaries.md)             |
| Steps for a specific change     | [workflows.md](workflows.md)               |
| **Actual behaviour**            | **the source and its tests**               |
