# Qeet ID Server - Full Production-Grade Codebase Audit

**Audit date:** 2026-09-05  
**Repository:** `qeet-id-server`  
**Branch audited:** `develop`  
**Original audit mode:** Read-only source, configuration, migration, contract, and test review.  
**Original assessment:** Critical  
**Remediation status:** All 26 confirmed findings implemented and validated in the current worktree; deployment prerequisites remain below.

## Remediation Ledger

The finding sections below preserve the evidence from the audited revision. The
current implementation status is:

| Finding | Status | Implemented control / evidence |
|---|---|---|
| QID-AUD-001 | Remediated | Runtime signing-key mutation route removed; key material is never returned by an API. |
| QID-AUD-002 | Remediated | User creation derives tenant scope from the authenticated principal; cross-tenant integration regression added. |
| QID-AUD-003 | Remediated | Legacy OIDC registration ignores body tenant authority and validates client input. |
| QID-AUD-004 | Remediated | OAuth authorization requires active membership in the client's tenant. |
| QID-AUD-005 | Remediated | GDPR request and worker paths enforce tenant ownership; database constraints quarantine legacy mismatches. |
| QID-AUD-006 | Remediated | Machine principals require exact canonical scopes for every protected route. |
| QID-AUD-007 | Remediated | Typed route policies default deny; the live authenticated router must have exact policy coverage. |
| QID-AUD-008 | Remediated | Shared egress policy rejects private, loopback, metadata, redirect, and DNS-rebinding destinations. |
| QID-AUD-009 | Remediated | Reversible domain secrets use context-bound envelope ciphertext; comparison-only credentials are hashed; legacy rows migrate online. |
| QID-AUD-010 | Remediated | SAML AuthnRequest correlation and response/assertion replay IDs are atomically consumed and concurrency-tested. |
| QID-AUD-011 | Remediated | Apple ID tokens require RS256 JWKS validation, `kid`, issuer, audience, time, nonce, and verified email. |
| QID-AUD-012 | Remediated | Public OAuth clients require syntactically valid S256 PKCE at authorization and redemption. |
| QID-AUD-013 | Remediated | MFA guesses share atomic per-challenge and per-account attempt budgets across replicas. |
| QID-AUD-014 | Remediated | One-time fragment links exchange for scoped HttpOnly sessions; portal request paths are token-free and logs redact legacy paths. |
| QID-AUD-015 | Remediated | Login challenges, recovery codes, and OTP codes are locked and conditionally consumed in one transaction. |
| QID-AUD-016 | Remediated | Outbox, webhook, GDPR purge/export workers use durable owner leases; retries carry stable event/delivery IDs. |
| QID-AUD-017 | Remediated | Encrypted shared signing-key registry supports candidate staging, explicit activation, replica sync, restart persistence, and timed retirement. |
| QID-AUD-018 | Remediated | Named security mutations write audit and outbox evidence in their mutation transaction; matrix includes bulk-import summaries. |
| QID-AUD-019 | Remediated | Password update, other-session revocation, audit, and outbox writes commit or roll back together. |
| QID-AUD-020 | Remediated | JSON/form/SAML body caps, trailing-value rejection, header limits, and connection timeouts are tested. |
| QID-AUD-021 | Remediated | Unsupported or malformed SCIM filters return RFC 7644 `invalidFilter`; absent filters remain paginated. |
| QID-AUD-022 | Remediated | HKDF-derived AEAD keys bind tenant, purpose, resource, and version; cross-context ciphertext fails authentication. |
| QID-AUD-023 | Remediated | CI walks the production router and compares methods and security classification with all five OpenAPI documents. |
| QID-AUD-024 | Remediated | Automatic social linking requires verified email; authenticated explicit linking cannot email-match another account. |
| QID-AUD-025 | Remediated | OpenAPI paths, production servers, architecture paths, migration inventory, and worker documentation match the live system. |
| QID-AUD-026 | Remediated | Session listing uses bounded, user-bound cursor pagination beyond 100 records. |

Deployment must apply migrations `0097` through `0104`, configure a persistent
`SECRETS_KEY` or AWS KMS-backed DEK, and follow
[`docs/JWT-KEY-ROTATION.md`](JWT-KEY-ROTATION.md) for two-phase key activation.
Consumers must adopt mandatory public-client PKCE and the token-free admin portal
session contract before rollout.

## Scope And Method

The audit followed the runtime trust path rather than reviewing files in isolation:

```text
entrypoints -> bootstrap -> route tree -> middleware -> handler -> service
            -> transaction -> SQL/migration -> worker -> external dependency
            -> OpenAPI contract -> tests
```

The review covered all five bounded contexts, `internal/platform`, the composition root, all entrypoints, all hand-written `queries.sql` files, migrations `0001` through `0096` (with `0082` intentionally absent), all five OpenAPI documents, repository and LLM documentation, unit/integration/security tests, worker wiring, and production configuration gates.

The following executable checks were run against the audited revision before this report was written:

- `go build ./...` - passed.
- `go vet ./...` - passed.
- `go test -race -count=1 ./...` - passed, including architecture and security packages.
- `go test -tags integration -timeout 10m -count=1 ./tests/integration/...` - passed (11.915s on the confirming run).
- 62 focused tests across authentication, MFA, OIDC, SAML, social, webhooks, GDPR, and JWT packages - passed.
- `TestEnforce_NonUserActorBypasses` - passed, confirming machine-principal RBAC bypass is current expected behavior.
- All 23 JWT tests - passed, confirming ES256, `kid`, unknown-key, retired-key, and algorithm-confusion controls.
- `go run ./tools/openapi-split verify` - passed for all 5 files and 269 documented paths. This verifies YAML/reference integrity, not router coverage.

### Audit limitations

- No production traffic, cloud IAM policy, reverse-proxy configuration, external IdP configuration, or customer webhook consumer was available.
- Integration tests that require Testcontainers are reported separately in Validation Results.
- External protocol libraries were evaluated through their configured use and the repository's surrounding state controls. This was not a source audit of every transitive dependency.
- `govulncheck` was not installed locally, so dependency vulnerability status was not independently revalidated; CI remains the available scanner of record.
- Findings are based on the audited revision only. The repository was clean and matched `origin/develop` at audit start.

## Architecture And Trust Model

Qeet ID is a Go modular monolith with five bounded contexts (`access`, `identity`, `federation`, `developer`, and `operations`), one PostgreSQL database, and a single composition root in `internal/bootstrap`. API replicas also start six embedded workers; `cmd/worker` can start the same workers independently.

The highest-risk architectural property is application-layer tenant isolation. There is no PostgreSQL RLS. The intended chain is:

```text
authenticated principal tenant
  -> httpx.EnforceTenantScope for {tenantID} paths
  -> httpx.RequireTenant in handlers
  -> tenant predicate in SQL
```

That model works for most path-scoped routes, but it does not protect routes without a `{tenantID}` path parameter, body-supplied tenant identifiers, or jobs that later act on independently stored foreign keys. Three confirmed P0 findings exploit exactly those gaps.

Authorization is split by actor type:

- End-user JWTs are checked against `permissionMap()` by `rbac.Enforce`.
- API keys, service principals, and agents bypass route RBAC by design and are intended to be bounded by credential scopes.
- Credential scopes are carried into principals and JWTs but are not generally enforced.
- Routes missing from `permissionMap()` fail open for end users as well.

## Controls Confirmed Correct

The following controls were traced and found to work as intended:

- ES256-only JWT verification uses a parser algorithm allowlist, mandatory `kid`, unknown-key rejection, issuer validation, audience validation, expiry validation, and RFC 7638 thumbprints.
- Authorization codes and OIDC refresh tokens use row locks and single-use/rotation state.
- Device Authorization and CIBA bind approval to the client's tenant and consume polling credentials under row locks.
- WebAuthn ceremony sessions are atomically consumed with `DELETE ... RETURNING`; RP ID/origin/signature validation is delegated to `go-webauthn`.
- Password hashing uses Argon2id with constant-time comparison and transparent legacy bcrypt upgrade.
- Password-reset and magic-link records use opaque hashed tokens, expiry checks, transactions, and row locks.
- SAML signature, issuer, audience, destination, and time-condition validation is performed by the configured `gosaml2` service provider; warning conditions are explicitly rejected.
- SCIM bearer tokens are hashed and resolve the tenant before provisioning operations.
- API keys and service-principal secrets are hashed and shown once.
- Tenant path mismatches are centrally rejected before RBAC.
- ABAC is deny-overrides and fails closed on malformed evaluation.
- ReBAC traversal has bounded depth and cycle detection.
- CSRF uses an HMAC-protected double-submit token; CORS precedes CSRF; cookie-bearing mutation routes remain protected unless explicitly protocol-exempt.
- Refresh-token reuse revokes the affected session or grant chain.
- Audit rows use a per-tenant transaction-scoped advisory lock and deterministic SHA-256 chaining.
- Secrets-vault values and stored third-party access/refresh tokens use AES-GCM with random nonces.
- Production startup rejects dev trust headers, disabled CSRF, wildcard origins, weak JWT secrets, missing ES256 key material, and missing configured vault key material.

## Findings

## [P0] QID-AUD-001 - Any authenticated caller can rotate and obtain the global JWT signing key

Category:
Security

Severity:
P0

Confidence:
High

Location:
`internal/federation/oidc/oidc.go:809-810`, `Handler.Mount`, `POST /v1/oidc/signing-keys/rotate`; `internal/federation/oidc/clients_admin.go:436-472`, `Handler.rotateKey`; `internal/bootstrap/permissions.go:16-230`, `permissionMap`

Problem:
The platform-wide signing-key rotation endpoint is in the generic authenticated route group but has no permission-map entry and no handler-level operator check. Any authenticated user, including a newly signed-up tenant-less user, can rotate the live issuer key and receive the new private PEM.

Evidence:
`Handler.Mount` registers `POST /oidc/signing-keys/rotate`. `permissionMap()` contains only the corresponding metadata read route. Unmapped routes pass through `rbac.Enforce`. `rotateKey` calls `issuer.Rotate()` before any audit write and returns `private_key_pem` in the response.

Attack / Failure Scenario:
An attacker creates or controls any account, obtains an access token, calls the rotation endpoint, and receives the new private key. They can mint arbitrary Qeet tokens. The active process immediately trusts the new key; other replicas continue using their own old in-memory key, producing issuer split-brain. If the audit transaction then fails, the key is already rotated without an audit record.

Impact:
Signing-key compromise, arbitrary token forgery, global authentication compromise, multi-replica outage, and loss of trustworthy token provenance across every Qeet product and external relying party.

Root Cause:
A platform-operator action was mounted under tenant/user authentication and the fail-open permission map. Key mutation is performed before authorization-independent durable orchestration exists.

Recommended Fix:
Remove the HTTP mutation endpoint until a dedicated platform-operator control plane exists. If retained, require a distinct operator principal and step-up authentication, perform authorization before mutation, coordinate rotation through durable shared key storage/KMS, publish old and new keys consistently across replicas, and audit before exposing private material. Never return a long-lived signing private key to a browser-facing client.

Required Tests:
- Anonymous, tenant-less user, member, tenant admin, API key, service principal, and agent calls all fail.
- Only a platform-operator principal can request rotation.
- Concurrent signing, verification, JWKS reads, and rotation pass under `-race`.
- Two replicas observe the same active and retired keys throughout rotation.
- Audit failure leaves the active key unchanged.

Cross-Repository Impact:
Server / Console / Login / SDK / Mobile / Docs / External

Breaking Change:
Yes

Should Fix Now:
Yes

## [P0] QID-AUD-002 - User creation trusts a body-supplied tenant ID

Category:
Security

Severity:
P0

Confidence:
High

Location:
`internal/identity/users/http.go:244-269`, `Handler.create`, `POST /v1/users`; `internal/identity/users/domain.go:42-50`, `CreateInput`; `internal/identity/users/repository.go:188-239`, `Repository.CreateWithCredential`

Problem:
The authenticated single-user create endpoint accepts required `tenant_id` from JSON and never replaces or validates it against `httpx.RequireTenant(r)`.

Evidence:
The route has no `{tenantID}` segment, so `EnforceTenantScope` cannot compare it. `Handler.create` validates the body and passes it unchanged. `CreateWithCredential` inserts `in.TenantID` directly. Neighboring API-key, invitation, group, webhook, and bulk-user handlers correctly derive or compare tenant scope.

Attack / Failure Scenario:
A caller with `user.write` in Tenant A submits Tenant B's UUID in the body and creates an active Tenant B user with an attacker-chosen password. The created account can authenticate and receives Tenant B in its token. Unmapped tenant administration routes then make this a practical takeover chain.

Impact:
Cross-tenant identity injection, unauthorized accounts, possible tenant takeover, corrupted seat/billing state, and unreliable audit attribution.

Root Cause:
Legacy body-scoped tenant input bypasses the central guard, and the handler omits the repository's required trusted tenant override.

Recommended Fix:
Call `httpx.RequireTenant(r)` before decoding or persistence and unconditionally assign `in.TenantID` from the principal. Prefer moving the endpoint to `/tenants/{tenantID}/users` in a versioned contract later, but do not delay the immediate server-side override.

Required Tests:
- Tenant A cannot create a user in Tenant B by body UUID.
- Omitted and mismatched body tenant values cannot alter scope.
- API keys and service principals require an appropriate enforced scope.
- Audit and outbox events carry the principal tenant.

Cross-Repository Impact:
Server / Console / SDK / Docs

Breaking Change:
No

Should Fix Now:
Yes

## [P0] QID-AUD-003 - Legacy OIDC client registration trusts a body-supplied tenant ID

Category:
Security

Severity:
P0

Confidence:
High

Location:
`internal/federation/oidc/oidc.go:76-160`, `CreateClientInput` and `Service.RegisterClient`; `internal/federation/oidc/oidc.go:780, 901-949`, `POST /v1/oidc/clients` and `Handler.registerClient`

Problem:
The legacy authenticated OIDC client-registration route accepts `tenant_id` from the body and persists it without comparison to the caller's tenant.

Evidence:
`registerClient` never calls `RequireTenant`. `RegisterClient` applies plan limits and inserts against `in.TenantID`. The newer `/v1/tenants/{tenantID}/oidc/clients` path correctly resolves the path/principal tenant and overwrites the body, proving the intended control.

Attack / Failure Scenario:
A connection administrator in Tenant A supplies Tenant B's UUID, registers a public or confidential client in Tenant B, receives its secret, and controls redirect URIs and grant types. They then combine it with QID-AUD-004 to mint Tenant B tokens for a nonmember.

Impact:
Cross-tenant OAuth client injection, malicious redirect registration, unauthorized grants, and downstream account/token compromise.

Root Cause:
Two competing client-registration paths exist; the legacy path predates the tenant-scoped handler pattern.

Recommended Fix:
Immediately derive `TenantID` from `RequireTenant` in the legacy handler. Deprecate and remove the non-tenant-scoped route after SDK/console coordination. Validate grant types, client type, and redirect URI policy during the same remediation.

Required Tests:
- Tenant A cannot register a client under Tenant B through either route.
- The legacy and tenant-scoped routes produce identical tenant ownership.
- A machine credential requires `connection.write` or an equivalent enforced scope.

Cross-Repository Impact:
Server / Console / Login / SDK / Docs / External

Breaking Change:
No initially; eventual route removal is breaking

Should Fix Now:
Yes

## [P0] QID-AUD-004 - OAuth authorization assigns the client's tenant without proving user membership

Category:
Security

Severity:
P0

Confidence:
High

Location:
`internal/access/authentication/loginsession.go:26-60`, `CreateLoginSession` and `ResolveLoginSession`; `internal/federation/oidc/oidc.go:224-263`, `Service.Authorize`; `internal/federation/oidc/oidc.go:970-1051`, `authorize` and `decision`

Problem:
The hosted SSO cookie resolves only a user ID. Authorization then derives the tenant exclusively from the OAuth client and stores that tenant in the authorization code without checking that the user belongs to it.

Evidence:
`ResolveLoginSession` returns `row.UserID` only. `Authorize` loads `GetClientRedirectInfo`, validates redirect/scopes, then inserts `{userID, info.TenantID}`. Device and CIBA flows explicitly call tenant-membership queries; the authorization-code flow does not. Existing integration-test commentary states that a tenant-less user is acceptable because tenant comes from the client.

Attack / Failure Scenario:
A user from Tenant A or a tenant-less signup authenticates to the hosted login, authorizes a known Tenant B client, and receives an access/ID/refresh token carrying Tenant B. Unmapped authenticated routes trust that tenant claim, and downstream services may treat the signed tenant claim as sufficient membership proof.

Impact:
Cross-tenant token issuance, tenant claim forgery by the authorization server itself, unauthorized access in this and downstream products, and invalid consent records.

Root Cause:
The SSO session is identity-only while the authorization service assumes the target client's tenant confers membership.

Recommended Fix:
Before consent lookup or code creation, require active membership of `userID` in the client's tenant. Bind consent to `(user, tenant, client)`. Preserve the tenant through the hosted-login flow or re-resolve it server-side; never trust the client association alone.

Required Tests:
- Tenant A and tenant-less users cannot authorize Tenant B clients.
- Active Tenant B members can authorize Tenant B clients.
- Suspended/deleted users and revoked memberships fail.
- Existing consent cannot bypass a later membership removal.

Cross-Repository Impact:
Server / Login / SDK / Docs / External

Breaking Change:
Yes

Should Fix Now:
Yes

## [P0] QID-AUD-005 - GDPR purge can erase a user in another tenant

Category:
Security

Severity:
P0

Confidence:
High

Location:
`internal/operations/gdpr/gdpr.go:48-76`, `Service.Request`; `internal/operations/gdpr/gdpr.go:128-184`, `tick`, `purgeOne`, and `purgeUserData`; `internal/operations/gdpr/gdpr.go:652-676`, `Handler.create`; `internal/operations/gdpr/queries.sql:119-171`; migrations `0018_gdpr.up.sql:2-14`

Problem:
The handler correctly stamps the caller's tenant on a purge request but accepts an arbitrary body `user_id`. Neither code nor schema proves that the target user belongs to that tenant. The worker later purges only by `user_id`.

Evidence:
`InsertPurgeRequest` stores independent foreign keys to tenant and user. `PurgeUserPII`, credential deletion, MFA deletion, and session revocation all filter only by user ID. There is no composite ownership foreign key or preflight membership query.

Attack / Failure Scenario:
A GDPR administrator in Tenant A submits a known Tenant B user UUID. The request appears in Tenant A's queue. Once its grace period expires, any worker redacts Tenant B's profile, deletes password and MFA credentials, and revokes sessions.

Impact:
Cross-tenant destructive data loss, account denial of service, compliance breach, and possible irreversible loss of authentication factors.

Root Cause:
The queued job stores two valid identifiers but does not enforce their relationship; the asynchronous executor trusts the malformed request.

Recommended Fix:
Validate the target with a tenant-scoped user lookup before inserting. Add a database-enforced ownership relation, preferably a composite foreign key backed by a unique `(id, tenant_id)` key. Carry `tenant_id` into every purge mutation predicate and revalidate inside the worker transaction.

Required Tests:
- Tenant A cannot queue or execute a purge for Tenant B.
- A manually inserted mismatched queue row cannot purge data.
- Concurrent workers process a valid purge once.
- Cancellation and completion remain tenant-scoped.

Cross-Repository Impact:
Server / Console / Docs

Breaking Change:
No

Should Fix Now:
Yes

## [P1] QID-AUD-006 - Machine credential scopes are not enforced

Category:
Security

Severity:
P1

Confidence:
High

Location:
`internal/access/authorization/rbac/enforce.go:48-94`, `Enforce`; `internal/platform/http/httpx/auth.go:157-177`, `RequireScope`; `internal/developer/api-keys/apikey.go:239-283`; `internal/developer/principal/principal.go:126-181`; `internal/developer/agents/agent.go:372-426`

Problem:
API keys, service principals, and agents bypass RBAC, but the scopes intended to replace RBAC are not generally checked.

Evidence:
`Enforce` immediately passes any actor whose type is not `user`. `RequireScope` has no route-middleware usage. Scopes are stored and copied into principals/JWTs. Apart from specialized vault retrieval checks, handlers do not consult them. The unit test `TestEnforce_NonUserActorBypasses` explicitly expects an API key to pass a denied route.

Attack / Failure Scenario:
An empty-scope API key creates service principals, mutates roles, changes SAML/LDAP configuration, queues GDPR operations, or rotates the global key. An agent scoped only for one vault secret can invoke unrelated tenant administration endpoints.

Impact:
Horizontal capability escalation within a tenant, durable backdoors, disclosure of sensitive administration data, and destructive actions by credentials advertised as least-privileged.

Root Cause:
The design separated user RBAC and machine scopes but implemented only the bypass half of that design.

Recommended Fix:
Create one exhaustive route policy table used for both user permissions and machine scopes. Deny machine actors on unmapped routes. Validate allowed scope names at credential issuance, map each route to required scope(s), and migrate existing credentials explicitly rather than granting wildcard compatibility.

Required Tests:
- Empty and unrelated scopes receive 403 on every protected route family.
- Correct read scopes cannot mutate.
- Correct write scopes work only in the credential's tenant.
- API key, service, and agent matrices are exercised independently.

Cross-Repository Impact:
Server / SDK / Docs / External

Breaking Change:
Yes

Should Fix Now:
Yes

## [P1] QID-AUD-007 - The route permission map fails open and omits administrative APIs

Category:
Security

Severity:
P1

Confidence:
High

Location:
`internal/bootstrap/permissions.go:1-230`, `permissionMap`; `internal/access/authorization/rbac/enforce.go:72-78`, unmapped-route pass-through; `internal/bootstrap/router.go:291-346`, authenticated mounts

Problem:
Routes absent from `permissionMap()` are allowed for end users. Multiple newer administrative modules and individual mutations are absent, so ordinary tenant members can perform privileged operations.

Evidence:
Confirmed omissions include user vendor import, group update, invite resend, ReBAC writes/deletes, legacy OIDC client deletion, shadow-AI review, social-provider administration, webhook detail/delivery operations, token-vault provider administration, all agent administration, auth-hook CRUD, verifiable-credential issuance/revocation, custom-domain changes, bot/risk settings, tenant rate-limit changes, SIEM sink CRUD, GDPR export administration, compliance evidence generation/read, and universal search. Handlers generally enforce tenant equality only, not role permission.

Attack / Failure Scenario:
A member installs a fail-open auth hook pointing to an attacker endpoint, creates a SIEM sink that receives future audit events, weakens risk/rate-limit settings, writes ReBAC tuples, issues credentials, exports another tenant member's personal data, or suspends all agents.

Impact:
Serious vertical privilege escalation, security-policy tampering, data exfiltration, and loss of administrative separation.

Root Cause:
Authorization is an incomplete hand-maintained allowlist with fail-open behavior and no router-to-policy coverage test.

Recommended Fix:
Make authenticated administrative routes default-deny. Associate policy metadata at route registration or generate the map from a typed route catalogue. Add every administrative route with a reviewed permission and explicitly mark self-service/PDP routes public-to-authenticated users.

Required Tests:
- Walk the live router and fail when an authenticated route lacks an explicit policy classification.
- For each role, verify every route family as allow/deny.
- Add regression tests for each representative omitted mutation and sensitive read.

Cross-Repository Impact:
Server / Console / SDK / Docs

Breaking Change:
Yes

Should Fix Now:
Yes

## [P1] QID-AUD-008 - Tenant-configured outbound endpoints permit SSRF and internal network access

Category:
Security

Severity:
P1

Confidence:
High

Location:
`internal/developer/webhooks/webhook.go:102-128, 346-379`; `internal/developer/auth-hooks/authhook.go:73-103, 145-171`; `internal/developer/credentials/tokenvault/tokenvault.go:128-191, 326-350`; `internal/federation/social/oauthclient.go:43-151`; `internal/federation/ldap/ldap.go:120-157, 286-309`; `internal/operations/siem/siem.go:75-109, 270-306`

Problem:
Webhook, auth-hook, token-vault, social-discovery, LDAP, and SIEM destinations accept tenant-provided URLs/hosts and use ordinary HTTP/LDAP clients without blocking loopback, private, link-local, metadata, Unix-socket-equivalent, redirect, or DNS-rebinding targets.

Evidence:
Validation is generally limited to `http://`/`https://` prefixes or URL syntax. The default HTTP transport follows redirects. LDAP accepts arbitrary `ldap://`/`ldaps://` destinations. There is no shared egress policy or post-DNS address validation.

Attack / Failure Scenario:
A tenant administrator, or any member while QID-AUD-007 exists, targets internal control-plane APIs, cloud metadata endpoints, localhost services, or private databases. Social discovery and token-vault flows can chain attacker-controlled discovery/token endpoints. Webhook/SIEM responses are persisted, exposing internal response fragments to the caller.

Impact:
Internal network reconnaissance, metadata/service credential theft, calls to unauthenticated internal services, and cross-service compromise.

Root Cause:
Outbound integrations are treated as ordinary URL validation rather than crossing an infrastructure trust boundary.

Recommended Fix:
Use a shared egress-safe dialer: allow only required schemes/ports, resolve every hop, reject private/loopback/link-local/multicast/unspecified ranges, disable or revalidate redirects, protect against DNS rebinding, and enforce deployment-level network egress policy. Offer explicit private-connector architecture for legitimate on-prem LDAP rather than weakening public SaaS egress controls.

Required Tests:
- IPv4/IPv6 loopback, RFC1918, link-local, metadata, decimal/hex IP, redirects, and DNS rebinding are rejected.
- Public HTTPS endpoints work.
- Self-hosted/private connector mode is separately authorized and tested.

Cross-Repository Impact:
Server / Deploy / Docs / External

Breaking Change:
Yes

Should Fix Now:
Yes

## [P1] QID-AUD-009 - Security-sensitive integration secrets are stored in plaintext

Category:
Security

Severity:
P1

Confidence:
High

Location:
Migrations `0010_mfa.up.sql`, `0016_webhooks.up.sql`, `0020_social.up.sql`, `0032_ldap.up.sql`, `0058_log_sinks.up.sql`, `0059_auth_hooks.up.sql`, `0071_token_vault.up.sql`, and `0086_mfa_push.up.sql`; corresponding services under `internal/access/mfa`, `internal/developer`, `internal/federation`, and `internal/operations/siem`

Problem:
TOTP seeds, webhook HMAC keys, social client secrets, LDAP bind passwords, SIEM tokens, auth-hook signing keys, token-vault provider client secrets, push tokens, and push device credentials are persisted as plaintext text columns.

Evidence:
The migrations explicitly declare plaintext `TEXT` columns, sometimes with comments such as `encrypt-at-rest in prod`, but the services pass raw values directly to sqlc. Only the generic secrets vault and connected-account access/refresh tokens use AES-GCM.

Attack / Failure Scenario:
A read-only database compromise, backup leak, support dump, or overly broad analytics role exposes authentication factors and customer integration credentials. TOTP seeds enable second-factor cloning; LDAP/social/SIEM credentials reach customer infrastructure.

Impact:
Credential compromise across Qeet and customer systems, MFA bypass, webhook forgery, and costly incident-response/rotation obligations.

Root Cause:
Encryption was added to dedicated vault tables but not adopted by earlier domain-owned secret columns.

Recommended Fix:
Migrate all reversible secrets to envelope-encrypted ciphertext/nonce/version columns backed by KMS, with tenant/resource-bound AAD. Hash credentials that only need comparison. Use expand-migrate-contract migrations and rotation runbooks; never edit existing migrations.

Required Tests:
- Database rows never contain submitted plaintext.
- Wrong tenant/resource AAD cannot decrypt.
- Key rotation and legacy-row migration preserve service continuity.
- Backups and diagnostic exports exclude secret material.

Cross-Repository Impact:
Server / Deploy / Docs / External

Breaking Change:
No API change; database rollout requires migration coordination

Should Fix Now:
Yes

## [P1] QID-AUD-010 - SAML assertions can be replayed during their validity window

Category:
Security

Severity:
P1

Confidence:
High

Location:
`internal/federation/saml/saml.go:296-317`, `buildSP`; `internal/federation/saml/saml.go:747-833`, `Handler.acs`; `internal/federation/saml/queries.sql:54-65`

Problem:
The SP validates signatures and assertion conditions but does not persist or consume assertion/response IDs and does not bind responses to an outstanding AuthnRequest through a request tracker.

Evidence:
`buildSP` configures issuer, ACS, audience, and certificate only. The ACS calls `RetrieveAssertionInfo`, provisions the user, and creates a fresh Qeet login code every time. The only single-use state is the post-ACS Qeet login code; no SAML assertion identifier appears in schema or queries.

Attack / Failure Scenario:
An attacker who captures a valid signed SAMLResponse re-posts it before `NotOnOrAfter`. Each replay produces a new login code and session even after the first code was consumed.

Impact:
Federated session compromise and repeated unauthorized login from one stolen assertion.

Root Cause:
Signature/condition validation was treated as complete SAML ceremony validation; replay and request-correlation state was omitted.

Recommended Fix:
Persist AuthnRequest IDs with short TTL, require matching `InResponseTo` for SP-initiated login, atomically consume request state, and store assertion/response IDs until expiry with unique constraints. Define and separately gate IdP-initiated SSO if supported.

Required Tests:
- The same signed assertion succeeds once and is then rejected.
- Unknown or already-consumed `InResponseTo` is rejected.
- IdP-initiated behavior is explicit and tested.
- Concurrent replay yields exactly one login code.

Cross-Repository Impact:
Server / Login / Docs / External

Breaking Change:
Potentially

Should Fix Now:
Yes

## [P1] QID-AUD-011 - Apple ID token claims are parsed without cryptographic or claims validation

Category:
Security

Severity:
P1

Confidence:
High

Location:
`internal/federation/social/apple.go:64-110`, `oauthClient.appleExchange`

Problem:
Sign in with Apple uses `jwt.ParseUnverified` and trusts `sub` and `email` without checking signature, algorithm, `kid`, issuer, audience, expiry, nonce, or `email_verified`.

Evidence:
The source comment explicitly says the token is read without re-verifying against Apple's JWKS. No nonce is sent in `beginAppleLogin`, and no Apple JWKS cache/verifier exists.

Attack / Failure Scenario:
Token substitution, a compromised/misrouted token endpoint response, proxy/TLS trust failure, or future endpoint behavior can supply attacker-selected identity claims that are linked to or used to create a Qeet account.

Impact:
Social-login account takeover and standards-noncompliant identity binding.

Root Cause:
TLS authenticity of the token response was incorrectly substituted for OIDC ID-token validation.

Recommended Fix:
Send and persist a nonce, fetch/cache Apple's JWKS, enforce ES256, resolve `kid`, validate signature, `iss=https://appleid.apple.com`, `aud=client_id`, `exp`, `iat`, and nonce, and require an acceptable verified-email claim before email linking.

Required Tests:
- Invalid signature, wrong `kid`, wrong issuer/audience, expiry, missing/mismatched nonce, and unverified email fail.
- Key rotation refreshes JWKS safely.

Cross-Repository Impact:
Server / Login / Docs

Breaking Change:
No

Should Fix Now:
Yes

## [P1] QID-AUD-012 - Public OAuth clients can use authorization code flow without PKCE

Category:
Security

Severity:
P1

Confidence:
High

Location:
`internal/federation/oidc/oidc.go:224-263`, `Authorize`; `internal/federation/oidc/oidc.go:455-522`, `ExchangeCode`; `internal/federation/oidc/queries.sql:92-108`

Problem:
PKCE is enforced only when a challenge was supplied. The server does not require S256 for public clients.

Evidence:
`GetClientRedirectInfo` does not return client type. Authorization stores nullable challenge fields. Exchange skips verifier checks when the challenge is absent. Discovery advertises S256 but does not make it mandatory.

Attack / Failure Scenario:
A SPA/mobile/desktop client omits PKCE. An intercepted authorization code can be redeemed by anyone who knows the public client ID and redirect URI.

Impact:
Authorization-code interception and user token theft.

Root Cause:
PKCE support was implemented as optional request decoration rather than a public-client requirement.

Recommended Fix:
Load client type during authorization and reject public-client requests without `code_challenge_method=S256`. Consider requiring PKCE for confidential clients as well. Validate verifier syntax and length.

Required Tests:
- Public client without PKCE fails at authorization.
- `plain`, missing method, malformed challenge, and malformed verifier fail.
- Correct S256 succeeds for public and confidential clients.

Cross-Repository Impact:
Server / Login / SDK / Mobile / Docs / External

Breaking Change:
Yes

Should Fix Now:
Yes

## [P1] QID-AUD-013 - MFA verification has no challenge/account attempt budget

Category:
Security

Severity:
P1

Confidence:
High

Location:
`internal/access/authentication/service.go:544-589`, `verifyAndConsumeMFAChallenge`; `internal/access/mfa/mfa.go:201-288`, `Verify` and `VerifyForLogin`; `internal/access/mfa/mfa.go:441-476`, `ChallengeOTP` and `VerifyOTP`; `internal/bootstrap/router.go:226-289`, limiter wiring

Problem:
TOTP, recovery-code, and email/SMS OTP verification do not track failed attempts per challenge, user, factor, or tenant. The login limiter is IP-based and authenticated verification uses generous user/tenant buckets.

Evidence:
Wrong MFA codes leave the login challenge intact until its 10-minute TTL. `Verify` loops through every recovery hash and returns invalid without incrementing state. `VerifyOTP` looks up only the submitted hash. No failed-attempt/locked state exists in MFA tables.

Attack / Failure Scenario:
A distributed attacker with an MFA challenge tries six-digit codes across IPs during the challenge window. Authenticated attackers can drive high-rate OTP/recovery verification against their own or stolen sessions. Repeated bcrypt checks also create CPU pressure.

Impact:
Reduced effective MFA entropy, credential-stuffing amplification, SMS/email abuse, and denial of service.

Root Cause:
Rate limiting was applied at transport identities but not at the security object being guessed.

Recommended Fix:
Add atomic per-challenge/factor failed-attempt counters, a small maximum (for example 5-10), terminal consumption/lockout, and tenant/user/device abuse signals. Keep IP limiting as an additional layer.

Required Tests:
- Wrong attempts atomically exhaust and invalidate a challenge.
- Distributed IPs share the same challenge budget.
- A correct code after exhaustion fails.
- Concurrent final attempts cannot exceed the budget.

Cross-Repository Impact:
Server / Login / Mobile / Docs

Breaking Change:
No

Should Fix Now:
Yes

## [P1] QID-AUD-014 - Admin-portal capability tokens are written to application logs

Category:
Security

Severity:
P1

Confidence:
High

Location:
`internal/federation/adminportal/adminportal.go:1-8, 164-171, 313-331`; `internal/platform/http/httpx/middleware.go:40-108`, `AccessLog`; `internal/platform/http/httpx/response.go:34-78`, `WriteError`

Problem:
The raw admin-portal token is the sole credential and is carried in the URL path. The application's own access logger records the raw path on every request.

Evidence:
Portal routes use `/v1/admin-portal/{token}/...`. `AccessLog` prefers a safe route pattern for `route` but also logs `path=r.URL.Path`. The redacting handler redacts by attribute key; `path` is not sensitive. Unhandled errors also log raw paths.

Attack / Failure Scenario:
Anyone with access to application, proxy, APM, or log-export systems retrieves a still-valid portal token and configures SAML or rotates/revokes SCIM credentials for that tenant.

Impact:
Credential disclosure, federation configuration compromise, and privilege escalation through a secondary observability system.

Root Cause:
A reusable bearer capability was placed in a routinely logged URL component without path-parameter redaction.

Recommended Fix:
Exchange the one-time URL token for a short-lived HttpOnly, Secure, narrowly scoped session cookie and redirect to a token-free path. Immediately sanitize route parameters in access/error logs and set strict `Referrer-Policy: no-referrer`. Shorten default TTL and rotate/revoke leaked links.

Required Tests:
- Access/error logs never contain raw portal tokens.
- Browser history and subsequent request paths are token-free after exchange.
- Cookie scope, expiry, CSRF, revocation, and capabilities are enforced.

Cross-Repository Impact:
Server / Login / Deploy / Docs

Breaking Change:
Yes

Should Fix Now:
Yes

## [P2] QID-AUD-015 - MFA login challenges and recovery codes are not atomically consumed

Category:
Bug

Severity:
P2

Confidence:
High

Location:
`internal/access/authentication/service.go:544-589`, `verifyAndConsumeMFAChallenge`; `internal/access/authentication/queries.sql:109-112`; `internal/access/mfa/mfa.go:201-288`, `Verify`; `internal/access/mfa/queries.sql:41-47`

Problem:
MFA login challenges are selected without a lock and deleted after successful verification with the delete error ignored. Recovery codes are listed without locks and marked used without an affected-row condition.

Evidence:
Two concurrent requests can read the same challenge before either deletes it. Two transactions can both read the same unused recovery-code hash and both update `used_at`. OTP records correctly use `FOR UPDATE`, showing the intended pattern.

Attack / Failure Scenario:
Two simultaneous submissions of one valid challenge/recovery code both complete and mint separate sessions or both open a step-up window.

Impact:
Single-use guarantee failure and duplicated authenticated sessions. Possession of the valid factor is still required, limiting severity.

Root Cause:
Check-then-delete/update logic is split across unlocked statements.

Recommended Fix:
Consume the login challenge in one transaction with `DELETE ... RETURNING` after successful verification or lock it before verification. Lock candidate recovery-code rows and use conditional `UPDATE ... WHERE used_at IS NULL RETURNING` before success.

Required Tests:
- Two concurrent valid challenge completions yield exactly one token pair.
- Two concurrent recovery-code uses yield exactly one success.
- Failed factor verification does not consume the challenge.

Cross-Repository Impact:
Server / Login / Mobile

Breaking Change:
No

Should Fix Now:
Yes

## [P2] QID-AUD-016 - Worker row locks are released before delivery or job execution

Category:
Reliability

Severity:
P2

Confidence:
High

Location:
`internal/developer/webhooks/queries.sql:56-65`, `GetDueDeliveries`; `internal/developer/webhooks/webhook.go:286-344`, `tick`; `internal/platform/events/outbox/outbox.go:94-164`, `Dispatcher.tick`; `internal/operations/gdpr/queries.sql:130-139, 188-197`; `internal/bootstrap/app.go:113-125`; `cmd/worker/main.go:1-78`

Problem:
Several workers use `FOR UPDATE SKIP LOCKED` through pool-level queries without an explicit transaction. PostgreSQL releases the lock when the statement ends, before network delivery or job processing.

Evidence:
Rows are loaded into memory, result sets closed, then processed and updated later. Every API replica starts embedded workers, and the standalone worker can run the same workers concurrently.

Attack / Failure Scenario:
Two replicas select the same webhook/outbox/export/purge rows and both process them. Webhooks and NATS events are duplicated; exports do redundant work; non-idempotent downstream consumers apply an event twice.

Impact:
Duplicate customer actions, event-ordering anomalies, unnecessary load, confusing attempts/dead-letter state, and unreliable exactly-once assumptions.

Root Cause:
`SKIP LOCKED` was used as if its lock survived outside the implicit statement transaction; no durable claim/lease state exists.

Recommended Fix:
Atomically claim rows in a short transaction (`UPDATE ... SET lease_owner, lease_until ... RETURNING`), then perform I/O outside it and finalize conditionally. Include stable delivery/event IDs in outbound requests and document at-least-once semantics. Allow operators to disable embedded workers when standalone workers run.

Required Tests:
- Two worker instances racing the same queue claim each row once per lease.
- Crash-after-publish redelivers with the same stable ID.
- Expired leases recover abandoned work.

Cross-Repository Impact:
Server / Deploy / External

Breaking Change:
No

Should Fix Now:
Yes

## [P2] QID-AUD-017 - Runtime signing-key rotation is process-local, non-durable, and not concurrency-safe

Category:
Reliability

Severity:
P2

Confidence:
High

Location:
`internal/platform/crypto/tokens/jwt.go:78-124, 136-181, 316-430`, `Issuer`; `internal/federation/oidc/clients_admin.go:436-472`, `rotateKey`

Problem:
`Issuer` mutates `active` and `verifiers` in memory without synchronization. Rotation affects one process only and relies on a human to persist the returned PEM and retired public key.

Evidence:
Concurrent `Sign`, `VerifyAccess`, `JWKS`, `KeyInfo`, `AddRetiredKeysPEM`, and `Rotate` access the same pointer/map with no mutex. No database/KMS state or replica broadcast exists. Retired keys have no encoded expiry despite documentation calling this a grace window.

Attack / Failure Scenario:
Legitimate rotation on one replica causes load-balanced requests to issue/verify against inconsistent keys. A restart reverts to old configured material. Concurrent map iteration/write can race or panic.

Impact:
Authentication outages, rejected valid tokens, lost rotation state, and nondeterministic runtime failures.

Root Cause:
A runbook operation was exposed as a mutable in-process API.

Recommended Fix:
Remove in-process rotation or implement a durable KMS/shared-store key lifecycle with versioned activation, replica convergence, explicit retire-at timestamps, and synchronization. Use immutable snapshots or locks inside `Issuer`.

Required Tests:
- `go test -race` with concurrent sign/verify/JWKS/rotate.
- Multi-instance activation and rollback tests.
- Restart persistence and retired-key expiry tests.

Cross-Repository Impact:
Server / Deploy / SDK / External

Breaking Change:
Potentially

Should Fix Now:
Yes, together with QID-AUD-001

## [P2] QID-AUD-018 - Important mutations can commit without audit or outbox records

Category:
Reliability

Severity:
P2

Confidence:
High

Location:
`internal/identity/users/http.go:244-304`, `create` and `publishCreated`; `internal/identity/users/bulk.go:178-202`; `internal/developer/agents/agent.go:451-477, 692-717`; handlers for auth hooks, SIEM, rate limits, domain verification, ReBAC, and VC issuance

Problem:
User creation commits its database transaction before starting a goroutine that writes audit/outbox rows with the request context and ignores all errors. Several security-sensitive modules do not audit mutations at all; agent lifecycle audit writes are best-effort after mutation.

Evidence:
`go h.publishCreated(r, u)` runs after `CreateWithCredential` commits. The goroutine reuses a context canceled when the request ends. `audit.Record`, `outbox.Enqueue`, and commit errors are discarded. Auth-hook, SIEM, rate-limit, domain, ReBAC, and VC handlers contain no audit recording.

Attack / Failure Scenario:
Request cancellation or database pressure leaves a user/security-policy mutation committed with no audit event or domain event. Incident responders cannot reconstruct who installed an outbound auth hook, altered SIEM export, or changed authorization tuples.

Impact:
Broken audit completeness, missed downstream provisioning/webhooks, compliance evidence gaps, and undetectable security changes.

Root Cause:
Atomic outbox/audit conventions are not enforced and some handlers treat security telemetry as best-effort.

Recommended Fix:
Move business mutation, audit row, and outbox row into the same transaction. Add an architecture/test rule for audited action categories. Do not launch request-owned goroutines for durable work.

Required Tests:
- Forced audit/outbox failure rolls back the mutation.
- Request cancellation after commit cannot lose required events.
- Every listed security mutation emits actor type, subject, tenant, target, and request ID.

Cross-Repository Impact:
Server / External

Breaking Change:
No

Should Fix Now:
Yes

## [P2] QID-AUD-019 - Password change can succeed while session revocation fails

Category:
Reliability

Severity:
P2

Confidence:
High

Location:
`internal/access/authentication/service.go:992-1026`, `ChangePassword`; `internal/identity/users/repository.go:575-577`, `SetPassword`

Problem:
Password upsert and revocation of other sessions execute as independent pool operations rather than one transaction.

Evidence:
`SetPassword` commits before `RevokeOtherSessionsForUser`. If revocation fails, the handler returns an error although the password has changed and potentially compromised sessions remain active.

Attack / Failure Scenario:
A transient database error occurs between statements. The victim believes the password change failed or retries, while an attacker's existing refresh session remains valid.

Impact:
Inconsistent credential state and failure of a core incident-response expectation.

Root Cause:
The users repository does not expose a transaction-bound password operation to authentication service.

Recommended Fix:
Run password update, other-session revocation, audit, and claims-change outbox event in one transaction. Decide and document whether the current session should also rotate.

Required Tests:
- Inject revocation failure and prove password remains unchanged.
- Successful change revokes every other refresh session atomically.

Cross-Repository Impact:
Server / Login / SDK

Breaking Change:
No

Should Fix Now:
Yes

## [P2] QID-AUD-020 - General request bodies and HTTP connection setup lack resource bounds

Category:
Reliability

Severity:
P2

Confidence:
High

Location:
`internal/platform/http/httpx/response.go:167-174`, `DecodeJSON`; `internal/bootstrap/server.go:13-24`, `startHTTPServer`; OAuth/SAML handlers calling `ParseForm`

Problem:
Generic JSON decoding reads an unbounded request body. The server has read/write timeouts but no `ReadHeaderTimeout`, `IdleTimeout`, or header-size policy. Form endpoints do not install route-specific body caps.

Evidence:
`DecodeJSON` constructs a decoder directly over `r.Body`; only bulk import has an explicit `LimitReader`. `http.Server` sets only `ReadTimeout` and `WriteTimeout`.

Attack / Failure Scenario:
Authenticated or public attackers send large JSON/form bodies or hold many idle keep-alive/header connections, consuming memory, CPU, and file descriptors.

Impact:
Availability degradation and increased cost under abuse.

Root Cause:
Validation constrains decoded fields but not transport bytes or connection lifecycle.

Recommended Fix:
Apply a global conservative `MaxBytesReader` with narrowly larger route overrides, reject trailing JSON values, set `ReadHeaderTimeout`, `IdleTimeout`, and `MaxHeaderBytes`, and enforce proxy limits consistently.

Required Tests:
- Oversized JSON/form/header requests receive 413/431 without large allocation.
- Valid bulk-import limits still work.
- Slow-header and idle-connection tests terminate within configured bounds.

Cross-Repository Impact:
Server / Deploy / SDK

Breaking Change:
Potentially for oversized undocumented requests

Should Fix Now:
No

## [P2] QID-AUD-021 - Unsupported SCIM filters silently become unfiltered listings

Category:
API

Severity:
P2

Confidence:
High

Location:
`internal/federation/scim/scim.go:518-555`, `parseUserNameFilter` and the user-list handler; `internal/federation/scim/groups.go:293-366`, `parseDisplayNameFilter` and the group-list handler; the SCIM ServiceProviderConfig response

Problem:
Only a narrow equality filter is parsed. Unsupported or malformed filters collapse to an empty filter, which is treated as no filter and returns a tenant-wide page.

Evidence:
The parser returns an empty string for unsupported forms while list queries add a predicate only when the parsed value is nonempty. The service advertises `filter.supported=true`.

Attack / Failure Scenario:
An IdP asks for one user with an unsupported but syntactically valid SCIM filter and receives up to the page limit of all provisioned users, causing over-disclosure to the provisioning client and reconciliation errors.

Impact:
Within-tenant data over-return, SCIM interoperability failures, and unsafe provisioning/deprovisioning behavior.

Root Cause:
Parser failure and absence of a filter share the same representation.

Recommended Fix:
Use a structured SCIM filter parser, distinguish absent/valid/unsupported/malformed states, and return RFC 7644 `invalidFilter` errors for unsupported expressions. Advertise the precise supported subset.

Required Tests:
- Unsupported attributes/operators and malformed expressions return SCIM errors.
- No-filter listing remains paginated.
- Exact supported filters return only matching resources.

Cross-Repository Impact:
Server / Docs / External

Breaking Change:
Yes for clients relying on the current incorrect fallback

Should Fix Now:
No

## [P2] QID-AUD-022 - Vault encryption is global and not bound to tenant or record context

Category:
Architecture

Severity:
P2

Confidence:
High

Location:
`internal/developer/credentials/secrets/keyprovider.go:8-25`; `internal/developer/credentials/secrets/secret.go:37-77`; `internal/developer/credentials/tokenvault/tokenvault.go:56-120`; `README.md` security claims

Problem:
One process-wide AEAD key encrypts every tenant's secret and token-vault value. AES-GCM is invoked with nil AAD; there is no HKDF tenant derivation despite documentation claiming per-tenant derived keys.

Evidence:
Both services call `kp.DataKey` once and build one GCM instance. `Seal`/`Open` use `nil` additional data. No HKDF implementation exists in the credential packages.

Attack / Failure Scenario:
A database-write capability can transplant ciphertext/nonce between tenant/resource rows and have the application decrypt it in the new context. Compromise of one cached DEK compromises every tenant's vault data.

Impact:
Weak cryptographic tenant separation and larger key-compromise blast radius.

Root Cause:
Database tenant predicates were treated as sufficient context binding for ciphertext.

Recommended Fix:
Derive per-tenant/versioned keys with HKDF or KMS encryption context and bind tenant ID, table, record ID, and purpose as AEAD AAD. Migrate ciphertext using version columns and staged dual-read support. Correct documentation until complete.

Required Tests:
- Ciphertext copied across tenants/resources fails authentication.
- Key versions rotate without data loss.
- Secrets and token-vault values use distinct purpose contexts.

Cross-Repository Impact:
Server / Deploy / Docs

Breaking Change:
Database migration only

Should Fix Now:
No

## [P2] QID-AUD-023 - The promised router-to-OpenAPI coverage gate does not exist

Category:
Testing

Severity:
P2

Confidence:
High

Location:
`AGENTS.md`, `CLAUDE.md`, `docs/llm/context.md`, all five `api/openapi/*.yaml` descriptions, `api/openapi/README.md`; `tests/integration/coverage_test.go`; `tools/openapi-split/main.go`

Problem:
Documentation repeatedly states that CI fails when a mounted route is absent from OpenAPI, but no test walks the live router and compares it with the five specs.

Evidence:
`tests/integration/coverage_test.go` contains behavioral security/protocol tests but no OpenAPI/router logic. No `chi.Walk` or OpenAPI test exists. `openapi-split verify` checks self-contained YAML/reference integrity only. Spec descriptions point to nonexistent `internal/http/router.go` and `internal/http/openapi_coverage_test.go` paths.

Attack / Failure Scenario:
A security-sensitive route is added or moved without correct contract authentication/error declarations. CI remains green, SDKs omit it, and reviewers believe a nonexistent gate covered the change.

Impact:
Contract drift, undocumented attack surface, and false confidence in release controls.

Root Cause:
Documentation survived an architecture move while the enforcement test was removed or never migrated.

Recommended Fix:
Build the real router with safe test dependencies, use `chi.Walk`, normalize patterns, union all five OpenAPI operations, and fail on undocumented routes plus documented-but-unmounted routes unless explicitly allowlisted.

Required Tests:
- A temporary mounted route without spec fails.
- A stale spec operation fails.
- Public/authenticated security declarations are compared with route classification.

Cross-Repository Impact:
Server / SDK / Docs

Breaking Change:
No

Should Fix Now:
Yes

## [P2] QID-AUD-024 - Social identity linking does not require a verified email

Category:
Security

Severity:
P2

Confidence:
Medium

Location:
`internal/federation/social/oauthclient.go:16-22, 126-151`, `userInfo`; `internal/federation/social/social.go:330-427`, `CompleteCallback` and `findOrCreateUser`; `internal/federation/social/platform.go:217-350`, `CompletePlatformCallback`; `internal/federation/social/github.go:61-128`

Problem:
Generic OIDC userinfo omits `email_verified`, and account resolution automatically reuses an existing account by email. GitHub verifies fallback email entries but accepts a nonempty profile email without checking verification.

Evidence:
The `userInfo` model has no verification field. Callback code requires only a nonempty email before `findOrCreateUser`. Existing users are linked by case-insensitive email.

Attack / Failure Scenario:
If an enabled upstream provider can return an unverified email matching a victim, an attacker authenticates to the provider and Qeet links the provider subject to the victim account.

Impact:
Conditional account takeover or identity-linking denial depending on provider guarantees.

Root Cause:
Email equality is used as proof of account ownership without carrying provider assurance metadata.

Recommended Fix:
Require verified-email assurance for automatic linking, implement provider-specific claim rules, and require an authenticated explicit linking ceremony when assurance is absent. Document provider prerequisites.

Required Tests:
- Unverified/missing verification claims cannot auto-link.
- Verified provider email links correctly.
- Existing-account collisions require explicit confirmation.

Cross-Repository Impact:
Server / Login / Docs

Breaking Change:
Potentially

Should Fix Now:
No

## [P3] QID-AUD-025 - API and architecture documentation contains stale paths and unusable server defaults

Category:
Documentation

Severity:
P3

Confidence:
High

Location:
All five `api/openapi/*.yaml` `info.description` and `servers`; `api/openapi/README.md:17-25`; `docs/llm/context.md`; repository memory from the prior audit

Problem:
Specs cite removed `internal/http/*` paths and claim a nonexistent coverage test. All server lists contain localhost URLs only. Prior architecture notes also contain stale binary names, migration counts, and worker descriptions.

Evidence:
The live router is `internal/bootstrap/router.go`; no `internal/http` directory or OpenAPI coverage test exists. Production API URLs are absent from all five specs.

Attack / Failure Scenario:
Generated clients default to localhost, contributors rely on nonexistent checks, and incident/change review follows stale ownership paths.

Impact:
Developer friction, deployment mistakes, and delayed discovery of contract/security drift.

Root Cause:
Documentation is hand-maintained across architecture changes without executable link/path validation.

Recommended Fix:
Correct paths and descriptions, add the canonical production server or server variables, and automate path/link and router-contract checks. Supersede architectural decisions in a new ADR rather than rewriting accepted historical ADRs.

Required Tests:
- Documentation link/path validation.
- OpenAPI server and route policy lint.

Cross-Repository Impact:
Server / SDK / Docs

Breaking Change:
No

Should Fix Now:
No

## [P3] QID-AUD-026 - Session listing is hard-limited without pagination

Category:
API

Severity:
P3

Confidence:
High

Location:
`internal/access/authentication/service.go:1065-1078`, `Service.ListSessions`; `internal/access/authentication/http.go:478-491`, `GET /v1/auth/sessions`

Problem:
The endpoint returns only the newest 100 sessions with no cursor or indication that more exist.

Evidence:
The service applies a fixed limit and the handler exposes no pagination input/output.

Attack / Failure Scenario:
A heavily used or abused account has more than 100 sessions; older sessions cannot be inspected or individually revoked through the normal account UI.

Impact:
Low-impact security operations and UX limitation.

Root Cause:
A defensive query cap was added without an API pagination contract.

Recommended Fix:
Add cursor pagination and a total/next indicator while retaining a bounded maximum page size.

Required Tests:
- More than 100 sessions can be paged and revoked.
- Cursor ownership is user-scoped and tamper-safe.

Cross-Repository Impact:
Server / Console / SDK / Docs

Breaking Change:
No

Should Fix Now:
No

## Accepted Security Trade-Offs

The following behaviors are deliberate and were not classified as implementation defects:

- **No PostgreSQL RLS:** application-layer tenant isolation is the chosen architecture. The P0 findings show that the current guardrails are insufficient, but absence of RLS alone is not mislabeled as a bug.
- **Rate limiter fails open on store errors:** documented availability decision. Residual abuse risk must be monitored and bounded with in-process fallback/edge controls.
- **Auth hooks default fail-open:** documented lockout-avoidance decision. It must remain visible to tenant administrators and audited.
- **Stateless access-token revocation is a no-op:** refresh/session revocation and short access TTL bound exposure. Discovery/docs should state that access JWTs remain valid until expiry.
- **Admin portal links are reusable until expiry/revocation:** intentional capability-link semantics. Logging the raw token is still a defect.
- **Public SAML/LDAP endpoints resolve a connection by unpredictable UUID:** selecting the target connection is not by itself cross-tenant authorization; the protocol credential/assertion must still authenticate against that connection. Enumeration/rate limits remain important.
- **Email delivery and CIBA notification are best-effort:** availability trade-off, not an authentication bypass, provided the API does not claim guaranteed delivery.

## Rejected Hypotheses

- **MFA push response trusts an attacker user ID:** rejected. The 256-bit device token is checked for that user, the challenge is row-locked, and challenge ownership/status/expiry are verified before update.
- **MFA login does not open the step-up window:** rejected. `VerifyForLogin` records verification in the same transaction before token/cookie issuance.
- **SAML condition warnings are logged but accepted:** rejected. Invalid time or audience returns `ErrSAMLAssertionConditions`.
- **WebAuthn challenge replay:** rejected. Ceremony state is consumed atomically with `DELETE ... RETURNING` before validation.
- **Authorization-code and refresh-token races:** rejected for OIDC. Both records are selected `FOR UPDATE` in a transaction and marked used/rotated before commit.
- **GDPR export leaks a cross-tenant user when the queued tenant/user pair is mismatched:** rejected. Payload collection rechecks both user and tenant and the job fails. GDPR purge does not have that protection and remains P0.
- **Unscoped SAML/LDAP connection lookup alone is a cross-tenant bypass:** rejected. The UUID chooses the tenant's own protocol verifier and successful external authentication binds results back to that connection's tenant.
- **Token-vault grants are plaintext:** rejected. Connected-account access and refresh tokens use AES-GCM; only provider client secrets remain plaintext under QID-AUD-009.

## Test Audit

### Existing strengths

- JWT negative tests cover unknown/missing `kid`, HS256 confusion, retired keys, tampering, issuer/audience, and expiry.
- Integration tests cover OIDC PKCE when supplied, code expiry/single use, refresh client binding/expiry, passkey session mismatch, MFA step-up, recovery/magic-link reuse, device authorization, signing-key behavior, admin portal TTL, and several tenant boundaries.
- CI runs unit tests with the race detector, architecture rules, integration tests, `govulncheck`, CodeQL, and linting.

### Missing security tests

1. Router-to-permission completeness and default-deny behavior.
2. Router-to-OpenAPI bidirectional coverage and security-scheme comparison.
3. Cross-tenant body-field tests for users and OIDC clients.
4. Cross-tenant queued-job tests for GDPR purge.
5. OAuth authorization membership tests.
6. Platform operator authorization for signing-key operations.
7. Machine scope matrix across API keys, services, and agents.
8. SAML assertion/request replay and concurrent replay.
9. Apple ID-token signature/claims/nonce tests.
10. MFA challenge/recovery-code concurrency and attempt exhaustion.
11. Multi-worker queue claiming and stable delivery-ID tests.
12. SSRF cases across IP encodings, redirects, IPv6, and DNS rebinding.
13. Ciphertext tenant/resource binding tests.
14. Fuzz tests for JWT wrappers, SCIM filters/PatchOp, SAML inputs, LDAP templates, OAuth forms/redirects, cursor decoding, and WebAuthn JSON.

No Go fuzz target (`func Fuzz...`) or explicit security concurrency test was found. Existing `-race` execution detects data races in exercised code but does not generate simultaneous state-transition requests.

## Documentation / Implementation Drift

- **DOCUMENTATION / IMPLEMENTATION DRIFT:** Machine credentials are documented as bounded by scopes; scopes are generally unenforced.
- **DOCUMENTATION / IMPLEMENTATION DRIFT:** OpenAPI route coverage is documented as a CI gate; no such gate exists.
- **DOCUMENTATION / IMPLEMENTATION DRIFT:** OpenAPI descriptions reference removed `internal/http` paths.
- **DOCUMENTATION / IMPLEMENTATION DRIFT:** Secrets vault is described as using per-tenant HKDF-derived keys; code uses one global AEAD key and no AAD.
- **DOCUMENTATION / IMPLEMENTATION DRIFT:** Worker documentation suggests `SKIP LOCKED` prevents duplicate processing; locks are released before work because queries do not run in explicit transactions.
- **PARTIAL IMPLEMENTATION:** OAuth PKCE supports S256 but does not require it for public clients.
- **PARTIAL IMPLEMENTATION:** Tamper-evident audit logging exists but important security mutations are missing or best-effort.
- **UNDOCUMENTED CAPABILITY:** Runtime signing-key rotation returns private key material through an ordinary authenticated API.

## Product Capability Gap Analysis

### MISSING PRODUCT CAPABILITY - Distributed signing-key lifecycle

**Feature:** KMS/HSM-backed, versioned, multi-replica signing-key lifecycle.  
**Why it matters:** Enterprise IdPs require rotation without split-brain or private-key exposure.  
**Who needs it:** Operators and every relying party.  
**Current gap:** Process-local rotation returns PEM to a caller and is not durable.  
**Evidence from repository:** `Issuer.Rotate` and `Handler.rotateKey`.  
**Implementation complexity:** High.  
**Security impact:** Critical positive impact.  
**API impact:** Replace/remove current rotation endpoint; additive status/activation API if needed.  
**Database impact:** Versioned key metadata or KMS references.  
**UI/SDK impact:** Operator UI only; SDKs consume stable JWKS.  
**Priority:** P0.

### MISSING PRODUCT CAPABILITY - Typed machine authorization policy

**Feature:** One authoritative permission/scope catalogue for user and machine actors.  
**Why it matters:** API keys, services, and agents need real least privilege.  
**Who needs it:** Developers, automation, agents, and security administrators.  
**Current gap:** Scopes are descriptive data, not an enforcement control.  
**Evidence from repository:** `rbac.Enforce`, `RequireScope`, credential issuance.  
**Implementation complexity:** Medium-high.  
**Security impact:** Critical positive impact.  
**API impact:** Scope validation/errors and discovery/catalog endpoint.  
**Database impact:** Scope catalogue/version and migration of existing credentials.  
**UI/SDK impact:** Scope pickers and typed SDK constants.  
**Priority:** P0/P1.

### MISSING PRODUCT CAPABILITY - Tenant-isolation defense-in-depth

**Feature:** Database-enforced ownership constraints and/or RLS for critical tables, plus static query-policy checks.  
**Why it matters:** A missed application predicate currently becomes cross-tenant compromise.  
**Who needs it:** Every customer and maintainer.  
**Current gap:** No RLS and several independently valid but mismatched foreign-key pairs.  
**Evidence from repository:** User/OIDC creation and GDPR purge findings.  
**Implementation complexity:** High, staged migration required.  
**Security impact:** Critical positive impact.  
**API impact:** None intended.  
**Database impact:** Composite keys/FKs, transaction tenant context, possibly RLS.  
**UI/SDK impact:** None.  
**Priority:** P1.

### MISSING PRODUCT CAPABILITY - Federation replay/conformance state

**Feature:** Shared request/assertion replay cache and automated SAML/OIDC/SCIM conformance suite.  
**Why it matters:** Federation correctness depends on protocol state beyond signature parsing.  
**Who needs it:** Enterprise SSO and provisioning customers.  
**Current gap:** No SAML assertion/request replay store; SCIM filter support is partial.  
**Evidence from repository:** SAML ACS and SCIM filter handlers.  
**Implementation complexity:** Medium.  
**Security impact:** High positive impact.  
**API impact:** Standards-correct errors and explicit IdP-initiated mode.  
**Database impact:** Short-lived request/assertion ID table or shared cache.  
**UI/SDK impact:** Minimal; clearer configuration/errors.  
**Priority:** P1.

### MISSING PRODUCT CAPABILITY - Secure outbound connector model

**Feature:** Egress policy, private connector/relay, destination verification, and integration health.  
**Why it matters:** Enterprise LDAP/webhooks must reach customer systems without exposing the control plane to SSRF.  
**Who needs it:** Self-hosted and enterprise federation customers.  
**Current gap:** Direct arbitrary outbound connections from the API/worker network.  
**Evidence from repository:** LDAP, webhook, auth-hook, social, SIEM, and token-vault clients.  
**Implementation complexity:** High.  
**Security impact:** High positive impact.  
**API impact:** Connector IDs/policies may replace raw destinations for private networks.  
**Database impact:** Connector registration and verification state.  
**UI/SDK impact:** Connection setup and health UI.  
**Priority:** P1/P2.

## Production Readiness Review

Qeet ID cannot currently be sold as a serious enterprise identity provider without conditions. The cryptographic primitives and many individual flows are thoughtfully implemented, but platform authorization and tenant ownership are not consistently enforced at the composition boundary. The P0 signing-key endpoint alone prevents production approval. Cross-tenant creation and erasure paths, machine scope bypass, incomplete user RBAC, federation replay, plaintext integration credentials, and SSRF are also release blockers.

Operationally, the product needs a durable distributed key lifecycle, explicit worker mode, queue leasing, complete audit guarantees, contract-policy coverage tests, and adversarial concurrency/fuzz coverage before enterprise claims are defensible.

## Prioritized Remediation Plan

### P0 - Fix immediately

1. Disable and remove public application access to signing-key rotation; rotate any key exposed in logs/test environments.
2. Override body tenant IDs in user and OIDC-client creation.
3. Enforce OAuth user membership in the client's tenant before consent/code issuance.
4. Validate and database-enforce GDPR purge target ownership; inspect/cancel pending mismatched rows.
5. Add temporary deny rules/WAF controls for affected endpoints while code fixes deploy.

### P1 - Fix before/with next release

1. Implement machine scope enforcement and default-deny route authorization.
2. Complete the permission catalogue for every authenticated route.
3. Add shared SSRF-safe egress controls.
4. Encrypt or hash every persisted security secret.
5. Add SAML request/assertion replay protection.
6. Validate Apple ID tokens and require public-client PKCE.
7. Add MFA challenge attempt budgets.
8. Remove capability tokens from logged URLs.

### P2 - Next sprint

1. Make MFA single-use state transitions atomic.
2. Add durable worker claims/leases and delivery IDs.
3. Replace process-local signing rotation with distributed key management.
4. Make audit/outbox writes atomic with mutations.
5. Make password update/session revocation atomic.
6. Add transport resource limits and SCIM filter correctness.
7. Bind vault ciphertext to tenant/resource context.
8. Implement router-policy/OpenAPI coverage and adversarial test matrices.

### P3 - Backlog

1. Correct stale docs and OpenAPI server metadata.
2. Add session pagination and low-impact API consistency improvements.

## Recommended Implementation Order

1. Global signing-key authorization and emergency key rotation.
2. Cross-tenant user, OIDC-client, OAuth authorization, and GDPR purge paths.
3. Default-deny route authorization and machine scope enforcement.
4. SSRF containment and capability-token leakage.
5. Secret-at-rest migration.
6. SAML/Apple/PKCE federation controls.
7. MFA attempt limits and atomic consumption.
8. Worker leasing/idempotency and audit transactionality.
9. API contract and authorization coverage gates.
10. Fuzz, concurrency, and failure-injection suites.
11. Documentation and lower-priority API improvements.

# Qeet ID Server Audit - Executive Summary

Audit Date:
2026-09-05

Repository:
`qeet-id-server` (`develop`)

Overall Assessment:
Critical

## Finding Summary

| Severity | Count |
|---|---:|
| P0 | 5 |
| P1 | 9 |
| P2 | 10 |
| P3 | 2 |

## Security Assessment

Authentication:
Strong password, session, refresh, passkey, and recovery primitives; MFA attempt budgets and two single-use races remain.

Authorization:
Critical. The global signing key is reachable by any authenticated user, the route map fails open, and machine scopes are unenforced.

Tenant Isolation:
Critical. Body-scoped user/OIDC creation, OAuth tenant assignment, and GDPR purge cross tenant boundaries.

OAuth/OIDC:
High risk. Core code/refresh rotation is sound; membership binding and public-client PKCE are not.

Sessions:
Moderate. Rotation/reuse controls are strong; password-change invalidation is not atomic.

Passkeys:
Good. Ceremony sessions are single-use and library validation is correctly used; add broader adversarial tests.

MFA:
High risk until attempt budgets and atomic recovery/challenge consumption are fixed.

Federation:
High risk due SAML replay, unverified Apple ID tokens, partial SCIM filtering, and outbound SSRF.

Agent Identity:
High risk because agent scopes do not constrain API access and administration routes are ungated.

Secrets/Crypto:
Critical signing-key authorization issue; primitives are strong, but many domain secrets remain plaintext and vault context binding is weak.

Database:
Generally parameterized and well indexed, but no RLS/composite ownership safety net and worker claims misuse transaction locks.

API Security:
High risk because route policy is incomplete/default-allow and no router-contract gate exists.

## Biggest Risks

1. Any authenticated account can rotate and obtain the global JWT private key.
2. Cross-tenant identities/OAuth clients can be created and cross-tenant users can be purged.
3. OAuth authorization can mint a tenant claim for a user who does not belong to that tenant.
4. User RBAC and machine scopes both fail open across substantial administration surfaces.
5. Tenant-controlled outbound integrations expose the service network to SSRF.

## Most Important Bugs

1. Missing authorization on signing-key rotation.
2. Body-supplied tenant trust in `POST /v1/users` and `POST /v1/oidc/clients`.
3. GDPR queued purge does not bind target user to request tenant.
4. MFA challenge/recovery single-use races.
5. Worker `SKIP LOCKED` queries release locks before processing.

## Missing Tests

1. Live router-to-permission default-deny matrix.
2. Cross-tenant body and asynchronous-job ownership tests.
3. Machine credential scope matrix.
4. Federation replay/ID-token/PKCE adversarial tests.
5. Concurrent state-transition, worker-claim, fuzz, and failure-injection tests.

## Missing Product Capabilities

1. Distributed KMS/HSM signing-key lifecycle.
2. Typed machine authorization policy and scope catalogue.
3. Database tenant-isolation defense-in-depth.
4. Federation replay state and conformance harness.
5. Secure outbound connector/egress model.

## Technical Debt

1. Hand-maintained fail-open route permission map.
2. Plaintext domain-owned integration secrets.
3. Process-local workers and key state in a horizontally scalable service.
4. Best-effort audit/outbox writes outside business transactions.
5. Stale contract/documentation paths and nonexistent enforcement claims.

## Production Readiness

Can this currently be confidently used by enterprise customers?

NO

Why:
The audited revision contains a remotely reachable global signing-key compromise, multiple cross-tenant writes/destructive paths, broad authorization bypasses, and material federation/secrets/SSRF weaknesses. Passing tests do not cover these trust-boundary failures.

## Recommended Next Steps

P0:
Disable signing-key rotation; repair and test every confirmed cross-tenant path; rotate potentially exposed keys.

P1:
Ship default-deny user/machine authorization, SSRF controls, secret encryption, federation replay/ID-token validation, PKCE enforcement, MFA attempt budgets, and token-free admin-portal sessions.

P2:
Repair concurrency/worker/audit transactionality, harden transport/resource limits, bind vault ciphertext context, and add executable route/contract/security coverage.

P3:
Correct documentation/server metadata and finish low-impact pagination/API consistency work.
