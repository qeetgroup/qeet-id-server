# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0 minor versions may include breaking changes — they will be called out explicitly under a **Breaking** subsection.

---

## [Unreleased]

> **Status: pre-1.0 — no versioned release has been published yet.** An earlier draft of this file dated a
> `1.0.0` release on 2026-06-22; that was premature — nothing has actually been launched. The first `1.0.0`
> tag will be cut at the initial public GA. **[ROADMAP.md](./ROADMAP.md) is the single source of truth for
> current shipped-vs-planned status;** this file records what lands in each release from that tag onward. (A
> still-earlier pre-implementation snapshot here — WebAuthn/SAML/SCIM/billing as 501s, HS256, bcrypt — no
> longer matches the codebase; all of those have since shipped.)

The changes below are the work staged for that first release.

### Release candidates and local test runtime

- `SERVICE_ENV` is now an explicit enum: `dev`, `local` (new — the Local-tier test-kit runtime for
  the DEV, TEST and STAGING environments, with every production gate on and loopback-only
  `APP_BASE_URL`/`LOGIN_BASE_URL`) or `prod`. Any other value refuses to start. New
  `SERVICE_PROFILE` (`dev`|`test`|`staging`, `local` only) is reported on `/healthz`. `prod` now also rejects a `*.localhost` `APP_BASE_URL`.
- `qeet-id-server healthcheck` probes `/readyz` on loopback for container health checks (the image is
  distroless).
- The image is stamped with `VERSION`/`COMMIT`/`DATE` build args, surfaced on `/healthz`.
- CI runs on `release/**`, and publishes an immutable `ghcr.io/qeetgroup/qeet-id-server:sha-<commit>`
  multi-arch image for each release-branch commit that passes every gate.

### Security

**Tenant isolation (2026-10-19)**

* **rbac:** role assignment now refuses users and roles from other organisations.
  `POST /v1/users/{userID}/tenants/{tenantID}/roles/{roleID}` checked only that the caller held
  `role.write` in its own tenant, then inserted whatever user and role ids it was given. A
  `user_roles` row is what makes someone a member, so any organisation admin could pull a user
  from another organisation in, with permissions, or attach another organisation's role to one
  of their own users. The insert now requires the role to be the tenant's own and the user to be
  a live member (or have it as their home tenant), in the same statement. Every refusal is the
  same `404 rbac.user_or_role_not_found` and is audited as `role.assign_refused`. A missing role
  id, which used to fail as a database error, gets the same 404.
* **groups:** adding a group member now refuses anyone outside the organisation.
  `POST /v1/groups/{id}/members/{userID}` checked only that the group was the caller's, then
  wrote whatever user id it was given, and the member list returned that user's email and display
  name. So any organisation admin could read the email and name behind any user id, add people
  from other organisations to their groups, or add ids with no account. The insert now requires a
  live member of the organisation, in the same statement, and every refusal is the same
  `404 group.user_not_found`. The member list shows only members of the organisation. Migration
  `0135` removes member rows that name no account and adds the missing foreign key to
  `"user".users`. Removing someone who isn't in the group no longer writes a `group.member_removed`
  audit entry.

**Dependencies and toolchain (2026-10-16)**

* **GO-2026-6617** (HTTP/2 server crash, HPACK encoder race; in `golang.org/x/net` and the Go standard
  library): Go toolchain 1.27.2 and `golang.org/x/net` v0.60.0. Go 1.25 has no fix, so the module
  now requires Go 1.26 and CI uses the same Go 1.27.2 the Dockerfile builds with (CI had been testing
  with 1.25.13 while the image was built with 1.27).
* `golang.org/x/crypto` v0.58.0 fixes GO-2026-6354/6355 (`x/crypto/ssh`, reachable only from test
  fixtures). `google.golang.org/grpc` v1.83.2 fixes GHSA-2v4p-qf9q-27wj (xDS servers, not used here).
* CI: `govulncheck` v1.9.0 and `golangci-lint` v2.14.0, which support Go 1.27 (v1.7.0 and v2.12.2
  could not run on it).

Remediation of a 2026-09-06 security review. Migration `0107`.

**Cross-tenant (P0)**

* **federation:** SAML SP and LDAP login resolved an existing account by email
  without checking it belonged to the connection's tenant. Emails are globally
  unique (`0022`), so anyone able to register a SAML connection — not plan-gated —
  could point it at an IdP they control, assert a victim's address and receive a
  token pair carrying the victim's user id, then `switch-tenant` into the
  victim's organization. The guard `social` already had is now shared by all
  three flows in `internal/federation/identitylink`.
* **scim:** `PATCH`/`PUT /scim/v2/Users/{id}` wrote through
  `users.UpdateTx`, which keys on user id alone with no tenant predicate. Any
  tenant's SCIM token could suspend (`active:false`) or rename a user in any
  other tenant. Both verbs now funnel through the ownership check `deleteUser`
  already performed.
* **outbox:** `GET /v1/admin/outbox/dlq` returned every tenant's dead-lettered
  event payloads. It was gated on `audit.read`, which is evaluated against the
  *caller's own* tenant, so every customer's org admin could read it. The table
  has no `tenant_id` to filter on and no platform-operator role exists, so the
  route is withdrawn — the DLQ is now inspected via direct database access, as
  the live queue already was. **Breaking:** see below.

**Authentication (P0/P1)**

* **passkeys:** user verification is now `required` on both the login and
  registration ceremonies. go-webauthn gates its UV check on an exact
  `== VerificationRequired`, so the previous `preferred`/unset values meant the
  UV flag was never checked and a passkey proved possession only — and
  passkey-signup accounts have no password, making the passkey the entire
  credential.
* **passkeys:** signature-counter regressions (`CloneWarning`) were computed and
  discarded, so a cloned credential authenticated indefinitely. Login and
  passkey-MFA now reject with `passkey.clone_detected`.
* **mfa:** TOTP codes are single-use. `0107` adds `auth.mfa_totp.last_used_step`
  and verification consumes the step in the same transaction, closing a ~90s
  replay window (RFC 6238 §5.2).
* **auth-hooks:** a hook answering 2xx with an unparseable body silently
  *allowed* the sign-in, ignoring a tenant's explicit `fail_open=false`. An
  undecidable response now follows the same fail-open/fail-closed policy as an
  unreachable hook. The documented fail-open default is unchanged.

**Abuse and disclosure (P1)**

* **http:** `X-Forwarded-For` was read left-most, i.e. attacker-controlled, and
  keyed the per-IP login limiter and 87 audit records. Client IP is now resolved
  positionally from the right under the new `TRUSTED_PROXY_HOPS` setting, and
  `chi/middleware.RealIP` — which rewrote `RemoteAddr` from the same header — was
  removed. **Deployments behind a proxy must set `TRUSTED_PROXY_HOPS`;** see
  `.env.example`.
* **oidc:** `/oauth/introspect` did not bind the token to the calling client
  (RFC 7662 §2.1). A public client needs only a `client_id`, making it a
  cross-tenant token oracle. Access tokens are now bound by tenant, refresh
  tokens by issuing client.
* **oidc:** RFC 8693 token exchange did not check the subject token belonged to
  the calling client's tenant, so any client holding the grant could indefinitely
  renew a token captured from another tenant.
* **social:** the hosted flow's `return_to` was redirected to unvalidated,
  immediately after the SSO cookie was set — an open redirect on the auth
  domain. It is now checked against an origin allowlist.
* **router:** root-mounted protocol routes (OIDC/SCIM/SAML/LDAP) inherited no
  rate limit at all. `POST /ldap/{id}/authenticate` in particular was
  unauthenticated password verification against a customer's directory. Directory
  auth now shares the login throttle; other protocol routes get a generous bound.
* **notifier:** `LogSender` logged the full message body, and it is the fallback
  for any channel without a provider — so with no SMS provider configured every
  SMS OTP was written to the logs in plaintext, and any SES init failure would do
  the same for reset tokens and magic links. The body is now suppressed outside
  development.
* **errors:** `errs.Error.Detail` is serialized to clients;
  `WithDetail(err.Error())` was leaking raw payment-provider response bodies and
  JWT verification internals (including an attacker-chosen `kid`). Those sites
  now use `Wrap`, which logs the cause instead.

**Reliability (P1)**

* **jobs:** a panic in any background worker unwound past the supervisor and
  terminated the whole process, HTTP server included. Workers now run under
  `recover()` and restart with capped backoff.
* **lifecycle:** the three shutdown phases shared one 15s deadline serially, so a
  busy HTTP drain left worker drain and trace flush with none. Each phase now has
  its own budget.
* **sse:** the activity and Qeet AI streams wrote to one `http.ResponseWriter`
  from both the handler and a keep-alive goroutine, and could write after
  `ServeHTTP` returned. Writes are serialized and the handler now waits for the
  ping goroutine.
* **db:** the pool set no `statement_timeout`, `lock_timeout` or
  `idle_in_transaction_session_timeout`, so one runaway query could hold a
  connection until the process died; with `DB_MAX_CONNS=10` a few would take the
  API down. Added, plus `MaxConnLifetimeJitter` to avoid a synchronized hourly
  reconnect storm.
* **db:** four `rows.Err()` checks were missing, silently returning truncated
  pages (users list, audit list), stranding leased outbox rows, and reverting
  tenant rate-limit overrides to defaults.

**Architecture**

* **tests:** the architecture fitness suite now enforces cross-context imports
  (`R3`), which were previously unconstrained — 37 edges had accumulated. Contexts
  may only reach each other through a declared shared kernel, and the
  context-level dependency graph is pinned so the known `access ↔ identity` cycle
  cannot be joined by a second one.

### Breaking

* **`GET /v1/admin/outbox/dlq` is removed.** It exposed every tenant's
  dead-lettered event payloads to any tenant admin. No console or SDK consumed
  it. Operators inspect `platform.outbox_dead_letter` directly.
* **`TRUSTED_PROXY_HOPS` must be set for deployments behind a reverse proxy.**
  Left at the default `0`, `X-Forwarded-For` is ignored and every client IP
  becomes the proxy's address — audit records and per-IP rate limiting degrade
  (safely, but visibly). Set it to the number of proxies that append to the
  header (`1` for a single Caddy/nginx/ALB).
* **Passkeys now require user verification.** Authenticators that cannot perform
  UV (a PIN-less security key) can no longer be enrolled or used to sign in.

---

### Security

Remediation of the 2026-09-05 production audit
([docs/PRODUCTION-AUDIT-2026-09-05.md](./docs/PRODUCTION-AUDIT-2026-09-05.md)),
plus follow-up fixes from reviewing that remediation. Migrations `0097`–`0106`.

* **authz:** route policy is default-deny for users *and* machine principals; the
  live router must have exact policy coverage (enforced by test). Machine
  credentials now need an exact scope match — `0105` writes the access existing
  credentials already had into their scope arrays so nothing silently breaks.
* **tenancy:** user creation, legacy OIDC client registration, OAuth
  authorization, and GDPR request/purge paths all derive or verify tenant scope
  instead of trusting a request body; composite FKs back it at the schema level.
* **keys:** the runtime signing-key rotation endpoint is gone. Keys live in a
  shared, envelope-encrypted registry with two-phase activation
  ([docs/JWT-KEY-ROTATION.md](./docs/JWT-KEY-ROTATION.md)).
* **federation:** SAML AuthnRequest correlation and response/assertion replay
  IDs are consumed atomically; Apple ID tokens get full JWKS/claims validation;
  public OAuth clients must use S256 PKCE; social auto-linking to an existing
  account requires a verified email.
* **egress:** tenant-configured outbound calls go through a shared policy that
  rejects private, loopback, metadata and DNS-rebinding destinations.
* **secrets:** reversible domain secrets use context-bound envelope ciphertext
  (tenant + purpose + resource); comparison-only credentials are hashed.
* **mfa:** per-challenge and per-account attempt budgets, shared across replicas.
* **admin portal:** one-time fragment links exchange for scoped HttpOnly
  sessions; capability tokens no longer appear in URLs or logs.
* **social login:** adopting an existing account requires both a verified email
  *and* that the account already belongs to the tenant being signed in to —
  emails are globally unique, so without the second check a tenant's own IdP
  could assert another tenant's user's address and be handed their identity.
* **csrf:** exemptions are exact/prefix/single-segment rather than bare
  prefixes, which had been exempting authenticated mutations mounted under a
  public feature area (`POST /v1/social/providers`,
  `POST /v1/oauth/bc-authorize/decision`).
* **scim:** user create/replace/patch/delete now write audit and outbox
  evidence in the mutation transaction, and bound their request bodies.
* **qeet ai:** tenant provider keys are envelope-sealed against their tenant, so
  ciphertext can no longer be transplanted between rows; BYOK `base_url` goes
  through the shared egress policy.
* **users:** an admin password reset revokes the target's sessions and records
  the act, matching self-service password change.

#### Breaking

* **Machine credentials** must carry explicit scopes. `0105` backfills existing
  rows with a compatibility set — review and narrow it.
* **Admin portal:** `0102` revokes every outstanding link (they predate the
  fragment-only format and may have leaked through path logs). The API moved
  from `/v1/admin-portal/{token}/…` to a cookie session established by
  `POST /v1/admin-portal/session`, and the CSRF exemption is gone, so callers
  must send `X-CSRF-Token`. Links are now single-use, default TTL 1h (was 24h).
* **Public OAuth clients** must send a valid S256 `code_challenge`.
* **IdP-initiated SAML** is refused unless the connection sets
  `allow_idp_initiated` (new in `0106`); replay protection applies either way.
* **OAuth redirect URIs** are validated at registration: HTTPS, HTTP loopback,
  or an RFC 8252 reverse-DNS private-use scheme.
* **Session listing** is cursor-paginated instead of hard-capped at 100.

### Features

* **mfa:** a phone is linked to an account with a one-time pairing code instead of a copied access token
  (QTID-369). `POST /v1/mfa/push/pairing` gives the signed-in person a code (`ABCDE-FGHJK`, Crockford base32,
  50 bits) after a step-up when they already hold a second factor; it links one phone, once, within five minutes,
  and a new one stops the person's earlier unused codes working. At most ten an hour (429 with `retry_after`).
  The mobile app, holding no session, exchanges it at the public `POST /v1/mfa/push/pairing/claim` for the
  account's `user_id`, its device and device credential, as registering a device returns them. A wrong, used,
  replaced, withdrawn or expired code, or one whose account is no longer active, answers `401
  mfa.pairing_code_invalid`, all alike, and the claim is throttled per address. `GET
  /v1/mfa/push/pairing/{id}` tells the screen showing a code when it has linked a phone, and `DELETE` withdraws
  an unused one. Audited as `mfa.push_pairing_created` and `mfa.push_device_linked`; an administrator's MFA
  reset withdraws live codes, and the `mfa-cleanup` job deletes expired ones after a day. Migration `0134`.
* **auth:** an organisation can cap how many live sessions one person holds in it at once — new
  `max_sessions` (none by default) and `session_limit_action` on its security policy. A sign-in at the cap
  either ends the person's least recently used session (`evict_oldest`, the default: audited as
  `auth.session_evicted`, announced as `session_limit`) or is refused with `auth.session_limit` (403, audited).
  The count happens as the session opens, under the account's lock, so simultaneous sign-ins cannot exceed it.
  Migration `0125`.
* **auth:** the session list describes each session: `device` ("Chrome on macOS", "Unknown device") and
  `device_kind` read from the user agent on the server, `country` where a trusted proxy reports one
  (`GEO_COUNTRY_HEADER`; omitted otherwise, never taken from the client), and `current` on the caller's own
  session. A session's last use now moves on requests made with its access tokens (at most once a minute), not
  only on renewal, so its idle timeout counts from its last use. Migration `0124`.
* **passkeys:** the session cleanup job also deletes passkey ceremony state that expired unfinished. The
  console and hosted sign-in pages now start a passkey ceremony in the background as they load (so the browser
  can offer passkeys in its autofill prompt), and most are never finished. The job's log line reports them as
  `ceremonies`.
* **auth:** magic-link sign-in works end to end. A link can be asked for from the console's sign-in page (no
  organisation: the account is found by its address, as password sign-in finds it) and from an organisation's
  hosted sign-in page (`app: "hosted_login"`, with the journey's `return_to`): the link opens where it was asked
  for, and the hosted login exchanges it at the new `POST /v1/auth/magic-link/session`, which opens the
  hosted-login session and returns where the journey continues. A link is exchanged only where it was issued
  for. Asking answers the same, and takes the same minimum time, whether or not the address has an account, and
  sends nothing to one without; requests are bounded to three per address and ten per caller (429), counted
  either way. New `POST /v1/auth/magic-link/resend` replaces a used or expired link without the address being
  typed again. Migration `0123`.
* **invites:** an invited person can accept with a passkey instead of a password. `POST /v1/invites/lookup`
  previews an invitation (organisation, address, whether an account already holds it, and the ways of accepting
  it: a password always, a passkey where the organisation allows passkeys). `POST
  /v1/invites/accept/passkey/begin` and `/finish` run the passkey ceremony: the email and organisation come from
  the invitation, and finishing creates the account with the passkey and no password, grants the invited role and
  accepts the invitation in one transaction, then returns a token pair as `POST /v1/invites/accept` does. A
  ceremony that expires, is abandoned or replaced, or is submitted twice creates nothing and leaves the invitation
  pending; an ordinary passkey sign-up cannot finish an invitation's ceremony. Migration `0122`.
* **deploy:** add deploy/release layer (Compose, Helm, migrate image, AWS KMS, CI→CD) ([3e176c5](https://github.com/qeetgroup/qeet-id-server/commit/3e176c59a8fca6bbf1bf614a4c97b0bdab5a8dfb))
* **frontend:** adopt @qeetrix/ui across admin, web, and docs ([c32b8b9](https://github.com/qeetgroup/qeet-id-server/commit/c32b8b9b7d152b1aeb94d8424ac3d7ef9d7667dd))


### Bug Fixes

* **mfa:** a sign-in's push approval request is delivered with care and its failures are seen (QTID-78). The
  request was handed to Expo's push service with no timeout and the answer thrown away, so a refused push, an
  uninstalled app or a push service outage left the sign-in waiting two minutes for nothing, with nothing logged.
  Now each push is high priority (it wakes an idle Android phone), lives as long as the request can be answered
  (two minutes), uses the app's `push-mfa` channel and is bounded to ten seconds; the service's answer is read
  and every refusal is logged with a token reference, never the token. A phone the service reports as no longer
  having the app (`DeviceNotRegistered`) is retired — its credential expires, so it is neither sent requests nor
  offered — until it is linked again. When the request reaches none of the person's phones, `POST
  /v1/auth/mfa/push` answers `502 mfa.push_delivery_failed` and the request is closed. New optional
  `EXPO_ACCESS_TOKEN`, sent with every push, for Expo projects with enhanced push security.
* **mfa:** a linked phone can be removed for real, its credential ages out, and its answers reach the server.
  Unlinking in the mobile app cleared only the app's storage: the server's revoke needed a signed-in session the
  app never holds, and the device credential never expired, so an "unlinked" or lost phone could still approve
  sign-ins. Now the app removes its phone with `POST /v1/mfa/push/devices/{id}/unlink` and its own device
  credential (`mfa.push_device_unlinked`); a device credential expires 180 days after the phone was last linked,
  after which the phone is not offered, gets no requests and cannot answer one; and an administrator can list
  and disconnect a member's phones at `/v1/users/{id}/push-devices[/{deviceID}]` (`user.read` / `user.write`,
  `mfa.push_device_revoked`). The app's answer to an approval request, and its unlink, carry no cookie, token or
  Origin and were refused by the CSRF check; both device-credential paths are now exempt, as they authenticate
  with the device credential, not a cookie. Migration `0132`.
* **mfa:** an expired push approval request reads as expired. A request past its two-minute expiry was still
  served as `pending`, so the mobile app offered to approve something the server would refuse. Now reading it,
  at `GET /v1/mfa/push/challenges/{id}` or during the sign-in that sent it, records and reports `expired`, and
  the scheduler's `mfa-cleanup` job removes requests a day after they expire.
* **mfa:** an administrator's MFA reset removes every second factor. It left push devices (and their pending
  approval requests) and the step-up window, so the person still showed as MFA-enabled and a device an attacker
  registered could still approve sign-ins. Now `DELETE /v1/users/{id}/mfa` removes the authenticator app,
  recovery codes, email/SMS factors, push devices and pending push requests, and what they earned (remembered
  devices, step-ups); passkeys stay, as they are how the person signs in. The `mfa.admin_reset` audit record
  names how many of each were removed (`removed`).
* **mfa:** a one-time code that cannot be delivered is no longer reported as sent. With no provider for a channel
  (SMS has none by default), setting up or challenging that factor answered that a code was sent while the code
  was logged and dropped. Now a channel that cannot reach anyone is refused with `503 mfa.delivery_unavailable`
  before any factor or code is stored (the development log still counts as delivery in development), and a
  provider failure answers `502 mfa.delivery_failed` and withdraws the code, audited as `mfa.otp_delivery_failed`.
  The server logs a warning at start when no SMS provider is configured.
* **auth:** remembered devices can be seen and forgotten, stay with the organisation that remembered them, and do
  not outlive a changed password. A device remembered to skip the second factor stayed trusted for 30 days with no
  way for anyone to remove it, so a stolen device cookie plus a password bypassed MFA for a month. Now `GET
  /v1/auth/trusted-devices` lists the caller's remembered devices (named, with when each was remembered, last
  used and expires, and the current one marked) and `DELETE /v1/auth/trusted-devices[/{id}]` forgets one or all;
  an administrator does the same for a member at `/v1/users/{id}/trusted-devices[/{deviceID}]` (`user.read` /
  `user.write`), for devices remembered in their own organisation. A device skips the second factor only in the
  organisation that remembered it, for that organisation's new `remember_device_days` (1–90, default 30). A
  changed password and an administrative factor reset forget every device, as signing out everywhere already did.
  Remembering, using and forgetting a device are audited (`auth.trusted_device_added`, `_used`, `_revoked`), and
  the session clean-up removes expired devices. Migration `0131`.
* **mfa:** sending email and SMS codes is limited. Any signed-in caller could request codes at about thirty a
  second, each staying valid for ten minutes, so a session could flood an inbox or a phone, run up the operator's
  SMS bill, or stack hundreds of live codes against five guesses. Now a code to one factor goes at most every
  30 seconds, ten an hour to one person and five an hour to one address or number over every account, refused
  with `429 mfa.code_send_limited` and `retry_after` (seconds); a new code makes the factor's earlier unused code
  stop working; a person may hold five email and SMS factors (`409 mfa.factor_limit`); SMS codes need a plan that
  includes them at sign-in and step-up as well as setup, and are refused without an organisation; and each code
  sent is audited as `mfa.otp_sent` with the destination masked. The scheduler's new `mfa-cleanup` job
  removes codes a day after they expire.
* **mfa:** sensitive operations need a step-up. Only switching the authenticator app off and regenerating
  recovery codes did, so a stolen access token could add its own factor, remove the owner's, mint an API key,
  change the sign-in policy or delete the organisation. A step-up of the calling session is now needed to add or
  remove one's own factors and sign-in methods (while holding a factor the organisation counts, so a first
  factor needs none), to create, change or revoke machine credentials (API keys, service principals, agents,
  OAuth clients and their secrets, SCIM tokens, credentials, webhooks, auth hooks), to create, reveal or delete
  secrets and vault and AI provider configuration, to change security, sign-in, risk, bot, IP and rate-limit
  settings or a user's MFA requirement, factors or password, to configure SAML, LDAP, social providers, domains,
  directory mappings and administrator portal links, to edit email templates, to change retention, anomaly
  settings and log streaming, and to update or delete the organisation, delete or purge a user, or delete one's
  own account. Each answers the existing `step_up_required` refusal. API keys, service principals and agents
  hold no session and cannot perform these; the hosted login's own sign-in counts as a step-up for the
  organisation's window after it. The catalogue is `stepUpRoutes` in `internal/bootstrap`, and a test fails
  when a mutating route that looks sensitive is neither in it nor exempted with a reason.
* **mfa:** setting up a new authenticator app no longer switches off the one that works, and needs a step-up
  while one is held. Starting a setup used to clear the confirmed app at once, so a single call with a stolen
  token turned the account's second factor off and left the owner unable to answer a challenge, while
  switching the app off properly needed a step-up. Now, while an app is confirmed, `POST
  /v1/mfa/totp/enroll/start` needs a step-up of the calling session (a first setup needs none) and the new app
  waits beside the confirmed one: the confirmed app keeps signing in and stepping up until a code from the new
  one confirms it, and a setup left unconfirmed for 30 minutes is ignored. The response adds `replacing`, and
  the start is audited with it. Asking for a new code to an email or SMS factor already confirmed no longer
  takes that factor away until it is confirmed again. Migration `0130`.
* **auth:** every sign-in is assessed for risk, and a risky one is confirmed. Risk was assessed only on a hosted
  sign-in from a remembered device in an organisation that remembers devices, and only to cancel that skip; the
  API sign-in and anyone without a second factor were never assessed, and the history impossible travel and
  device reputation compare against was written only then. Now the API, hosted, self-registration and magic-link
  sign-ins are all assessed, once, and each records its country and a coarse browser-and-OS device key (kept 90
  days; the scheduler's `sign-in-history-cleanup` job removes older ones). A risky sign-in skips no factor on a
  remembered device; one by someone with no second factor answers a challenge met by a code sent to their
  verified email (the challenge's one `email` factor, named by its own id, sent with `POST /v1/auth/mfa/send`),
  audited as `auth.sign_in_confirmed` with the session method `<first factor>_email_confirmed` and no step-up,
  or is refused with `403 auth.risk_verification_unavailable` when there is no verified address. A magic link has
  proved the mailbox already, so it goes in. Settings that cannot be read still fail open, as before. Migration
  `0133`.
* **mfa:** a step-up belongs to the session that earned it. It was recorded per person, so proving a factor in
  one browser unlocked sensitive actions in every other session the person held for five minutes, and every
  sign-in with a second factor did the same. Now a step-up is recorded against the calling session only: it
  ends with that session (revoked, expired or ended by idleness), a sign-in with a second factor steps up the
  session it opens and no other, and a changed password or an administrative factor reset clears the person's
  step-ups everywhere. Principals without a session (API keys, agents, hosted-login cookies) cannot step up. The
  security policy adds `step_up_window` (1m–60m, default 5m) and `step_up_methods` (the factor types that count;
  null for every one), both applied at once. The `step_up_required` refusal carries `window_seconds` and, when
  the organisation limits them, `allowed_methods`; `GET /v1/mfa/step-up/status` reports the same. A refusal is
  audited as `mfa.step_up_required` and a completed step-up as `mfa.step_up_verified`, both with the session.
  Migration `0129`.
* **mfa:** every confirmed second factor is now challenged at sign-in, not only an authenticator app. A person
  whose second factor is an email or SMS code, a passkey (while their organisation allows passkeys) or a push
  device used to sign in on their password alone. Both password sign-in paths now challenge when any factor
  is held, and the challenge lists exactly those factors (`factors`, with each email/SMS factor's id and masked
  destination; `methods` their types). It is met by a code (authenticator app, recovery, or one sent with the
  new `POST /v1/auth/mfa/send`), a passkey assertion from `POST /v1/auth/mfa/passkey/begin`, or an approved push
  sent with `POST /v1/auth/mfa/push` (`push: true` answers `mfa.push_pending` until approved, at no attempt cost).
  The passkey ceremony and push request are bound to the challenge, so an approval signs in once. The token-flow
  MFA endpoints are CSRF-exempt like `/v1/auth/login` (the mfa_token is the credential), which also lets the
  console complete an MFA sign-in through its server. Migration `0126`.
* **mfa:** an organisation's MFA requirement is enforced at sign-in. `mfa_enforcement` was stored, shown and
  reported as a passing compliance control, and an account marked as requiring MFA showed a badge, but neither
  changed how anyone signed in. Both password sign-in paths now challenge an account that must use a second
  factor: everyone under `required`; under `admin_only`, anyone holding a role (directly or through a group)
  that grants a write permission; and any account marked as requiring MFA, whatever its organisation sets. An
  account that must and holds no factor gets an enrolment challenge (`enrollment_required`) instead of a
  session: it sets up an authenticator app with the new `POST /v1/auth/mfa/enroll`, and the code confirming
  the app completes the challenge, returning the account's new `recovery_codes`. Hosted self-registration into
  such an organisation answers the same enrolment challenge. The security policy adds `mfa_grace_days` (0–90)
  and the read-only `mfa_enforced_since`: in the grace period the accounts the organisation already had are
  prompted (`enrollment_due_at`) and may put the setup off with `skip: true`, which is refused with
  `mfa.enrollment_required` (403) once it ends. Every challenge is audited as `auth.mfa_challenged` with its
  reason (`enrolled`, `tenant_required`, `admin_required`, `user_required`), a skipped setup as
  `auth.mfa_enrollment_deferred`. The SOC 2 and ISO 27001 MFA evidence control now reports whether MFA is
  enforced — failing while optional or during a grace period — and how many accounts hold no factor yet.
  Organisations that already required MFA are enforced from the upgrade, with no grace period. Migration
  `0127`.
* **mfa:** magic-link sign-in meets the same second-factor decision as password sign-in. Completing a link
  issued tokens (console) or the hosted-login session with no second-factor evaluation, so reading the mailbox
  was enough to sign in to an account that holds a factor or whose organisation requires one. Now, where a
  factor is held or required, `POST /v1/auth/magic-link/consume` answers an MFA challenge completed at
  `POST /v1/auth/mfa`, and `POST /v1/auth/magic-link/session` one completed at `POST /v1/auth/session/mfa`
  (with `return_to`), on the same terms as the hosted password sign-in — a trusted device skips it where the
  organisation allows — and drawing on the same attempt budget. The link is spent before the challenge, so an
  abandoned or failed challenge leaves no session and no link to reuse. A challenge records how the first
  factor was proven (`first_factor`, audited on `auth.mfa_challenged`); a met challenge is audited as
  `auth.mfa_verified`, and the session's method is `magic_link_mfa` (or `password_mfa`). Migration `0128`.
* **auth:** sessions end by themselves. A session used to end only when something revoked it: every renewal
  issued a fresh 30-day refresh token, so a session renewed once a month never ended, and an organisation's
  `session_max_age` was stored and shown but never applied. Now a session ends at its maximum age however
  active it is, and once it goes longer than its idle timeout without a renewal (each renewal restarts it).
  Both bounds come from the organisation's security policy when the session opens — new
  `session_idle_timeout` next to `session_max_age` — or from the new `SESSION_MAX_AGE` (720h) and
  `SESSION_IDLE_TIMEOUT` (24h) where it sets none; switching organisation never extends a session. An access
  token never outlives its session (its `exp` is the session's end when that comes first, and the shortest idle
  timeout is longer than an access token), and a hosted-login sign-in lasts no longer than the organisation's
  idle timeout or maximum age when those are under its usual 30 minutes. A renewal
  past either bound is refused with the new `auth.session_timed_out` (401); the session ends, the audit
  records `auth.session_expired` with the bound reached, and `session.revoked` subscribers are told `expired`.
  Sign-in and renewal responses add `session_expires_at` and `idle_expires_at`, and the session list adds
  `expires_at`, `idle_expires_at` and `status` (`active`, `revoked`, `expired`); expired sessions are no longer
  counted, listed as active, or ended again by a sign-out everywhere. An application's grant ends at the same
  maximum age however often it is renewed. `ACCESS_TOKEN_TTL` must now be shorter than 15m, the shortest idle
  timeout. Migration `0121`.
* **auth:** an account can no longer lose its last way to sign in. Removing a passkey, unlinking a connected
  account, or an administrator unlinking someone's identity used to delete it without looking at what the account
  had left, so a passkey-only account could remove its passkey and never sign in again. Each removal now counts
  the account's ways in — its password and passkeys while its organisation allows them, and linked identities
  that can still sign in — under the
  account's lock, in the same transaction, and refuses the last one with `auth.last_sign_in_method` (409),
  recorded as `auth.sign_in_method_removal_refused`. New `GET /v1/auth/sign-in-methods` reports the counts so a
  client can disable or explain the action first.
* **social:** an organisation's social providers can be switched off, changed field by field and removed. A
  provider could not be switched off — every save switched it back on — and a save without a secret replaced
  the stored one with an empty one. New `PATCH /v1/social/providers/{provider}` changes only the fields given
  (`enabled`, `client_id`, `client_secret`, `discovery_url`); `POST /v1/social/providers` keeps whether a
  provider is on and keeps the stored secret when none is given. New `DELETE /v1/social/providers/{provider}`
  removes one, keeping the identities people linked through it (they work again if it is added back); it is
  refused with `social.provider_in_use` (409) while someone in the organisation can sign in only through it.
  A switched-off or removed provider now refuses sign-in with the same answer as one never set up
  (`social.provider_not_configured`), so the refusal does not reveal which. Every change is audited
  (`social_provider.created`, `.updated`, `.enabled`, `.disabled`, `.deleted`), naming the fields changed but
  never the secret.
* **policy:** the organisation security policy could not be saved from the console: the API read
  `session_max_age` as nanoseconds while the console sends `"720h"` (400), the console's "Basic" complexity and
  "Disabled" MFA options are not values the database accepts (500), and omitting the IP lists failed (500).
  Session bounds are now read and written as duration strings, every field is checked, and an out-of-range
  value is refused with `validation_failed` naming the field.
* **oidc:** an access token an application receives on a user's behalf can no longer manage the user's account or
  organisation. Such tokens verified like the user's own, so a token approved only for `openid email` could list
  and end the user's sessions or, for an administrator, delete users. They now carry `client_id` (RFC 9068) —
  authorization code, refresh, device, back-channel and token exchange alike — and every authenticated route
  refuses them with `auth.application_token` (403) except `GET /v1/oauth/userinfo`. The user's own tokens are
  unchanged. Granting applications specific management scopes is still to come.
* **auth:** signing out everywhere — and an administrator's force sign-out — also closes the other ways back in:
  the person's remembered devices are forgotten (the second factor is asked again), their unredeemed authorisation
  codes are spent, and their device and back-channel sign-in requests that are pending or approved but not yet
  collected are denied. The responses and audit records add `trusted_devices` and `pending_authorizations`.
* **auth:** every way a session ends is announced to subscribed applications. `session.revoked` used to fire
  only for sign-out and refresh-token reuse, and never for a session with no organisation. Now sign-out,
  reuse detection, signing out other sessions or everywhere, an administrator's force sign-out or password
  set, password change (not for the session kept) and reset, organisation switch, suspension and
  reactivation, SCIM deprovisioning, erasure (before the account is redacted) and expiry (when the cleanup
  removes the session) each queue one signal per ended session, naming `user_id`, `session_id`, `reason`,
  `revoked_at` and a per-signal `event_id`. A session with no organisation is announced to every organisation
  the user belongs to (`tenant_id` null). Signals are queued in the transaction that ends the session
  (`EnqueueTx`) under a savepoint: if queueing fails the session still ends and
  `session_revocation_signal_failures_total` counts it. Delivery, signing and retries are unchanged.
* **auth:** an organisation's sign-in method switches are enforced. `password_enabled`, `passkey_enabled` and
  `magic_link_enabled` used to change only the stored policy. Now a switched-off method is refused where the
  credential is accepted — `auth.method_disabled` (403) for passwords and magic links, `passkey.disabled` for
  passkeys — as an access decision, not a wrong credential: a hosted sign-in that names its application is
  refused before the password is checked, the console's once it is verified, and a passkey before the assertion
  is verified. Magic links are issued, and stay valid, only while allowed, for the organisation's
  `magic_link_ttl_minutes` instead of a fixed hour. The hosted login reads `sign_in_methods` from the
  login context and offers only those. A policy write that would switch every method off, or switch on the email
  or SMS one-time-code sign-in (which does not exist), is refused with 422; the console no longer offers those
  two switches. Changes apply to the next sign-in (the policy is not cached).
* **social:** signing in with a social provider no longer creates an account in an organisation that does not
  allow self-registration. **Behaviour change:** the setting now governs social sign-up as it already did
  password and passkey sign-up, and it defaults to off — an organisation that wants social sign-up must turn
  self-registration on. A refused attempt writes nothing but an audit entry (`social.signup_refused`: the
  provider and the asserted address), and the hosted login tells the person registration is closed
  (`error=registration_closed`) instead of reporting a provider failure. Accounts already linked to the
  provider, and existing accounts matched by a verified address, sign in as before.
* **scheduler:** the `session-expiry-cleanup` job works. It deleted by a session expiry column that
  does not exist, so every run failed with an undefined-column error and no session was ever removed.
  It now deletes API and console sessions ended — or whose refresh tokens all expired — more than seven
  days ago (their refresh tokens go with them) and hosted-login sessions expired more than seven days
  ago, keeps every live session and anything ended inside the window, and logs how many it removed
  (zero when there is nothing to remove). The scheduler process itself is still not part of the
  deployed image; shipping and starting it is tracked separately.
* **auth:** switching organisation (`POST /v1/auth/switch-tenant`) replaces the session instead of
  adding one. **Behaviour change:** the session switched from now ends — its refresh token is refused
  and `session.revoked` subscribers are told, with reason `tenant_switch` — where before it stayed
  renewable for 30 days and every switch left another live session behind. The new token carries the
  claims the target organisation's authentication hook adds (the hook may also refuse the switch),
  and renewals keep a session's hook claims instead of dropping them after the first access token
  expires. An access token whose session has already ended can no longer switch (it used to open a
  fresh session). The person's own session list shows one entry per sign-in. Migration `0120`.
* **auth:** signing out of the hosted login now signs the browser out of the applications it signed
  in to. Both ways of signing out — the hosted login's own (`DELETE /v1/auth/session`) and an
  application's (`/v1/oauth/logout`) — used to delete only the browser's SSO session, so every
  application kept renewing its refresh grant for up to 30 days. Now the grants started through that
  session are revoked (renewals included), codes it minted that no application has redeemed can no
  longer be redeemed, and the sign-out is audited (`auth.signed_out`: the session, the registered
  application that asked, what was ended). Other browsers and API sessions stay signed in; without a
  session cookie nothing is ended. Migration `0119` records which hosted-login session started each
  code and grant; grants issued before it are not tied to a session and are not ended this way.
* **recovery:** "Forgot password" works from hosted login and the React SDK, and the emailed link
  lands where the reset was requested. The request carried `tenant_id`, which the endpoint rejected
  (400, no email). It is now accepted and ignored (email is unique platform-wide). A request with
  `app: "hosted_login"` links to hosted login's `/reset` page, carrying `return_to` only when it is
  this API's `/oauth/authorize` endpoint; otherwise the link opens the console's reset screen, as before.
* **passkeys:** synced passkeys (iCloud Keychain, Google Password Manager, password managers) can
  sign in and complete passkey MFA. Their backup-eligible and backup-state flags were never stored,
  and go-webauthn rejects a login whose backup-eligible flag differs from the one at registration.
  Migration `0116` adds the columns; passkeys registered before it must be registered again.
* **api:** align Postman baseUrl to port 4000 (matches standardized backend port) ([202aa84](https://github.com/qeetgroup/qeet-id-server/commit/202aa845ad0d527367d32c0e1a454b9cfd2b12f3))
* **passkeys:** an account created by passkey signup (console or hosted login) can sign in with
  that passkey. The account was created with a database-generated id instead of the WebAuthn user ID
  the passkey was registered under, so the user handle the browser returns matched no user.
  Accounts created this way before the fix must add their passkey again (or reset their password).
* **deploy:** assemble DB_URL via interpolation; drop distroless-incompatible healthcheck ([94da569](https://github.com/qeetgroup/qeet-id-server/commit/94da5697a3c1f8f0fc48a3418965d8b2c7c5b9b9))
* **oidc:** derive issuer/discovery scheme from X-Forwarded-Proto ([f03b6dd](https://github.com/qeetgroup/qeet-id-server/commit/f03b6dd193fd94b1e162e0f8364575385d6937bd))
* **repo:** correct doc drift, dead docs targets, eslint login wiring, image license ([c250c60](https://github.com/qeetgroup/qeet-id-server/commit/c250c603d4fdf9dc8af5ddb91b6a381992436e4a))


### Refactoring

* **backend:** unify SAML error envelope, bound SMTP, log encode errors ([2fed216](https://github.com/qeetgroup/qeet-id-server/commit/2fed21639b4318adafb729fda113d5de026f080f))
* rename qeet-identity → qeet-id across module path, URLs, names ([9c438ef](https://github.com/qeetgroup/qeet-id-server/commit/9c438ef523875ecd5a9ee2692ac67b762d5f3b99))
