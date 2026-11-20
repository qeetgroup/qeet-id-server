# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are named after the month they
ship, `YEAR.MONTH.N` (see Branches and releases in [AGENTS.md](AGENTS.md)).

## [Unreleased]

The first release, 2027.1.0, is in preparation. No version has been published yet.

### Added

- `GET /v1/users/stats` counts the organization's own people by team (`by_team`: department, team and count) and
  by location (`by_location`), from their metadata, as `by_department` does: largest first, up to 200 each, and
  always sent (an empty list when there are none).
- `GET /v1/users` names people in one read: `id` and `email` (each repeatable, up to 200; an email in any case)
  answer exactly those members, with the other filters, and `include_deleted=true` adds the members since
  deleted, each marked with `deleted_at` and status `deleted`, so history can still name them.
- `GET /v1/users` filters `admins_without_mfa` (the owners and admins with no second factor, exactly those the
  summary counts) and `in_group` (in one of the organization's groups, or in none), and pages by cursor in
  every order: by name, by when last seen and by creation, either way, stable when sort keys tie. A cursor
  works only with the sort and order of the page that gave it.
- `GET /v1/me/permissions`: a person's own effective permissions in the organization their token is for,
  with every grant behind them, as `GET /v1/users/{userID}/organizations/{organizationID}/permissions`
  answers. It needs no permission, so someone holding none (the built-in member role) reads empty lists and
  the console can show them what they may use; another person's still need `role.read`.
- Metrics for sign-ins (`sign_ins_total`, by method and outcome), the token endpoint
  (`oauth_token_requests_total`, by grant and outcome), rate-limit rejections (`rate_limit_rejections_total`)
  and webhooks (`webhook_deliveries_total`, `webhook_pending_deliveries`, `webhook_oldest_pending_age_seconds`).
  Database queries and outbound calls are traced spans.
- Continuous profiling: `PPROF_ADDR` serves the runtime profiles on their own listener (loopback only outside dev).
- A local monitoring stack, `make obs-up`: Prometheus with alert and SLO burn-rate rules, Alertmanager, Loki,
  Tempo, Pyroscope through Grafana Alloy, and Grafana with three dashboards. Each of the 21 alerts links to its
  runbook in `observability/README.md`.
- `api/postman/`: every call as one Postman collection, a folder per API document, with a local environment
  that sign-in and create calls fill in. `make openapi` rebuilds it with the documents; `make openapi-check`
  fails when it is stale.
- Every `make` target runs in Go (`cmd/devtool`), so it works the same on Windows, macOS and Linux. Each
  setting it uses is read from the environment or `.env` first, with a default.
- `make fmt` and `make fmt-check` (part of `make ci`) format every language: Go (gofmt, goimports),
  JavaScript, JSON, YAML and Markdown (Prettier), shell (shfmt).
- `make load` (k6, failing on a missed SLO), `make dast` (OWASP ZAP), `make fuzz-api` (Schemathesis) against a
  running local server, and `make sonar-up` / `make sonar` for a local SonarQube Community Build.
- `tests/`: `architecture` checks the layout rules; `contract` checks that every read answers as its document
  says; `e2e` runs sign-up to sign-out, organization isolation, and an application signing a person in with
  OpenID Connect (second factor, consent, PKCE, the ID token checked against the published keys).

- Sign-in requests reach the native Qeet ID apps: Apple Push Notification service for iOS (token-based,
  `APNS_AUTH_KEY`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_BUNDLE_ID`, `APNS_SANDBOX`) and Firebase Cloud Messaging
  for Android (`FCM_SERVICE_ACCOUNT`). Each phone is sent through its platform's service. A service without
  credentials is off; a phone it would serve is not sent the request but finds it when the app opens, and the
  sign-in no longer fails for that phone alone.
- `POST /v1/mfa/push/devices/{id}/push-token`: a linked phone replaces the push token its platform rotated,
  with its unexpired device credential.
- `POST /v1/mfa/push/devices/{id}/pending`: a linked phone lists the sign-in requests waiting on its account,
  with its unexpired device credential, so a request whose push was late or lost can still be answered.
- The pairing claim answers the linked account's email (`account.email`), so the app can name it.
- A sign-in or step-up request for a phone records where it came from (`context.location`, such as
  "Bengaluru, India"), from the trusted proxy's country and city headers, so the phone can show it.
- Access requests: a person asks their organization for one of its roles, for up to 90 days or for good,
  with a reason (`/v1/me/access-requests`, the roles they can ask for, cancel); the people who can give roles
  are told in the app and on their linked phones, and approve (step-up; held to the rule for giving the role
  directly; nobody answers their own) or deny with a note (`/v1/organizations/{organizationID}/access-requests`). A
  time-limited role is taken back when its time is up, and a request nobody answers lapses after 14 days
  (the `access-request-sweep` job). Every step is audited (`access_request.*`).
- `GET /v1/organizations/{organizationID}/critical-events`: the organization's open anomaly alerts and critical audit
  events (suspensions, lockouts, the AI agent kill switch, second factors reset or turned off, roles given,
  sign-in risk settings changed) of the last hours, newest first, levelled high or medium, for an on-call
  administrator. Needs `audit.read`.
- Linked phones can be sent notices besides sign-in requests (an access request to answer): an alert on
  iOS, a data message with its text on Android, kept for a day. Sign-in requests are unchanged.
- `JWT_SIGNING_KEY` may be an RSA key of 2048 bits or more as well as an EC P-256 key. Tokens are signed with
  the active key's algorithm, RS256 for an RSA key and ES256 for an EC key; the discovery document names it and
  `/.well-known/jwks.json` publishes an RSA key with `n` and `e`. OpenID Connect requires a provider to support
  RS256, so a deployment that is to be OpenID Certified, or serves applications that accept only RS256, signs
  with an RSA key. The key a development instance makes for itself stays ES256. A rotation may change the key's
  type: the retired key's tokens still verify for the grace period.

### Changed

- The API says organization, not tenant. Paths under `/v1/tenants/{tenantID}/…` are under
  `/v1/organizations/{organizationID}/…`; every `tenant_id` JSON field and query parameter is
  `organization_id`, and `?tenant=` (a slug) is `?organization=`; the access token's `tenant_id` claim is
  `organization_id`; and the `tenant.*` permissions (`tenant.read`, `tenant.write`, `tenant.delete`), error
  codes (such as `tenant.owner_only` and `tenant.slug_taken`), audit actions and events (such as
  `tenant.created` and `tenant.updated`) are `organization.*`. No release has shipped, so the old names
  are not accepted alongside: every client, and every product that reads the token, follows the new
  names.
- The API documents mark as required every field the server always sends (a nullable one may be null),
  and document what was missing: `logo_url` on an organization (answered, and taken on create and
  update; `plan` is not taken on update), `providers`, `self_registration_enabled`,
  `remember_device_enabled` and `sign_in_methods` on the hosted login's context, `available` and `source`
  on Qeet AI's status, the 200 answer with `frontchannel_logout_uris` when the hosted login signs out,
  the answer of the LDAP hosted sign-in, the context of an AuthZEN evaluation, and `status` on a new SAML
  service provider. Where a read and a write shared one definition, the write has its own, with every
  field optional as the server takes it: `SecurityPolicyUpdate`, `AuthPolicyUpdate`, `RiskSettingsUpdate`,
  `OrganizationRateLimitsUpdate`, `SAMLConnectionUpdate` (with `allow_idp_initiated`) and
  `SAMLServiceProviderUpdate`; an LDAP connection's update no longer lists every field as required. The
  admin portal's context read answers `PortalContext`, as its session does. Invitation, SAML connection
  and Qeet AI source states are enumerated, and an organization's plan may be `starter`. The answers
  themselves are unchanged.
- Releases follow a fixed monthly rhythm: the branch is cut on the first working day of the month, tested for
  about two weeks and released on the third Tuesday; urgent fixes still ship as hotfixes. The first release
  is `2027.1.0`, planned for Tuesday 19 January 2027, and the documents name it that way throughout. Its
  release checks are in `docs/roadmap/release-checks.md`. From the first release the API documents'
  `info.version` is the release's version too, instead of a version of their own.
- `make sonar` measures coverage with every test, the database ones too, across packages (so it needs Docker
  and takes about eight minutes), and leaves the development tools, the demo seed, the test harness and the
  build scripts out of the figure. It counted unit tests only, which read 18% where the tests cover 72%.
- The API documents are named for the bounded contexts they serve: `auth.yaml` is `access.yaml` and
  `management.yaml` is `identity.yaml` (their sources too). URLs, operations and schemas are unchanged.
- The Qeet AI tool catalogue moved from `api/qeetai/` into the server (`internal/operations/qeetai`), embedded.
- `.env.example` is grouped by area with one short note per group.

- One sqlc configuration, `sqlc.yaml` at the root, lists every package (`make sqlc-check` also fails on a
  `queries.sql` it doesn't list). A NULL-able uuid, timestamptz or date column is now a `*uuid.UUID` or
  `*time.Time` in generated code, and the hand-written `pgtype` converters are gone.
- Shared helpers for handlers: `httpx.PathUUID` for a UUID route parameter, `paging.Limit` / `paging.Clamp`
  for a page size and the `paging.Result` list body (`next_cursor` only when there is another page),
  `audit.Actor.EventIn` and `audit.RecordAlone`. The activity cursor is the one every other list uses.
- An audit event about no particular resource records none, where `compliance.control_owner_removed` and
  `siem.sink_tested` stored the nil UUID. The email message and suppression lists clamp a `limit` over 100
  to 100 (it fell back to 50).
- The members list (`GET /v1/users`) pages by cursor alone, in its default order; any other order answers its
  first page. `next_cursor` is left out on the last page of the members list, the organizations list
  (`GET /v1/organizations`) and the organization picker (`GET /v1/me/organizations`), as on every other list. The
  picker answers at most 200 for a larger or malformed `limit` instead of refusing it.
- An email address or phone number a code goes to is masked by one rule wherever it is shown or audited:
  the first character of the address and its domain (`a****@example.com`), or the number's last three
  digits (`*********123`). The GDPR export (which wrote `a***@example.com` and `***123`) and the emailed
  sign-in confirmation (`a***@example.com`) now follow the rule MFA factors already used.
- Helpers that existed in several copies are one each: the Server-Sent Events writer of the activity stream
  and Qeet AI (`internal/platform/http/sse`; the activity stream's keep-alive comment is now `: ping`, as
  Qeet AI's), random codes and tokens and the hash they are stored as (`internal/platform/crypto/codes`,
  moved from `platform/http`; every stored hash is unchanged), rotating an API key, service-principal or
  agent secret (`internal/developer/rotation`), the plan, seat, notifier, address, password, sign-in
  method, branding and database-handle interfaces, and the small string helpers (`internal/platform/strutil`).
- One OAuth token endpoint, `POST /v1/oauth/token`, serves every grant, chosen by `grant_type`:
  authorization_code, refresh_token, device_code, token exchange and CIBA for applications, and
  client_credentials for service principals and AI agents. Discovery's `token_endpoint` names it and
  `grant_types_supported` lists client_credentials. `POST /v1/oauth/token-code` and `POST /v1/agents/token`
  are removed: an agent now sends `grant_type=client_credentials` with its id as `client_id` and its secret
  as `client_secret`, in the form or by HTTP Basic, and its refusals take the RFC 6749 §5.2 shape
  (`invalid_client`, or `unauthorized_client` for an agent that isn't active) in place of the error
  envelope. A client_credentials answer carries `expires_at` beside `expires_in`, and its token's claims are
  unchanged. Every `invalid_client` answer is described alike, whatever kind of client the id names. The
  agent's token is rate-limited with the other token traffic, no longer with sign-in. A `resource` sent
  with client_credentials is refused with `invalid_target` rather than ignored. The operation is
  `requestToken`; `requestClientCredentialsToken` and `mintAgentToken` are gone, and so is the
  `principal.grant_unsupported` error code.
- The device and CIBA grants collect an approval through one step: both re-check the client's grant, spend
  the request and store the refresh token in one transaction.
- A `limit` above a list's maximum is capped at the maximum, no longer answered with the default page
  size: the SCIM console lists (`/v1/organizations/{organizationID}/scim/users` and `/scim/groups`, at most 200) and the OAuth grants (`/v1/organizations/{organizationID}/oauth/grants`, at most 500).
- A SCIM token rotated through the admin portal is recorded as the console's rotation is: `scim.token_rotated`
  names the new token and `"replaced": "all"`. Resolving or retrying a directory error, and changing a
  directory mapping, record the caller's user agent with the rest of the request.
- The federation packages (OIDC, SAML, SCIM, LDAP, social, admin portal, directory, identity links) keep
  every static query in their `queries.sql`, checked by sqlc against the schema; only the directory's
  filtered event and error lists build their SQL. Their services own each transaction and the audit row it
  commits with.

- The development seed (`cmd/seed`) writes only through the server's services and handlers: no SQL, and
  nothing dated back, so it is a third of its former size and follows every schema change by itself. It keeps
  the ten demo organizations, their people, roles, groups, SSO, SCIM, applications, API keys, webhooks, agents
  and second factors; states only time reaches (expired invitations, a past-due renewal, months of sign-in
  history) are gone. It seeds an empty database only: `make seed-reset` recreates the local database, then
  seeds, and `-reset` is removed. Applications get the client IDs the server mints, printed in its summary.
- The server records the checksum of each migration file it applies (`public.schema_migration_checksums`)
  and refuses to start on a database whose applied migrations aren't recorded as the files it carries: one
  built before a baseline file was edited, one migrated with the `migrate` tool, and, once, every database
  migrated by a build from before the records. The refusal names the file and the way out
  (`make db-reset`); the scheduler refuses too, and `qeet-id-server schema-check` answers not
  compatible. Before, such a database had the same migration number, so the server started on it and
  failed query by query. `make migrate-up` and `cmd/migrate` are gone: the server and the seed apply
  migrations, and `make migrate-down` calls the `migrate` CLI itself.
- The database schema is one baseline of 12 migrations (`0001`–`0012`: one file per schema, every table in its
  final shape) in place of 243 incremental ones. A database the earlier migrations built is refused at start
  as newer than this build and has to be recreated (`make db-reset`); no release has shipped, so nothing is
  carried over.
- The schema `"user"` is named `account`, so it no longer has to be quoted.
- Inside the server the word is organization, not tenant. The schema `tenant` is `organization`,
  `tenant.tenants` is `organization.organizations`, every `tenant_id` column is `organization_id`, the
  row-security policy is `organization_isolation`, and the Go code, SQL and comments follow. The API
  followed in its own change (above).
- A secret is stored only encrypted. The plaintext columns left from before encryption, and the code that read
  them and encrypted them on first use, are gone: webhook and auth hook signing secrets, Token Vault and
  social provider client secrets, LDAP bind passwords, SIEM tokens, authenticator app secrets and push tokens.
- The one-time sign-in codes of SAML, OIDC connection, social and console sign-in are one table
  (`auth.login_codes`), and the sign-in states of the last three are one (`auth.oauth_states`). A code or a
  state is accepted only by the flow that issued it. One store spends each (`internal/federation/logincode`,
  `internal/federation/oauthstate`): a code is spent by its first exchange even when it is refused, so one
  whose connection is turned back on stays spent.
- SAML, LDAP, OIDC single sign-on and social sign-in find, adopt and create accounts through one flow
  (`internal/federation/provision`) under the strictest checks any of them applied, and OIDC single sign-on
  and social sign-in share one OpenID Connect relying party (`internal/federation/oidcrp`). A linked
  identity's next sign-in records the address the provider now gives on the link, for every protocol.
- OIDC single sign-on keeps an account in step with the ID token as SAML and LDAP keep it with theirs: the
  display name, the address when the provider vouches for it on the organization's domain, and the groups
  the groups claim reaches through a SCIM group's external id or the connection's group mappings. A token
  that says it leaves the groups out (Microsoft Entra ID's overage), or a connection that reads no groups
  claim, changes no membership.
- Every table with an `organization_id` has an index leading on it and, unless it is an append-only log or outlives
  its organization, a foreign key to the organization; ten indexes another index already covered are dropped;
  eleven columns whose values are a fixed list have a CHECK.
- Dropped, as nothing used them: the `pgcrypto` extension, `auth.passkey_challenges`, `auth.agents.disabled_at`,
  and `organization.security_policies.password_min_length` and `password_complexity`.
- The webhook deliveries list (`GET /v1/webhooks/{id}/deliveries`) leaves `next_cursor` out on its last page,
  where it sent an empty one, and takes a `limit` above 200 as 200 rather than 50.
- The audit log list (`GET /v1/organizations/{organizationID}/audit`) leaves out `next_cursor` on its last
  page, as the other lists do. A `limit` above a list's maximum now reads the maximum instead of the default:
  the audit log, its anomalies and the activity history (200), and search (50).
- A compliance evidence run's audit event (`compliance.evidence_generated`) records the request's address,
  user agent and request ID, and an API key or agent as its actor, as other events do.
- The bot detection overview (`GET /v1/organizations/{organizationID}/security/bots`) lists its detections in
  `items`, as every list does, in place of `recent`, and leaves `next_cursor` out on the last page.
- A `limit` above a list's maximum asks for the maximum rather than the default (security anomalies and bot
  detections, authorization decisions and access requests: 200; relation-tuple objects and role holders: 500),
  and a malformed one asks for the default: the role holders and access requests lists no longer answer 400
  for it.
- The audit rows of failed password sign-ins, magic-link requests (a resent link's too, which now also has
  the user agent), and push pairing codes created and claimed carry the request ID as well as the client
  address and user agent.
- A second-factor change or proof (authenticator app, recovery codes, email or SMS code) commits with its audit
  rows in the service, and one that fails for a reason other than a wrong code, its audit row included, no
  longer costs the person one of their attempts.

### Removed

- Two unused pieces of code that touched every organization's rows: a query that ended all of an account's
  sessions, and the rate limiter's list of every organization's overrides. They were the last entries the
  organization guard held for review.
- `offset` on `GET /v1/users`: the members list pages by cursor.
- `cmd/worker` and `EMBEDDED_WORKERS`: no image built the standalone worker, so the API always runs the
  background workers. A leftover `EMBEDDED_WORKERS` is ignored.
- `JWT_SECRET`: nothing signed or verified with it, yet the server required it and checked its strength. Tokens
  are signed with `JWT_SIGNING_KEY`; stored secrets are sealed with `SECRETS_KEY`. A leftover value is ignored.
- Push through Expo (`EXPO_PUSH_URL`, `EXPO_ACCESS_TOKEN`), which served the retired React Native app. Sign-in
  requests go through APNs and FCM only.
- `api/postman`: the OpenAPI documents in `api/openapi/` are the only API contract.
- Settings no environment set, now fixed in the code: the sign-in lockout (`LOGIN_LOCKOUT_*`, `LOGIN_SPRAY_*`),
  the application secret lockout (`CLIENT_AUTH_LOCKOUT_*`), the password hasher's limits (`PASSWORD_HASH_*`),
  the Qeet AI turn limits (`QEETAI_HISTORY_MESSAGES`, `QEETAI_HISTORY_BYTES`, `QEETAI_MAX_OUTPUT_BYTES`) and
  `TOKEN_EXCHANGE_MAX_DEPTH`, each at its former default. An organization still tunes its own lockout in its
  authentication policy. A leftover value is ignored.
- Reading data no database holds, since every database is built from the baseline: bcrypt password hashes,
  Argon2id hashes of machine secrets (API keys, service-principal, agent and OAuth client secrets) and their
  upgrade to SHA-256, and the two envelope schemes before the one that names its key. Such a value is refused.
- The error codes a domain answered for a `{organizationID}` path that is malformed or names another organization
  (`adminportal`, `agent`, `analytics`, `audit`, `authhook`, `billing`, `email`, `gdpr`, `oidc`, `retention`,
  `saml`, `scim`, `siem` and `webhook` `.organization_mismatch`, `.organization_invalid` or `.organization_id_invalid`). The
  organization check in front of every such route answers first, with `bad_request` or `forbidden`, so they
  could not be returned.

### Fixed

- The Users summary's `by_department` and the list's `department` filter read only the metadata of the people
  whose home is the organization. A member managed by another organization, whose metadata the organization
  never sees, was counted and matched by that organization's department.
- SonarQube's five findings, all in two scripts. The load test makes its accounts' password for each run
  instead of carrying one, and takes the accounts in turn, not at random. The Postman generator states its
  32-bit wrap, its sort order and its path pattern plainly; the collection it writes is unchanged.
- The development sandbox's checkout page works again: the API's stricter content policy refused its form, so the
  page now carries a policy of its own that allows its form and the return to the application.
- `make dast` sends `SCAN_TOKEN` on its requests: ZAP split the option at the space and scanned signed out. The
  scan and load reports can be written on Linux, where the scanners' containers run as their own users.
- The OAuth documents show both answers the revocation, device-authorization, backchannel and logout endpoints
  give to a bad request (an RFC 6749 error, or the API's own for a request that can't be read), and list the
  `unsupported_token_type` and `unknown_user_id` errors.
- The activity list and summary refuse a malformed `from`, `to`, `actor` or `subject` (400) instead of dropping
  the filter and answering unfiltered events.
- `POST /v1/auth/magic-link/resend` refuses an empty token, and `POST /v1/account/delete` a malformed body, instead
  of answering as if they were valid.
- The suspended-users and directory-event lists lower an out-of-range `limit` into range, as every other list does,
  instead of answering 400.
- The API documents describe what the server accepts and answers, as found by fuzzing them against it: 429, 400
  and 413 where they can happen; request bodies that refuse unknown fields and empty required values, and accept
  `null` for optional ones; the three request bodies that were undocumented; the page-size and filter rules.

- Traces reach the collector: an `OTEL_EXPORTER_OTLP_ENDPOINT` without a path posted to `/`, not `/v1/traces`.
- `GET /v1/organizations/{organizationID}/login-domain` answered `"records": null` with no domain set, and an MFA
  challenge without factors `"factors": null`: both now answer `[]`, as documented.
- The API documents describe what the server answers: create organization's 402 for a paid plan, and a free
  plan in its example; SCIM errors as `application/scim+json`; SAML metadata as `application/samlmetadata+xml`;
  404 for an unknown role's permissions and 400 for an unknown compliance framework; 200 for the authenticator
  app's confirm and verify calls. The eight sign-in answers that are a token pair or an MFA challenge each match
  exactly one of the two.

- A plan bought through checkout (an organization's upgrade or a paid sign-up) is audited as
  `billing.plan_changed` (`via: checkout`) on the organization's chain, in the same transaction, as a plan
  switch is; it left no audit row. Completing the same checkout again, as a payment provider's retry does,
  still changes nothing.
- Retrying one webhook delivery (`POST /v1/webhooks/{id}/deliveries/{deliveryID}/retry`) and sending a test
  event (`POST /v1/webhooks/{id}/test`) are audited, as `webhook.delivery_retried` and `webhook.test_sent`, in
  the same transaction as the change; they left no audit row.
- An invitation accepted by signing up with a passkey records the request ID with the acceptance, and an
  administrator unlinking a social identity records the caller's actor type, as other audit rows do.
- The audit rows of an administrator's suspension, reactivation, suspension review, deletion and member
  removal record the caller's browser (user agent) too, and those of a second-factor reset, a passkey removal,
  an ended session and signing someone out everywhere record the caller's actor type (an API key's or a
  service's), where they always said user.
- A device code approved by a person who then left the application's organization still bought tokens;
  collecting it now needs the person to be an active member, as an authorization code and a backchannel
  approval do, and a refusal spends it.

- A migration that gave up waiting for a busy table left the database marked half-applied, so nothing
  started on it until someone put the version back by hand. It changed nothing, so the database now stays
  at the migration before it and the next start runs it again. A concurrent index build that gives up is
  still left for the manual recovery.
- A request whose client hung up or gave up waiting is answered 499 and noted at info level, not logged as an
  unhandled error and counted as a 500.
- Registering a Token Vault provider without a name, client ID or client secret is refused with the fields named
  (`validation_failed`), and a bad token URL is reported as `tokenvault.provider_token_url_invalid` instead of the
  authorize URL's code. An API key's name is held to its documented 200 characters.
- Two reads of a Token Vault token due for refresh at the same moment refresh it once, so a provider that rotates
  refresh tokens no longer sees one presented twice and breaks the connection.
- `_` and `%` typed into the global search, the suspended-accounts search and the directory sync events and errors
  searches now match only themselves, as they already did in the member list and the audit and activity searches.
- `outbox_dead_lettered_total` and the "dead-lettered" log line count only events actually moved to the dead-letter
  table: an event whose lease another worker took over is left to that worker, and the move is now one statement,
  so an event can no longer be both dead-lettered and still queued.
- The standalone scheduler (`cmd/scheduler`) follows `LOG_LEVEL` and `LOG_FORMAT` as the API and the worker do; it
  logged JSON at Info whatever they said.
- Stripe payment events keep arriving while a webhook secret rotates: any v1 signature in the header that is right
  is accepted, where only the last was compared.
- The protected-resource metadata (`/.well-known/oauth-protected-resource`) names the authorization server by its
  issuer identifier (`JWT_ISSUER`), not the host the request reached, so clients behind a proxy discover the right
  server.
- A role someone holds for a time through an access request, then is given for good, is no longer taken back when
  the request's time is up: the permanent assignment clears the request's end.
- The authorization endpoint (`/v1/oauth/authorize`) takes its parameters by form POST as well as by GET, as
  OpenID Connect Core requires: a POST is answered 303 to the same request by GET.
- The development seed (`make seed`) runs again: one demo organization asked for a lockout window shorter than
  the 15 minutes the sign-in policy now allows.

### Security

- Request metrics count a made-up HTTP method as `other`. Each one used to add series of its own, so anyone
  could grow the server's memory and its `/metrics` answer without limit, with no sign-in.
- A caller's `traceparent` header is linked to the request's trace, never obeyed. Before, any caller could turn
  tracing on for all its requests, whatever `OTEL_TRACES_SAMPLER_RATIO` said, and choose the trace they joined.
- `make dev-observed` serves profiles on loopback on macOS and Windows, where Docker reaches it, instead of on
  every network the workstation is on. The local database, NATS and the mail catcher are published on loopback
  too, like the rest of the local stack: the database has a default password, and the mail catcher shows every
  sign-in link.
- `make sonar` leaves `.env` and `.secrets/` out by name, so local keys are never sent for analysis even when
  the scanner can't read `.gitignore`.
- A vault secret is created, changed or deleted only together with its audit record, and revealed or read
  through `/v1/vault/{name}` only once the read is recorded; so is a Token Vault access token. When the record
  can't be written the request fails and nothing changes or leaves, where before the change stood or the value
  was returned unrecorded. Retrying a webhook's given-up deliveries is likewise kept only with its record.
- An organization's OpenID Connect social provider, and an OpenID Connect provider of the console's own
  sign-in, signs someone in only with an ID token its published key signed, from its issuer, for the client,
  carrying the sign-in's nonce, about the subject its userinfo names, as OIDC single sign-on already
  required. Every request to such a provider follows the outbound policy, so a client secret is never sent
  over plain http or to a local address.
- A refused account adoption or creation through SAML, LDAP or social sign-in is recorded as a failed
  sign-in (`auth.sign_in_failed`, with the error code as its reason), as OIDC single sign-on already did. The
  record names the account only when it is the organization's own.
- A SAML sign-in to a suspended or deleted account gets no one-time code, as OIDC and social sign-in don't.
- An ID token's signature is checked only against the published key it names (`kid`), and Sign in with Apple's
  keys are fetched again at most once in ten seconds for a key not yet seen, as for every other provider.

- An organization's OpenID Connect social provider (any provider found by its `discovery_url`) verifies an
  address only on a domain the organization has verified. Elsewhere it creates the account with the address
  unverified and never signs in to an existing account by its address, so a provider pointed at a server of
  the organization's own can't make verified accounts for other people's addresses or open the invitations
  sent to them. GitHub, X, Discord and Apple sign-ins are unchanged.
- No social provider creates an account on a domain another organization has verified, or on one whose
  organization requires single sign-on.
- No social provider signs in to an account that owns or administers its organization by matching the
  address (`social.account_administers`), as SAML, LDAP and OIDC single sign-on already refuse. Such an
  account keeps its own credentials and can connect the provider from its account.
- Self-service sign-up (password sign-up, hosted registration, passkey sign-up and the console's own social
  sign-up) creates no account on a domain an organization has verified, unless it is that organization's own
  registration, so nobody can claim a colleague's address before their organization's single sign-on or
  directory creates it. The answer is the same neutral one an address with an account gets.
- A hosted password sign-in that names another organization's application is held to a lockout no looser than
  the platform's, so an organization with a lenient lockout can't be used to guess other people's passwords
  faster, and the account's own organization's "password sign-in off" switch applies whichever application is
  named. An organization's lockout settings may now only be stricter than the platform's (threshold 3–5,
  window and lock 15 minutes to 24 hours) and govern the lock on one network: the lock on every network always
  uses the platform's settings, so a strict organization can't lock someone else out everywhere.
  `LOGIN_LOCKOUT_THRESHOLD_MAX`, `LOGIN_LOCKOUT_WINDOW_MIN` and `LOGIN_LOCKOUT_DURATION_MIN` are removed.
- A magic link always follows the account's own organization's rules (whether links are allowed, how long
  they last), whichever organization's sign-in page asked. The asking organization brands the email and sees the
  request in its audit log only for its own members, so naming it no longer reveals whether an address has an
  account, or puts another organization's wording around someone's link.
- Email templates may place a one-time link (`reset_url`, `magic_url`, `invite_url`) only as a whole link in
  the HTML and on a line of its own in the text, never in the subject, preheader or among other words. The
  built-in default texts now put the link on its own line.
- When a password reset or a sign-in link proves an account's address for the first time, everything set up
  on the account before (passkeys, second factors, linked accounts, pending verifications and sign-in codes,
  personal API keys, and on the sign-in-link path the password) is removed and recorded as
  `auth.credentials_removed`, so whoever registered someone else's address first keeps no way in. A sign-in
  link now marks the address verified, and so does signing up for the console with a platform provider that
  verified it.
- When SCIM comes to vouch for an account nobody vouched for (its holder never proved the address, and the
  directory didn't provision it), by a create that adopts it, a replace, or a patch of its external ID or
  address, every credential and sign-in set up on it is removed and recorded as `auth.credentials_removed`, so
  the directory no longer vouches for a squatter's working password or passkey.
- An organization that requires single sign-on on its domain can no longer be sidestepped: no social provider
  (its own or the console's) signs in, adopts or links an account there, no session is switched into that
  organization, and a member can't move their address off its domains (`verification.email_managed`). Nor can an
  address the organization's directory or single sign-on provides be changed, or any address be moved onto a
  domain another organization manages. Break-glass members are unaffected.
- Taking authority away through a group is held to the rule for giving it: removing someone from a group or
  deleting it needs what the group's roles carry, removing someone also needs to outrank them, and taking a role
  off a group needs that role. Removing a group member and deleting a group now need a fresh second factor, so
  an owner who holds their role through a group can no longer be demoted by a group editor.
- GDPR erasure and export requests, and reading an export, follow the rule for deleting an account: an
  administrator can no longer erase or export a co-owner, or anyone else who outranks them.
- Rotating a service principal's or an agent's secret needs every scope it carries, as creating one does, so
  `apikey.write` alone no longer hands over an owner's credential. API-key rotation now checks the key's scopes
  however many keys the organization has (it skipped the check past the first 1,001).
- SCIM no longer changes the address of an account that administers its organization (403): moving it to a
  fresh mailbox on the domain would have sent that account's password reset to whoever controls the directory.
- Changing what a connection trusts (a SAML certificate or entity ID, metadata from elsewhere, an OIDC
  connection's issuer, discovery URL, client or allowed organizations, an LDAP connection's server, bind or base DN,
  filter or TLS settings, an OpenID Connect social provider's discovery URL) now needs a caller who outranks
  every administrator linked to it (`rbac.trust_change_outranks_caller`), as the changed connection could sign
  in as them; admin-portal sessions can't make such a change once an administrator is linked.
- Single sign-on, domain capture and group sync now count as an administrator anyone who owns the organization
  or holds any permission other than the plain reads (organization, people, roles, groups, connections, API keys,
  webhooks, billing, policy, audit and analytics). A permission added later counts too, so a role holding only
  `gdpr.write`, `secret.read`, `billing.write` or `branding.write` is no longer adopted by its address, captured
  by the domain's identity provider or given through an identity provider group.
- Email and phone verification codes can no longer be guessed across resends: ten wrong codes in an hour for
  one flow refuse even the right code until the hour has passed (`verification.attempts_exceeded`, with
  `retry_after`). At most ten codes an hour go to one person and five to one address over every account
  (`verification.code_send_limited`, 429), a new code replaces the earlier ones, a code the provider refuses
  is withdrawn, and email-change codes have eight digits.
- Phone verification is held to the same limits as MFA text messages: the number must be in E.164 form, SMS must
  be in the plan of the organization the session is in (`billing.upgrade_required`; a session in no organization
  is refused), an SMS provider must be set up (`verification.delivery_unavailable`, 503), and a code goes at most
  every 30 seconds, ten an hour to one person and five an hour to one number (`verification.code_send_limited`).
- A sign-out request (`/v1/oauth/logout`) skips its confirmation only for an `id_token_hint` that is a real ID
  token issued to a registered application for the signed-in person. Any other token the server signs, such as
  a forced sign-in's `login_after` marker or an access token, is refused with `invalid_request`, so a crafted
  link can no longer sign a visitor out and revoke their application grants.
- Wrong application secrets now lock a confidential application out only for the network they came from (an
  IPv4 address or an IPv6 /64), so anyone who knows a public `client_id` can no longer lock the application out
  for all its users. The lockout's audit record and event name the `source_network`. Counters left by networks
  that stopped trying are deleted a week after their last wrong secret.
- Removing a member's linked phone, forgetting their remembered devices or unlinking their social sign-in now
  follows the same rule as resetting their second factor: only an owner can do it to an owner
  (`rbac.target_is_owner`), and nobody can do it to someone holding a permission they don't
  (`rbac.target_outranks_caller`).
- Suspending or deleting an organization now stops its machine credentials at once, as it already ended its
  people's sessions: its API keys no longer authenticate, its service principals and agents get no new tokens,
  and the service and agent tokens already issued are refused (and introspect as inactive). Reactivating the
  organization restores them.
- A personal API key now does only what both its scopes and its person's current permissions allow: once the
  person loses a permission (a role removed or changed), the key loses it too, and reading the secrets vault
  needs the person's `secret.read`. Keys that act for no one are unchanged.
- An invitation is accepted only while the person who sent it may still give it: their account active, still
  in the organization and still able to give its role. Otherwise every way of accepting it (password, passkey,
  signed-in link or inbox) and its preview answer `invite.invalid`. Removing someone from an organization, or
  deleting their account, withdraws the invitations they sent there.
- Qeet ID acting as a SAML identity provider now applies the organization's address rules and its second-factor
  requirement before it signs an assertion, as OpenID Connect sign-in already does: a refused address gets
  `auth.address_not_allowed` (recorded), and a session that didn't meet a required second factor is sent to sign
  in again, then refused (`step_up_required` or `mfa.enrollment_required`) if that sign-in still didn't.
- Approving a backchannel (CIBA) sign-in request now meets the application's organization's rules, as approving
  a device does: the person must still be a member of it, approve from an address its rules allow, and through a
  session that met the second factor it requires. Collecting the tokens needs the application still to hold the
  CIBA grant and the person still to be a member, and a request is spent only together with its refresh token.
- Starting a passkey sign-up (`/v1/signup/passkey/begin` and `/v1/register/passkey/begin`) now answers alike
  whether or not the address has an account, and no longer holds the address while the ceremony runs. An
  address that is taken, or on a domain another organization manages, is refused when the ceremony finishes,
  with the same neutral answer as before, so the status code no longer reveals which addresses have accounts.
- A relationship (ReBAC) check now expands at most 1,000 distinct object#relation pairs, and the checks of one
  request (an AuthZEN evaluation or batch, or a relation check with its explanation) read at most 5,000
  relationship sets together, as does one relationship graph; past either the request is refused with
  `rebac.check_too_complex` (422), so wide relationship sets can no longer make one request run unbounded
  database queries.
- Auth-hook calls are now signed as webhook deliveries are: `X-Qeet-Timestamp` and an `X-Qeet-Signature` over
  the timestamp, a `.` and the body, so a receiver can refuse a replayed call. For 24 hours after a hook's
  secret is changed, calls carry a signature with the old secret too (the hook shows
  `previous_secret_expires_at`), so the endpoint can move over without refusing calls. A receiver that checked
  the old body-only signature must switch to the new scheme.
- Plans' audit retention is now enforced: once a day, each organization's audit events older than its plan's
  `audit_retention_days` (7, 30 or 90 days; unlimited keeps everything) are deleted in batches, and the purge is
  recorded as `audit.events_purged`. A purge checkpoint written with each batch keeps the hash chain verifiable
  from the first event kept. A chain found broken is left for investigation.
- The server no longer starts without its permission catalogue or billing plans: seeding them at start-up is
  tried up to five times, two seconds apart, and if it still fails the server stops with an error naming the
  catalogue, instead of running with an empty one.
- Qeet AI sends the console only the tools it offered the model. A call to any other tool, such as a change tool
  the model was steered into, is dropped before it is stored or sent, recorded as `qeetai.tool.refused`, and
  noted in the reply so the person and the model know it was not run.
- A SAML or social one-time login code trades only while the connection or provider that issued it is still on,
  as OpenID Connect codes already do: switching a connection off, putting it back to draft, switching a provider
  off or deleting either stops the codes it issued in the last five minutes. Codes issued before the upgrade no
  longer trade.
- An organization registers an API resource on a host only once it has verified that host or a domain above it
  (`oidc.resource_domain_unverified`), and never the platform's own token issuer or audience, their host or the
  API's public host (`oidc.resource_reserved`), so no organization gets tokens whose audience another's service
  or the platform trusts. Identifiers without a host, such as URNs, are unaffected.
- A signed SAML sign-in request on the Redirect binding is read exactly as signed: a query that gives
  `SAMLRequest`, `RelayState`, `SigAlg` or `Signature` twice, or under a percent-encoded name, is refused
  (`saml.request_signature_invalid`), so an unsigned request or relay state can no longer ride beside a signed one.
- A Token Vault provider's token URL, authorize URL and client can no longer change while anyone is connected
  through it (`tokenvault.provider_in_use`), and tokens are kept only under the token URL that issued them, so a
  connected person's refresh token only ever goes back to the endpoint it came from. Deleting a provider now
  disconnects everyone connected through it, so one set up again under its name inherits nobody's tokens.
- The email-delivery webhook refuses a signing certificate URL with a query string or fragment and keeps at most
  eight certificates, so requests naming the topic can no longer make the server fetch and keep a certificate each.
- Only a public (native) application's loopback redirect may name another port (RFC 8252); a confidential web
  application's redirect must match what it registered exactly, so a local process listening on another port
  can't receive its authorization codes.
- A request whose path carries an encoded slash or backslash (`%2F`, `%5C`) is refused with 400 `bad_request`, so
  the router and every check that matches a path (permissions, step-up, organization scoping, CSRF and
  idempotency) always see the same route.
- An organization that requires a second factor of its administrators now requires it of everyone holding an
  administrative permission, the same ones single sign-on never adopts by address (such as `user.credentials`,
  `user.suspend`, `session.revoke` and `member.invite`), not only of holders of a `*.write` permission.
- No hosted-login session opens from an address the account's own organization refuses, whichever way the person
  signed in (passkey, password, a password through another organization's application, a sign-in link, social or
  single sign-on): the session reaches the account's self-service routes, so its own address rules apply.
- Resending an invitation, which revives an expired one, needs every permission of the role it grants, as
  creating it does (`rbac.grant_exceeds_caller`), so `member.invite` alone can no longer reissue an invitation to a
  role above the caller's.
- Service principals, SCIM tokens, webhooks, auth hooks and OpenID Connect applications record who created them.
  Deleting an administrator, removing one from an organization or deprovisioning one through SCIM revokes the
  admin-portal links and pending invitations they issued there and records the critical
  `user.integrations_left` event with how many of each, and the integrations they created that still work, so
  someone reviews them.
- A Stripe payment event is refused when its signed timestamp is more than five minutes from now, so a captured
  event can't be replayed later.
- A SAML assertion valid for longer than a day can no longer be replayed after a day: its response and assertion
  IDs are kept against replay until it expires (plus the allowed clock skew), not a fixed 24 hours.
- An authorization code or an approved backchannel (CIBA) request buys no token once its person has left the
  application's organization, as the token endpoint already promised, nor once the application has lost the grant
  (or, for CIBA, is no longer confidential).
- Sign-in lockout counts an address as the account lookup reads it (the database's own lowercasing), so case
  variants of an address with non-ASCII letters can no longer get counters of their own.
- A machine secret (API key, service principal, agent or application secret) still stored in the old Argon2id
  form now waits for the bounded password hasher and is answered "try again" when it is full, so a flood of wrong
  secrets can no longer starve everyone's sign-in.
- Taking a guest's last role in an organization, which ends their membership, now ends their sessions there, as
  removing them from the organization does; an access request's time-limited role ending does the same.
- `golang.org/x/crypto` is updated to v0.59.0 (with `x/sync`, `x/sys` and `x/text`), the first release past the
  advisory GO-2026-5932 in its unmaintained `openpgp` package, which this server never used; `govulncheck` now
  reports nothing, in the code or in the modules it requires.
- A refresh carries forward only the granted scopes the application still registers, and says so in `scope`;
  one with none of them left is refused with `invalid_scope`. Registering a scope again doesn't bring it back
  without a new consent.
- An application's access token now names, in `sid`, the hosted-login session it was issued in, as its ID token
  does, and introspects inactive once that session is signed out (a session that only expired still renews
  through its grant). Device and backchannel tokens, which come from no session, name none; a token from token
  exchange keeps a session of its own.
- An audit chain can no longer be rewritten unnoticed together with its checkpoint: each verification checkpoint,
  and the checkpoint a purged chain starts from, carries an HMAC under a key derived from the secrets key, and a
  checkpoint without it breaks the chain (`audit.chain_checkpoint_unsigned`). Verifying on demand checks the
  chain's checkpoint too. After rotating `SECRETS_KEY`, keep the old key until the audit-chain-verify job has
  run, which signs the checkpoints again.
