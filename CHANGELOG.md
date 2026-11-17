# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release, 1.0.0, is in preparation. No version has been published yet.

### Added

- Sign-in requests reach the native Qeet ID apps: Apple Push Notification service for iOS (token-based,
  `APNS_AUTH_KEY`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_BUNDLE_ID`, `APNS_SANDBOX`) and Firebase Cloud Messaging
  for Android (`FCM_SERVICE_ACCOUNT`). Each phone is sent through the service that issued its token; Expo tokens
  still go to Expo. A service without credentials is off; a phone it would serve is not sent the request but
  finds it when the app opens, and the sign-in no longer fails for that phone alone.
- `POST /v1/mfa/push/devices/{id}/push-token`: a linked phone replaces the push token its platform rotated,
  with its unexpired device credential.
- `POST /v1/mfa/push/devices/{id}/pending`: a linked phone lists the sign-in requests waiting on its account,
  with its unexpired device credential, so a request whose push was late or lost can still be answered.
- The pairing claim answers the linked account's email (`account.email`), so the app can name it.
- A sign-in or step-up request for a phone records where it came from (`context.location`, such as
  "Bengaluru, India"), from the trusted proxy's country and city headers, so the phone can show it.
- Access requests: a person asks their organisation for one of its roles, for up to 90 days or for good,
  with a reason (`/v1/me/access-requests`, the roles they can ask for, cancel); the people who can give roles
  are told in the app and on their linked phones, and approve (step-up; held to the rule for giving the role
  directly; nobody answers their own) or deny with a note (`/v1/tenants/{tenantID}/access-requests`). A
  time-limited role is taken back when its time is up, and a request nobody answers lapses after 14 days
  (the `access-request-sweep` job). Every step is audited (`access_request.*`).
- `GET /v1/tenants/{tenantID}/critical-events`: the organisation's open anomaly alerts and critical audit
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

- The server records the checksum of each migration file it applies (`public.schema_migration_checksums`)
  and refuses to start on a database whose applied migrations aren't recorded as the files it carries: one
  built before a baseline file was edited, one migrated with the `migrate` tool, and, once, every database
  migrated by a build from before the records. The refusal names the file and the way out
  (`make db-reset`); the scheduler and the worker refuse too, and `qeet-id-server schema-check` answers not
  compatible. Before, such a database had the same migration number, so the server started on it and
  failed query by query. `make migrate-up` is gone, and `cmd/migrate` no longer applies migrations by
  default: the server and the seed apply them.
- The database schema is one baseline of 12 migrations (`0001`–`0012`: one file per schema, every table in its
  final shape) in place of 243 incremental ones. A database the earlier migrations built is refused at start
  as newer than this build and has to be recreated (`make db-reset`); no release has shipped, so nothing is
  carried over.
- The schema `"user"` is named `account`, so it no longer has to be quoted.
- Inside the server the word is organization, not tenant. The schema `tenant` is `organization`,
  `tenant.tenants` is `organization.organizations`, every `tenant_id` column is `organization_id`, the
  row-security policy is `organization_isolation`, and the Go code, SQL and comments follow. The API is
  unchanged: its paths, JSON fields, token claim and its permission, event and error names still say
  tenant, and are renamed in one later change.
- A secret is stored only encrypted. The plaintext columns left from before encryption, and the code that read
  them and encrypted them on first use, are gone: webhook and auth hook signing secrets, Token Vault and
  social provider client secrets, LDAP bind passwords, SIEM tokens, authenticator app secrets and push tokens.
- The one-time sign-in codes of SAML, OIDC connection, social and console sign-in are one table
  (`auth.login_codes`), and the sign-in states of the last three are one (`auth.oauth_states`). A code or a
  state is accepted only by the flow that issued it.
- Every table with an `organization_id` has an index leading on it and, unless it is an append-only log or outlives
  its organization, a foreign key to the organization; ten indexes another index already covered are dropped;
  eleven columns whose values are a fixed list have a CHECK.
- Dropped, as nothing used them: the `pgcrypto` extension, `auth.passkey_challenges`, `auth.agents.disabled_at`,
  and `organization.security_policies.password_min_length` and `password_complexity`.

### Fixed

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
- The development seed (`make seed`) runs again: one demo organisation asked for a lockout window shorter than
  the 15 minutes the sign-in policy now allows.

### Security

- An organisation's OpenID Connect social provider (any provider found by its `discovery_url`) verifies an
  address only on a domain the organisation has verified. Elsewhere it creates the account with the address
  unverified and never signs in to an existing account by its address, so a provider pointed at a server of
  the organisation's own can't make verified accounts for other people's addresses or open the invitations
  sent to them. GitHub, X, Discord and Apple sign-ins are unchanged.
- No social provider creates an account on a domain another organisation has verified, or on one whose
  organisation requires single sign-on.
- No social provider signs in to an account that owns or administers its organisation by matching the
  address (`social.account_administers`), as SAML, LDAP and OIDC single sign-on already refuse. Such an
  account keeps its own credentials and can connect the provider from its account.
- Self-service sign-up (password sign-up, hosted registration, passkey sign-up and the console's own social
  sign-up) creates no account on a domain an organisation has verified, unless it is that organisation's own
  registration, so nobody can claim a colleague's address before their organisation's single sign-on or
  directory creates it. The answer is the same neutral one an address with an account gets.
- A hosted password sign-in that names another organisation's application is held to a lockout no looser than
  the platform's, so an organisation with a lenient lockout can't be used to guess other people's passwords
  faster, and the account's own organisation's "password sign-in off" switch applies whichever application is
  named. An organisation's lockout settings may now only be stricter than the platform's (threshold 3–5,
  window and lock 15 minutes to 24 hours) and govern the lock on one network: the lock on every network always
  uses the platform's settings, so a strict organisation can't lock someone else out everywhere.
  `LOGIN_LOCKOUT_THRESHOLD_MAX`, `LOGIN_LOCKOUT_WINDOW_MIN` and `LOGIN_LOCKOUT_DURATION_MIN` are removed.
- A magic link always follows the account's own organisation's rules (whether links are allowed, how long
  they last), whichever organisation's sign-in page asked. The asking organisation brands the email and sees the
  request in its audit log only for its own members, so naming it no longer reveals whether an address has an
  account, or puts another organisation's wording around someone's link.
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
- An organisation that requires single sign-on on its domain can no longer be sidestepped: no social provider
  (its own or the console's) signs in, adopts or links an account there, no session is switched into that
  organisation, and a member can't move their address off its domains (`verification.email_managed`). Nor can an
  address the organisation's directory or single sign-on provides be changed, or any address be moved onto a
  domain another organisation manages. Break-glass members are unaffected.
- Taking authority away through a group is held to the rule for giving it: removing someone from a group or
  deleting it needs what the group's roles carry, removing someone also needs to outrank them, and taking a role
  off a group needs that role. Removing a group member and deleting a group now need a fresh second factor, so
  an owner who holds their role through a group can no longer be demoted by a group editor.
- GDPR erasure and export requests, and reading an export, follow the rule for deleting an account: an
  administrator can no longer erase or export a co-owner, or anyone else who outranks them.
- Rotating a service principal's or an agent's secret needs every scope it carries, as creating one does, so
  `apikey.write` alone no longer hands over an owner's credential. API-key rotation now checks the key's scopes
  however many keys the organisation has (it skipped the check past the first 1,001).
- SCIM no longer changes the address of an account that administers its organisation (403): moving it to a
  fresh mailbox on the domain would have sent that account's password reset to whoever controls the directory.
- Changing what a connection trusts (a SAML certificate or entity ID, metadata from elsewhere, an OIDC
  connection's issuer, discovery URL, client or allowed tenants, an LDAP connection's server, bind or base DN,
  filter or TLS settings, an OpenID Connect social provider's discovery URL) now needs a caller who outranks
  every administrator linked to it (`rbac.trust_change_outranks_caller`), as the changed connection could sign
  in as them; admin-portal sessions can't make such a change once an administrator is linked.
- Single sign-on, domain capture and group sync now count as an administrator anyone who owns the organisation
  or holds any permission other than the plain reads (organisation, people, roles, groups, connections, API keys,
  webhooks, billing, policy, audit and analytics). A permission added later counts too, so a role holding only
  `gdpr.write`, `secret.read`, `billing.write` or `branding.write` is no longer adopted by its address, captured
  by the domain's identity provider or given through an identity provider group.
- Email and phone verification codes can no longer be guessed across resends: ten wrong codes in an hour for
  one flow refuse even the right code until the hour has passed (`verification.attempts_exceeded`, with
  `retry_after`). At most ten codes an hour go to one person and five to one address over every account
  (`verification.code_send_limited`, 429), a new code replaces the earlier ones, a code the provider refuses
  is withdrawn, and email-change codes have eight digits.
- Phone verification is held to the same limits as MFA text messages: the number must be in E.164 form, SMS must
  be in the plan of the organisation the session is in (`billing.upgrade_required`; a session in no organisation
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
- Suspending or deleting an organisation now stops its machine credentials at once, as it already ended its
  people's sessions: its API keys no longer authenticate, its service principals and agents get no new tokens,
  and the service and agent tokens already issued are refused (and introspect as inactive). Reactivating the
  organisation restores them.
- A personal API key now does only what both its scopes and its person's current permissions allow: once the
  person loses a permission (a role removed or changed), the key loses it too, and reading the secrets vault
  needs the person's `secret.read`. Keys that act for no one are unchanged.
- An invitation is accepted only while the person who sent it may still give it: their account active, still
  in the organisation and still able to give its role. Otherwise every way of accepting it (password, passkey,
  signed-in link or inbox) and its preview answer `invite.invalid`. Removing someone from an organisation, or
  deleting their account, withdraws the invitations they sent there.
- Qeet ID acting as a SAML identity provider now applies the organisation's address rules and its second-factor
  requirement before it signs an assertion, as OpenID Connect sign-in already does: a refused address gets
  `auth.address_not_allowed` (recorded), and a session that didn't meet a required second factor is sent to sign
  in again, then refused (`step_up_required` or `mfa.enrollment_required`) if that sign-in still didn't.
- Approving a backchannel (CIBA) sign-in request now meets the application's organisation's rules, as approving
  a device does: the person must still be a member of it, approve from an address its rules allow, and through a
  session that met the second factor it requires. Collecting the tokens needs the application still to hold the
  CIBA grant and the person still to be a member, and a request is spent only together with its refresh token.
- Starting a passkey sign-up (`/v1/signup/passkey/begin` and `/v1/register/passkey/begin`) now answers alike
  whether or not the address has an account, and no longer holds the address while the ceremony runs. An
  address that is taken, or on a domain another organisation manages, is refused when the ceremony finishes,
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
- Plans' audit retention is now enforced: once a day, each organisation's audit events older than its plan's
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
- An organisation registers an API resource on a host only once it has verified that host or a domain above it
  (`oidc.resource_domain_unverified`), and never the platform's own token issuer or audience, their host or the
  API's public host (`oidc.resource_reserved`), so no organisation gets tokens whose audience another's service
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
  the router and every check that matches a path (permissions, step-up, organisation scoping, CSRF and
  idempotency) always see the same route.
- An organisation that requires a second factor of its administrators now requires it of everyone holding an
  administrative permission, the same ones single sign-on never adopts by address (such as `user.credentials`,
  `user.suspend`, `session.revoke` and `member.invite`), not only of holders of a `*.write` permission.
- No hosted-login session opens from an address the account's own organisation refuses, whichever way the person
  signed in (passkey, password, a password through another organisation's application, a sign-in link, social or
  single sign-on): the session reaches the account's self-service routes, so its own address rules apply.
- Resending an invitation, which revives an expired one, needs every permission of the role it grants, as
  creating it does (`rbac.grant_exceeds_caller`), so `member.invite` alone can no longer reissue an invitation to a
  role above the caller's.
- Service principals, SCIM tokens, webhooks, auth hooks and OpenID Connect applications record who created them.
  Deleting an administrator, removing one from an organisation or deprovisioning one through SCIM revokes the
  admin-portal links and pending invitations they issued there and records the critical
  `user.integrations_left` event with how many of each, and the integrations they created that still work, so
  someone reviews them.
- A Stripe payment event is refused when its signed timestamp is more than five minutes from now, so a captured
  event can't be replayed later.
- A SAML assertion valid for longer than a day can no longer be replayed after a day: its response and assertion
  IDs are kept against replay until it expires (plus the allowed clock skew), not a fixed 24 hours.
- An authorization code or an approved backchannel (CIBA) request buys no token once its person has left the
  application's organisation, as the token endpoint already promised, nor once the application has lost the grant
  (or, for CIBA, is no longer confidential).
- Sign-in lockout counts an address as the account lookup reads it (the database's own lowercasing), so case
  variants of an address with non-ASCII letters can no longer get counters of their own.
- A machine secret (API key, service principal, agent or application secret) still stored in the old Argon2id
  form now waits for the bounded password hasher and is answered "try again" when it is full, so a flood of wrong
  secrets can no longer starve everyone's sign-in.
- Taking a guest's last role in an organisation, which ends their membership, now ends their sessions there, as
  removing them from the organisation does; an access request's time-limited role ending does the same.
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
