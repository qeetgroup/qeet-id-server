# Qeet ID 1.0 release checks

The ideas for after 1.0 are in [ideas.md](ideas.md); how they fit together is in the [README](README.md).

> **Status note (verified 15 Nov 2026):** this is the October 2026 release-readiness review and its
> seven evidence gates, not a live deployment-status page. The code, migration range and branch
> model have moved since it was written. Re-read the current Jira issues, workflow runs, release
> branch and deploy/kit state before using a “where things stand” statement below operationally.

This review defines seven checks Qeet ID 1.0 has to pass before real customers use it. The checks
prove that the selected release candidate works once deployed together with the console, hosted
login pages and SDKs; a merge or a large unit-test suite is not that evidence.

Unit and database tests show that the code does what it should in isolation. They don't show that a real customer can sign in through the deployed login page, that we can recover from a lost database, or that the service stays up under load. Launching without that evidence means the first customers find the problems for us.

The checks came out of an independent review of the backend in October 2026.

**Where things stood when reviewed, with the 15 Nov 2026 repository check noted:**

- The October server candidate was merged in PRs #533 to #535 on 29 October 2026. The repository has
  advanced since then; the exact candidate must be selected again.
- GitHub records later CI attempts. The latest checked server Verify run (12 Nov 2026, `7cfbe8b7`)
  failed before recording any steps, so it is not green evidence for the current candidate.
- Production and staging state are owned by deploy/kit and were not re-verified from this repository.
- Console, hosted-login, SDK and deploy compatibility must be read from their current repositories
  and Jira issues rather than inferred from this dated review.

**How to get there:**

- Fix CI billing and get one full, green CI run that publishes the release image (G-01).
- Set up a staging copy of production from that image.
- Run G-02 to G-06 there, and book the independent review (G-07).
- Write down the features supported for the first customers.
- Go live with one or two friendly organizations first, and widen only after the checks pass.

**Done when:**

- Every child ticket is Done, or its remaining risk is accepted in writing by the product owner on that ticket.
- The server, console, hosted login, SDKs and deploy changes are released together.

These are evidence requests. Their absence from this review does not prove that
production infrastructure lacks a control. Coordinate deploy/kit/SDK work with
their owners; this review did not inspect those environments.

Do not make launch depend on implementing every later idea. Use an explicit
supported-feature list and a limited customer pilot, then widen rollout only
after these gates pass. Release readiness cannot be inferred from code-review
completion or from a large feature count.

## G-01: Full CI on the 1.0 release candidate

**In short.** Run the complete CI pipeline once on the exact commit we will release, and publish the release image from that run.

**Why we need it.** CI is our proof that the released code builds and passes every test and security scan, and that the image we deploy is the one that was tested.

On PR #533 and the October `release/1.0.0` merges, GitHub refused to start any CI job because the
qeetgroup organization's Actions billing failed. Later workflow attempts exist, but the latest
server Verify run checked on 15 Nov 2026 failed before recording a step. Neither that attempt nor an
earlier green run on a laptop proves the current candidate, and this repository does not establish
that a release image exists.

**What Qeet ID has today:**

- CI runs one Verify job (build, vet, lint, generated SQL, vulnerability scan, API contract checks); the other tests and the security scan run locally before each push (make ci). candidate.yml builds the image for testing on each release branch.
- The last local full make ci passed the tests, lint, the sqlc check and the vulnerability scan; four security-scan warnings were then annotated and that scan re-run on its own.
- Production deploys the image CI builds (ghcr.io/qeetgroup/qeet-id-server:sha-<commit>); it is never rebuilt by hand.

**Steps:**

- Fix GitHub Actions billing or the spending limit for the qeetgroup organization (Settings, Billing & plans).
- Set `info.version` to `1.0.0` in the five `api/openapi/src/*/openapi.yaml` files and in qeet-repo.yml, then run `make openapi` (see Versioning in `api/openapi/README.md`).
- Run CI on the exact current release-candidate commit.
- Fix anything that fails on a branch from develop and merge it the normal way.
- Record the release-candidate commit, the image digest and the configuration it is meant to run with (supported features and environment variables).

**Done when:**

- All six CI jobs pass on one commit and its release image is published.
- The commit and image digest are written on this ticket.
- Any later candidate commit gets a new full run before release.

**Depends on:**

- Owner: a GitHub organization admin for billing; the server team for any fixes.
- Blocks G-02 to G-06, which all deploy this image.

**From the review:** One immutable release candidate with full `make ci`, each accepted regression, resolved or explicitly accepted release risks, and a recorded feature/configuration matrix. Earlier partial green runs do not cover later commits. *Owner and dependencies:* Server team; existing programme

## G-02: Customer sign-in journeys end to end

**In short.** Walk through every sign-in and account journey a real customer will use, on a deployed copy of Qeet ID, using the real console, hosted login page and SDKs.

**Why we need it.** The server's tests call its handlers directly. A real sign-in also goes through the hosted login page, browser cookies and redirects, the SDK inside the customer's app and, for enterprise customers, their own identity provider. Problems between these pieces only show up when they run together.

Social sign-in (GitHub, Facebook, X, Discord and Apple) has only been tested against fake providers so far.

**What Qeet ID has today:**

- The server supports passkeys, passwords, magic links, MFA, account recovery, OIDC for apps, SAML and LDAP sign-in, SCIM provisioning and social sign-in per organization.
- The console, hosted login and SDKs need their updates for the 1.0 server before this can run.

**Steps:**

- Set up two separate customer organizations, plus one person who belongs to the first and is a guest in the second.
- Passkey, password and account-recovery sign-in, including MFA.
- A sample app using the SDK: OIDC authorisation code with PKCE, token refresh and logout.
- SAML sign-in and SCIM provisioning with a real identity provider, for example Microsoft Entra ID or Okta.
- Each social provider with a real registered app.
- Offboard a person (suspend, then delete) and check they can't get back in; rotate an API key and a service-principal secret.

**Done when:**

- Each journey passes in the deployed environment, with the results recorded on this ticket.
- At no step can either organization see the other's people, apps or settings.
- Each problem found gets its own bug ticket.

**Depends on:**

- Needs G-01's release image and a staging environment.
- Needs the console, hosted-login and SDK updates, a real app registered with each social provider, and a test organization at an identity provider.

**From the review:** Two isolated customer orgs plus a home/guest account; passkey/password/recovery, OIDC code/refresh/logout, actual supported SAML/SCIM IdP fixtures, offboarding and key rotation. Exercise deployed browser/SDK paths, not only direct handlers. *Owner and dependencies:* Server + kit + client owners; phases 1-4

## G-03: Backup restore and upgrade rehearsal

**In short.** Prove that we can restore Qeet ID from a backup, and that the upgrade to 1.0 runs safely on production-sized data.

**Why we need it.** A backup that has never been restored is not one we can rely on. Part of Qeet ID's data is encrypted with keys that rotate, so a restore also needs the right key versions; otherwise stored secrets can't be read.

The schema starts from a 12-file baseline (migrations 0001 to 0012, written in November 2026 before
any database held real data); every change after it is a new migration. One that adds an index to
an existing table builds it while the service keeps running (`CONCURRENTLY`), and an interrupted
build can leave an invalid index that has to be cleaned up before retrying.

**What Qeet ID has today:**

- Encrypted columns carry key IDs, and the keys rotate.
- The audit log is a signed hash chain that can be verified.
- Migrations that add an index to an existing table use CREATE INDEX CONCURRENTLY.

**Steps:**

- Restore a backup into an isolated environment with the encryption and signing key versions it needs.
- After the restore, check sign-in, reading stored secrets (for example SAML keys and webhook secrets), organization isolation and audit-chain verification.
- Measure how much data could be lost (recovery point objective, RPO) and how long recovery takes (recovery time objective, RTO).
- Run every migration newer than the last production schema on a copy of production data;
  interrupt one concurrent index build and recover from it. Read the highest migration when
  selecting the candidate.
- Write down the rollback or roll-forward path.

**Done when:**

- The restore works and the measured RPO and RTO are recorded here.
- The upgrade and recovery steps are in the runbook.
- Nobody edits the schema-version table by hand to start a build that doesn't match the database.

**Depends on:**

- Owners: deploy and kit (the backups live in the infrastructure), with the server team.
- Needs G-01's image and the staging environment.

**From the review:** Restore a backup into an isolated environment with the required encryption/signing key versions; verify sign-in, secrets, organization isolation and audit-chain verification. Record measured RPO/RTO. Rehearse interrupted concurrent-index migration and a supported rollback/roll-forward path; never fake schema version records to boot an incompatible binary. *Owner and dependencies:* Deploy/kit + server; 2.9, 5.4

## G-04: Load and failure test

**In short.** Put a deployed Qeet ID under realistic peak load and break its dependencies one at a time, to confirm that it slows down gracefully instead of falling over.

**Why we need it.** Password hashing is deliberately slow (Argon2), so a burst of sign-ins can take all the CPU. Overload shedding added protection: a bounded queue that turns surplus sign-ins away quickly with a 503 and Retry-After, so token refresh, the admin API and health checks keep working. That protection has never been measured under load.

We also need to know how many users one instance can serve, and what happens when NATS, email or the SIEM destination is down.

**What Qeet ID has today:**

- A bounded password hasher (as many hashes at once as CPUs, twice that waiting, each for at most 1 second), and the metric password_hasher_rejections_total.
- An earlier local load test on the production image found the bottlenecks behind overload shedding and instance sizing.
- The rate limiter and auth hooks deliberately let requests through if their store fails; both are recorded decisions.

**Steps:**

- Two server replicas sharing one rate-limiter store, with Postgres sized like production.
- A sign-in surge at twice one instance's capacity, alongside normal token refresh, admin API and health traffic.
- One noisy organization, a slow live-activity reader, a stalled AI provider and database contention.
- Outages of NATS, the email provider and the SIEM destination, then their recovery.
- Measure p95 and p99 latency, memory, database pool use, error rates and recovery time.

**Done when:**

- Surplus sign-ins get a 503 within about 100 ms, other flows keep p95 under 100 ms, and /readyz answers within 1 second (the overload-shedding targets).
- Memory and pool use stay bounded, and the service recovers by itself when each dependency comes back.
- The password hasher's limits (`internal/platform/crypto/password/hasher.go`) are tuned from the results, and the instance sizing uses the measured capacity.
- The rate limiter and auth hooks still let requests through when their store fails.

**Depends on:**

- Needs G-01's image and the staging environment.
- Related: overload shedding and instance sizing.

**From the review:** Two replicas, shared limiter store, noisy organization, slow SSE consumer, stalled AI provider, database contention and NATS/mail/SIEM outages. Measure p95/p99, bounded memory/pool use and recovery lag against chosen targets. Preserve deliberate failure policies. *Owner and dependencies:* Server + operations; 2.10, 5.7, R-01/R-02

## G-05: Revoked access really stops

**In short.** Prove that when access is taken away (a session ended, an app's grant revoked, a key deleted) the old credential stops working everywhere it matters.

**Why we need it.** Revocation is the control enterprises rely on when someone leaves or a key leaks. It has several layers: the server refusing the credential, an event being queued, the event reaching the customer's app, and the app acting on it. Each layer can fail on its own, so "we revoked it" has to be shown layer by layer, not assumed.

**What Qeet ID has today:**

- Ending a session makes its access tokens refused (401 auth.session_revoked); suspending or deleting a person ends every sign-in; personal API keys stop with the person; disabled service principals and agents are refused.
- An open live-activity stream ends within 30 seconds of the reader losing access, and at token expiry.
- Webhooks tell apps about session and user events.

**Steps:**

- Revoke, in turn: a session, an OAuth grant (a connected app), an API key, a service-principal secret and an agent token.
- After each, try the old credential on the API, on token introspection and on token refresh, with a live-activity stream open while access is removed.
- Record separately: the server refused it, the event was queued, it was delivered, and the test app acted on it.

**Done when:**

- After each revocation the server refuses the old credential.
- An open activity stream ends within 30 seconds.
- The result for every layer is recorded here, and any gap becomes a bug ticket.

**Depends on:**

- Needs G-01's image, the staging environment and a test app that receives webhooks.

**From the review:** Prove effective revocation across session, grant, API key, service/agent token, introspection and open streams. Distinguish server revocation, queued delivery, delivered notification and relying-party acknowledgement. *Owner and dependencies:* Server + integrating applications; 1.10, R-02

## G-06: Privacy and support readiness

**In short.** Rehearse the privacy requests and support work we have to handle from day one: data export, erasure, the list of subprocessors, support bundles and who owns an incident.

**Why we need it.** Customers, India's DPDP Act and the GDPR expect us to export or erase a person's data on request and to know who processes it. Erasure is tricky because backups keep data for the restore window.

Support work must not leak secrets or personal data, and someone has to own an incident in the middle of the night.

**What Qeet ID has today:**

- Data export and erasure exist; erasure covers passkeys, OTP destinations, linked identities, directory profiles, vault grants, devices and notifications.
- A deleted organization's data is purged after a restore window.
- Qeet AI runs only with the customer's own model key in production for 1.0.

**Steps:**

- Rehearse one export and one erasure end to end, including what happens to that person's data in backups during the restore window.
- List the subprocessors (AWS, the email provider, AI model providers used through customer keys, Stripe) and what data reaches each.
- Check that support bundles and logs leave out secrets and personal data.
- Name the incident and recovery owners and how to reach them.

**Done when:**

- Each item is rehearsed or written down, has an owner, and is linked here.

**Depends on:**

- Owners: product and operations; the staging environment for the rehearsal.

**From the review:** Rehearse export/erasure/restore-window handling; document model subprocessors and data boundaries; redact support bundles; assign incident response and recovery ownership. Existing GDPR work is a dependency, not a new finding. *Owner and dependencies:* Server + product/operations; 2.7, 5.1

## G-07: Independent security review

**In short.** Have someone outside the team test Qeet ID's sign-in and organization isolation, and map our controls to a recognised security standard before we make any compliance claim.

**Why we need it.** Our own reviews and scanners find a lot, but an identity provider is a high-value target and enterprise buyers ask for independent evidence.

Claims such as "NIST AAL2" or "ASVS compliant" need test evidence behind them; without it they become a liability.

**What Qeet ID has today:**

- Internal reviews: the Phase 1 security programme, the enterprise plan and an October 2026 backend review, whose five findings are fixed.
- CI runs gosec (the security scan) and govulncheck (the vulnerability scan).
- A local run of the OpenID Foundation conformance suite (November 2026): the Basic OP, Config OP,
  RP-initiated logout and back-channel logout plans have no failure against a build that signs with
  an RSA key (RS256). The run against staging, which a certification needs, is still to do.

**Steps:**

- Map the in-scope requirements of OWASP ASVS 5.0.0 (the Application Security Verification Standard) to tests or manual evidence.
- Run the OpenID Foundation conformance tests for the OIDC profiles we support.
- Commission an independent penetration test of sign-in, tokens and organization isolation.
- Decide which NIST SP 800-63B authentication assurance level, if any, we will claim. Email codes are not NIST out-of-band authentication, and synced passkeys don't give AAL3.

**Done when:**

- Every finding is fixed or its risk is accepted in writing.
- No conformance or assurance claim appears in marketing or documentation without the evidence behind it.

**Depends on:**

- Owner: security and product; a budget for an outside tester; the staging environment.

**From the review:** Map scoped ASVS 5.0.0 requirements to actual tests/manual evidence; run protocol conformance and an independent auth/organization security review. Define the intended authentication assurance before making NIST claims. Email OTP is not NIST out-of-band authentication; syncable passkeys do not establish AAL3. *Owner and dependencies:* Security/product; standards below
