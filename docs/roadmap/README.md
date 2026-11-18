# Release checks and roadmap

This folder holds two things for Qeet ID:

- **[release-checks.md](release-checks.md):** the seven checks the first release, 2027.1.0, has to pass before real customers use it.
- **[ideas.md](ideas.md):** 25 product ideas for after the first release. None is approved.

Both came out of a backend review and product research done in October 2026. These pages keep the full reasoning, the proposed APIs and the sources behind each item.

## Status (19 November 2026)

- **First release:** `2027.1.0`, planned for Tuesday 19 January 2027. Its branch, `release/2027.1.0`, is cut by
  1 December 2026 (see Branches and releases in [AGENTS.md](../../AGENTS.md)).
- **Release checks:** open. CI has to run on the release candidate first (G-01), and the other checks need a staging copy of production, which waits for the AWS production freeze to lift.
- **Ideas:** none started. The product owner picks one, with a design partner, after the first release is stable.
- **Review findings:** the review's five defects are fixed in the first release (see the table below).

## Index

| ID        | Name                                                       | Detail                                                                              |
| --------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| G-01      | Full CI on the release candidate                           | [release-checks.md](release-checks.md#g-01-full-ci-on-the-release-candidate)        |
| G-02      | Customer sign-in journeys end to end                       | [release-checks.md](release-checks.md#g-02-customer-sign-in-journeys-end-to-end)    |
| G-03      | Backup restore and upgrade rehearsal                       | [release-checks.md](release-checks.md#g-03-backup-restore-and-upgrade-rehearsal)    |
| G-04      | Load and failure test                                      | [release-checks.md](release-checks.md#g-04-load-and-failure-test)                   |
| G-05      | Revoked access really stops                                | [release-checks.md](release-checks.md#g-05-revoked-access-really-stops)             |
| G-06      | Privacy and support readiness                              | [release-checks.md](release-checks.md#g-06-privacy-and-support-readiness)           |
| G-07      | Independent security review                                | [release-checks.md](release-checks.md#g-07-independent-security-review)             |
| F-01      | Preview a policy change before it goes live                | [ideas.md](ideas.md#f-01-preview-a-policy-change-before-it-goes-live)               |
| F-02      | Access reviews and time-limited admin access               | [ideas.md](ideas.md#f-02-access-reviews-and-time-limited-admin-access)              |
| F-03      | Offboarding receipt                                        | [ideas.md](ideas.md#f-03-offboarding-receipt)                                       |
| F-04      | Rehearse a federation change before it affects people      | [ideas.md](ideas.md#f-04-rehearse-a-federation-change-before-it-affects-people)     |
| F-05      | Agent actions through a credential broker, with approvals  | [ideas.md](ideas.md#f-05-agent-actions-through-a-credential-broker-with-approvals)  |
| F-06      | Evidence pack for a release and an organization's controls | [ideas.md](ideas.md#f-06-evidence-pack-for-a-release-and-an-organizations-controls) |
| N-01      | Sign in CI jobs and workloads without stored secrets       | [ideas.md](ideas.md#n-01-sign-in-ci-jobs-and-workloads-without-stored-secrets)      |
| N-02      | Task-scoped agent identity with shared budgets             | [ideas.md](ideas.md#n-02-task-scoped-agent-identity-with-shared-budgets)            |
| N-03      | Permission-aware AI retrieval with source records          | [ideas.md](ideas.md#n-03-permission-aware-ai-retrieval-with-source-records)         |
| N-04      | Pin approved MCP tool servers to a reviewed revision       | [ideas.md](ideas.md#n-04-pin-approved-mcp-tool-servers-to-a-reviewed-revision)      |
| N-05      | What could this account reach if it were compromised?      | [ideas.md](ideas.md#n-05-what-could-this-account-reach-if-it-were-compromised)      |
| N-06      | Least-privilege suggestions from real usage                | [ideas.md](ideas.md#n-06-least-privilege-suggestions-from-real-usage)               |
| N-07      | Two-way trust between partner organizations                | [ideas.md](ideas.md#n-07-two-way-trust-between-partner-organizations)               |
| N-08      | Per-app disclosure rules and pairwise subject IDs          | [ideas.md](ideas.md#n-08-per-app-disclosure-rules-and-pairwise-subject-ids)         |
| N-09      | Recovery readiness and quorum-approved recovery            | [ideas.md](ideas.md#n-09-recovery-readiness-and-quorum-approved-recovery)           |
| N-10      | Authenticator and device assurance                         | [ideas.md](ideas.md#n-10-authenticator-and-device-assurance)                        |
| N-11      | Authorisation decisions close to customer services         | [ideas.md](ideas.md#n-11-authorisation-decisions-close-to-customer-services)        |
| N-12      | Customer-controlled encryption keys                        | [ideas.md](ideas.md#n-12-customer-controlled-encryption-keys)                       |
| N-13      | Outbound-only connector for private directories            | [ideas.md](ideas.md#n-13-outbound-only-connector-for-private-directories)           |
| N-14      | Promote configuration between environments                 | [ideas.md](ideas.md#n-14-promote-configuration-between-environments)                |
| N-15      | Integration diagnostics for customer apps                  | [ideas.md](ideas.md#n-15-integration-diagnostics-for-customer-apps)                 |
| PQ-01     | Cryptographic inventory and post-quantum plan              | [ideas.md](ideas.md#pq-01-cryptographic-inventory-and-post-quantum-plan)            |
| PQ-02     | Evidence of post-quantum TLS on real connections           | [ideas.md](ideas.md#pq-02-evidence-of-post-quantum-tls-on-real-connections)         |
| PQ-03     | Post-quantum signatures on long-lived audit exports        | [ideas.md](ideas.md#pq-03-post-quantum-signatures-on-long-lived-audit-exports)      |
| RESIDENCY | Data residency and dedicated deployments (discovery)       | [ideas.md](ideas.md#residency-data-residency-and-dedicated-deployments-discovery)   |

## How to choose an idea

Pick one problem that a named customer has, then one idea. The research recommends N-03 (permission-aware AI retrieval) for a customer that runs AI retrieval, otherwise N-05 (exposure analysis); N-01 (workloads without stored secrets) as the strongest adoption feature; and PQ-01 as the practical first post-quantum step. Among N-10 to N-15, test demand for N-15 or N-14 first.

### Suggested sprint sequence after the first release stabilises

Illustrative sequencing for one team; two-week slots are planning assumptions.
Do not run every track simultaneously. Continue a slot if its security/acceptance
gate is not met, and re-estimate after discovery rather than promising a date.

| Slot                     | Bounded deliverable                                                                                                                                                               | Exit decision                                                                                 |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| 0: discovery             | Interview 3-5 design partners, choose one buyer/problem, establish baseline pain, data-flow threat model and success measures. Confirm the first release's operational stability. | A partner commits to a controlled pilot; otherwise stop/reprioritize.                         |
| 1: N-03 contract         | One source identity/ACL mapping, proposed OpenAPI, isolated authorization fixtures and a fake retrieval adapter.                                                                  | No organization or subject ambiguity; required permissions and integration owner agreed.      |
| 2: N-03 vertical slice   | One real read-only connector, pre-model authorization and source-provenance recording with synthetic/non-sensitive data.                                                          | Unauthorized canaries never reach the fake model; lineage reconciles.                         |
| 3: N-03 controlled pilot | ACL changes, deletion, cache reuse, quotas, SDK/docs, observability and rollback. Limited opt-in partner traffic after review.                                                    | Measured usefulness, latency and isolation meet agreed targets; no automatic broad rollout.   |
| 4: N-01 trust contract   | One CI issuer's exact trust selectors, preview API and external-verifier threat model. Preserve existing token clients.                                                           | Consumer/contract approval and replay/key-rollover policy agreed.                             |
| 5: N-01 pilot            | One CI integration authenticates without a stored Qeet secret; exercise disabled trust and token lifecycle.                                                                       | Adoption and failure handling demonstrated before adding Kubernetes/SPIFFE providers.         |
| 6: PQ-01 evidence        | Read-only crypto inventory and dependency/exposure report, with unknowns and operator/organization separation.                                                                    | Partners can act on the report; choose whether PQ-02 merits an authorized staging experiment. |

If the selected buyer does not operate RAG, replace slots 1-3 with the N-05
exposure-analysis pilot. N-02/N-04 follow a proven AI integration; N-06 follows
adequate observation coverage. N-07/N-08/N-09 require named partner/privacy/recovery
requirements and dedicated security/consumer review. PQ-03 remains a later
interoperability track. The table is not authorization to start any of them.

## Rules for every idea

All routes below are illustrative and **do not exist by virtue of this document**.
Resolve naming and contracts before implementation. Retain the current modular
monolith and consumer-declared interfaces; wire dependencies in bootstrap. Do not
introduce microservices or a second authorization engine just to implement a pilot.

- Organization scope comes from `httpx.RequireOrganization(r)`. A `{organizationID}` path
  must match it; no path/body/header organization value grants authority. Every related
  object must be looked up within that scope, with SQL predicates and applicable RLS.
- Separate administrative configuration, integration evaluation and a person's
  own actions. Give each a deliberately reviewed permission/machine scope; do not
  grant chatbot users broad administrative permission merely to evaluate access.
- Actor identity and delegation come from verified credentials/server records,
  never a model-generated `user_id`, tool output or caller-asserted approval.
  IDs, task handles and decision receipts are not authentication credentials.
- Management writes need audit events, validation, concurrency control and
  idempotency with explicit unknown-outcome behavior. Long analyses should return
  an organization-scoped job ID, with bounded work, status/cancel operations and expiry.
- Bound input size, graph depth, candidate counts, concurrency, storage and
  provider costs. Apply egress restrictions and redaction to every connector.
  Paginate list APIs and never put secret key material or raw tokens in responses.
- Ship OpenAPI, normal and cross-organization denial tests, dependency-failure cases,
  metrics and a disable/rollback procedure with every pilot. Do not present
  a mocked test as evidence of real provider or deployment compatibility.
- JWT/JWKS/claims, federation/webhook contracts and changes to other repositories
  require explicit approval and consumer coordination. This section approves none.

## Foundations to finish before a pilot

Do not let novel APIs outrun their operating model. Before production pilots,
reuse or finish the existing API/versioning, billing/entitlement, audit, retention,
idempotency, admission-control and observability work. Add reproducible SDK
examples and conformance fixtures for the selected feature. Define retention
for new task, provenance, analysis and evidence records; assess personal-data
processing, customer exports and erasure. Chargeable work needs transparent
usage and limits, not unbounded background tasks on a shared organization tier.

A feature requires an adoption path, not only routes in this repository. Name
the consuming app/SDK, integration owner, operating cost, security failure mode
and support process. Keep a portable, documented exit/export path. Never make
"the model says it is safe" an authorization or compliance decision.

## Plan items referred to

Numbers such as "4.4" or "5.3" in these pages are items of the October 2026 enterprise plan. All of them are built in the first release.

| Item | What it covers                                                                                                                                                                                                                                                            |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1.1  | Machine credentials (API keys, service principals, agents) may only carry scopes the creator holds                                                                                                                                                                        |
| 1.2  | Adding someone to a group checks the group's roles (no self-promotion to owner); add the route to step-up; SCIM can't add to admin groups                                                                                                                                 |
| 1.3  | Admins can act on (password, MFA reset, suspend, delete, purge, role removal) only people with fewer privileges; only owners act on owners; built-in owner role read-only                                                                                                 |
| 1.4  | Owners can always be offboarded: home org suspend/delete/SCIM deactivate never blocked by ownership elsewhere; policy for who may create orgs; enforce org limit                                                                                                          |
| 1.5  | Tokens can't cross organizations: resource identifiers unique platform-wide and on a verified domain; app tokens default aud = client_id                                                                                                                                  |
| 1.8  | Adding credentials / changing email needs recent sign-in even without a second factor; first-password set included                                                                                                                                                        |
| 1.9  | Recovery: send to the stored address; expire outstanding reset/magic links on any credential change; per-address forgot-password limit                                                                                                                                    |
| 1.10 | Offboarding ends everything: SCIM suspend/delete end all sign-ins; personal API keys stop with the user; disabled service principals' tokens refused                                                                                                                      |
| 1.15 | Token exchange can't widen scopes/resources; sign login_after                                                                                                                                                                                                             |
| 2.4  | Audit completeness: passkeys, bot/risk settings, anomaly resolve, billing profile/trial/webhook plan change, role-permission grants in the org log, organization edits, restore/purge/mfa-required in-tx, PATCH /v1/users, self-service delete/export, phone verification |
| 2.7  | GDPR: erasure covers passkeys, OTP destinations, linked identities, directory profiles, vault grants, devices, notifications; export payload expires; erasure record kept; FKs don't block purges                                                                         |
| 2.9  | Migrations don't lock hot tables (CONCURRENTLY + lock timeout)                                                                                                                                                                                                            |
| 2.10 | Background throughput: SIEM (lease, loop, metadata, honest evidence), anomaly scorer, scheduler (parallel, checkpointed chain verify), outbox                                                                                                                             |
| 2.11 | Retention jobs for every growing table (esp. login attempts with attacker-tried emails); batched deletes                                                                                                                                                                  |
| 2.12 | ABAC: missing attribute = unknown (no fail-open deny); AuthZEN properties                                                                                                                                                                                                 |
| 3.1  | Domain capture: "SSO required" per verified domain (wire sso_enabled/jit_enabled), break-glass admins, SSO-only orgs                                                                                                                                                      |
| 3.3  | JIT roles/groups + attribute sync on every SSO sign-in (SAML attributes, LDAP memberOf)                                                                                                                                                                                   |
| 3.4  | SAML SP robustness: certificate rollover (2 certs), clock skew, metadata URL import/refresh, encrypted assertions                                                                                                                                                         |
| 3.5  | Enterprise OIDC connections (validated ID token, issuer/organization restriction, claim mapping)                                                                                                                                                                          |
| 3.6  | Admin portal completes a setup (SP/SCIM URLs, domain verification, test sign-in)                                                                                                                                                                                          |
| 3.8  | SCIM tokens: several, expiring, overlap on rotation, refused for suspended orgs                                                                                                                                                                                           |
| 4.1  | Organization-aware apps: one app for many customer orgs, `organization` parameter, org_id/roles/permissions claims, per-org custom permissions                                                                                                                            |
| 4.2  | Finer permissions (user.delete/suspend/credentials, session.revoke, member.invite, organization.delete) + built-in Admin/Member/Viewer roles + rename/delete roles                                                                                                        |
| 4.4  | M2M for customers' APIs (client_credentials on machine apps with resource/scope), private_key_jwt, secret rotation with overlap                                                                                                                                           |
| 4.6  | Consent withdrawal + "connected apps" API; grants list filters/cursor                                                                                                                                                                                                     |
| 4.7  | Webhook events: user.created from every path, sign-in success/failure, MFA, invitations, roles, apps/keys                                                                                                                                                                 |
| 5.1  | Deleted organizations' data purged after a restore window (DPA)                                                                                                                                                                                                           |
| 5.2  | Region: relabel + read-only until real data residency exists                                                                                                                                                                                                              |
| 5.3  | Audit tamper evidence (no UPDATE/DELETE for the app role, signed chain anchor) + audit export with hashes                                                                                                                                                                 |
| 5.4  | Encryption key ids + rotation                                                                                                                                                                                                                                             |
| 5.7  | Admission control (overload shedding) + shard the platform audit chain lock                                                                                                                                                                                               |
| 5.8  | Metrics (sign-ins by method, queue lags) + supply chain (scan/sign the prod image, SBOM)                                                                                                                                                                                  |

## Glossary

| Term                     | Meaning                                                                                                                                                        |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RBAC, ABAC, ReBAC        | Three ways Qeet decides access: by role, by attributes of the person and the resource, and by relationships such as "Alice is a viewer of document 123".       |
| AuthZEN                  | An OpenID standard API for asking "may this subject do this action on this resource?".                                                                         |
| OIDC, OAuth              | The standards apps use to sign people in with Qeet and to get access tokens.                                                                                   |
| PKCE                     | A protection for the OAuth authorisation-code flow that stops a stolen code being used.                                                                        |
| SAML, SCIM, LDAP         | Enterprise standards for single sign-on, for creating and removing accounts from a company directory, and for talking to a directory such as Active Directory. |
| JIT provisioning         | Creating or updating a person's account and roles at the moment they sign in through SSO.                                                                      |
| SSF, CAEP                | OpenID Shared Signals: a standard way to tell apps that, for example, a session was revoked.                                                                   |
| RAG                      | Retrieval-augmented generation: an AI assistant searches documents and answers from them.                                                                      |
| MCP                      | Model Context Protocol: a standard for giving AI agents tools that live on other servers.                                                                      |
| KMS, BYOK                | A cloud key management service; "bring your own key" means the customer holds the key.                                                                         |
| SPIFFE                   | An open standard for giving workloads (services, jobs) a verifiable identity.                                                                                  |
| ML-KEM, ML-DSA, SLH-DSA  | NIST's post-quantum standards (FIPS 203, 204 and 205) for key exchange and signatures.                                                                         |
| ASVS                     | OWASP's Application Security Verification Standard, a checklist of security requirements.                                                                      |
| AAL                      | NIST's authenticator assurance levels (AAL1 to AAL3) in SP 800-63B.                                                                                            |
| RPO, RTO                 | How much data a recovery can lose, and how long it takes.                                                                                                      |
| p95, p99                 | The latency that 95% or 99% of requests stay under.                                                                                                            |
| Step-up                  | Asking a signed-in person to authenticate again before a sensitive action.                                                                                     |
| Break-glass              | Emergency admin accounts that can still sign in when SSO is required or down.                                                                                  |
| Egress policy            | The server's rules for which outside addresses it may call.                                                                                                    |
| Row-level security (RLS) | Postgres rules that keep each organization's rows separate.                                                                                                    |
| Design partner           | A customer who agrees to try an early version and give feedback.                                                                                               |
| Shadow mode              | Running a new check and recording its answer without enforcing it.                                                                                             |

## What other products already offer

This is a representative comparison, not every vendor, package or deployment.
Official pages were fetched on 2026-10-28; pricing, contractual SLAs, latency and
commercial feature availability were not benchmarked. Absence from a page is
not evidence that a vendor lacks a capability.

| Platform        | Capability documented in official sources                                                                                                                                                                                                                                               | Implication for Qeet ID                                                                                                                               |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| WorkOS          | [Pipes](https://workos.com/docs/pipes) offers token vending and relay without exposing provider tokens to caller environments; [FGA](https://workos.com/docs/fga) provides hierarchical resource-scoped authorization.                                                                  | A token vault, relay, or fine-grained authorization alone is not unique. Build on existing primitives and emphasize usable policy/evidence workflows. |
| Auth0           | [Token Vault](https://auth0.com/docs/secure/tokens/token-vault) documents user and privileged-worker exchanges; [log streams](https://auth0.com/docs/customize/log-streams) document SIEM destinations, health, retries and PII controls.                                               | Do not claim competitors lack SIEM integration or brokerage. Existing 2.10/4.7/5.3 work addresses much of this baseline.                              |
| Clerk           | [Machine authentication](https://clerk.com/docs/guides/development/machine-auth/overview) includes OAuth access tokens, M2M tokens and API keys. The fetched page distinguishes its M2M tokens from OAuth client-credentials support.                                                   | Machine identity is not unique; differentiate governance and revocation evidence, not the mere existence of keys.                                     |
| Keycloak        | [Authorization Services](https://www.keycloak.org/docs/latest/authorization_services/index.html#_policy_evaluation_tool) includes policy evaluation with identity/context inputs, configuration import/export and UMA permission workflows.                                             | Basic simulation and approval-based resource sharing already have precedents.                                                                         |
| OpenFGA         | [Immutable authorization models](https://openfga.dev/docs/getting-started/immutable-models) support explicit model IDs, shadow checks and gradual rollouts. It is an authorization engine, not a full identity-provider substitute.                                                     | Versioned models and shadow evaluation are established; combine them with Qeet's identity lifecycle and operator evidence.                            |
| ZITADEL         | [Actions](https://zitadel.com/docs/concepts/features/actions) extend identity flows with custom logic, timeouts and configurable error behavior.                                                                                                                                        | Hooks alone are not differentiated; safe change/rehearsal workflows may add value.                                                                    |
| Microsoft Entra | [Access reviews](https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview) and [PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure) include recurring reviews and time-/approval-based privileged activation. | Access reviews and just-in-time privilege are competitive capabilities, not inventions. A simpler app-facing version needs customer validation.       |

## Standards notes

- [OAuth Security BCP, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
  informs audience restriction, PKCE, refresh protection and client authentication.
  Much of that work is already in 1.5/1.15/2.8/4.4/4.10; do not open duplicates.
  DPoP itself is RFC 9449, not RFC 9700.
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
  is published guidance, not a forthcoming version. Map requirements to the
  chosen assurance/use case; possessing a passkey feature alone proves neither
  AAL3 nor whole-product conformance.
- [OWASP ASVS 5.0.0](https://asvs.owasp.org/) is the fetched stable verification
  baseline. Version requirement references and attach actual evidence; a checklist
  or clean scanner alone is not independent certification.
- [OpenID CAEP 1.0](https://openid.net/specs/openid-caep-1_0.html) defines security
  event types including session revocation and credential/claims changes, using
  SSF. It is a useful interoperability direction for F-03, not a reason to replace
  working webhooks or claim delivery automatically revokes external sessions.

## Ideas considered and not taken

The review looked at these and decided against them. Don't reopen them without new evidence.

- API-key creator-scope checks and suspended-user rejection are present in
  [the handler](../../internal/developer/apikey/apikey.go) and
  [verification query](../../internal/developer/apikey/queries.sql). These duplicate
  1.1 and 1.10; do not reopen them on the earlier reviewer's claims.
- Token-vault S256/browser binding is present in
  [connect](../../internal/developer/credentials/tokenvault/tokenvault.go) and
  [binding setup](../../internal/developer/credentials/tokenvault/tokenvault.go).
  Do not repeat 1.13 or recommend SameSite=Strict for a cross-site OAuth callback.
- A missing audience on a portable VC does not establish a replay defect.
  [VC verification](../../internal/developer/credentials/vc/vc.go) checks the issued
  credential and revocation registry. Presentation binding is a separate design.
- Agent sponsorship is documented as accountability, not an ongoing authority
  bound. Sponsor-governed lifetime is a proposal below, not a proven bypass.
- Browser-supplied AI tool results do not prove cross-user access or backend
  privilege escalation. Conversation ownership is checked and actual API calls
  remain subject to normal server authorization. Future mutating AI tools would
  require a separate server-enforced approval design.
- Exact matching to a registered logout URI does not require the additional
  domain-ownership rule proposed by a reviewer. No new logout bypass was proven.
- Speculative organization-switch/device/CIBA races were not demonstrated by the
  presented evidence; a liveness check later in a path is not a bypass by itself.
- Organization-deletion/revocation events are expected; suppressing them because an
  organization was soft-deleted would break downstream cleanup. Do not do that.
- Clearing MFA failure locks merely because an organization was reactivated
  would weaken a security control. Do not adopt that suggestion.
- Ordinary in-flight AI completion, hypothetical startup races and a 24-hour
  purge racing a ten-minute stream were not accepted as demonstrated defects.
- Keep existing deliberate auth-hook/rate-limiter failure policies unchanged.
  Existing plan items, including default audience, org limits, SSO, GDPR, billing,
  audit completeness, admission control and image provenance, remain owned by
  the original programme rather than becoming duplicate findings here.

## Review findings fixed in the first release

The review found five defects. All are fixed, with tests, in the first release's code:

| ID    | What was wrong                                                                                                         | Fix                                                                                                                         |
| ----- | ---------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| R-01  | Tool calls from OpenAI-compatible AI providers were not bounded, so a misbehaving provider could crash a conversation. | `2b722ccd`: tool calls are numbered by Qeet and capped in count and size.                                                   |
| R-02  | A live activity stream kept sending events after its reader lost access.                                               | `c40fbbc1`: the stream ends within 30 seconds of losing access, and at token expiry.                                        |
| R-03  | A retried request with the same idempotency key could run twice if the first was slow.                                 | `0c8f64f2`: an unanswered claim is never taken over; the retry gets a 409.                                                  |
| R-04  | The live activity stream could skip events when a reader reconnected or fell behind.                                   | `c40fbbc1`: replay pages through the audit log, and a reader that falls behind is told to reconnect.                        |
| AI-01 | Qeet AI conversations had no limits on history or reply size.                                                          | `f6084539`: history and replies are capped, one turn runs at a time, and production uses only the customer's own model key. |

## Sources

Official sources were retrieved on 2026-10-29. Vendor documentation establishes
publicly documented capabilities, not independently tested performance, pricing,
licensing or universal availability. Standards and protocols must be version-pinned
and rechecked before building. No customer willingness-to-pay study or exhaustive
patent/market search was performed; none of these ideas is certified unique.

- **S1:** [Microsoft Entra workload identity federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation), external-workload trust and exact issuer/subject/audience validation.
- **S2:** [SPIRE concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/) and [JWT-SVID](https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/), workload attestation, identity and audience/expiry validation.
- **S3:** [Microsoft Entra agent identities](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/what-is-agent-id), ephemeral agents and autonomous/delegated access.
- **S4:** [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html), token exchange and actor delegation; task-tree budgeting/revocation is additional application semantics.
- **S5:** [Auth0 for AI Agents](https://auth0.com/docs/get-started/auth0-for-ai-agents), document-level RAG authorization, brokerage and asynchronous authorization. These primitives are not unique to Qeet.
- **S6:** [MCP tools](https://modelcontextprotocol.io/specification/latest/server/tools), [authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization) and [security best practices](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices), dynamic catalogs, resource binding, consent and SSRF/token-passthrough controls.
- **S7:** [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html), internal/external access analysis and policy checks.
- **S8:** [AWS policy generation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html), observed usage, documented coverage limits and human customization.
- **S9:** [Entra cross-tenant access](https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview) and [B2B direct connect](https://learn.microsoft.com/en-us/entra/external-id/b2b-direct-connect-overview), inbound/outbound restrictions and mutual agreement.
- **S10:** [OIDC subject identifier types](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes), public and pairwise subject semantics.
- **S11:** [Entra emergency access](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access) and [Vault control groups](https://developer.hashicorp.com/vault/docs/enterprise/control-groups), emergency-path practice and additional approval thresholds.
- **S12:** [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), final ML-KEM/ML-DSA/SLH-DSA standards and published errata notices.
- **S13:** [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final), transition guidance; its document history lists the final publication on 2026-10-27.
- **S14:** [Cloudflare PQC](https://developers.cloudflare.com/ssl/post-quantum-cryptography/), separate key-agreement/signature migration and connection-segment support.
- **S15:** [AWS KMS hybrid TLS](https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html), compatibility and CloudTrail negotiated-group evidence with telemetry caveats.
- **S16:** [AWS KMS key specifications](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html), including managed ML-DSA signing; service support is not proof of Qeet deployment validation.

Fetched 2026-10-29 by the research tracks and selectively cross-checked in the
main review. Sources establish documented precedent, not a comparison proving
absence elsewhere, certifications, deployed Qeet behavior or pricing.

- **T1:** [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) and [Entra device-compliance policy](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance): attestation/assurance distinctions and managed-device admission with report-only rollout.
- **T2:** [OPA management](https://www.openpolicyagent.org/docs/management-introduction) and [signed bundles](https://www.openpolicyagent.org/docs/management-bundles): local evaluation/distribution precedent; signatures alone do not provide the proposed freshness guarantee.
- **T3:** [AWS KMS encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html), [cross-account access](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying-external-accounts.html), [unusable keys and data keys](https://docs.aws.amazon.com/kms/latest/developerguide/unusable-kms-keys.html), and [external key stores](https://docs.aws.amazon.com/kms/latest/developerguide/keystore-external.html): custody, authorization, cached-key and availability boundaries.
- **T4:** [Entra on-premises provisioning architecture](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/on-premises-application-provisioning-architecture): outbound agents, certificate lifecycle and availability responsibilities.
- **T5:** [Auth0 Deploy CLI](https://auth0.com/docs/deploy-monitor/deploy-cli-tool) and [Keycloak import/export](https://www.keycloak.org/server/importExport): multi-environment configuration precedent and import/consistency cautions.
- **T6:** [OIDF RP testing example](https://gitlab.com/openid/conformance-suite/-/wikis/Brazil-RP-Testing-Instructions-and-Example-Configuration) and [suite build/run guidance](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-%26-Run): simulated-server testing and operating requirements. The example is profile-specific; verify coverage before reusing it for generic OIDC.
