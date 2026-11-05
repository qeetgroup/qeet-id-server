# Qeet ID roadmap ideas after 1.0

**None of these ideas is approved.** Each is a hypothesis to test with a customer who has the problem before anything is built. The [README](README.md) explains how to choose one, the rules every idea must follow, the plan items and terms used below, and the sources (S1 to S16, T1 to T6).

Each idea starts with a plain explanation (in short, why, what exists today), followed by the detail from the October 2026 research: the first version to build, the proposed API routes, the controls, how to measure success and the dependencies. The routes are illustrative; none exists yet.

## Part 1: Building on what 1.0 already has (F-01 to F-06)

These are hypotheses about useful combinations, not claims that no competitor
offers them. Validate demand with design partners before choosing one. All new
organization APIs must derive tenant scope from the principal and enforce the
matching tenant path. New routes need OpenAPI and denial tests. Token, SAML,
SCIM, webhook or cross-repository changes need explicit design/consumer review.

### F-01: Preview a policy change before it goes live

**In short.** Let an admin see exactly who would gain or lose access before a new authorisation policy goes live, and refuse to activate it if the policy changed after the preview.

**Why we need it.** Today a policy change takes effect the moment it is saved. A small mistake in an ABAC condition or a role can lock out a whole team, or open data to the wrong people, and the admin hears about it from users.

For example, an admin tightens "finance documents need department = finance" but forgets contractors. A preview would show "12 contractors lose access" before saving.

Enterprise buyers expect this kind of change control. Keycloak and OpenFGA have policy evaluation tools; what is missing is an impact summary over many cases before activation.

**What Qeet ID has today:**

- /v1/check with an explanation, and effective permissions that say which role or group grants each one.
- ABAC evaluation accepts a draft policy and says whether the draft decided the outcome.
- ABAC policies keep every version with its author, and an old version can be restored.
- A decision log keeps 30 days of /v1/check, AuthZEN and evaluation decisions.

**Research detail.**

- **Increment:** Existing [RBAC explanations](../../internal/access/authorization/rbac/http.go)
  and ABAC/ReBAC decisions already answer individual questions. Add immutable
  candidate versions, bounded before/after scenario evaluation and an impact
  summary before activation; do not call the existing simulator a missing feature.
- **MVP:** Tenant-scoped draft/version and evaluation operations; return newly
  allowed/denied cases, explanation, input/policy version and expiry. Activation
  checks the expected version to reject stale previews. No simulation mutates grants.
- **Acceptance:** Production and simulation share decision logic; tenant isolation,
  deny precedence and unknown attributes remain identical. Approved test fixtures
  reproduce the report; a concurrent policy change invalidates stale activation.
- **Dependencies / priority:** 2.12 and 4.2; L; first post-launch candidate.
  Measure prevented accidental permission changes and operator time, not an
  unsupported claim of unique policy technology.

### F-02: Access reviews and time-limited admin access

**In short.** Let an organisation regularly review who has access (people, guests, API keys, service principals and AI agents together) and give admin rights for a limited time instead of for ever.

**Why we need it.** Access piles up. People change teams, contractors stay after their project ends, API keys outlive their purpose. ISO 27001 and SOC 2 auditors ask for periodic access reviews, and security teams want admin rights granted "for two hours, approved by someone else" rather than permanently.

Microsoft Entra offers access reviews and Privileged Identity Management. Qeet's angle is one review that covers machine and AI identities as well as people, each with a clear owner.

**What Qeet ID has today:**

- Built-in owner, admin, member and viewer roles, custom roles and finer permissions (user.delete, user.suspend, session.revoke and so on).
- Effective permissions show which role or group grants each permission.
- Each agent has an accountable sponsor, and offboarding can reassign agents to someone else.
- API keys and service principals show when they were last used.
- Break-glass members for emergencies.

**Research detail.**

- **Increment:** Review humans, guests, API keys, service principals and sponsored
  agents in one campaign, with explicit owners and revocation decisions. Add
  temporary privilege only after the finer-permission model is stable.
- **MVP:** Review snapshots and reviewer decisions; optional justification,
  step-up, distinct approver and expiry for elevation. An organization may opt
  into sponsor-transfer/expiry policy; do not silently change existing agent lifetime.
- **Acceptance:** Self-approval is refused where separation is required; expiry
  is enforced by authorization even if a cleanup job is down; temporary grants
  never bypass ABAC denies or last-owner safeguards. Export decisions and outcomes.
- **Dependencies / priority:** 1.1-1.4, 2.4, 4.2; L; post-launch/customer-led.
  Entra already provides reviews/PIM, so value must come from Qeet integration
  and operator simplicity rather than a novelty claim.

### F-03: Offboarding receipt

**In short.** When someone is offboarded, produce one record that shows every session and credential that was ended, and whether each connected app received the news and acted on it.

**Why we need it.** When an employee leaves, the security team needs proof, not hope, that every way in is closed. Qeet ID already ends sessions and credentials, but an auditor or incident responder can't see in one place what was ended, which apps were told, and which haven't confirmed.

For example, a leaver still has a session in a customer's app that never processed the webhook; today nobody can tell. Saying "done" because a webhook was queued would be misleading.

**What Qeet ID has today:**

- Suspending or deleting a person ends all their sign-ins, their access tokens are refused once the session ends, personal API keys stop, and agents they sponsor can be reassigned.
- Session signals are published internally (internal/platform/events/sessionsignal), and webhooks deliver user and session events with every attempt recorded.

**Research detail.**

- **Increment:** Extend existing
  [session signals](../../internal/platform/events/sessionsignal/sessionsignal.go)
  into a queryable operation record showing each credential/session category
  and external delivery outcome. This adds evidence to 1.10, not another
  implementation of basic revocation.
- **MVP:** A tenant-scoped offboarding operation ID with states such as local
  enforcement complete, notification pending, delivered and receiver acknowledged.
  Initially expose local evidence; add SSF/CAEP transport only as a separately
  reviewed adapter, keeping existing webhook contracts stable.
- **Acceptance:** Retry is idempotent; a failed receiver is visible; no UI/API
  says an external session ended merely because a webhook was queued. An independent
  relying-party fixture acknowledges and demonstrates refusal of the old session.
- **Dependencies / priority:** 1.10, 2.4, 2.10, 4.7 and R-02; L;
  useful post-launch design-partner pilot. Differentiation hypothesis: verifiable
  offboarding outcomes across human and machine identities.

### F-04: Rehearse a federation change before it affects people

**In short.** Before an admin changes a SAML or OIDC connection or its attribute and group mappings, show what the change would do (who gets which roles, which certificates expire, what breaks) without touching real accounts.

**Why we need it.** Federation changes are a common cause of outages. An identity provider's certificate rolls over, an attribute is renamed or a group mapping is removed, and suddenly nobody can sign in, or someone becomes admin by accident. Admins usually find out on Monday morning.

For example, removing the group mapping that gave the only two admins their role would warn: "this removes admin from everyone, and break-glass access is lost".

**What Qeet ID has today:**

- SAML connections have an offline preflight check (metadata and certificates, no network) in the admin API and the admin portal.
- The admin portal can run a test sign-in against a SAML connection.
- Directory mappings have a preview, and directory events record each failure with its reason.
- Two certificates during rollover, encrypted assertions, and just-in-time roles and groups.

**Research detail.**

- **Increment:** The [directory subsystem](../../internal/federation/directory/directory.go)
  already has activity/error/mapping primitives, and phase 3 adds setup and
  certificate support. Add a preflight report for a proposed connection or
  mapping change before it affects users.
- **MVP:** Validate metadata/certificate dates/domain binding against staged
  configuration and sanitized fixtures; preview JIT/group-mapping effects and
  warn about privilege expansion, unlinked admin adoption or break-glass loss.
  Never mutate production identities during a diagnostic run.
- **Acceptance:** Deterministic fixtures cover rollover, missing attributes and
  mapping removal. Outbound probes use the existing egress policy and redact
  assertions/credentials. SCIM here is inbound provisioning: do not assume Qeet
  can poll arbitrary customer IdP directories to certify sync health.
- **Dependencies / priority:** 3.1, 3.3-3.6, 3.8; L; a read-only pilot after
  federation integration. Measure setup/support time with actual customers.

### F-05: Agent actions through a credential broker, with approvals

**In short.** Let an AI agent call an outside service (for example create a Jira issue or read a Google Drive file) through Qeet, within strict limits and with optional human approval, without the agent ever holding the person's credential.

**Why we need it.** Companies want AI agents to act for people. Handing an agent a raw OAuth token means it can do anything that token allows, for as long as it lasts, and nobody sees what it did. A broker keeps the credential inside Qeet, checks each action against limits (which service, method and resource, how many times, until when), asks a person when needed, and records the decision.

For example: "the travel agent may read my calendar and create at most three draft events this week", and it can't send email even if the token would allow it.

WorkOS Pipes and Auth0 Token Vault offer similar relays; Qeet's value would be per-action limits, approvals and evidence.

**What Qeet ID has today:**

- Agents with sponsors, pause and resume, secret rotation and a kill switch.
- A token vault where people connect third-party accounts, bound to their browser.
- Scoped delegation, and token exchange that can't widen scopes.

**Research detail.**

- **Increment:** Build on agents, the token vault, scoped delegation and kill
  switches. The product already intends a brokered-call path; the added value
  would be action-specific constraints, approvals and evidence, not inventing relay.
- **MVP:** A limited provider/action catalog with approved destinations and
  methods, explicit resource/action bounds, usage budget, expiry and optional
  human approval bound to the exact normalized operation. Return the provider's
  result, never its raw credential to an agent. Start read-only.
- **Acceptance:** Scope/resource widening, stale approval, replay, revoked consent,
  suspended agent and unexpected redirects are denied. Changing the operation
  invalidates approval. Caller identity and decision receipt are audited without
  secrets; no model output itself grants authority.
- **Dependencies / priority:** 1.5, 1.15, 4.4, 4.6 and relevant proof-of-possession
  decisions; L; later opt-in pilot. WorkOS Relay/Auth0 Token Vault already provide
  related mechanics, and token/claim changes require consumer coordination.

### F-06: Evidence pack for a release and an organisation's controls

**In short.** A downloadable, signed package that shows auditors which version of Qeet ID ran, how it was configured, and which controls were actually tested and passed, not just switched on.

**Why we need it.** Enterprise customers go through audits (SOC 2, ISO 27001) and vendor reviews, and they ask us for evidence: which version was running, whether MFA was enforced, when the last restore drill was, whether offboarding really revoked access. Today that means screenshots and emails.

A setting being on is not proof that the control worked, so the package must show real test results and clearly mark anything missing or failed.

**What Qeet ID has today:**

- The audit log is a tamper-evident hash chain with a signed anchor, and can be exported with hashes.
- Metrics, and a release image that is scanned and signed, with a software bill of materials.

**Research detail.**

- **Increment:** Extend 5.3's signed audit export with an evidence manifest that
  links the software revision, configuration digest, policy version, actual test
  results, restore-drill timestamp and revocation outcomes. Do not duplicate the
  audit exporter or equate an enabled setting with evidence that a control worked.
- **MVP:** Downloadable, tenant-redacted manifest plus verification instructions;
  operational evidence stays operator-only unless explicitly safe to disclose.
  Missing, expired and failed checks remain distinguishable from passed checks.
- **Acceptance:** Tampering is detectable; missing artifacts prevent a passed
  status; no secret/PII or another tenant's evidence is included. An independent
  verifier can check the package without trusting the console's rendering.
- **Dependencies / priority:** 2.4, 5.3, 5.8 and executed release drills; L;
  post-launch. This is evidence packaging, not SOC 2/ISO/NIST certification.

## Part 2: New capabilities for AI, machines and enterprises (N-01 to N-09)

**Product recommendation.** Build a recognizable strength around explaining and
controlling what human, workload and AI identities can do, then proving that
the restrictions were applied. Do not try to win by accumulating protocols or
putting "AI" and "quantum" in feature names. Market leadership and uniqueness
cannot be established by this research; adoption, trust, reliability, integration
effort, support and distribution must also be demonstrated.

My first differentiation experiment is **N-03, permission-aware AI retrieval
with provenance and safe reuse**, for a customer that actually deploys RAG.
**N-01, secretless workload federation**, is a strong enterprise adoption feature,
not a unique invention. **PQ-01, cryptographic exposure planning**, is the most
practical quantum-related starting point. For customers without AI retrieval,
choose **N-05, exposure analysis**, instead of manufacturing an AI use case.

The December 1.0 fixes and G-01-G-07 still come first. None of the following
automatically becomes a release blocker, a current bug, an implementation task,
or a replacement for F-01-F-06. Each is a hypothesis to validate with a buyer.

| ID | Proposed capability | Customer problem | Increment beyond earlier proposals | Investment position |
| --- | --- | --- | --- | --- |
| N-01 | Secretless workload federation | CI jobs and services retain long-lived secrets | External workload proof into existing machine identities; not another M2M grant | Adoption pilot |
| N-02 | Task-scoped agent identity and shared budgets | Parallel agents multiply authority and spend | Execution-tree lifecycle and conserved reservations above F-05 operations | AI customer-led |
| N-03 | Authorized retrieval, provenance and safe answer reuse | AI receives or reuses data after access changes | Data-input enforcement and lineage, not F-01 simulation or F-06 release evidence | First differentiation experiment |
| N-04 | MCP integration revision trust | An approved tool integration changes underneath an operator | Server/tool identity and revision pinning, not basic discovery/DCR | After an enforcing adapter exists |
| N-05 | Identity exposure analysis | Operators cannot explain what a compromised identity could reach | Current cross-subsystem exposure, not proposed-policy comparison | Alternative first pilot |
| N-06 | Evidence-based least-privilege recommendations | Permissions grow, but safe reductions are unclear | Usage evidence feeding F-01/F-02, not another approval engine | After trustworthy observations |
| N-07 | Bilateral partner-organization trust | Suppliers and customers need mutual control of collaboration | Versioned two-party agreement above 4.1 memberships/apps | Two-customer discovery |
| N-08 | Application disclosure contracts | Clients receive unnecessary identity data or correlatable identifiers | Per-client claim release and optional pairwise subjects | Privacy-led design partner |
| N-09 | Recovery resilience and quorum controls | IdP outages or helpdesk mistakes cause lockout/takeover | Recovery readiness and constrained recovery authorization, beyond JIT access | Read-only readiness first |
| PQ-01 | Cryptographic asset and exposure planning | Enterprises do not know what to migrate or why | PQ exposure horizons and consumer dependencies beyond 5.4 key rotation | Read-only starting point |
| PQ-02 | Negotiated transport evidence | A PQ setting is mistaken for actual protected traffic | Per-hop negotiated evidence, not a global badge | Authorized staging experiment |
| PQ-03 | Long-lived artifact signature pilot | Audit evidence must remain verifiable for years | PQ verification profile extending 5.3/F-06, not JWT replacement | Later interoperability research |

The "starting slice" below assumes one or two two-week sprints with a backend
engineer, security review and a cooperating integration owner. It is a bounded
prototype/discovery estimate, not a promise of production completion. Cross-repo
SDK, console, application, deploy and kit effort must be estimated separately.

### N-01: Sign in CI jobs and workloads without stored secrets

**In short.** Let a CI job (for example GitHub Actions) or a Kubernetes workload get a short-lived Qeet token by proving who it is with its platform's own identity token, so no long-lived Qeet secret is stored in it.

**Why we need it.** Today a customer's CI pipeline or backend service signs in to Qeet with a service-principal secret or API key that someone copied into the CI settings. Those secrets leak through logs, forks and former employees, and rotating them without breaking deployments is painful.

GitHub Actions, GitLab, Kubernetes and the cloud platforms already issue a signed token that says "this is repository X, branch main, environment production". Qeet can trust that token under exact rules and issue a short-lived Qeet token in exchange.

Microsoft Entra (workload identity federation) and SPIFFE already do this. Enterprises expect it; it is an adoption feature rather than something unique.

**What Qeet ID has today:**

- Service principals with client secrets, rotation with an overlap, and last use.
- OAuth client credentials for machine apps, private_key_jwt, and token exchange.

**Research detail.**

**Problem and buyer.** Platform teams copy credentials into CI, Kubernetes and
background workers, then must rotate them without outages. Let an approved
external workload prove its identity and obtain bounded Qeet authority without
storing a long-lived Qeet secret.

**Proposed APIs:**
```text
POST   /v1/tenants/{tenantID}/workload-trusts
POST   /v1/tenants/{tenantID}/workload-trusts/{trustID}/evaluations
DELETE /v1/tenants/{tenantID}/workload-trusts/{trustID}
```
Evaluations preview a match without minting credentials. Actual issuance would
use a separately reviewed federated-assertion authentication method on the
existing OAuth token surface, not a tenant-selecting unauthenticated CRUD API.

**Starting slice and controls.** Support one CI OIDC issuer, exact issuer/audience/
subject and repository/environment restrictions, one mapped principal and a
short-lived token no longer valid than its source assertion. Derive the token's
tenant from the authenticated stored mapping, not an external tenant claim.
Use a separate external verifier rather than relaxing the normal Qeet JWT verifier.
Test key rollover, replay policy, disabled trust, wrong audience, protected-branch
selectors, malicious discovery URLs and cross-tenant targets. Removing a trust
stops new issuance; document how already-issued credentials become ineffective.

**Measure.** All jobs in the bounded pilot authenticate without a stored Qeet
secret, with a measured issuance/revocation SLO. "Secretless" does not eliminate
signing keys, bootstrap trust or workload compromise.

**Foundation/dependencies.** Extend [service principals](../../internal/developer/principal/principal.go)
and [token exchange](../../internal/federation/oidc/token.go), after 4.4 and its contract
decisions. CI/SDK changes are required; SPIFFE/SPIRE support is a later adapter,
not something to emulate with generic issuer matching. Entra workload federation
and SPIFFE are established precedents [S1, S2].

### N-02: Task-scoped agent identity with shared budgets

**In short.** Give each AI agent run (a "task") its own short-lived identity and a shared allowance, so one workflow can be cancelled on its own and child workers can't multiply the agent's budget.

**Why we need it.** An AI agent often splits work into sub-tasks run by child workers. If each child gets the agent's full permissions and full budget (say 10 API calls or Rs 500 of spend), ten children get ten times the allowance.

When one workflow goes wrong, the only lever today is pausing the whole agent, which stops all its other work too. For example, a support agent is handling 50 tickets and one ticket's workflow loops: we want to cancel just that task.

**What Qeet ID has today:**

- Agents with sponsors, pause, resume and resume-all, and delegation with actor claims.
- Qeet AI conversations have bounded history, and one turn runs at a time per conversation.

**Research detail.**

**Problem and buyer.** AI platform teams need to cancel one workflow without
disabling an entire agent, and prevent ten child workers from each receiving
the same ten-call or monetary allowance.

**Proposed APIs:**
```text
POST /v1/tenants/{tenantID}/agent-tasks
POST /v1/tenants/{tenantID}/agent-tasks/{taskID}/children
POST /v1/tenants/{tenantID}/agent-tasks/{taskID}/cancellations
GET  /v1/tenants/{tenantID}/agent-tasks/{taskID}/usage
```
A task records purpose, expiry, allowed resources/actions, root/parent identity
and a shared reservation ledger. A child inherits at most the intersection of
its ancestors' and current caller's authority. Task handles are bound to an
authenticated actor; knowing a handle never gives access.

**Starting slice and controls.** One root/child execution tree and one mediated
read operation, initially using opaque server records rather than new JWT claims.
Make reservation, settlement and cancellation idempotent and atomic. Ambiguous
external outcomes remain reserved until reconciled; blind refunds can enable
overspending. Expired/revoked tasks deny further checked operations. Keep depth
and fan-out bounded; do not infer revocation semantics from historical `act` claims.

**Measure.** In a fake-provider concurrency test, 100 sibling attempts against
a root allowance of ten admit at most ten; every mediated operation has one
traceable root. Verify renewal/child creation cannot reset the root allowance.
This controls integrated execution paths, not arbitrary calls made outside them.

**Foundation/dependencies.** [Agent lifecycle](../../internal/developer/agents/agent.go),
existing delegation, AI-01 and F-05's broker/enforcement boundary. The increment
is a conserved execution-tree budget, not another broker or sponsor policy.
Runtime/SDK propagation is required. Entra Agent ID already documents ephemeral
agents, and RFC 8693 already provides delegation concepts [S3, S4].

### N-03: Permission-aware AI retrieval with source records

**In short.** When an AI assistant searches a company's documents to answer a question (retrieval-augmented generation, RAG), let Qeet decide which documents that person may see before any text reaches the model, and keep a record of the sources used.

**Why we need it.** Companies are putting their wikis, drives and tickets behind AI assistants. The biggest risk is the assistant quoting a document the person isn't allowed to read, such as a salary sheet or an HR case, or serving a cached answer after someone's access was removed. Many RAG setups filter after the fact, or not at all.

Qeet already knows who can access what, so it can check each candidate document first and record the evidence. For example, an employee asks "what is our bonus policy?": the draft board memo is filtered out because they aren't in the board group, and the record lists exactly which documents the answer used.

Auth0 documents permission-aware RAG. Our difference would be the source records, plus safe reuse of cached answers.

**What Qeet ID has today:**

- AuthZEN evaluation and the combined decision over RBAC, ABAC and ReBAC, with explanations.
- ReBAC relationships, for example "document 123 has viewer Alice".
- A 30-day decision log.
- Qeet AI with the customer's own model keys and bounded history.

**Research detail.**

**Problem and buyer.** Enterprise AI teams need to know which permitted source
material reached an answer, and prevent documents or cached answers from being
served after the user's access changes.

**Proposed APIs:**
```text
POST /v1/tenants/{tenantID}/ai/data-sources
POST /v1/tenants/{tenantID}/ai/retrieval-authorizations
GET  /v1/tenants/{tenantID}/ai/retrievals/{retrievalID}/provenance
```
Keep content storage/vector search in the application or a scoped connector;
Qeet supplies authorization and evidence, not a new general-purpose vector database.
A trusted adapter supplies resource/chunk identities, content digests and ACL
revisions. Qeet resolves the subject from authentication or validated delegation,
evaluates candidates, and records the material actually admitted by that adapter.

**Starting slice and controls.** One read-only source and one retrieval adapter.
Filter before text enters the model, not after an answer is generated. Bind
decisions to source, identity, policy/ACL version and expiry. Reject stale or
unknown ACL state under a defined freshness policy. Revalidate cached-answer
dependencies for each recipient; never share cache entries solely by prompt text.
Treat embeddings, provenance and conversation history as sensitive data too.
Fabricated model citations must not create trusted provenance records.

**Measure.** Unauthorized canary chunks never reach a fake model; every admitted
chunk has connector-verified lineage; revoked, deleted and cross-tenant fixtures
are denied; p95 added authorization latency is measured against a partner-agreed
budget. A receipt proves what the integration supplied, not that an answer is
correct. Revocation cannot recall information already disclosed to a provider.

**Foundation/dependencies.** [AuthZEN](../../internal/access/authorization/authzen/authzen.go),
the composed decider, audit, AI-01, data-source identity/ACL synchronization and
SDK enforcement. Auth0 already documents document-level RAG authorization [S5].
The differentiating hypothesis is source lineage plus permission-aware reuse
and clear freshness limits, not the invention of permission-aware RAG.

### N-04: Pin approved MCP tool servers to a reviewed revision

**In short.** When an organisation approves an MCP tool server for its AI agents, record exactly what was approved, and stop agents from using it if its tools change until someone reviews the change.

**Why we need it.** MCP (Model Context Protocol) servers give AI agents tools such as "search tickets" or "send email". An admin approves a server after reading its tool list. Later the server's descriptions, input schemas, issuer or destination can change without anyone noticing, on purpose ("tool poisoning") or by accident, and agents start using tools nobody approved.

For example, a "read calendar" tool quietly gains a "send invites" parameter. Pinning the approval to a revision catches that.

**What Qeet ID has today:**

- Qeet AI has a tool catalogue (api/qeetai/tools.manifest.json) and a tool loader.
- Outbound calls go through the egress policy.
- Dynamic client registration for MCP clients and agents, and OAuth metadata.

**Research detail.**

**Problem and buyer.** Enterprise platform teams approve a tool server, then its
descriptions, schemas, issuer or destination change. Operators need to know what
was approved and stop unreviewed changes from reaching an agent.

**Proposed APIs:**
```text
POST /v1/tenants/{tenantID}/mcp/servers
POST /v1/tenants/{tenantID}/mcp/servers/{serverID}/revisions
POST /v1/tenants/{tenantID}/mcp/servers/{serverID}/revisions/{revisionID}/approvals
```
Capture revisions server-side with verified origin, resource/audience, issuer,
tool names, descriptions and schemas. Bind approval to the complete digest and
server identity; namespace tool identities rather than trusting display names.

**Starting slice and controls.** Curated remote HTTPS servers and one enforcing
dispatch adapter; no downloading/executing arbitrary local MCP binaries. Handle
authorization-dependent tool catalogs per relevant profile, not as one universal
list. Bound schema complexity/remote references, apply egress policy to discovery
and redirects, and require correct audience and per-client consent. Do not pass
upstream tokens through to unrelated downstream services.

**Measure.** All unapproved description/schema/identity-change fixtures stop before
dispatch; a different server cannot reuse a same-named tool's approval; safe
approved controls continue working. Measure detection-to-quarantine delay.
Unchanged metadata does not prove unchanged server behavior and this does not
eliminate prompt injection. Clients must actually use the enforcing adapter.

**Foundation/dependencies.** [Tool catalog](../../api/qeetai/tools.manifest.json),
[tool loader](../../internal/operations/qeetai/tools.go), egress policy and existing
MCP/OAuth metadata work. This is revision trust, not a duplicate DCR/discovery
feature. Pin a supported MCP specification version and follow its security model
[S6]; the specification is not a product guarantee.

### N-05: What could this account reach if it were compromised?

**In short.** Given a person, API key or service principal, show every sensitive thing it could do in Qeet and through which grants, so incident responders can judge the damage of a compromise in minutes.

**Why we need it.** When an account or key is stolen, the first question is "what can the attacker do with it?" Today an admin pieces that together from role lists, group memberships, ABAC policies and ReBAC relationships, which is slow and error-prone in the first hour of an incident.

For example: "Alice's laptop was stolen. Can her sessions delete people or read SAML secrets?" The answer would be "yes: group IT-Admins, then role admin, then user.delete".

AWS IAM Access Analyzer does this for cloud permissions.

**What Qeet ID has today:**

- Effective permissions, with the role or group that grants each one.
- ReBAC graph expansion and the User 360 view.
- /v1/check with explanations.

**Research detail.**

**Problem and buyer.** Incident responders ask, "If this account or credential
is compromised, which sensitive operations could it perform, and through which
grants?" Separate role lists cannot reliably answer that question.

**Proposed APIs:**
```text
POST /v1/tenants/{tenantID}/exposure-analyses
GET  /v1/tenants/{tenantID}/exposure-analyses/{analysisID}
```
Return bounded access paths with evidence, captured context, configuration
fingerprint, freshness and explicit conditional/unknown/truncated coverage.
Analyze current permissions; F-01 remains the home for proposed-change simulation.

**Starting slice and controls.** Three sensitive operations, human direct/group
grants and one machine credential type. Reuse actual route and domain decision
semantics; do not equate role possession, sponsorship or a relationship edge
with proven usable access. Credential possession and session conditions must be
stated assumptions. No raw secrets, cross-tenant graph expansion or automatic repair.

**Measure.** Every asserted path agrees with the relevant evaluator for its
captured context. A design partner can answer three incident-impact questions
in under ten minutes and identify a genuinely actionable exposure. Those are
pilot targets, not current product performance claims.

**Foundation/dependencies.** [ReBAC graph expansion](../../internal/access/authorization/rebac/rebac.go),
[User 360](../../internal/identity/users/user360.go), stable finer permissions/ABAC and
resource classifications. External cloud/SaaS reachability requires explicit
connectors and is outside the first slice. AWS Access Analyzer already documents
access paths and internal/external exposure analysis [S7].

### N-06: Least-privilege suggestions from real usage

**In short.** Suggest permissions that could safely be removed, based on what each role, person or key actually used over a period, with the evidence shown and a person deciding.

**Why we need it.** Roles grow over time, and nobody dares remove anything in case it breaks something. Access reviews (F-02) ask reviewers to decide, but they have no data to decide with. Usage evidence helps: "members of this role haven't used billing.write in 90 days".

It must respect emergency and seasonal access (year-end finance, break-glass) and never remove access just because it wasn't used. AWS generates policies from CloudTrail usage in a similar way.

**What Qeet ID has today:**

- The audit log, a 30-day decision log, and last use for API keys and service principals.
- Effective permissions with where each grant comes from.

**Research detail.**

**Problem and buyer.** IAM owners see permissions accumulate but cannot safely
distinguish unnecessary access from emergency or seasonal business requirements.

**Proposed APIs:**
```text
POST /v1/tenants/{tenantID}/access-observations
POST /v1/tenants/{tenantID}/least-privilege-analyses
GET  /v1/tenants/{tenantID}/least-privilege-analyses/{analysisID}
```
Recommendations include observation windows, collector coverage, grant provenance,
business exceptions and evidence. Authenticate collectors and bind their app and
tenant server-side. Separate simulated checks, allowed attempts and completed
operations; sign-in history alone is insufficient.

**Starting slice and controls.** One participating application, one custom role,
deterministic recommendations and manual review. Missing observations produce
"insufficient evidence," not "safe to remove." Do not revoke access based solely
on an LLM or inactivity. Approved changes flow through F-01/F-02 and revalidate
current grants instead of introducing a competing grant-mutation API.

**Measure.** Reviewers find a proposed 80% of a small pilot sample relevant, with
no removal of declared emergency/seasonal requirements. Report coverage and the
time saved, not merely a count of suggested permission removals.

**Foundation/dependencies.** Authorization/audit observations, 2.4/2.11, 4.2/4.4,
N-05 where useful, SDK collectors and retained evidence. AWS policy generation
from CloudTrail is a documented precedent with coverage limits and human review
[S8]. This is advisory optimization, not autonomous authorization.

### N-07: Two-way trust between partner organisations

**In short.** Let two Qeet organisations, for example a manufacturer and its supplier, agree a versioned, two-sided arrangement for which of one's people may use which of the other's apps; either side can end it.

**Why we need it.** B2B collaboration today means inviting partner staff one by one as guests. The inviting side controls everything, and the partner can't see or limit what its own staff can reach.

Suppliers, franchises and joint ventures need both sides in control: the supplier decides which of its employees take part, and the manufacturer decides which apps they may use and under what MFA rules. Microsoft Entra has cross-tenant access settings for this.

**What Qeet ID has today:**

- Invitations and guest membership: a person whose home is one organisation can be a member of another through a role.
- Apps that serve many customer organisations, and the finer permissions.

**Research detail.**

**Problem and buyer.** Suppliers, franchises and joint ventures need both
organizations to control collaboration. An invitation grants local membership;
it does not express a continuing two-party access agreement.

**Proposed APIs:**
```text
POST /v1/tenants/{tenantID}/partner-trust-offers
POST /v1/tenants/{tenantID}/partner-trust-acceptances
POST /v1/tenants/{tenantID}/partner-trusts/{trustID}/revocations
```
Each administrator acts only within their authenticated tenant. The server
links the two sides through an intended-recipient-bound offer. Both approve the
same version, applications, populations, assurance conditions and expiry.
The effective permission is the intersection of both sides' restrictions and
the resource organization's normal authorization; trust never merges tenant data.

**Starting slice and controls.** Two Qeet organizations and one application, with
offer/accept/revoke and no automatic provisioning. Unilateral approval grants
nothing; changed terms invalidate prior acceptance; either side can terminate
future online evaluations. Do not import partner admin roles or blindly trust
MFA claims. Define existing token/session revocation separately using F-03.

**Measure.** Compare verified onboarding steps and elapsed time with two partners'
current process; all unilateral, stale and foreign-tenant approval tests deny.

**Foundation/dependencies.** [Invitations](../../internal/identity/invitations/invite.go),
tenant membership, 4.1/4.2 and client/SDK/login integration. Entra already documents
cross-tenant policies and mutual B2B direct-connect agreements [S9]. Qeet's
opportunity is an application-facing agreement workflow, not ambient cross-tenant
authority or inventing bilateral trust.

### N-08: Per-app disclosure rules and pairwise subject IDs

**In short.** Let an organisation control exactly which personal attributes each app receives, and optionally give each app a different user ID, so apps can't link a person across services.

**Why we need it.** Today an app that asks for the profile and email scopes gets those attributes, and every app sees the same user ID (the sub claim). Privacy-sensitive customers in health, finance and the public sector want each app to get only what it needs, and want to stop two unrelated apps matching their records by user ID.

OpenID Connect already defines "pairwise" subject IDs for this. It needs careful design so that ID tokens, UserInfo, introspection and refresh never leak the shared ID.

**What Qeet ID has today:**

- OIDC discovery advertises the public subject type, and UserInfo filters by scope.
- Apps get the identifier and attributes they asked for.
- Consent and connected-apps management.

**Research detail.**

**Problem and buyer.** Privacy-sensitive applications need only a subset of a
person's attributes and should not receive unnecessary cross-application
identifiers. Give application owners a predictable, testable disclosure contract.

**Proposed APIs:**
```text
POST /v1/tenants/{tenantID}/claim-release-policies
POST /v1/tenants/{tenantID}/claim-release-evaluations
```
Associate a policy with a verified client registration. Evaluations report claim
names, reasons and required consent without unnecessarily returning values.
Consider pairwise subjects only for explicitly opted-in new clients, preserving
all existing clients' identifiers and contracts.

**Starting slice and controls.** Map every disclosure surface, then prototype
two sandbox clients in distinct sectors. A pairwise ID-token `sub` alone is not
unlinkability if UserInfo, introspection or another claim reveals the shared ID.
Keep sector mappings stable; test ID token, UserInfo, refresh and logout consistency.
Consent/release policy can narrow claims but must not change internal tenant scope
or let an unrelated client reuse another sector's subject.

**Measure.** Remove unnecessary personal fields while preserving the agreed
application journey; demonstrate stable same-sector and distinct cross-sector
subjects with no accidental disclosure through alternate endpoints.

**Foundation/dependencies.** Current [public-subject discovery](../../internal/federation/oidc/discovery.go),
[scope-filtered UserInfo](../../internal/federation/oidc/userinfo.go), 4.1/4.6,
durable mappings and SDK/relying-party migration design. OIDC already defines
pairwise subject identifiers [S10]. Treat this as a contract/security review,
not permission to change today's JWT claims. Selective-disclosure credentials
are a later separate profile, not a new name for the current JWT-VC format.

### N-09: Recovery readiness and quorum-approved recovery

**In short.** Show an organisation whether it could recover if its identity provider or admin devices failed, let it rehearse that, and later let account recovery require two of three trusted people to approve.

**Why we need it.** Two failures hurt enterprises. One is lockout: the SSO provider is down, or the only admin lost their passkey. The other is takeover: an attacker talks one helpdesk operator into resetting an owner's account. Most organisations don't know which recovery paths actually work until they need one.

A readiness report and drills make that visible, and quorum approval means one person is never enough. For example: "identity provider outage: break-glass admin Priya can sign in with a passkey; the second custodian has no factor enrolled, so you are not ready".

**What Qeet ID has today:**

- Break-glass members who can still sign in when SSO is required.
- MFA recovery codes, step-up, and account recovery sent only to the stored address.

**Research detail.**

**Problem and buyer.** IT/security teams need a usable recovery route during an
IdP or device outage without allowing one helpdesk operator to take over an owner.

**Proposed APIs:**
```text
GET  /v1/tenants/{tenantID}/recovery-readiness
POST /v1/tenants/{tenantID}/recovery-drills
POST /v1/tenants/{tenantID}/recovery-cases
POST /v1/tenants/{tenantID}/recovery-cases/{caseID}/approvals
```
The first slice exposes readiness and simulated drills only; it cannot reset
credentials. Live recovery cases require a separately approved assurance design.

**Starting slice and controls.** Identify pre-enrolled custodians with independent
authentication, then rehearse IdP outage and one absent custodian. Model a two-of-
three approval bound to the exact account/action, policy version, expiry and
one-time challenge. Duplicate, self, stale and foreign-tenant approvals fail.
Quorum adds authorization, not identity proof. Preserve home-account authority,
admin hierarchy, MFA locks and suspension; no guest-admin account takeover and
no unauthenticated tenant-selection fallback. If no valid custodian remains,
escalate under an approved recovery procedure, not a bypass.

**Measure.** Demonstrably usable independent recovery paths and time to a valid
recovery decision, against a customer-agreed objective. Distinguish a configured
backup factor from a successfully exercised recovery path.

**Foundation/dependencies.** Existing break-glass/recovery/step-up mechanisms,
1.8-1.10, 3.1, notifications and customer runbooks. Entra emergency-access guidance
and Vault control groups are precedents [S11]. A quorum policy must cover applicable
old recovery paths too; adding a new endpoint alone cannot make recovery safer.

## Part 3: More enterprise options (N-10 to N-15)

| ID | Candidate | Relationship to previous work | Who must need it |
| --- | --- | --- | --- |
| N-10 | Enterprise authenticator and device assurance | New verified-assurance input; not MFA, browser familiarity or N-09 recovery | Enterprise IAM and endpoint-security teams |
| N-11 | Bounded-freshness distributed authorization | New runtime distribution; not F-01 preview/versioning | Application teams with measured authorization latency/connectivity pain |
| N-12 | Tenant/customer-controlled encryption keys | Expands the customer-key item in the discovery queue; not 5.4 rotation or AI BYOK | A buyer with an explicit key-custody procurement requirement |
| N-13 | Outbound-only private enterprise connector | Expands the private-connectivity discovery item; not data residency | Hybrid enterprises with private directories/applications |
| N-14 | Approved configuration promotion and drift | Expands the environment-promotion discovery item under F-01 | Teams repeatedly configuring multiple environments |
| N-15 | Customer relying-party integration diagnostics | New customer test workflow; distinct from F-04 incoming-IdP checks and G-02 release tests | Developers integrating customer apps and SDKs |

**Investment recommendation:** among this added set, test demand for N-15 or
N-14 first. Prefer existing tools and better examples if they solve the support
problem. N-12/N-13 need a committed enterprise buyer and an operating model;
N-10 starts in shadow mode; N-11 requires architecture approval before any real
enforcement moves. These options do not displace N-03/N-05's earlier recommended
pilots unless customer evidence changes the priority. Do not start six new teams.

All APIs below are proposed, not implemented. The rules for every idea in the README apply:
principal-derived tenant scope, matching paths, explicit permissions, tenant
predicates/RLS, bounded work, audit, retention, OpenAPI and denial tests. Runtime
delivery credentials must not inherit tenant-administration privileges. Existing
JWT/federation/webhook contracts and other repositories require separate approval.
Sprint slices are prototypes or discovery, not production delivery promises.

### N-10: Authenticator and device assurance

**In short.** Let an organisation require that sensitive apps are used only with an approved authenticator (a specific passkey model) on a compliant, company-managed device, checked with verifiable evidence.

**Why we need it.** A passkey proves the person, not the device: a valid passkey on a personal, unpatched laptop still passes. Regulated enterprises want rules such as "only YubiKeys on company laptops that pass our device-management check" for finance or admin apps.

That needs two kinds of evidence Qeet doesn't use yet: passkey attestation (which authenticator model it is) and device posture from the company's device-management tool, such as Intune or Jamf.

**What Qeet ID has today:**

- Passkeys store the authenticator's model ID (AAGUID) and backup flags.
- Trusted devices (remembered browsers) and risk signals, which serve other purposes.

**Research detail.**

**Problem.** An enterprise wants an approved authenticator and a compliant
workstation for a sensitive application. A valid passkey, MFA flag or remembered
browser does not prove all three. Keep authenticator provenance, device posture
and authentication assurance as separate evidence types.

**Proposed APIs:**
```text
GET  /v1/tenants/{tenantID}/device-assurance/policy
PUT  /v1/tenants/{tenantID}/device-assurance/policy
POST /v1/tenants/{tenantID}/device-assurance/providers
GET  /v1/tenants/{tenantID}/device-assurance/assessments/{assessmentID}
```
The [passkey implementation](../../internal/access/passkeys/passkey.go) already retains
credential/AAGUID and backup information; [trusted devices](../../internal/access/authentication/trusteddevice.go)
and [risk signals](../../internal/access/threat/risk/risk.go) serve other purposes.
Add trusted attestation assessment and separately authenticated posture-provider
observations, not an administrator-writable `compliant: true` field.

**Pilot and enforcement.** One opted-in tenant, supported attestation format and
one posture-provider integration, initially shadow-only. Validate attestation
chains/metadata and cryptographically bind posture evidence to the current
endpoint/session, not a supplied device ID. Bind observations to tenant, user,
application, credential/device key, source time and evidence version. Define
freshness, replay and revocation behavior; stale evidence cannot renew its own
lease. Required-but-unknown assurance must not silently pass.

**Acceptance.** Forged, stale, revoked, replayed, wrong-device and cross-tenant
evidence never passes the pilot fixtures. Nonparticipating consumer enrollment
remains unchanged. Measure supported-fleet coverage, unknown/error rates and
user friction; a proposed target is explainable results for 95% of the explicitly
supported pilot fleet, not all devices. No threshold was measured here.

**Limits and ownership.** Attestation is not device compliance; a roaming key
does not attest the workstation, and `backupEligible=false` does not prove AAL3.
This is not an MDM replacement or blanket attestation mandate. Access/security,
hosted-login/SDK and customer endpoint owners must address device proof, privacy,
metadata maintenance and provider costs. Start with two discovery/pilot sprints;
live enforcement requires separate review. NIST and Entra provide precedents [T1].

### N-11: Authorisation decisions close to customer services

**In short.** Let a customer's service make Qeet authorisation decisions locally, from a signed, short-lived snapshot of policies and data, instead of calling Qeet for every check.

**Why we need it.** Some customer services make thousands of checks per request, or run where the network is slow or unreliable. A central call per check adds latency and a dependency. Tools like OPA distribute signed policy bundles for local evaluation.

The hard part is freshness: a local copy can't see a revocation until it refreshes, so the rules must bound how stale it may be and fall back to an online check.

**What Qeet ID has today:**

- /v1/check, AuthZEN evaluation, and the combined decision over RBAC, ABAC and ReBAC.

**Research detail.**

**Problem.** Customer applications may need authorization close to their services
when measured network latency or partitions make central checks impractical.
This is not permission to move Qeet management enforcement out of the server.

**Proposed management and separately scoped runtime APIs:**
```text
POST /v1/tenants/{tenantID}/authorization/evaluators
PUT  /v1/tenants/{tenantID}/authorization/evaluators/{evaluatorID}/distribution
POST /v1/tenants/{tenantID}/authorization/evaluators/{evaluatorID}/revocations
GET  /v1/tenants/{tenantID}/authorization/evaluators/{evaluatorID}/bundles/current
POST /v1/tenants/{tenantID}/authorization/evaluators/{evaluatorID}/leases
```
Reuse [the composed decision semantics](../../internal/access/authorization/decide/decide.go)
and [AuthZEN](../../internal/access/authorization/authzen/authzen.go). F-01 handles
policy changes; this adds distribution and conformance. The current server-owned
enforcement architecture must be explicitly revisited for customer-app evaluation.

**Pilot and enforcement.** Shadow-only, one customer service and one custom
permission. Distribute a bounded, consistent snapshot of policies AND required
authorization data. Bind signed artifacts to tenant, app/evaluator, semantics
version, digest, snapshot time, monotonic epoch, expiry and eligible operations.
Protect sensitive snapshots in transport/storage and use dedicated artifact keys.
Explicitly require signature verification; signature validity alone proves neither
freshness nor acceptable current authority.

**Acceptance.** Compare against the server on the same captured context; reject
tampering, cross-tenant/audience substitution, rollback, expired leases and
stale renewals. Unsupported applicable rules return `require_online`, never an
allow with the rule omitted. Persist revocation high-water marks; after trusted
state loss, require online bootstrap. A proposed 60-second lease starts from the
authoritative snapshot, not download time; 304 responses cannot extend it.
Measure divergences and p95 on stated hardware, not an invented performance SLA.

**Limits and ownership.** An unreachable evaluator cannot guarantee immediate
revocation. Keep mandatory live authentication, lifecycle and step-up controls
online; if required checks are unavailable, deny. An acknowledgement proves
activation, not every enforcement decision. Authorization/security and customer
runtime/SDK/deploy owners must approve semantics and staleness. OPA is a precedent
for distribution [T2], not a reason to translate Qeet policies into a new language
or introduce another engine without a separate design. Two shadow-pilot sprints
are a starting estimate; production compatibility is substantially more work.

### N-12: Customer-controlled encryption keys

**In short.** Let a regulated customer protect its stored secrets in Qeet with a key held in its own cloud key service (KMS), so it can withdraw access to its data.

**Why we need it.** Banks, insurers and public-sector buyers often require customer-managed keys in procurement: if they revoke the key, the vendor can no longer read their data.

It is expensive to run and easy to get wrong: a withdrawn key must never break other customers or the platform. It is separate from Qeet AI's bring-your-own-key (the customer's model API key) and from our own key rotation.

**What Qeet ID has today:**

- Envelope encryption with key IDs and rotation, a registry of encrypted columns, and a key-provider boundary.

**Research detail.**

**Problem.** A regulated customer requires control over encryption authority for
its own stored secrets. This expands the discovery queue, not AI-provider BYOK
and not the existing deployment-wide re-encryption worker.

**Proposed APIs:**
```text
POST /v1/tenants/{tenantID}/encryption-keys
POST /v1/tenants/{tenantID}/encryption-keys/{keyID}/validations
POST /v1/tenants/{tenantID}/encryption-keys/{keyID}/activations
POST /v1/tenants/{tenantID}/encryption-keys/{keyID}/suspensions
GET  /v1/tenants/{tenantID}/encryption-key-operations/{operationID}
```
Existing [envelopes](../../internal/platform/crypto/envelope/envelope.go) bind context;
the [key-provider boundary](../../internal/developer/credentials/secrets/keyprovider.go)
and [bootstrap key registry](../../internal/bootstrap/keys.go) are the starting points.
Not every encrypted-column context identifies an organization: some identify
users, sessions or platform material. Map real ownership before extending custody.

**Pilot and enforcement.** Vault values only, two synthetic tenants and one
supported regional KMS service. Use independent random tenant data keys wrapped
under approved tenant/customer key references; do not wrap the shared deployment
data key and call that isolation. Preserve tenant/purpose/resource binding.
Pin validated key identity and permissions, never accept raw cloud credentials
or arbitrary KMS URLs. Activation uses a resumable, audited migration operation.
The existing resealer must not silently move customer-key records back to shared keys.

**Acceptance.** Swapped tenant/key/context data fails; migration/restart/restore
retains correct ownership and versioned dependencies. Key withdrawal fails closed
only for covered operations in that tenant, never global startup/readiness or
unrelated tenants. Start without cross-request plaintext-key caching; any later
cache requires a bounded non-sliding lease and documented withdrawal delay.
Use per-tenant concurrency/circuit breakers and test another tenant's availability.

**Limits and ownership.** Withdrawal does not recall plaintext or cached data
keys; AWS explicitly documents this [T3]. Keep local suspension separate from
observed customer-KMS denial. Restore needs the original required key versions
and authorization. Old backups/exports may remain outside new custody; neither
withdrawal nor migration proves erasure. Never fall back to operator encryption.
Customer-managed does not mean post-quantum-safe. Vault/security, deploy/IAM,
customer key administrators and SDK/console owners share this high-operating-cost
feature. Two pilot sprints scope only vault values, not all customer data or HYOK.

### N-13: Outbound-only connector for private directories

**In short.** A small connector the customer runs inside their network that connects out to Qeet, so Qeet can use their private LDAP or Active Directory without the customer opening a firewall port.

**Why we need it.** Many enterprises keep Active Directory or LDAP on their own premises and won't expose it to the internet. Qeet's LDAP sign-in today needs the directory to be reachable from Qeet.

An outbound-only connector, like Microsoft Entra's provisioning agent, solves that without a VPN or a general tunnel. It has to be tightly limited so it never becomes a back door into the customer's network.

**What Qeet ID has today:**

- LDAP federation connects directly to a reachable directory.
- Outbound calls go through the egress policy, which blocks private addresses.

**Research detail.**

**Problem.** Hybrid enterprises need bounded access to private directories and
applications without opening inbound firewall access or granting a general tunnel.
This expands the private-connectivity discovery item, not physical data residency.

**Proposed administrative APIs:**
```text
POST /v1/tenants/{tenantID}/private-connectors/enrollments
POST /v1/tenants/{tenantID}/private-connectors/{connectorID}/targets
POST /v1/tenants/{tenantID}/private-connectors/{connectorID}/jobs
POST /v1/tenants/{tenantID}/private-connectors/{connectorID}/revocations
```
Add a typed operation adapter beside [LDAP](../../internal/federation/ldap/ldap.go),
preserving [public egress policy](../../internal/platform/network/egress/egress.go).
Do not make arbitrary private addresses globally acceptable. N-01 supplies
workload-trust concepts; F-05 can later use an approved private action adapter.

**Pilot and enforcement.** One outbound-mTLS connector, one LDAPS target,
constrained read-only lookup/test operations. A stepped-up admin authorizes
single-use enrollment bound to expected workload identity and key possession;
runtime tenant identity comes from the verified connector record, not job input.
Both server and connector-local policy approve target, protocol, port, trust,
base/filter template, allowed attributes and actions. Validate actual resolved
addresses, referrals and redirects; block metadata and unintended loopback access.
Target credentials remain local; no arbitrary commands, plugins or remote shell.

**Acceptance.** Reject foreign-tenant enrollment/jobs, target escape, expired
jobs, replay and stale lease owners. Bound queues, execution time, retries and
results; authenticate the original actor and reauthorize at dispatch. Revocation
stops new leases; already authorized work may finish within its bounded deadline.
Future writes require operation-specific idempotency/reconciliation, not blind
replay after an unknown outcome. Never store end-user passwords in durable jobs.
Measure onboarding time and connected dispatch latency with the customer network.

**Limits and ownership.** No inbound opening, open proxy or new sign-in bypass.
Certificate renewal, signed runtime distribution, local patching, failover fencing
and customer credential recovery need a separately approved connector/deploy owner.
Server still owns identity/adoption/JIT decisions. Entra documents outbound-only
agents as an established pattern [T4]. Two discovery/pilot sprints cannot deliver
a supported multi-protocol fleet; defer without a hybrid-enterprise buyer.

### N-14: Promote configuration between environments

**In short.** Let a team copy reviewed configuration, for example OIDC client settings, from development to staging to production as a plan they approve, without copying secrets.

**Why we need it.** Customers run separate Qeet organisations for development, staging and production, and recreate apps and settings by hand in each. Mistakes creep in, secrets get pasted around, and nobody can explain why production differs from staging.

A promote-with-diff workflow, like Auth0's Deploy CLI, fixes that.

**What Qeet ID has today:**

- Admin APIs for OIDC clients and other resources, with idempotency keys on the create routes.

**Research detail.**

**Problem.** Teams repeat configuration between development, staging and production,
accidentally copy secrets, or cannot explain environmental drift. This explicitly
expands F-01 and the earlier promotion discovery item, not a second change engine.

**Proposed APIs:**
```text
POST /v1/tenants/{tenantID}/configuration/plans
GET  /v1/tenants/{tenantID}/configuration/plans/{planID}
POST /v1/tenants/{tenantID}/configuration/plans/{planID}/approvals
POST /v1/tenants/{tenantID}/configuration/plans/{planID}/apply
```
Build an allowlisted, versioned manifest over validated resource operations such
as [OIDC client updates](../../internal/federation/oidc/clients_admin.go). Keep process
configuration, user accounts and sessions out of it. Export no plaintext secrets,
ciphertext, hashes or suffix hints; target-local aliases reference independently
provisioned secrets without granting a reveal permission.

**Pilot and enforcement.** At most five existing OIDC clients in two nonproduction
environments. Authenticate source export and target planning/approval/application
independently; a source admin/token has no target authority. Approve the exact
normalized diff, target revision, overrides, reference revisions and expiry.
Target operation AND underlying resource permissions must pass. Drift invalidates
stale approval; record the applied operation outcome atomically with bounded DB
changes. No deletion, credential rotation or federation-policy activation initially.

**Acceptance.** Identical normalized input is a no-op; self-approved, stale,
changed-reference and cross-tenant plans fail. Interrupted-response retry does not
apply a committed plan twice. Existing secrets/unmanaged fields remain unchanged.
Initial approval governs promotions only; ordinary authorized admin changes are
reported as drift, not falsely claimed to be blocked by this workflow.

**Limits and ownership.** Start with diff/export in sprint one, bounded approved
application in sprint two; this assumes F-01's change-control design is available.
Measure operator time and promotion error rates against repeated real work. CLI/CI,
SDK, console and environment provisioning need additional owners and estimates.
Auth0 Deploy CLI and Keycloak import/export are precedents, including destructive
import warnings [T5]. Do not build a generic tenant clone or backup system.

### N-15: Integration diagnostics for customer apps

**In short.** Help developers find out why their app's sign-in with Qeet fails, by running standard OAuth and OIDC test scenarios against their app and explaining the result.

**Why we need it.** Integration mistakes (a wrong redirect URI, missing PKCE, not checking the nonce or audience) are the most common support requests for an identity provider. Developers lose days, and some give up.

A test run that says "your app accepted a token with the wrong audience" is faster than a support thread. The OpenID Foundation conformance suite can test apps this way.

**What Qeet ID has today:**

- Internal OAuth flow tests; SDKs for Node, Go and React; OpenAPI specs and a Postman collection (qeet-apis).

**Research detail.**

**Problem.** Integrating developers need reproducible explanations for OAuth/OIDC
and SDK failures before real-user onboarding. Here the customer's relying party
is the test subject: F-04 tests incoming IdP changes, and G-02 tests Qeet releases.

**Proposed APIs, only if a hosted workflow is justified:**
```text
POST /v1/tenants/{tenantID}/integration-targets
POST /v1/tenants/{tenantID}/integration-targets/{targetID}/runs
GET  /v1/tenants/{tenantID}/integration-runs/{runID}
POST /v1/tenants/{tenantID}/integration-runs/{runID}/cancellations
```
Reuse the scenarios behind [OAuth flow tests](../../internal/federation/oidc/authorize_db_test.go)
and upstream conformance tooling where the selected profile fits [T6]. Test
helpers that inject principals are not evidence of full auth behavior and must
not become a public account-provisioning API.

**Pilot and enforcement.** First test whether a local runner plus SDK examples
solves the problem; do not automatically build a hosted service. For a hosted
pilot, require verified target ownership and explicit testing consent for exact
staging initiation/callback URLs. Jobs reference approved target IDs, never
arbitrary URLs. Apply egress controls to all runner/browser traffic, redirects
and subresources; block production/private/metadata/loopback targets. Do not run
uploaded customer code inside the API process.

**Acceptance.** One cooperating RP and one authorization-code/S256 profile with
synthetic identities. Valid flows pass; invalid signature, issuer, audience,
state and applicable nonce cases produce observable rejection. No observed
rejection means inconclusive, not success. Record suite/profile/SDK versions and
configuration digest, redact tokens/assertions, and expire test artifacts. Retry
returns the same run instead of blindly repeating protocol steps.

**Limits and ownership.** Isolate runners, issuer/keys, databases, cookies and
credentials from production; production must not trust the sandbox issuer.
Invalid responses belong only in the isolated test provider. Two pilot sprints
cover one RP, not all SDKs or a certification program. Measure diagnosis/support
time; target a useful first report within 30 minutes once the approved target is
configured. Runner operations, consent, abuse prevention, browser/suite updates,
deploy/kit and SDK/customer-app integration need real owners and recurring budgets.

### Choosing among N-10 to N-15

The numbering is a catalog, not a commitment or implementation order. Do not
append another long feature list without first collecting adoption evidence.

| Customer evidence | Candidate next discovery | First exit gate |
| --- | --- | --- |
| Developers repeatedly abandon integration or need lengthy support | N-15 | One useful local-runner report; prove hosted operations are worth their cost before adding APIs |
| Teams make frequent manual environment changes | N-14 | Safe manifest/diff for five existing clients with no secret export |
| Procurement requires tenant key control | N-12 | Written custody, coverage, withdrawal/cache, restore and outage-isolation contract |
| A private directory cannot be reached without network exceptions | N-13 | One authenticated outbound connector performs a confined lookup without changing global egress |
| A managed enterprise fleet needs stronger application admission | N-10 | Explainable shadow assessments with no invalid-evidence passes |
| Measured network cost justifies distributed decisions | N-11 | Architecture approval and same-snapshot shadow conformance; no mandatory online check removed |

For a selected candidate, use a discovery/contract sprint, a bounded vertical
slice, then a separately approved operational/customer pilot. The one/two-sprint
examples exclude cross-repository delivery and production hardening. The definition
of done includes threat-model review, denied/unknown/outage behavior, OpenAPI,
isolation tests, quotas, retention, rollback and supported-client documentation.
No source implementation or scope expansion is approved by this entry.

**AI and quantum continuity.** N-10 can supply verified assurance to F-05/N-02;
N-11 may reduce repeated N-03 checks only after freshness semantics are approved;
N-12/N-13 add custody and transport dependencies to PQ-01. These connections are
not reasons to claim prompt-injection immunity, instantaneous offline revocation
or quantum safety. PQ-01 through PQ-03 remain the practical quantum roadmap;
no new cryptographic algorithm or production JWT change is proposed here.

## Part 4: Post-quantum cryptography (PQ-01 to PQ-03)

Post-quantum cryptography is software cryptography designed to resist relevant
future quantum attacks; these proposals do not need a quantum computer. Use
standards and maintained implementations, not new cryptographic constructions.

Official NIST pages confirm FIPS 203/204/205 were finalized on 2024-08-13;
FIPS 203/204 also publish errata notices. On the research date, IR 8547's page
lists the final transition report dated 2026-10-27 [S12, S13]. Recheck standards,
profiles, library support and errata when a pilot starts. Federal transition
guidance is not automatically a universal private-enterprise deadline.

- **ML-KEM (FIPS 203)** establishes shared keys. It is not a JWT-signing algorithm.
- **ML-DSA (FIPS 204)** and **SLH-DSA (FIPS 205)** are signature algorithms.
- Hybrid TLS key exchange, certificate authentication and stored-data encryption
  are different properties. Improving one does not prove the others migrated.
- Algorithm standardization is not FIPS 140 validation of the deployed module,
  operating environment and approved mode. Avoid whole-product certification claims.
- "Harvest now, decrypt later" concerns long-lived confidential data in captured
  traffic, including key-unwrapping traffic. Short-lived tokens do not make
  captured personal data short-lived. Rotation cannot retract previously captured data.
- The [server starts an HTTP listener](../../internal/bootstrap/server.go); public TLS
  evidence must include the actual terminator and every relevant hop. A Go version,
  configured curve list or TLS 1.3 cipher-suite name does not prove a negotiated
  hybrid group. This review did not inspect the deployed network.
- Do not replace ES256, change JWT/JWKS/`kid` handling, disable validation, invent
  a hybrid JWT format, or declare "quantum-safe" from these proposals.

### PQ-01: Cryptographic inventory and post-quantum plan

**In short.** A read-only report of every place Qeet ID uses public-key cryptography for an organisation (signing keys, encryption, TLS), who depends on it, and what would need to move to post-quantum algorithms first.

**Why we need it.** Future quantum computers could break today's public-key algorithms (RSA and elliptic curves). NIST published post-quantum standards in 2024 (ML-KEM for key exchange; ML-DSA and SLH-DSA for signatures) and has set transition timelines. Enterprise security and procurement teams are starting to ask vendors for their post-quantum plan.

The practical first step is knowing what you have. What matters most is data that must stay secret for years ("harvest now, decrypt later") and signatures that must stay verifiable for years.

**What Qeet ID has today:**

- JWT signing keys (ES256) with key IDs and rotation.
- A registry of encrypted columns, and envelope encryption with key IDs.

**Research detail.**

**Problem and buyer.** Enterprise security/procurement teams need an inventory
of what depends on vulnerable public-key cryptography, who must migrate, and
which data or evidence has a long enough lifetime to prioritize.

**Proposed APIs:**
```text
GET /v1/tenants/{tenantID}/crypto/assets
GET /v1/tenants/{tenantID}/crypto/exposure-plan
```
Return purpose, algorithm/parameters, public key ID, owner, consumer dependencies,
confidentiality/authenticity horizon, evidence source/freshness and unknowns.
Operators collect deployment-wide facts; tenants see only sanitized implications
for their resources. Tenant admins cannot change the shared signer or see others'
key inventories. No decrypted secret material is needed.

**Starting slice and controls.** Inventory issuer metadata from
[KeyInfo](../../internal/platform/crypto/tokens/jwt.go), the
[encrypted-column registry](../../internal/bootstrap/keys.go), and operator-supplied
transport/backup-retention evidence. Separate configured support, observed behavior
and operator attestation. Do not mistake first observation for first exposure,
or use an unexplained single "quantum safety score."

**Measure.** Every pilot asset has provenance or an explicit unknown, and two
design partners can identify an owner and next action for their most important
dependency. Distinguish confidentiality migration from archival signature risk.

**Dependencies/position.** Builds on 5.4 and can feed F-06, but adds PQ exposure
planning rather than another rotation worker. One read-only starting sprint;
inventory completeness and customer value remain unverified. NIST migration
guidance provides the standards basis [S12, S13].

### PQ-02: Evidence of post-quantum TLS on real connections

**In short.** Record and show which real network connections to and from Qeet used hybrid post-quantum key exchange, and where something in the path prevented it.

**Why we need it.** Modern TLS can use hybrid post-quantum key exchange (for example X25519MLKEM768) to protect traffic recorded today from being decrypted in future. But a setting on one server doesn't prove every hop used it: a load balancer or an old client can quietly fall back.

Customers who ask "is our traffic quantum-protected?" need evidence per connection, not a badge. Cloudflare and AWS KMS publish this kind of evidence.

**What Qeet ID has today:**

- The server speaks plain HTTP behind a TLS terminator (Caddy or a load balancer); the TLS settings live in the deploy repository.

**Research detail.**

**Problem and buyer.** An organization needs to prove which actual connections
used hybrid key establishment and where legacy peers or proxies prevented it.

**Proposed API:**
```text
GET /v1/tenants/{tenantID}/crypto/transport-evidence
```
Evidence identifies the connection segment, build/configuration reference, time,
TLS version, negotiated group, certificate algorithms separately, resumption state,
coverage and errors. Missing evidence is unknown, not success. Shared topology
details remain operator-only unless safe for tenant disclosure.

**Starting slice and controls.** Model one staging ingress and one permitted
outbound/KMS path, initially with supplied telemetry fixtures. An operator-approved
experiment then checks hybrid-capable and classical-only peers, a representative
proxy, resumption and invalid certificates. Tenants cannot supply arbitrary URLs
to scan or change global TLS policy. Preserve certificate checks and explicit
fallback policy; no hidden insecure retries to make a test pass.

**Measure.** Correct classical/hybrid/unknown classification with provenance,
measured handshake sizes, latency/error impact and a rehearsed rollback. A protected
edge hop cannot conceal an unobserved origin hop. Cloudflare documents per-segment
PQC and AWS KMS documents negotiated-group evidence in CloudTrail [S14, S15].

**Dependencies/position.** PQ-01, deployment/kit owners, supported clients and
authenticated telemetry. This is measurement/integration, not custom TLS crypto.
One staging discovery sprint, then capacity/compatibility work as evidence dictates.

### PQ-03: Post-quantum signatures on long-lived audit exports

**In short.** Add an optional second, post-quantum signature (ML-DSA) to audit exports, so exports kept for many years stay verifiable after today's signature algorithms weaken.

**Why we need it.** Audit exports may be kept for seven to ten years for regulators. If today's elliptic-curve signatures can be forged in future, an old export's signature proves nothing.

Adding an independent ML-DSA signature now, beside the existing one, keeps long-term evidence trustworthy. Access tokens are short-lived and don't need this.

**What Qeet ID has today:**

- A signed anchor on the audit chain, and audit export with hashes.

**Research detail.**

**Problem and buyer.** Audit exports retained for years need a verification
strategy whose lifetime differs from short-lived access tokens.

**Proposed APIs:**
```text
POST /v1/tenants/{tenantID}/audit/exports/{exportID}/pq-evidence
GET  /v1/tenants/{tenantID}/audit/exports/{exportID}/pq-evidence
```
These are opt-in future operations over an immutable, authorized export after
5.3 exists. Operators select an approved signature/container profile and key
custody. Separate artifact keys from the JWT issuer; no changes to access-token
algorithms, claims, JWKS or existing verifier behavior.

**Starting slice and controls.** An isolated, synthetic export with its existing
classical signature plus an independently keyed ML-DSA detached signature over
the same precisely defined manifest. Require both under the pilot policy using
a reviewed container/profile, not a bespoke combined algorithm. Evaluate published
implementations or managed signing support; decide runtime minimum, key custody,
quotas, costs and region support before integration.

**Measure.** Two independent implementations verify; changed bytes, substituted
keys and missing/invalid required signatures fail. Record signature size and
verification cost. Preserve archival public keys and trust/timestamp history.
A fresh PQ signature cannot retroactively prove that an old export was truthful.

**Dependencies/position.** 5.3, 5.4, F-06, independent cryptographic review and
long-term format compatibility. Start with a two-week interoperability spike,
not production token migration. NIST signature standards and AWS managed ML-DSA
documentation are precedents [S12, S16]; FIPS validation is a separate question.

## Part 5: Discovery queue

These may be commercially important but are not claimed as unique or currently
broken. Do not turn them into parallel implementation without a specific buyer.

- **Customer-controlled tenant keys:** distinguish this from 5.4 deployment-key
  rotation. Investigate tenant-specific custody, cache/revocation behavior,
  unavailable customer KMS, cryptographic erasure and backup recovery without
  allowing one customer to stop the shared platform. Requires a separate threat
  model and operating-cost decision.
- **Environment configuration promotion:** expand F-01 only if customers need
  approved dev-to-production promotion of connections, client policies and
  mappings, with secret references rather than copied credentials and drift checks.
  It is an extension of change control, not a competing configuration system.
- **Deployment isolation and residency:** real regional storage, disaster recovery,
  private connectivity or dedicated deployments require deploy/data architecture
  work. The existing 5.2 region-label correction is not implementation of residency.
  Do not advertise physical residency based on a tenant setting.

### RESIDENCY: Data residency and dedicated deployments (discovery)

**In short.** Find out whether customers need their data kept in a specific country or region, private network connectivity, or a dedicated deployment, and what it would cost us to offer that.

**Why we need it.** Large Indian and international enterprises, and regulated sectors, often ask where their data is stored, and may require India-only or EU-only storage, a private link (such as AWS PrivateLink) or a single-tenant deployment.

Qeet ID runs one shared deployment. Offering residency is deploy and data-architecture work (separate databases, backups and disaster recovery per region), not a setting. The organisation's region field was relabelled in 1.0 so it doesn't suggest residency we don't have.

**What Qeet ID has today:**

- One shared deployment; the region field is a label, read-only until real residency exists.

**Steps:**

- Find customers with the requirement and write down their region, recovery, connectivity and isolation needs.
- Estimate the deploy, data and running cost of each option: a regional shared deployment, a dedicated deployment, private connectivity.
- Decide whether to offer it, and which option first.

**Done when:**

- A written decision with costs, linked here.
