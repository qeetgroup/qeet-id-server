# Qeet ID — Sprint Plan (Differentiators + E2E Test Coverage)

> **What this folder is.** A sprint-by-sprint execution plan with two jobs in every sprint:
> 1. **Test what exists** — concrete, copy-paste end-to-end test scenarios for already-built features, so you (the maintainer) can verify the platform actually works before building on top of it.
> 2. **Build what nobody else has** — one or two *differentiator* features per sprint that solve problems other identity platforms (Auth0, Okta, Clerk, WorkOS, Stytch, Keycloak, FusionAuth, Zitadel, Ory) leave unsolved.
>
> Goal stated by the team: **"our platform has solutions for all types of problems."** This plan is how we get there, one testable sprint at a time.

| | |
|---|---|
| **Created** | 2026-05-29 |
| **Last updated** | 2026-05-29 |
| **Baseline** | branch `ms/signin-with-qeet` @ `bf778f4` |
| **Companion doc** | [Competitive Analysis & Roadmap](../COMPETITIVE-ANALYSIS-AND-ROADMAP.md) — read it first for the gap analysis & backlog IDs (#1–#37) |
| **Cadence** | 2-week sprints, starting Jun 2026 |

---

## How to use this folder

- Each `sprint-N.md` is **self-contained and shippable**. Do them in order — later sprints depend on earlier ones being tested and green.
- Every sprint file has the same shape:
  - **Part A — Test existing features (E2E)**: scenarios with `curl`/Postman steps, expected results, and a pass/fail checklist. No code to write — just verify and tick boxes.
  - **Part B — Build differentiator feature(s)**: the *problem other platforms can't solve*, our design, the exact backend/frontend/docs changes, acceptance criteria, and how you test it yourself.
  - **Definition of Done**: the checklist that closes the sprint.
- **Backlog IDs**: `#N` references the roadmap backlog in the companion doc. `DN` references a **Differentiator** defined below.

### Legend

| Symbol | Meaning |
|---|---|
| ✅ | Implemented & verified |
| 🟡 | Partial / stubbed (returns 501 or not enforced) |
| ❌ | Not built |
| 🚀 | New differentiator feature (the stuff competitors don't have) |
| 🧪 | Test task (verify existing behaviour) |

---

## The differentiator philosophy

Most platforms solve *authentication*. We aim to solve the **operational pain around identity** that every team hits and no vendor fully fixes:

1. **Testing auth is miserable** → we ship a first-class **Test Mode + Dev Inbox** (D1).
2. **Authorization is a black box** ("why was I denied?") → **Explainable Authorization** (D2).
3. **Passwordless account recovery is unsolved** → **Resilient Recovery** (D3).
4. **You can't independently prove your audit log wasn't tampered with** → **Publicly-Verifiable Audit** (D5).
5. **Migrating off a vendor means forcing password resets** → **Zero-Downtime Universal Importer** (D9).
6. **AI agents are abusing human credentials** → **First-class Agent Identity & Delegation** (D7).
7. **Support staff impersonate users with no guardrails; breaches can't be contained fast** → **Safe Impersonation + Tenant Kill-Switch** (D8).
8. **"SSO tax"** — enterprise SSO/SCIM gated behind $$$ tiers → **Qeet ID includes them**. Enterprise readiness is not a luxury add-on.

### Differentiator catalog

| ID | Feature | Problem it solves (that others don't) | Sprint |
|---|---|---|---|
| **D1** | Test Mode & Dev Inbox | Auth flows are painful to test; OTP/magic-links go to real inboxes; token expiry can't be simulated | [1](sprint-1.md) |
| **D2** | Explainable Authorization (`/authz/explain`) | "Why was this allowed/denied?" is unanswerable in every RBAC system | [2](sprint-2.md) |
| **D3** | Resilient Passwordless Recovery | Lost-passkey lockout is the #1 unsolved passwordless problem | [3](sprint-3.md) |
| **D4** | Edge-Verifiable Tokens + Token Explain | Tokens are opaque; can't verify at the edge without phoning home | [4](sprint-4.md) |
| **D5** | Publicly-Verifiable Audit (Merkle transparency) | You must *trust the vendor* that the audit log is intact | [5](sprint-5.md) |
| **D6** | Consent & Preference Ledger + Portability Bundle | Consent is bolted-on; no cryptographic proof of consent; no clean data export | [6](sprint-6.md) |
| **D7** | AI-Agent Identity & Delegation (MCP-native) | Agents borrow human tokens; no scoped/auditable delegation | [7](sprint-7.md) |
| **D8** | Safe Impersonation + Tenant Kill-Switch | Support impersonation is unsafe; breach containment is slow | [8](sprint-8.md) |
| **D9** | Zero-Downtime Universal Importer | Vendor lock-in: migration forces password resets | [9](sprint-9.md) |
| **D10** | Continuous Trust + Compliance Evidence Autopilot | Risk is point-in-time; SOC2/ISO evidence is manual toil | [10](sprint-10.md) |
| **D11** | Identity Graph + auto-merge | Same human shows up as N duplicate accounts across providers; nobody de-dupes safely | [11](sprint-11.md) |
| **D12** | Break-glass admin recovery + auth canaries | If the IdP itself is down/misconfigured you lock yourself out; no per-tenant auth health signal | [18](sprint-18.md) |
| **D13** | Time-Travel Identity (point-in-time state) | "What could user X access on date Y?" is unanswerable for audits/incidents | [19](sprint-19.md) |
| **D14** | Data Residency + BYOK | No per-tenant region pinning / customer-held encryption keys for sovereignty | [20](sprint-20.md) |

> **Sprints 11–20 are the "close every gap" half.** Sprints 1–10 are differentiator-forward; sprints 11–20 implement the table-stakes gaps found in the [Competitive Analysis](../COMPETITIVE-ANALYSIS-AND-ROADMAP.md) (backlog #1–#37), **enterprise-first**, while still carrying the new differentiators D11–D14. The [coverage matrix](#coverage-matrix--every-gap-mapped-to-a-sprint) below proves nothing is left unscheduled.

---

## Sprint summary

| Sprint | Window (2026) | 🧪 Existing features tested | 🚀 Differentiator built |
|---|---|---|---|
| [1](sprint-1.md) | Jun 1 – Jun 12 | Signup, login, refresh+theft detection, logout, sessions, `/me`, forgot/reset password, magic link | **D1** Test Mode & Dev Inbox |
| [2](sprint-2.md) | Jun 15 – Jun 26 | Users CRUD, tenants, groups, invites, RBAC (roles/perms/assign/effective/`check`) | **D2** Explainable Authorization (+ group-RBAC, closes #15) |
| [3](sprint-3.md) | Jun 29 – Jul 10 | MFA TOTP enroll/verify/disable, recovery codes, email/phone OTP delivery | **D3** Resilient Passwordless Recovery (depends on #1 passkeys) |
| [4](sprint-4.md) | Jul 13 – Jul 24 | OIDC discovery, client registration, authorize+PKCE, token-code, userinfo, `client_credentials` | **D4** Edge-Verifiable Tokens + Token Explain (+ RS256/JWKS #3, OIDC completion) |
| [5](sprint-5.md) | Jul 27 – Aug 7 | Audit list + hash-chain verify, analytics overview | **D5** Publicly-Verifiable Audit (Merkle checkpoints + external verifier) |
| [6](sprint-6.md) | Aug 10 – Aug 21 | Webhooks CRUD/HMAC/retry/DLQ, GDPR erasure request/cancel/purge | **D6** Consent & Preference Ledger + Portability Bundle |
| [7](sprint-7.md) | Aug 24 – Sep 4 | API keys, service principals, webhook delivery (re-verify under agent load) | **D7** AI-Agent Identity & Delegation (MCP-native) |
| [8](sprint-8.md) | Sep 7 – Sep 18 | Sessions revoke, API-key revoke, branding/policy storage | **D8** Safe Impersonation + Tenant Kill-Switch |
| [9](sprint-9.md) | Sep 21 – Oct 2 | Password login under imported hashes, user import | **D9** Zero-Downtime Universal Importer |
| [10](sprint-10.md) | Oct 5 – Oct 16 | Policy enforcement (#6), adaptive paths, full regression pass | **D10** Continuous Trust + Compliance Evidence Autopilot |
| | | **— Sprints 11–20: close the gaps (enterprise-first) —** | |
| [11](sprint-11.md) | Oct 19 – Oct 30 | Social login flows, account linking | **#2** Social OAuth finish + **#26** account linking + **D11** Identity Graph & auto-merge |
| [12](sprint-12.md) | Nov 2 – Nov 20 ⏳XL | SAML conformance suite | **#9** SAML 2.0 (SP + IdP) |
| [13](sprint-13.md) | Nov 23 – Dec 11 ⏳XL | SCIM provisioning/deprovisioning | **#10** SCIM 2.0 + **#11** org-level SSO connections |
| [14](sprint-14.md) | Dec 14 – Jan 8 | Portal config flows, LDAP bind | **#12** self-serve enterprise Admin Portal + **#13** LDAP/AD |
| [15](sprint-15.md) | Jan 11 – Jan 22 | Throttling, lockout, risk signals | **#16–#21** Attack-Protection suite (breached-pwd, brute-force, bot, adaptive MFA, step-up, anomaly) |
| [16](sprint-16.md) | Jan 25 – Feb 12 ⏳XL | SDK conformance against live API | **#27** OpenAPI completion + **#22** client SDKs + **#28** CLI |
| [17](sprint-17.md) | Feb 15 – Mar 5 ⏳XL | Embedded components, hosted flows | **#23** prebuilt UI components + **#24** hosted login UI |
| [18](sprint-18.md) | Mar 8 – Mar 19 | Hook execution, canary runs | **#25** Actions/Hooks engine + **D12** Break-glass admin recovery + auth canaries |
| [19](sprint-19.md) | Mar 22 – Apr 9 ⏳XL | ReBAC checks, device flow, time-travel queries | **#29** fine-grained/ReBAC authz + **#30/#32** OAuth 2.1 / device flow / CIBA + **D13** Time-Travel Identity |
| [20](sprint-20.md) | Apr 12 – Apr 30 | Billing, region pinning, BYOK, observability | **#33** billing + **#34/#35/#37** Kafka/S3/OTel + **#36** SOC2/ISO + **D14** Data Residency + BYOK |

> Dates are **target windows** from the 2026-05-29 baseline (sprints 1–10 in 2026, 11–20 spill into 2027). `⏳XL` marks items the [roadmap](../COMPETITIVE-ANALYSIS-AND-ROADMAP.md) rates **XL** — they may span two sprints (split e.g. `12a`/`12b`). Adjust capacity freely, but preserve order. Record actual ship dates in each sprint's changelog row.
>
> **Ordering note:** the Attack-Protection suite (sprint 15, #16–#21) feeds **D10 Continuous Trust** (sprint 10). Sprint 10 ships with whatever signals exist; sprint 15 deepens it. If you want richer trust scoring in sprint 10, pull sprint 15 earlier.

---

## Coverage matrix — every gap mapped to a sprint

This is the audit trail proving the [Competitive Analysis](../COMPETITIVE-ANALYSIS-AND-ROADMAP.md) backlog (**#1–#37**) is fully scheduled — nothing in the gap analysis is left without a home.

### Roadmap backlog → sprint

| # | Gap (from COMPETITIVE-ANALYSIS) | Sprint |
|---|---|---|
| #1 | Finish WebAuthn/passkey ceremony | [3](sprint-3.md) (prereq) |
| #2 | Finish social OAuth (Google/GitHub/MS/Apple) | [11](sprint-11.md) |
| #3 | RS256/ES256 signing + JWKS rotation | [4](sprint-4.md) |
| #4 | Real email/SMS providers | [3](sprint-3.md) (prereq) |
| #5 | Argon2id + multi-scheme password verify | [9](sprint-9.md) |
| #6 | Wire policy enforcement (IP/MFA/session-age) | [10](sprint-10.md) |
| #7 | Distributed rate limiting (Redis) | [20](sprint-20.md) (infra) |
| #8 | Reconcile root README/CHANGELOG | [1](sprint-1.md) + ongoing |
| #9 | SAML 2.0 (SP + IdP) | [12](sprint-12.md) |
| #10 | SCIM 2.0 server | [13](sprint-13.md) |
| #11 | Org-level SSO connections + domain routing | [13](sprint-13.md) |
| #12 | Self-serve Admin Portal (embeddable) | [14](sprint-14.md) |
| #13 | LDAP/AD federation | [14](sprint-14.md) |
| #14 | Audit log export (CSV/SIEM) | [5](sprint-5.md) |
| #15 | Group-level RBAC resolution | [2](sprint-2.md) |
| #16 | Breached-password detection | [15](sprint-15.md) |
| #17 | Brute-force + suspicious-IP throttling | [15](sprint-15.md) |
| #18 | Bot detection | [15](sprint-15.md) |
| #19 | Adaptive / risk-based MFA | [15](sprint-15.md) |
| #20 | Step-up authentication primitive | [15](sprint-15.md) |
| #21 | Anomaly detection + security notifications | [15](sprint-15.md) |
| #22 | First-party client SDKs (TS/React/Next/Go/Python) | [16](sprint-16.md) |
| #23 | Prebuilt UI components | [17](sprint-17.md) |
| #24 | Hosted / embeddable login UI | [17](sprint-17.md) |
| #25 | Actions/Hooks extensibility engine | [18](sprint-18.md) |
| #26 | Custom registration / progressive profiling / account-linking | [11](sprint-11.md) + [18](sprint-18.md) |
| #27 | Complete OpenAPI spec | [16](sprint-16.md) |
| #28 | CLI (`qeetid`) | [16](sprint-16.md) |
| #29 | Fine-grained / ReBAC authorization | [19](sprint-19.md) |
| #30 | OAuth 2.1 + device flow + token-exchange + DPoP | [7](sprint-7.md) (token-exchange) + [19](sprint-19.md) |
| #31 | AI-agent / MCP identity | [7](sprint-7.md) |
| #32 | CIBA (decoupled auth) | [19](sprint-19.md) |
| #33 | Stripe billing | [20](sprint-20.md) |
| #34 | Kafka/queue outbox publisher | [20](sprint-20.md) |
| #35 | S3 / object storage for assets | [20](sprint-20.md) |
| #36 | SOC 2 / ISO 27001 posture | [10](sprint-10.md) + [20](sprint-20.md) |
| #37 | Observability (OpenTelemetry) | [20](sprint-20.md) |

### Differentiators → sprint

D1→[1](sprint-1.md) · D2→[2](sprint-2.md) · D3→[3](sprint-3.md) · D4→[4](sprint-4.md) · D5→[5](sprint-5.md) · D6→[6](sprint-6.md) · D7→[7](sprint-7.md) · D8→[8](sprint-8.md) · D9→[9](sprint-9.md) · D10→[10](sprint-10.md) · D11→[11](sprint-11.md) · D12→[18](sprint-18.md) · D13→[19](sprint-19.md) · D14→[20](sprint-20.md)

**Result: 37/37 backlog gaps + 14/14 differentiators scheduled.** ✅

---

## How you test (the standard harness)

Every Part-A scenario assumes the local stack is up:

```bash
make db-up && make migrate-up      # Postgres + schema
make dev-backend                   # API on http://localhost:4000
# (optional) make dev-admin        # Admin UI on http://localhost:3002
curl -s http://localhost:4000/healthz   # sanity
```

Conventions used in every sprint:

- **Base URL**: `http://localhost:4000` (env `QEETID_BASE`).
- **Auth header**: `Authorization: Bearer <access_token>` from the login response.
- **CSRF**: state-changing browser calls need the CSRF cookie+header; for `curl` against the API, set `CSRF_DISABLED=true` in `backend/.env` for local testing (never in prod).
- **Test runners**: ad-hoc `curl` for exploration; **Postman/Newman** (`make test-api`) for repeatable regression; Go tests (`make test-backend`) for unit/integration.
- **From Sprint 1 onward**, prefer **Test Mode (D1)**: spin an ephemeral test tenant, read OTPs/magic-links from the **Dev Inbox** endpoint instead of a real mailbox, and use the **test clock** to fast-forward token expiry. This makes every later sprint testable in seconds.

### Per-scenario format

```
🧪 SCENARIO — <name>
  Pre:    <setup>
  Steps:  <numbered curl/UI actions>
  Expect: <observable result>
  Pass:   [ ] <assertion 1>  [ ] <assertion 2>
```

### Definition-of-Done template (copied into each sprint)

- [ ] All Part-A scenarios pass (boxes ticked) and added to the Postman/Newman regression suite.
- [ ] Part-B feature: backend endpoints + migrations merged; unit/integration tests green.
- [ ] Part-B feature: admin UI wired (no mock data) where applicable.
- [ ] Docs: matching MDX page added/updated under `content/docs/`.
- [ ] Companion roadmap status flags (✅/🟡/❌) updated; backlog item checked off.
- [ ] This sprint's changelog row filled with the actual ship date.

---

## Changelog

| Date | Change |
|---|---|
| 2026-05-29 | Created the sprint folder: index + sprint-1…sprint-10. Defined differentiator catalog D1–D10 and existing-feature E2E test coverage map. |
| 2026-05-29 | **Extended to sprints 11–20 (enterprise-first):** scheduled every COMPETITIVE-ANALYSIS gap (#1–#37) as implementation work, added differentiators D11–D14 (Identity Graph, Break-glass+canaries, Time-Travel Identity, Data Residency+BYOK), and added the coverage matrix proving 37/37 gaps + 14/14 differentiators are scheduled. |
