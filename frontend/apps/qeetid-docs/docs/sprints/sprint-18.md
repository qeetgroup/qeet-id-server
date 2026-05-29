# Sprint 18 — Actions/Hooks Engine (#25) + 🚀 Break-glass Admin Recovery & Auth Canaries (D12)

| | |
|---|---|
| **Window** | 2027-03-08 → 2027-03-19 (2 weeks) |
| **Theme** | Customer-defined logic in the auth pipeline, plus operational resilience for the auth system itself |
| **Depends on** | Sprint 16 (SDKs), Sprints 6/15 (webhooks/risk), Sprint 8 (lockdown) |
| **Closes** | Gap **#25** (Actions/Hooks); New differentiator **D12** |
| **Status** | ⬜ Not started |

**Why:** Auth0 Actions / Zitadel Actions v2 / FusionAuth Lambdas let customers inject custom logic (enrich tokens, block sign-ups, sync to CRM). We have none. **And** a problem nobody addresses: *what happens when the identity system itself fails or locks you out?* We add **break-glass admin recovery** and **synthetic auth canaries** so you find out before your customers do.

---

## Part A — 🧪 Test the newly-built feature (E2E)

### 🧪 SCENARIO 18.1 — Actions/Hooks (#25)
- **Steps:** register an action on `pre-registration`, `post-login`, and `pre-token-issuance` that calls an external endpoint (your test server); trigger each.
- **Expect:** action runs at the right pipeline stage; can **enrich** token claims, **block** (deny sign-up), or **require step-up**; timeouts/failures fail safe per policy; runs are logged.
- **Pass:** [ ] each hook point fires [ ] claim enrichment lands in the token (verify via Sprint-4 explain) [ ] a denying action blocks the flow [ ] action timeout → safe default + alert [ ] versioned + per-tenant.

### 🧪 SCENARIO 18.2 — Break-glass admin recovery (D12)
- **Pre:** simulate "we're locked out" — e.g. the only admin's MFA device is lost AND SSO is misconfigured.
- **Steps:** invoke the break-glass procedure (pre-provisioned, sealed recovery credentials + quorum approval).
- **Expect:** a time-boxed, heavily-audited emergency admin session is granted only after the configured quorum (e.g. 2-of-3 sealed shares) and cool-down; everything is alerted to all owners.
- **Pass:** [ ] single share insufficient [ ] quorum + cool-down grants emergency access [ ] session is time-boxed, scope-limited, loudly audited [ ] auto-revokes; can't be silently abused.

### 🧪 SCENARIO 18.3 — Auth canaries (D12)
- **Steps:** enable a per-tenant synthetic canary that performs a real end-to-end login (test user via Sprint-1 Test Mode) every N minutes.
- **Expect:** canary results feed an auth SLO/status view; a broken flow (e.g. SAML cert expired) raises an alert **before** real users hit it.
- **Pass:** [ ] canary runs on schedule [ ] failure alerts + shows on status page [ ] per-method canaries (password/passkey/SSO) [ ] no pollution of real metrics.

**Part A exit:** scenarios green; canaries running for the local tenant; break-glass rehearsed + documented.

---

## Part B — Build

### B1. Actions/Hooks engine (#25)
**Backend**: `internal/actions/` — pipeline hook points (`pre-registration`, `post-login`, `pre-token-issuance`, `pre-mfa`, `post-provision`), **external-endpoint targets** (Zitadel-v2 style: customer hosts the logic; we call it with signed payloads + timeouts) and/or sandboxed inline JS. Versioned, per-tenant, with run logs + replay. Claim-mutation contract for token enrichment. Migration `0042_actions.up.sql`: `actions.definitions`, `actions.runs`.
**Frontend (admin)**: Actions registry/editor + run logs + test-fire. (Replaces the "bots"/automation stub.)

### B2. Break-glass + canaries (D12)
**Backend**: `internal/breakglass/` — sealed recovery credentials (Shamir shares / sealed env), quorum approval, time-boxed emergency principal, loud alerting; designed to work even if SSO/IdP integrations are down (local-only path). `internal/canary/` — scheduled synthetic auth runs per tenant per method using Test-Mode users; SLO store + status endpoint. Migration `0043_breakglass_canary.up.sql`.
**Frontend**: Break-glass setup (define quorum/holders) + emergency-access flow; **Auth Status/SLO** dashboard (per-tenant, per-method health) — turns the unaddressed "is our auth healthy?" question into a real signal.

**Docs**: `content/docs/extensibility/actions.mdx`, `content/docs/operations/break-glass.mdx`, `content/docs/operations/auth-canaries.mdx`.

### Acceptance criteria
- [ ] Actions run at each hook point; can enrich/deny/step-up; fail safe; versioned + logged + replayable.
- [ ] Break-glass requires quorum + cool-down, yields a time-boxed loudly-audited session, works without external IdPs, and auto-revokes.
- [ ] Canaries run per method on schedule, alert on failure, and surface on an auth SLO/status view without polluting real metrics.

---

## Definition of Done
- [ ] Part A: actions + break-glass + canary scenarios pass.
- [ ] Part B: `actions`, `breakglass`, `canary` modules, migrations, tests green.
- [ ] Admin Actions editor + break-glass setup + Auth Status dashboard live.
- [ ] `extensibility/actions.mdx`, `operations/break-glass.mdx`, `operations/auth-canaries.mdx` published.
- [ ] Roadmap: #25 checked; D12 noted; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
