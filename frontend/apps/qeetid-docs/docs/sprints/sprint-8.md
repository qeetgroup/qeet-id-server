# Sprint 8 — Sessions/Keys E2E + 🚀 Safe Impersonation + Tenant Kill-Switch (D8)

| | |
|---|---|
| **Window** | 2026-09-07 → 2026-09-18 (2 weeks) |
| **Theme** | Verify revocation paths, then ship two operational superpowers: guarded support impersonation and instant breach containment |
| **Depends on** | Sprints 1, 5 (audit), 7 (revocation patterns) |
| **Closes** | New differentiator **D8** |
| **Status** | ⬜ Not started |

**Why:** Two real operational gaps. (1) Support staff routinely need to "see what the user sees," but most platforms either forbid it or allow unguarded impersonation with no consent and weak audit. (2) When a tenant is breached, responders need a single, instant action to **revoke everything** — sessions, tokens, keys — and force re-auth. Neither is solved cleanly elsewhere.

---

## Part A — 🧪 Test existing features (E2E)

### 🧪 SCENARIO 8.1 — Session revocation propagation
- **Steps:** create 3 sessions; revoke one via `DELETE /v1/auth/sessions/{id}`; confirm access + refresh both fail for that session immediately.
- **Pass:** [ ] revoked session's access token rejected [ ] its refresh token rejected [ ] others unaffected.

### 🧪 SCENARIO 8.2 — API-key & principal revocation
- **Steps:** revoke an API key and disable a service principal mid-use.
- **Pass:** [ ] immediate effect [ ] audit records the revocation actor.

### 🧪 SCENARIO 8.3 — Branding & policy storage round-trip
- **Steps:** `PUT /v1/tenants/{t}/branding` (logo/colors/domain) then GET; `PUT /v1/tenants/{t}/policy` (IP allow/deny, MFA mode, session age) then GET.
- **Expect:** values persist & return. *(Enforcement of policy is roadmap #6 / Sprint 10 — here we only verify storage.)*
- **Pass:** [ ] branding round-trips [ ] policy round-trips.

**Part A exit:** green + in Newman (`FOLDER=Sessions`, `FOLDER=Branding`).

---

## Part B — 🚀 D8: Safe Impersonation + Tenant Kill-Switch

### B1. Safe Impersonation ("Support Mode")
**The problem.** Debugging "it doesn't work for this customer" needs seeing their view, but naive impersonation = privacy violation + no accountability. 

**Our solution.**
- **Consent-gated**: impersonation requires either explicit user consent (a grant the user can give/revoke) **or** a break-glass approval by a second admin (four-eyes) for support tiers that allow it — configurable per tenant.
- **Time-boxed & scoped**: an impersonation session is short-TTL, visibly **marked** (token carries `act` = support agent, like D7's actor chain), and can be **read-only** or **limited-scope** (no password changes, no MFA disable, no billing).
- **Fully audited & visible to the user**: every impersonated action is audited with the real operator's identity and surfaced to the end user ("Acme Support viewed your account on …"). Anchored via D5.
- **Banner + auto-expiry**: the admin UI shows a persistent "You are impersonating X" banner; session auto-ends.

Endpoints: `POST /v1/tenants/{t}/users/{u}/impersonate` (returns a marked session, subject to consent/approval policy), `POST /v1/impersonation/{id}/end`, `GET /v1/users/{u}/impersonation-history`.

### B2. Tenant Kill-Switch ("Breach Containment")
**The problem.** During an incident, responders waste precious minutes revoking sessions, rotating keys, and disabling logins piecemeal. 

**Our solution.** One action, instant blast-radius control:
- `POST /v1/tenants/{t}/lockdown` with options: revoke **all** sessions & refresh tokens, revoke/rotate **all** API keys & principal secrets, invalidate outstanding OIDC tokens (bump revocation epoch from D4), force MFA re-enrollment or step-up on next login, optionally freeze new logins entirely.
- `POST /v1/tenants/{t}/lockdown/lift` to restore, with a required reason + second-admin approval.
- Every lockdown/lift is audited + webhooked (`tenant.lockdown.*`) and broadcast to integrations/SIEM.

### Design / changes
**Backend**
- `internal/impersonation/` + `internal/lockdown/` (or fold into `tenant`/`auth`): impersonation grants & marked sessions; lockdown orchestrator that fans out revocations across sessions, refresh tokens, api keys, principals, and the token revocation epoch (D4).
- Migration `0033_impersonation_lockdown.up.sql`: `impersonation_sessions`, `impersonation_consents`, `tenant.lockdown_state`.
- Reuse D4 revocation digest so edge verifiers honor lockdown instantly.

**Frontend (admin)**
- Impersonation: "Impersonate" action on user detail (gated by policy/approval) + global impersonation banner + per-user impersonation history.
- Lockdown: a prominent, confirm-twice **"Lock down tenant"** control on the security page + status indicator + lift flow.

**Docs**
- `content/docs/operations/impersonation.mdx`, `content/docs/operations/breach-lockdown.mdx`.

### Acceptance criteria
- [ ] Impersonation can't start without consent or four-eyes approval (per policy); is time-boxed, marked, and scope-limited.
- [ ] Impersonated actions are audited with the operator's real identity and visible to the user.
- [ ] Sensitive actions (password/MFA/billing) are blocked during impersonation.
- [ ] Kill-switch revokes sessions + tokens + keys and bumps the revocation epoch so edge verifiers reject within one digest refresh.
- [ ] Lift requires reason + second approval; everything audited + webhooked.

### 🧪 How you test D8
1. Try to impersonate without consent → blocked. Grant consent (or simulate four-eyes) → marked session issued; confirm `/tokens/explain` shows operator as `act`.
2. While impersonating, try to disable the user's MFA → blocked; confirm the user sees the impersonation in their history.
3. Trigger `lockdown`; confirm all the user's sessions/keys die immediately and the edge verifier (D4) rejects a previously-valid token after pulling the new revocation digest.
4. Lift lockdown with a second admin; confirm restoration + audit + webhook.

---

## Definition of Done
- [ ] Part A: scenarios pass + in Newman.
- [ ] Part B: impersonation + lockdown modules, migrations, revocation fan-out, tests green.
- [ ] Admin impersonation (gated) + banner + history, and kill-switch + lift UIs live.
- [ ] `operations/impersonation.mdx` + `operations/breach-lockdown.mdx` published.
- [ ] Roadmap: D8 noted; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
