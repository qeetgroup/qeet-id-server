# Sprint 19 — Fine-grained/ReBAC Authz (#29) + OAuth 2.1/Device/CIBA (#30, #32) + 🚀 Time-Travel Identity (D13) ⏳XL

| | |
|---|---|
| **Window** | 2027-03-22 → 2027-04-09 (3 weeks, ⏳XL) |
| **Theme** | Authorization beyond roles, the last OAuth standards, and point-in-time identity forensics |
| **Depends on** | Sprint 2 (RBAC/explain), Sprint 5 (audit/event sourcing), Sprint 7 (token-exchange) |
| **Closes** | Gaps **#29** (FGA/ReBAC), **#30** (OAuth 2.1/device/token-exchange/DPoP), **#32** (CIBA); New differentiator **D13** |
| **Status** | ⬜ Not started |

**Why:** RBAC can't express "can user edit *this specific document* because they're in the team that owns the folder it's in." That's **relationship-based authorization** (Google Zanzibar / OpenFGA / Ory Keto / WorkOS FGA / Auth0 FGA). We add it, finish the remaining OAuth standards, and — because we already event-source identity + have a verifiable audit chain — ship the rare ability to answer **"what could this user access on date Y?"**

---

## Part A — 🧪 Test the newly-built feature (E2E)

### 🧪 SCENARIO 19.1 — ReBAC check + explain (#29)
- **Steps:** model relations (`document:readme#owner@user:alice`, `folder:docs#parent@…`); query `POST /v1/fga/check` for `user:bob can edit document:readme`.
- **Expect:** decision follows relationship tuples + rewrite rules; `POST /v1/fga/explain` shows the path (extends Sprint-2 D2 explainability to ReBAC); `expand` lists who has a relation.
- **Pass:** [ ] tuple-based allow/deny correct [ ] nested/inherited relations resolve [ ] explain shows the relationship path [ ] check is low-latency under many tuples.

### 🧪 SCENARIO 19.2 — Device authorization flow (#30)
- **Steps:** CLI/TV-style: `POST /oauth/device/code` → show user_code → user approves on phone → device polls `/token`.
- **Pass:** [ ] device code + verification URI issued [ ] polling respects `slow_down`/`authorization_pending` [ ] approval mints tokens [ ] expiry enforced.

### 🧪 SCENARIO 19.3 — Token exchange (RFC 8693) + DPoP (#30)
- **Pass:** [ ] token exchange downscopes/delegates (reuses Sprint-7 `act` chains) [ ] DPoP sender-constrained tokens bound to a key; replay on another client rejected.

### 🧪 SCENARIO 19.4 — CIBA (#32)
- **Steps:** back-channel: initiate auth for a user out-of-band (e.g. push approval), poll/notify on completion.
- **Pass:** [ ] decoupled approval works [ ] poll + ping modes [ ] expiry/denied handled.

### 🧪 SCENARIO 19.5 — Time-Travel Identity (D13)
- **Steps:** `GET /v1/users/{u}/access-at?ts=2027-01-15T00:00:00Z` and `GET /v1/users/{u}/timeline`.
- **Expect:** reconstructs the user's roles/groups/permissions/identities **as they were** at that timestamp, from the event log + audit chain; timeline shows every change with the audit proof (D5).
- **Pass:** [ ] point-in-time access matches what was true then (verify against a known change) [ ] timeline is complete + ordered [ ] each entry links to a verifiable audit proof [ ] works for revoked/merged accounts.

**Part A exit:** scenarios green + in Newman (`FOLDER=Authz`, `FOLDER=OAuth`).

---

## Part B — Build

### B1. Fine-grained / ReBAC authz (#29)
**Backend**: `internal/fga/` — Zanzibar-style relationship store + check/expand/explain, or **embed OpenFGA** as the engine with Qeet ID as the management/identity layer. Authorization model DSL per tenant; tuple write API; consistency + caching for low-latency `check`. Migration `0044_fga.up.sql`: `fga.tuples`, `fga.models`. Unify with RBAC: roles become a special case; `check` can consult both.
**Frontend (admin)**: relationship/model editor (extends `access/policies`), tuple browser, ReBAC explain visualizer.

### B2. OAuth 2.1 standards (#30, #32)
**Backend**: device authorization grant; token exchange (RFC 8693, building on Sprint 7); DPoP (RFC 9449) sender-constrained tokens; CIBA (back-channel) with poll/ping/push. Align defaults to OAuth 2.1 (PKCE everywhere, no implicit). Update discovery metadata.

### B3. Time-Travel Identity (D13)
**Backend**: `internal/timetravel/` — a projection/replay over the existing transactional outbox events + audit chain to reconstruct identity state at any timestamp; `access-at` + `timeline` endpoints; each result carries D5 inclusion proofs. (If full event sourcing isn't present for every domain, add change-event capture for users/roles/groups/identities first.)
**Frontend (admin)**: a user "Timeline" view + "View access as of \<date\>" mode for investigations/audits.

**Docs**: `content/docs/authorization/fga.mdx`, `content/docs/api/oauth-advanced.mdx` (device/exchange/DPoP/CIBA), `content/docs/identity/time-travel.mdx`.

### Acceptance criteria
- [ ] ReBAC check/expand/explain correct + low-latency; unified with RBAC; per-tenant model.
- [ ] Device flow, token exchange, DPoP, CIBA conform to their RFCs (negative tests included).
- [ ] Time-travel reconstructs accurate point-in-time access with verifiable audit proofs, incl. for merged/revoked users.

---

## Definition of Done
- [ ] Part A: all scenarios pass + in Newman.
- [ ] Part B: `fga` (or embedded OpenFGA), OAuth-2.1 grants, `timetravel` module, migrations, tests green.
- [ ] Admin ReBAC model editor + user Timeline / access-as-of views live.
- [ ] `authorization/fga.mdx`, `api/oauth-advanced.mdx`, `identity/time-travel.mdx` published.
- [ ] Roadmap: #29, #30, #32 checked; D13 noted; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
