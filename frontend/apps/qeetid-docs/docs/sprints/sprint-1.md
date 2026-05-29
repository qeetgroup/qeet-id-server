# Sprint 1 — Core Auth E2E + 🚀 Test Mode & Dev Inbox (D1)

| | |
|---|---|
| **Window** | 2026-06-01 → 2026-06-12 (2 weeks) |
| **Theme** | Lock down the auth foundation, then make the whole platform trivially testable |
| **Depends on** | Nothing (this is the base) |
| **Closes** | New differentiator **D1**; supports all later sprints' testing |
| **Status** | ⬜ Not started |

**Why this sprint is first:** you can't trust features built on an unverified base, and you can't iterate fast if testing OTPs/magic-links means checking a real mailbox. So we (A) prove core auth end-to-end, then (B) build the test harness that makes every subsequent sprint a 30-second loop.

---

## Part A — 🧪 Test existing features (E2E)

> Stack up (`make db-up && make migrate-up && make dev-backend`), `CSRF_DISABLED=true` in `backend/.env` for curl. Set `QEETID_BASE=http://localhost:4000`.

### 🧪 SCENARIO 1.1 — Signup creates user + personal tenant
- **Pre:** clean DB.
- **Steps:**
  1. `curl -s -X POST $QEETID_BASE/v1/auth/signup -H 'Content-Type: application/json' -d '{"email":"alice@test.dev","password":"Sup3r-Secret!","display_name":"Alice"}'`
- **Expect:** `201`, body has `user.id`, `tenant.id`, `access_token`, `refresh_token`.
- **Pass:** [ ] user row exists [ ] a personal tenant was auto-created [ ] tokens returned [ ] password not echoed back.

### 🧪 SCENARIO 1.2 — Login with correct + wrong password
- **Steps:** login with correct password, then with a wrong one.
- **Expect:** correct → `200` + tokens; wrong → `401`. Both responses take ≥ ~250ms (timing floor).
- **Pass:** [ ] correct logs in [ ] wrong rejected [ ] no user-enumeration difference in message/latency.

### 🧪 SCENARIO 1.3 — Refresh-token rotation
- **Steps:** `POST /v1/auth/refresh` with the refresh token; then call refresh again with the **same old** token.
- **Expect:** first call → `200` with a **new** refresh token (rotated); reusing the old one → `401`.
- **Pass:** [ ] new refresh token differs [ ] old token rejected after rotation.

### 🧪 SCENARIO 1.4 — Refresh-token **theft detection** (the differentiator we already have)
- **Steps:** login → get refresh token R1. Rotate R1 → R2 (normal). Now replay R1 again (simulating a thief who stole R1).
- **Expect:** replay of R1 → `401` **and the entire session is revoked** (R2 also stops working); an audit event is written.
- **Pass:** [ ] R2 invalidated after R1 replay [ ] `GET /v1/auth/sessions` shows the session gone/revoked [ ] audit event recorded.

### 🧪 SCENARIO 1.5 — Sessions: list + revoke
- **Steps:** login twice (two devices) → `GET /v1/auth/sessions`; then `DELETE /v1/auth/sessions/{id}` for one.
- **Expect:** two sessions listed; after delete, that session's tokens stop working; the other still works.
- **Pass:** [ ] both sessions listed with IP/UA [ ] targeted revoke works [ ] other session unaffected.

### 🧪 SCENARIO 1.6 — `/me`, logout
- **Steps:** `GET /v1/auth/me` with access token; `POST /v1/auth/logout`; call `/me` again.
- **Expect:** first `/me` → user context; after logout → `401`.
- **Pass:** [ ] `/me` returns correct identity+tenant [ ] logout revokes session.

### 🧪 SCENARIO 1.7 — Forgot/reset password
- **Steps:** `POST /v1/auth/forgot-password` for alice; grab the reset token (from logs today; from **Dev Inbox** once D1 ships); `POST /v1/auth/reset-password`; login with new password.
- **Expect:** reset succeeds; **all existing sessions revoked**; old password fails; new works.
- **Pass:** [ ] enumeration-safe response (same for unknown email) [ ] token single-use [ ] sessions revoked on reset.

### 🧪 SCENARIO 1.8 — Magic link login
- **Steps:** `POST /v1/auth/magic-link/start`; grab token; `POST /v1/auth/magic-link/consume`.
- **Expect:** consume → `200` + session/tokens; token single-use; expires after TTL.
- **Pass:** [ ] login without password [ ] reused link rejected [ ] expired link rejected.

**Part A exit:** all 8 scenarios green + added to the Newman regression suite (`make test-api FOLDER=Auth`).

---

## Part B — 🚀 D1: Test Mode & Dev Inbox

### The problem nobody solves well
Testing authentication is painful on every platform: OTPs and magic links land in real mailboxes, you can't fast-forward token expiry, and you pollute prod data with test users. Clerk has a partial "test emails/phones"; nobody offers a full **deterministic sandbox + dev message inbox + controllable clock** as a first-class, self-host feature.

### Our solution
A **Test Mode** that any tenant can flip on (and that's default-on for tenants flagged `is_test`):
1. **Dev Inbox** — every message the platform would send (magic link, email/phone OTP, password-reset, invite, verification) is captured to a queryable store instead of (or in addition to) the real sender. Read it via API + an admin "Dev Inbox" screen.
2. **Deterministic test users** — magic emails/phones (e.g. `+1555…`, `*@test.qeetid.dev`) that always accept a fixed OTP (e.g. `000000`) so automated tests don't need the inbox.
3. **Test clock** — a per-request/ per-test-tenant `X-Qeetid-Test-Clock` (or stored offset) that shifts "now" so you can test token/session/OTP **expiry** in seconds, not hours.
4. **Ephemeral tenants** — `POST /v1/test/tenants` creates a throwaway tenant with auto-TTL cleanup, so tests never touch real data.

### Design / changes

**Backend**
- New module `internal/testmode/`:
  - `POST /v1/test/tenants` → create ephemeral tenant (returns admin token); background reaper deletes after TTL.
  - `GET /v1/test/inbox?tenant_id=&to=&type=` → list captured messages (magic link, otp, email, sms) with their tokens/codes extracted.
  - `DELETE /v1/test/inbox` → clear.
- `internal/platform/notifier/`: add a `CapturingSender` that wraps the configured sender and writes to a `test.messages` table when the tenant/env is in test mode. **Hard guard:** Test Mode is rejected unless `SERVICE_ENV != production` **or** tenant `is_test=true`.
- `internal/platform/clock/`: introduce a `Clock` interface (replace direct `time.Now()` in token/OTP/session TTL checks). Test clock honored only for test tenants.
- Migration `0026_testmode.up.sql`: `test.messages`, `tenant.is_test` column, `tenant.test_clock_offset`.

**Frontend (admin)**
- New screen **Developers → Dev Inbox**: live table of captured messages with "copy link/code" buttons; tenant test-mode toggle; "Reset test data" button. (Replaces the placeholder dev area.)

**Docs**
- New `content/docs/testing.mdx`: "Testing Qeet ID locally — Test Mode, Dev Inbox, magic credentials, clock control," with copy-paste examples that the rest of these sprints reference.

### Acceptance criteria
- [ ] Creating an ephemeral test tenant works and it auto-expires.
- [ ] A magic-link/OTP send in test mode appears in the Dev Inbox API + admin screen within 1s and is **not** sent to a real provider.
- [ ] Magic test users accept the fixed OTP.
- [ ] Advancing the test clock past a token's TTL makes that token expire on the next call.
- [ ] Test Mode is **impossible to enable in production** for non-test tenants (guard test covers this).

### 🧪 How you test D1
1. `curl -X POST $QEETID_BASE/v1/test/tenants` → get `tenant_id` + admin token.
2. Run Scenario 1.7/1.8 again but read the token from `GET /v1/test/inbox?type=magic_link` instead of logs.
3. Set the test clock +2h, retry the magic link → expired. Set it back → works (fresh link).
4. Confirm in admin **Dev Inbox** the messages render with copy buttons.

---

## Definition of Done
- [ ] Part A: all 8 scenarios pass + in Newman suite.
- [ ] Part B: `testmode` module + clock abstraction + migration merged; tests green; prod guard verified.
- [ ] Admin Dev Inbox screen live (no mocks).
- [ ] `content/docs/testing.mdx` published.
- [ ] Roadmap doc: note D1 added; this file's status → ✅; changelog row filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
