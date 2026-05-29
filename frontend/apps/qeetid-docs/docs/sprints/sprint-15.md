# Sprint 15 — Attack-Protection Suite (#16–#21)

| | |
|---|---|
| **Window** | 2027-01-11 → 2027-01-22 (2 weeks) |
| **Theme** | Auth0-grade defenses: breached passwords, brute-force, bots, adaptive MFA, step-up, anomaly alerts |
| **Depends on** | Sprints 1 (Test Mode), 4 (revocation), 7 (Dev Inbox for notifications) |
| **Closes** | Gaps **#16, #17, #18, #19, #20, #21**; turns the admin `threats/*` + `mfa/*` stubs real; deepens **D10** (continuous trust) |
| **Status** | ⬜ Not started |

**Why:** Auth0's moat is its **Attack Protection** suite. Qeet ID has none of it (the admin "threats" screens are mocks). This sprint builds the whole defensive layer at once because the pieces share infrastructure (a risk-signal pipeline). It also feeds **D10 Continuous Trust** (Sprint 10) — if you want richer trust scoring earlier, run this sprint before Sprint 10.

---

## Part A — 🧪 Test the newly-built feature (E2E)

### 🧪 SCENARIO 15.1 — Breached-password detection (#16)
- **Steps:** sign up / reset with a known-pwned password (use a test value the local HIBP-range mock returns as breached).
- **Expect:** blocked (or warned, per policy) at signup, login, and reset; never sends the full password/hash off-box (k-anonymity range query).
- **Pass:** [ ] breached pw blocked per policy [ ] only the SHA-1 prefix leaves the box [ ] clean pw passes.

### 🧪 SCENARIO 15.2 — Brute-force + suspicious-IP throttling (#17)
- **Steps:** hammer login with wrong passwords from one IP; then distributed across IPs for one account.
- **Expect:** progressive throttle/lockout per IP **and** per account; legit user notified; lockout auto-expires (Test Clock).
- **Pass:** [ ] per-IP throttle [ ] per-account lockout [ ] notification sent (Dev Inbox) [ ] auto-unlock.

### 🧪 SCENARIO 15.3 — Bot detection (#18)
- **Steps:** simulate bot-like traffic (no JS challenge token / known-bad signals); compare to human.
- **Expect:** risk raised; optional CAPTCHA/Turnstile challenge injected; pluggable provider.
- **Pass:** [ ] bot signals raise risk [ ] challenge injected above threshold [ ] humans unaffected.

### 🧪 SCENARIO 15.4 — Adaptive / risk-based MFA + step-up (#19, #20)
- **Steps:** log in from a known device/IP (low risk) vs a new device/new country/impossible-travel (high risk).
- **Expect:** low risk → no extra friction; high risk → **step-up** (MFA/passkey re-challenge). A `step-up` primitive also guards sensitive actions and sets `acr`/`amr` claims.
- **Pass:** [ ] risk score drives MFA prompt [ ] step-up enforced before sensitive action [ ] `acr/amr` reflected in token (verify via Sprint-4 token explain).

### 🧪 SCENARIO 15.5 — Anomaly detection + notifications (#21)
- **Pass:** [ ] new-device / new-location login fires a user notification [ ] admin sees anomaly events [ ] tunable sensitivity.

**Part A exit:** scenarios green + in Newman (`FOLDER=Security`); admin threat dashboards show **real** data.

---

## Part B — Build: the risk pipeline + defenses

### Design / changes
**Backend**
- New module `internal/risk/`: a **signal pipeline** evaluated at login & sensitive actions, producing a risk score + reasons (reuses the D2 "explain" pattern). Signals: IP/ASN reputation, geo + impossible travel, device fingerprint drift, velocity, breached-credential hit, bot score.
- `internal/risk/breached`: HIBP-style **k-anonymity** range client (pluggable; cache prefixes) — #16.
- `internal/risk/throttle`: per-IP + per-account brute-force throttle/lockout with notifications — #17. (Distributed via Redis from #7.)
- `internal/risk/bot`: pluggable bot/CAPTCHA provider interface (Turnstile/hCaptcha/reCAPTCHA) — #18.
- **Adaptive MFA / step-up** (#19, #20): policy that maps risk → required auth level; `POST /v1/auth/step-up` issues an elevated session; `acr`/`amr` claims; sensitive-scope gating (ties to D7 agents + D8 impersonation + D10 trust).
- **Anomaly + notifications** (#21): detectors + the (real, #4) notifier; `tenant.anomaly.*` webhooks.
- Migration `0041_risk.up.sql`: `risk.events`, `risk.lockouts`, `risk.device_fingerprints`, policy fields for thresholds.

**Frontend (admin)**
- Replace stubs: **Threats → Bots / Anomalies / Rate-limits / IP-allowlist** become real dashboards; **MFA → Adaptive** policy editor; risk-event log with the "why" explanation.

**Docs**
- `content/docs/security/attack-protection.mdx` (suite overview), `content/docs/security/adaptive-mfa.mdx`, `content/docs/security/step-up.mdx`.

### Acceptance criteria
- [ ] Breached passwords blocked via k-anonymity (full secret never leaves the box).
- [ ] Brute-force throttling works per-IP and per-account, distributed (Redis), with auto-expiry + notifications.
- [ ] Bot challenge injects above a tunable threshold via a pluggable provider.
- [ ] Risk score drives adaptive MFA; step-up enforced for sensitive actions with `acr/amr` claims.
- [ ] Anomalies notify users + admins; thresholds tunable per tenant.
- [ ] Admin threat/MFA screens show real data (no mocks).

---

## Definition of Done
- [ ] Part A: all scenarios pass + in Newman.
- [ ] Part B: `risk` module (breached/throttle/bot/adaptive/anomaly), step-up, migrations, tests green; Redis (#7) used for distributed state.
- [ ] Admin threat + adaptive-MFA dashboards real (stubs replaced).
- [ ] `security/attack-protection.mdx`, `adaptive-mfa.mdx`, `step-up.mdx` published.
- [ ] Roadmap: #16–#21 (and #7 Redis) checked; status ✅; changelog filled; D10 trust signals upgraded.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
