# Sprint 3 — MFA & Passwordless E2E + 🚀 Resilient Passwordless Recovery (D3)

| | |
|---|---|
| **Window** | 2026-06-29 → 2026-07-10 (2 weeks) |
| **Theme** | Verify MFA & OTP delivery, then solve the #1 unsolved passwordless problem: **account recovery** |
| **Depends on** | Sprint 1 (Dev Inbox for OTPs). Differentiator D3 also depends on roadmap **#1 (finish passkeys)** and **#4 (real email/SMS)** — pull those in here. |
| **Closes** | New differentiator **D3**; supports roadmap **#1, #4** |
| **Status** | ⬜ Not started |

**Why:** Passkeys are table stakes, but the dirty secret of going passwordless is **recovery** — lose your device and you're locked out. Every platform punts this back to "email a link" (which re-introduces the password-era weakness) or to support tickets. We make recovery a real, secure, multi-factor flow.

> **Note:** WebAuthn/passkey ceremony is currently `501`. This sprint assumes roadmap #1 lands the ceremony (or schedule #1 at the start of this sprint). The Part-A MFA/OTP tests do not depend on passkeys and can run today.

---

## Part A — 🧪 Test existing features (E2E)

### 🧪 SCENARIO 3.1 — TOTP enrollment
- **Steps:** `POST /v1/mfa/totp/enroll/start` → get secret + provisioning URI; compute a code (use a TOTP lib / `oathtool`); `POST /v1/mfa/totp/enroll/confirm` with the code.
- **Expect:** confirm returns **10 recovery codes** (once); MFA now enabled for the user.
- **Pass:** [ ] secret + otpauth URI returned [ ] wrong code rejected [ ] recovery codes minted once.

### 🧪 SCENARIO 3.2 — TOTP verification window
- **Steps:** `POST /v1/mfa/totp/verify` with current code, then with a code from 2 minutes ago (use Test Clock).
- **Expect:** current → ok; stale → rejected (±1 step window).
- **Pass:** [ ] current accepted [ ] expired rejected [ ] replay of same code rejected.

### 🧪 SCENARIO 3.3 — Recovery codes
- **Steps:** verify using a recovery code; reuse the same code.
- **Expect:** first use ok; reuse rejected (single-use); count decrements.
- **Pass:** [ ] one-time use enforced [ ] remaining count correct.

### 🧪 SCENARIO 3.4 — Disable TOTP
- **Steps:** `DELETE /v1/mfa/totp`.
- **Expect:** secret + all recovery codes wiped; MFA off.
- **Pass:** [ ] full teardown [ ] audit event recorded.

### 🧪 SCENARIO 3.5 — Email & phone OTP delivery (via Dev Inbox)
- **Steps:** `POST /v1/users/{id}/verify/email/start` → read 6-digit code from Dev Inbox → `…/confirm`. Repeat for phone.
- **Expect:** confirm marks `email_verified_at` / `phone_verified_at`; code expires in 10m (test with Test Clock); single-use.
- **Pass:** [ ] code delivered to inbox [ ] confirm sets verified timestamp [ ] expiry + single-use enforced.

**Part A exit:** green + in Newman (`FOLDER=MFA`, `FOLDER=Verification`).

---

## Part B — 🚀 D3: Resilient Passwordless Recovery

### The problem nobody solves well
Passwordless adoption stalls because **losing your authenticator = lockout**, and the common "fix" (email a magic link) silently makes email the weakest single factor — defeating the phishing-resistance passkeys were meant to provide. Auth0/Clerk/WorkOS mostly fall back to email or support. Nobody ships a configurable, **multi-factor, anti-takeover recovery quorum** for passwordless accounts.

### Our solution — "Recovery Quorum"
Recovery requires satisfying a **tenant-configurable quorum of independent factors**, not a single channel:
- **Factors** (any that the user has registered): a second passkey/trusted device, a verified recovery email, a verified recovery phone (OTP), printed recovery codes, and optionally **trusted contacts** (social recovery — N-of-M approvals from designated people).
- **Policy** (per tenant): e.g. "require 2 of {recovery-code, trusted-device, recovery-email+phone}" for account recovery; high-value tenants can require 3.
- **Anti-takeover safeguards:**
  - **Cool-down + notification**: initiating recovery alerts all the user's channels and imposes a delay (configurable, e.g. 24h) before the new credential is usable, during which any existing factor can **cancel** the recovery (stops attacker-initiated recovery).
  - **Step-down protection**: a recovery can't *raise* privileges or disable MFA silently; it re-binds a new authenticator only.
  - Full audit trail (ties into D5 verifiable audit).
- **Self-service enrollment**: users register recovery factors up front (admin and end-user UI), so recovery isn't an afterthought.

### Design / changes

**Backend**
- New module `internal/recovery2/` (or extend `recovery`): 
  - `POST /v1/recovery/start` → opens a recovery attempt, returns required factors per tenant policy, fires notifications + cool-down.
  - `POST /v1/recovery/factor` → submit a factor proof (recovery code, OTP from recovery email/phone, trusted-device assertion, trusted-contact approval token).
  - `POST /v1/recovery/complete` → once quorum met **and** cool-down elapsed, bind new passkey/credential.
  - `POST /v1/recovery/cancel` → any valid existing factor cancels an in-flight recovery.
- Migrations `0028_recovery_quorum.up.sql`: `recovery_attempts`, `recovery_factors`, `trusted_contacts`, tenant `recovery_policy` (quorum + cool-down).
- Notifications via the (now real, #4) email/SMS senders.

**Frontend**
- **Admin**: tenant **Recovery Policy** editor (choose quorum, cool-down). 
- **End-user/account**: "Recovery setup" page to register recovery email/phone/codes/trusted contacts; and the recovery flow UI itself.

**Docs**
- `content/docs/authentication/account-recovery.mdx`: the recovery-quorum model + how to configure.

### Acceptance criteria
- [ ] A passkey-only user who "loses their device" can recover by satisfying the configured quorum.
- [ ] A single compromised channel (e.g. just email) is **insufficient** to recover when policy requires ≥2 factors.
- [ ] Attacker-initiated recovery is cancellable by the real user during cool-down, and the real user is notified on every channel.
- [ ] Recovery binds a new credential only; never disables MFA or escalates roles.
- [ ] Every recovery step is audited.

### 🧪 How you test D3
1. Enroll a user with a passkey + recovery code + recovery email/phone. Set tenant quorum = 2.
2. Simulate device loss: start recovery, submit only the recovery email OTP (1 factor) → blocked.
3. Add the recovery code (2 factors) → quorum met, but blocked until cool-down. Advance Test Clock past cool-down → complete; register a new passkey; log in.
4. Re-run, but as "attacker": start recovery, then from the victim's existing session call `/recovery/cancel` → attempt aborted, victim notified (check Dev Inbox).

---

## Definition of Done
- [ ] Part A: scenarios pass + in Newman.
- [ ] Roadmap #1 (passkeys) + #4 (email/SMS) landed and tested (pre-req).
- [ ] Part B: recovery-quorum module + migrations + tests green; cool-down/cancel verified.
- [ ] Admin recovery-policy + end-user recovery-setup + recovery-flow UIs live.
- [ ] `account-recovery.mdx` published; `passkeys.mdx` updated for real ceremony.
- [ ] Roadmap: #1/#4 checked; D3 noted; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
