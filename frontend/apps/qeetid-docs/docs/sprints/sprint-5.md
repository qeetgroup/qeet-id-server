# Sprint 5 — Audit & Analytics E2E + 🚀 Publicly-Verifiable Audit (D5)

| | |
|---|---|
| **Window** | 2026-07-27 → 2026-08-07 (2 weeks) |
| **Theme** | Verify the audit chain & analytics, then make the audit log provable to a third party — no vendor trust required |
| **Depends on** | Sprints 1–2 (generate auditable events) |
| **Closes** | New differentiator **D5**; supports roadmap **#14 (audit export)** |
| **Status** | ⬜ Not started |

**Why:** Qeet ID already has a hash-chained, append-only audit log — a genuine edge. Sprint 5 turns that from "trust us, it's tamper-evident" into **"here's cryptographic proof your auditor can verify independently."** No mainstream CIAM offers externally-verifiable audit.

---

## Part A — 🧪 Test existing features (E2E)

### 🧪 SCENARIO 5.1 — Audit events are written for mutations
- **Steps:** perform a mix of actions (create user, assign role, reset password, revoke session); `GET /v1/tenants/{t}/audit`.
- **Expect:** each action produces an event with actor, action, target, IP/UA, request_id, timestamp.
- **Pass:** [ ] all actions logged [ ] actor attribution correct [ ] cursor pagination works.

### 🧪 SCENARIO 5.2 — Hash-chain integrity verify
- **Steps:** `GET /v1/tenants/{t}/audit/verify`.
- **Expect:** chain verifies (each event hash links to prior).
- **Pass:** [ ] verify returns OK on an intact chain.

### 🧪 SCENARIO 5.3 — Tamper detection (negative test)
- **Steps:** in a **test DB only**, mutate one audit row's payload directly via SQL; re-run `/verify`.
- **Expect:** verify **fails** and points at the first broken link.
- **Pass:** [ ] tampering detected [ ] break location reported. *(Restore/rebuild the test DB after.)*

### 🧪 SCENARIO 5.4 — Analytics overview
- **Steps:** `GET /v1/tenants/{t}/analytics/overview` after seeding logins/MFA/failures.
- **Expect:** MAU/DAU, login & MFA trends, failed-login trend, login-method mix reflect seeded data.
- **Pass:** [ ] KPIs match seeded data [ ] trends render in admin dashboard.

**Part A exit:** green + in Newman (`FOLDER=Audit`, `FOLDER=Analytics`).

---

## Part B — 🚀 D5: Publicly-Verifiable Audit (Merkle Transparency)

### The problem nobody solves well
Tamper-evident audit logs (where they exist) are verified **by the same vendor that stores them** — circular trust. For SOC 2 / regulatory disputes / insider-threat scenarios, customers want to prove integrity **independently**, even against a malicious or compromised provider. This is solved in certificate transparency and some blockchains, but **not** in CIAM audit products.

### Our solution — Merkle checkpoints + external anchoring
1. **Per-tenant Merkle tree** over audit events (on top of the existing hash chain). Periodically (e.g. hourly / every N events) compute a **signed checkpoint** = `{tree_size, root_hash, timestamp, signature}`.
2. **Inclusion + consistency proofs**: 
   - `GET /v1/tenants/{t}/audit/{event_id}/proof` → Merkle inclusion proof that event E is in checkpoint C.
   - `GET /v1/tenants/{t}/audit/checkpoints` → signed checkpoint history; `…/consistency?from=&to=` → proof that the log is append-only between two checkpoints (no rewrite).
3. **External anchoring** (optional, pluggable): publish checkpoint roots to an independent witness — an append-only public log, a customer-owned S3 WORM bucket, a transparency-log service, or email-to-self. Even a public Git/RFC3161 timestamp works. The point: the root is recorded **outside** Qeet ID's control.
4. **Standalone verifier**: a tiny open-source CLI (`qeetid-audit-verify`) that takes an event export + proofs + a checkpoint and verifies inclusion/consistency **without touching our servers**. Hand it to your auditor.

### Design / changes
**Backend**
- `internal/audit/`: add Merkle layer over events; checkpoint builder (background job); proof endpoints; signing with the OIDC signing key (from #3/D4) so checkpoints are verifiable via JWKS.
- Anchoring interface `Witness` with implementations: `S3WORM`, `Webhook`, `Stdout/Git` (start simple).
- **Audit export (#14)**: `GET /v1/tenants/{t}/audit/export?format=csv|jsonl` (streamed) + SIEM webhook streaming — exports include the proofs so they're self-verifying.
- Migration `0030_audit_merkle.up.sql`: `audit.checkpoints`, `audit.tree_nodes` (or compute on read), anchor records.

**Frontend (admin)**
- **Security → Audit**: "Integrity" panel showing latest checkpoint, anchor status, and a "Download verifiable export" button (events + proofs + checkpoint). One-click "Verify now."

**Docs**
- `content/docs/audit.mdx`: add "Verifiable audit & external anchoring," including how to run `qeetid-audit-verify`.

### Acceptance criteria
- [ ] Checkpoints are produced, signed, and verifiable via the public JWKS key.
- [ ] Inclusion proof verifies a specific event against a checkpoint.
- [ ] Consistency proof detects any attempt to rewrite/delete history between checkpoints.
- [ ] The standalone verifier validates an export **offline** with zero calls to Qeet ID.
- [ ] At least one anchoring backend (S3 WORM or webhook) records roots externally.
- [ ] CSV/JSONL export streams large logs without OOM.

### 🧪 How you test D5
1. Generate 1k events; pull the latest checkpoint; export events+proofs; run `qeetid-audit-verify` offline → PASS.
2. Tamper one exported event → verifier FAILS on inclusion.
3. In a test DB, delete a historical event and rebuild a checkpoint → **consistency** proof between old and new checkpoint FAILS (rewrite detected).
4. Confirm the checkpoint root also appears in the configured external anchor (e.g. the WORM bucket).

---

## Definition of Done
- [ ] Part A: scenarios pass (incl. tamper negative test) + in Newman.
- [ ] Part B: Merkle checkpoints, inclusion/consistency proofs, ≥1 anchor, export (#14), standalone verifier shipped.
- [ ] Admin Integrity panel + verifiable export live.
- [ ] `audit.mdx` updated; verifier published OSS.
- [ ] Roadmap: #14 checked; D5 noted; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
