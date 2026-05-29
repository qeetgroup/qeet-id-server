# Sprint 10 — Policy Enforcement E2E + 🚀 Continuous Trust + Compliance Evidence Autopilot (D10)

| | |
|---|---|
| **Window** | 2026-10-05 → 2026-10-16 (2 weeks) |
| **Theme** | Wire & verify policy enforcement, then ship continuous (not point-in-time) trust and turn the audit log into automatic compliance evidence |
| **Depends on** | Sprints 1–9 (full stack). Pulls in roadmap **#6 (policy enforcement)**; builds on **#16–#21 (attack protection)** and D5 (verifiable audit). |
| **Closes** | New differentiator **D10**; roadmap **#6**; advances **#36 (SOC2/ISO posture)** |
| **Status** | ⬜ Not started |

**Why:** Two finishing pieces. (1) The per-tenant security policy (IP allow/deny, MFA-required, session age) is **stored but not enforced** — close that gap and verify it. (2) Then leapfrog the market: replace point-in-time risk checks with a **continuous trust score** that drives adaptive step-up, and auto-generate **audit-backed compliance evidence** so SOC 2 / ISO audits stop being manual toil.

---

## Part A — 🧪 Test existing features (E2E) + full regression

### 🧪 SCENARIO 10.1 — Policy enforcement now active (roadmap #6)
- **Pre:** set tenant policy: IP allowlist excludes your current IP; MFA mode = required; session max-age = short.
- **Steps:** attempt login from a disallowed IP; from an allowed IP without MFA; let a session exceed max-age.
- **Expect:** disallowed IP → blocked; missing MFA → step-up demanded; stale session → forced re-auth.
- **Pass:** [ ] IP allow/deny enforced in request path [ ] MFA-required enforced [ ] session max-age enforced.

### 🧪 SCENARIO 10.2 — Full regression pass
- **Steps:** run the entire Newman suite (`make test-api`) + backend tests (`make test-backend`) across all folders built in Sprints 1–9.
- **Pass:** [ ] 100% of regression scenarios green [ ] no flaky tests [ ] coverage report archived.

**Part A exit:** green; the suite is the project's standing regression gate.

---

## Part B — 🚀 D10: Continuous Trust + Compliance Evidence Autopilot

### B1. Continuous Trust Score
**The problem.** Risk is usually evaluated **only at login** (Auth0 Adaptive MFA fires once). But sessions live for hours/days; a token stolen mid-session sails through. Few platforms re-evaluate trust **continuously**.

**Our solution.**
- A per-session **trust score** updated on signals throughout the session: IP/ASN change, device-fingerprint drift, impossible travel, anomalous action velocity, breached-credential hits (#16), bot signals (#18), time-of-day, and sensitivity of the action requested.
- **Adaptive enforcement**: when the score drops below a tenant-configurable threshold for the attempted action, demand **step-up** (re-auth / MFA / passkey) inline — not a full re-login. Sensitive scopes (and D7 agent sensitive-actions) require a minimum trust floor.
- Exposes `GET /v1/sessions/{id}/trust` and emits `session.trust.changed` webhooks; integrates the Sprint-2 `explain` style so you can see **why** trust dropped.

### B2. Compliance Evidence Autopilot
**The problem.** SOC 2 / ISO 27001 audits are mostly evidence-gathering toil: screenshots, CSVs, "prove access reviews happened." The data already lives in Qeet ID's audit log — but nobody turns it into auditor-ready evidence automatically.

**Our solution.**
- **Control mapping**: map Qeet ID events/config to common controls (SOC 2 CC-series, ISO 27001 Annex A): e.g. "CC6.1 logical access" ← role assignments + MFA enforcement; "access review" ← periodic effective-permission snapshots; "change management" ← admin config changes.
- **Evidence packs**: `POST /v1/compliance/evidence?framework=soc2&period=…` generates a **signed, audit-anchored** (D5) evidence bundle: access-review reports, MFA-coverage stats, admin-action logs, incident (lockdown D8) records, data-subject requests (D6), key-rotation history (D4) — each linked to verifiable audit proofs.
- **Continuous posture dashboard**: replaces the admin compliance **stubs** (SOC2/ISO/retention) with real, live posture (e.g. "% users with MFA," "stale admin grants," "overdue access reviews") + scheduled evidence generation + data-retention automation.

### Design / changes
**Backend**
- `internal/trust/`: signal collectors + scoring engine + step-up trigger; session trust state; `GET /v1/sessions/{id}/trust`. Reuses attack-protection signals (#16–#21).
- `internal/compliance/`: control registry, evidence-pack builder (signed + anchored), retention automation jobs.
- Migration `0035_trust_compliance.up.sql`: `session.trust_events`, `compliance.controls`, `compliance.evidence_runs`.

**Frontend (admin)**
- **Security → Trust**: live session trust, threshold config, step-up policy (turns the `threats/*` stubs real together with #16–#21).
- **Compliance**: real posture dashboards + "Generate evidence pack" + retention policy editor (replaces SOC2/ISO/retention stubs).

**Docs**
- `content/docs/security/continuous-trust.mdx`, `content/docs/compliance/evidence.mdx`.

### Acceptance criteria
- [ ] Trust score updates mid-session on injected risk signals and triggers step-up below threshold (without full re-login).
- [ ] Sensitive actions/scopes enforce a trust floor; agent sensitive-actions (D7) respect it.
- [ ] Evidence pack generates for SOC 2 and ISO 27001, is signed, and each item links to a verifiable audit proof (D5).
- [ ] Compliance dashboard shows real MFA coverage / stale-grant / access-review metrics (no mock data).
- [ ] Retention automation purges/redacts per policy on schedule.

### 🧪 How you test D10
1. Mid-session, change source IP/ASN (or inject an impossible-travel signal) → `GET /sessions/{id}/trust` drops; next sensitive action demands step-up; satisfy it → action proceeds.
2. Drop trust below the floor for a `payments:write` scope → blocked until re-auth.
3. Generate a SOC 2 evidence pack for last 30 days; verify its signature; spot-check that the "access review" item's audit proofs validate with the standalone verifier (D5).
4. Confirm the admin Compliance dashboard shows real MFA-coverage % matching your seeded data, and the threat screens now show live trust data instead of mocks.

---

## Definition of Done
- [ ] Part A: policy enforcement (#6) verified + **full regression suite green**.
- [ ] Part B: trust engine + step-up + compliance evidence + retention automation, migrations, tests green.
- [ ] Admin Trust + real Compliance dashboards live (former stubs replaced).
- [ ] `security/continuous-trust.mdx` + `compliance/evidence.mdx` published.
- [ ] Roadmap: #6 checked, #36 advanced; D10 noted; status ✅; changelog filled.
- [ ] **Program-level**: update the [Competitive Analysis & Roadmap](../COMPETITIVE-ANALYSIS-AND-ROADMAP.md) gap matrix — flip D1–D10 features and tested existing features to ✅, and re-baseline remaining roadmap phases.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
