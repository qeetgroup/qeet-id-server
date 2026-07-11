# Qeet ID — Console UX/Enterprise-Polish Audit

Piggybacks on the per-module click-through in `qa/TESTING-FINDINGS.md`'s phase sequence — not a separate pass. For every console screen visited, tag whether it uses the shared `@qeetrix/ui` blocks (`dashboard-shell`, `settings-layout`, `page-state`, `onboarding-wizard`, `auth`, `pricing-table` — see `qeetrix/packages/ui/src/blocks/`) or hand-rolls an equivalent. Systemic gaps (many screens hand-rolling the same pattern) get batch-fixed first; one-off inconsistencies only if time remains.

## Legend

- **Uses block?**: `Y` (uses the appropriate `@qeetrix/ui` block) · `N` (hand-rolled equivalent) · `N/A` (no applicable block)
- **Priority**: `Systemic` (same gap repeats across many screens — batch fix) · `One-off` (isolated — lower priority)

## Audit

| Screen | Uses block? | Which block would apply | Notes | Priority |
|---|---|---|---|---|
| `security/sessions.tsx` | N/A | — | Functional & clean. Missing enterprise polish: no "current session" marker (you can revoke your own session with no warning), no pagination (rendered 28 rows flat), no "revoke all other sessions" bulk action. | One-off (P3) |
| `auth/mfa/recovery-codes.tsx`, `auth/mfa/totp.tsx` | N/A | — | No step-up challenge UI when the backend demands `step_up_required` (403) — see QID-17. A reusable step-up modal would serve both screens (and any future sensitive action). | Systemic (tie to QID-17) |
