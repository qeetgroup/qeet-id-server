---
name: release-readiness
description: Comprehensive pre-release audit for qeet-identity — cross-checks gap analysis, protocol status, test coverage, migration safety, and security rules before cutting a release. Trigger when the user says "release check", "ready to ship", "v1.0 readiness", "pre-release audit", or "cut a release".
---

# Release readiness audit

Pre-1.0 project — ~29% of v1.0 must-haves landed at the time this skill was written. Use this skill to produce a structured go/no-go report.

## Inputs

- `$ARGUMENTS` may name a target — e.g. `v1.0`, `v0.5-beta`, `phase-1`. If empty, audit against v1.0.

## Phase 1 — Snapshot the state

Run in parallel:

1. `git status` + `git log --oneline -10` — current branch state.
2. Read [documents/IMPLEMENTATION-STATUS.md](../../../documents/IMPLEMENTATION-STATUS.md), [documents/FEATURE-MATRIX.md](../../../documents/FEATURE-MATRIX.md), [documents/GAP-ANALYSIS.md](../../../documents/GAP-ANALYSIS.md), [documents/PROTOCOL-STATUS.md](../../../documents/PROTOCOL-STATUS.md).
3. List `backend/migrations/` and note the highest version.
4. List mounted routes via the [/routes](../../commands/routes.md) command.
5. `git diff main...HEAD` if on a non-main branch.

## Phase 2 — Cross-check docs vs. code

For each requirement marked "done" in `IMPLEMENTATION-STATUS.md`:

- Is there a code path for it? Grep the relevant module.
- Is there a test? (`*_test.go` or a Postman request with assertions.)
- Is the endpoint in [openapi.yaml](../../../backend/api/openapi.yaml) and the [Postman collection](../../../backend/api/qeet-identity.postman_collection.json)?

Flag any "done" item missing one of those — per [../../rules/docs.md](../../rules/docs.md), "done" requires test or recorded manual demo.

For each item still on `GAP-ANALYSIS.md`: confirm it's actually unimplemented (grep for it). Sometimes docs lag.

## Phase 3 — Security review

Run [../../agents/qeetid-reviewer.md](../../agents/qeetid-reviewer.md) on the diff vs. `main`. In addition, check:

- All entries in [documents/PROTOCOL-STATUS.md](../../../documents/PROTOCOL-STATUS.md) marked compliant: does the code actually back the claim?
- No token signing-algorithm regressions (grep for `HS256` — should be intentional, never as a fallback).
- No new `*.env`, `*.pem`, `*.key` files staged.
- Audit chain integrity: scan [internal/audit/audit.go](../../../backend/internal/audit/audit.go) — no recent edits weakening the chain.
- Outbox dispatcher healthy: read [internal/platform/outbox/outbox.go](../../../backend/internal/platform/outbox/outbox.go) for any TODO/FIXME comments suggesting unfinished work.

## Phase 4 — Migration safety

- Every migration under `backend/migrations/` has both `.up.sql` and `.down.sql`.
- Sequence numbers are contiguous, no gaps.
- No edits to migrations from `main` since branch divergence (use `git log -- backend/migrations/<file>`).
- New tables include `tenant_id` and a FK.

## Phase 5 — Test pass

Recommend (don't auto-run unless asked):

- `make test` — Go + frontend.
- `make typecheck` — frontend.
- `make lint` — both.
- `make test-api-ci` — Postman/Newman with reports.

If the user wants you to run them, do so. Capture any failure; group by module.

## Phase 6 — Produce the report

Markdown output with these sections:

```
# Release readiness — <target>

## Verdict
GO | GO WITH CAVEATS | NO-GO — one sentence.

## Done since last release
- ...

## Blockers (must fix before release)
- [module/area] one-line + link to source

## Caveats (ship is OK but track)
- ...

## Doc drift detected
- ...

## Security findings
- ...

## Test status
- ...

## Suggested next steps
1. ...
```

Sources: cite a specific file:line or doc line for every claim. Reviewers should be able to verify without re-running the audit.

Do not edit any files in this skill — pure reporting. If the user wants you to fix something, that's a separate request.
