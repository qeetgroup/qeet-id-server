---
name: gap-fill
description: Pick the next-best unimplemented item from documents/GAP-ANALYSIS.md, scope it, and start an implementation plan against the qeet-identity codebase. Trigger when the user says "next gap", "what should I work on", "pick from gap analysis", "what's next on v1.0", or anything that asks Claude to choose the next piece of work.
---

# Gap-fill — pick and scope the next work item

This skill picks the next gap to implement, scopes it, and produces a plan. It does **not** start writing code — that's the user's call after the plan.

## Phase 1 — Read the source of truth

Read in order:

1. [documents/GAP-ANALYSIS.md](../../../documents/GAP-ANALYSIS.md) — the unimplemented list.
2. [documents/IMPLEMENTATION-STATUS.md](../../../documents/IMPLEMENTATION-STATUS.md) — what's in flight.
3. [documents/FEATURE-MATRIX.md](../../../documents/FEATURE-MATRIX.md) — capability rollup.
4. [documents/PROTOCOL-STATUS.md](../../../documents/PROTOCOL-STATUS.md) — compliance items.

## Phase 2 — Score the candidates

For each gap item, score it on:

- **Blocker rank** — does v1.0 require this? Block-1 (must) / Block-2 (should) / Block-3 (nice).
- **Effort** — small / medium / large, your best guess in hours. Use existing similar modules as a yardstick.
- **Dependency depth** — does it depend on other unimplemented items? List the deps.
- **Risk** — low / medium / high. Security/auth changes default to medium+.

If `$ARGUMENTS` is a category or module name (e.g. `mfa`, `passkey`, `SCIM`), restrict to gaps in that area.

## Phase 3 — Pick

Recommend exactly **one** item. Prefer:

1. Block-1 with no unresolved deps, low/medium risk, small/medium effort.
2. Then Block-1 with one resolvable dep.
3. Then Block-2 small wins.

If everything left is large/high-risk, say so honestly and ask the user to split scope or take the smallest of them.

## Phase 4 — Scope the chosen item

Produce:

```
# Next: <item title>

## Why this one
One paragraph — block rank, effort, why preferred over the runners-up.

## What it touches
- Backend modules: [...]
- Migrations needed: yes/no — if yes, sketch the schema delta
- Frontend changes: which app(s), which routes
- API surface: list new/changed endpoints
- Audit/outbox events: which new event types

## Sketch (not a final design)
- Files to add/modify, with paths
- One-paragraph approach for the non-obvious parts

## Risks / open questions
- ...

## Doc updates required on merge
- ...

## Suggested next action
"Run the /add-endpoint skill for <endpoint>"  OR
"Run /module-new <name> and follow up with /migration-new <name>"  OR
"Open a design issue first — too many unknowns"
```

## Phase 5 — Hand back

Stop here. Don't start implementing. The user picks whether to proceed, refine scope, or pick a different item.

If they say go, switch to the relevant skill or command — [add-endpoint](../add-endpoint/SKILL.md), [/module-new](../../commands/module-new.md), [/migration-new](../../commands/migration-new.md).
