# Documentation rules — `documents/`

The folder under [documents/](../../documents/) is the authoritative state of the project. If the docs and the code disagree, **fix the docs in the same PR** — don't leave drift.

## Files and what they own

| File | Owns |
|---|---|
| [IMPLEMENTATION-STATUS.md](../../documents/IMPLEMENTATION-STATUS.md) | Every requirement (Phase 1/2/3) mapped to its module + status (done / partial / not started). |
| [FEATURE-MATRIX.md](../../documents/FEATURE-MATRIX.md) | Capability-by-capability matrix. Higher-level than IMPLEMENTATION-STATUS. |
| [GAP-ANALYSIS.md](../../documents/GAP-ANALYSIS.md) | What's still missing for v1.0. The "what's left" list. |
| [PROTOCOL-STATUS.md](../../documents/PROTOCOL-STATUS.md) | OAuth/OIDC/SAML/SCIM/WebAuthn compliance status. |
| [README.md](../../documents/README.md) | Index of the folder. |

## Update rules

- **Finishing a feature** — update [IMPLEMENTATION-STATUS.md](../../documents/IMPLEMENTATION-STATUS.md) and [FEATURE-MATRIX.md](../../documents/FEATURE-MATRIX.md). Move the entry off [GAP-ANALYSIS.md](../../documents/GAP-ANALYSIS.md) if it was there.
- **Starting a new feature** — add a row marked in-progress. Don't leave it as TBD with no owner.
- **Security/protocol-relevant change** — update [PROTOCOL-STATUS.md](../../documents/PROTOCOL-STATUS.md) and call it out in the PR.

## What counts as "done"

A feature is **not done** until at least one of:

- A test exercises the happy path end-to-end (Go test or Postman request with assertions), or
- A manual demo is recorded in the PR description (steps to reproduce + screenshots / curl output).

Marking something "done" without one of those is forbidden — see [CLAUDE.md](../../CLAUDE.md) ("Don'ts").

## Style

- Markdown. Tables are fine; prose is fine; don't mix wildly different formats in one section.
- Link to source paths and concrete lines (`[file.go:42](path/to/file.go#L42)`). The IDE renders them clickable.
- Don't paste long code blocks into the status docs — link to the file. Code blocks rot; links update with the file.
- Don't put dates in the body text. Git history has them. Exception: dates on planned milestones.

## Other docs

- [README.md](../../README.md) — user-facing project overview. Keep terse; deep stuff goes under `documents/`.
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — how humans contribute. Keep CLAUDE.md and CONTRIBUTING.md aligned — when one changes a workflow, update the other.
- [CHANGELOG.md](../../CHANGELOG.md) — user-visible changes per release. Append-only after a release tag.
- [SECURITY.md](../../SECURITY.md) — vulnerability reporting. Don't move the contact info without coordination.
- [CLAUDE.md](../../CLAUDE.md) — AI-facing project guide. References these rule files.

## Don't

- ❌ Claim a feature is complete in `documents/` without the test or demo. Reviewers will catch it; the CI doesn't.
- ❌ Create a new top-level doc when one of the existing files is the right home for the content.
- ❌ Duplicate content across files. Link instead.
