# CLAUDE.md — qeet-id-server

**Read [AGENTS.md](AGENTS.md) first.** It is the model-neutral instruction file and the source of
truth for this repository. This file adds only Claude-specific guidance and does not duplicate
architecture.

```text
CLAUDE.md  →  AGENTS.md  →  docs/llm/*
```

## Canonical context

| File | For |
|---|---|
| [qeet-repo.yml](qeet-repo.yml) | Machine-readable repository identity |
| [AGENTS.md](AGENTS.md) | **Rules, commands, what CI enforces** |
| [docs/llm/architecture-map.md](docs/llm/architecture-map.md) | "Where is X?" |
| [docs/llm/context.md](docs/llm/context.md) | How the backend works |
| [docs/llm/subsystems.md](docs/llm/subsystems.md) | Subsystem map + real filenames |
| [docs/llm/boundaries.md](docs/llm/boundaries.md) | Ownership and hard limits |
| [docs/llm/workflows.md](docs/llm/workflows.md) | Step-by-step for common changes |

Parent context: **L0** `qeetgroup/qeet-context` (organization standards) · **L1**
`qeetgroup/qeet-id-context` (Qeet ID product architecture). Read them when a task needs
organization or product understanding; this repository does not restate them.

## The five things most likely to trip you up here

1. **Tenant scope comes from `httpx.RequireTenant(r)`** — never from a path, body or header. There
   is **no PostgreSQL RLS**; a missing `WHERE tenant_id = $1` is a cross-tenant data exposure.
2. **`make lint` is `go vet` only.** CI also runs `golangci-lint` v2.12.2. Passing locally proves
   less than it looks.
3. **A new route without an OpenAPI entry fails CI** — `tests/integration/coverage_test.go`.
4. **Wiring goes in `internal/bootstrap`.** `internal/platform` importing a bounded context fails
   the architecture test.
5. **Two behaviours that look like bugs are deliberate, with ADRs:** the rate limiter fails **open**
   on store error, and auth hooks default to **fail-open**. Do not "fix" them.

## Working style in this repository

- **Read before editing.** 77 packages, and similar names mean different things —
  `internal/access/risk/ipallow` is not `internal/access/threat/risk`.
- **Prefer `rg`/`grep` over guessing a path.** Use the architecture map.
- **Match the neighbouring package's shape** rather than introducing an abstraction: `queries.sql` +
  `sqlc.yaml` + generated `dbgen/` + service + handler.
- **Never hand-edit `dbgen/`** — it is sqlc output.
- **Do not read `.env` or `.secrets/`** into anything you write. Both are gitignored and hold real
  local key material.

## Finishing a change

```bash
go build ./... && go test -race ./... && make lint && git diff
make test-integration      # if the change touched a route
```

## Issues and the project board

Issues live in `qeetgroup/qeet-id-server`.

- **Title:** `[feat] …`, `[fix] …`, `[chore] …`
- **Body:** Context / Requirements / Acceptance criteria
- Roadmap board: org Project **#24**. Setting board fields needs the `project` scope —
  `gh auth refresh -s project`.

> **Note:** earlier revisions of this file referenced subagents at `.claude/agents/issue-tracker.md`
> and `.claude/agents/product-manager.md`. **No `.claude/` directory exists in this repository.**
> Those references were dangling and have been removed rather than recreated. Create the agents if
> they are wanted; do not assume they are available.

## Escalate rather than proceed

Stop and report if a task would weaken a security control, bypass `EnforceTenantScope`, edit an
applied migration, change JWT claims or signing, change SCIM/SAML/webhook contracts, restructure the
chi route tree, or require modifying another repository.

Cross-repository impact: `qeet-id-context/CHANGE-MATRIX.md`.
