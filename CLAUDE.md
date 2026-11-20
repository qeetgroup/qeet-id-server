# CLAUDE.md — qeet-id-server

**Read [AGENTS.md](AGENTS.md) first.** It is the model-neutral instruction file and the source of
truth for this repository. This file adds only Claude-specific guidance and does not duplicate
architecture.

```text
CLAUDE.md  →  AGENTS.md  →  docs/llm/*
```

## Canonical context

| File                                                         | For                                   |
| ------------------------------------------------------------ | ------------------------------------- |
| [qeet-repo.yml](qeet-repo.yml)                               | Machine-readable repository identity  |
| [AGENTS.md](AGENTS.md)                                       | **Rules, commands, what CI enforces** |
| [docs/llm/architecture-map.md](docs/llm/architecture-map.md) | "Where is X?"                         |
| [docs/llm/context.md](docs/llm/context.md)                   | How the backend works                 |
| [docs/llm/subsystems.md](docs/llm/subsystems.md)             | Subsystem map + real filenames        |
| [docs/llm/boundaries.md](docs/llm/boundaries.md)             | Ownership and hard limits             |
| [docs/llm/workflows.md](docs/llm/workflows.md)               | Step-by-step for common changes       |

Parent context: **L0** `qeetgroup/qeet-context` (organization standards) · **L1**
`qeetgroup/qeet-id-files` (Qeet ID product architecture). Read them when a task needs
organization or product understanding; this repository does not restate them.

## The five things most likely to trip you up here

1. **Organization scope comes from `httpx.RequireOrganization(r)`** — never from a path, body or header.
   Row-level security (migration 0011) backs it up only on organization-owned tables in
   organization-administration requests; a person's own routes, background jobs, sign-in and
   account-level tables run unscoped, so a missing `WHERE organization_id = $1` is still a cross-organization
   data exposure there. Code that acts across organizations by design says so with
   `postgres.AcrossOrganizations`.
2. **A query on an organization-owned table must mention `organization_id`.** `internal/platform/database/organizationguard` fails `go test`
   otherwise; an exception needs an allowlist line with a reason.
3. **A new route without an OpenAPI entry fails CI** — `internal/bootstrap/openapi_coverage_test.go`.
4. **Wiring goes in `internal/bootstrap`.** `internal/platform` must not import a bounded context
   (rule R1 in AGENTS.md; `make lint` and CI fail on it).
5. **Two behaviours that look like bugs are deliberate, with ADRs:** the rate limiter fails **open**
   on store error, and auth hooks default to **fail-open**. Do not "fix" them.

## Working style in this repository

- **Read before editing.** Over a hundred packages, and similar names mean different things —
  `internal/access/ipallow` is not `internal/access/threat/risk`.
- **Prefer `rg`/`grep` over guessing a path.** Use the architecture map.
- **Match the neighbouring package's shape** rather than introducing an abstraction: `queries.sql`
  (an entry in the root `sqlc.yaml`) + generated `dbgen/` + service + handler. NULL-able uuid and
  time columns are `*uuid.UUID` / `*time.Time`: no `pgtype` conversions.
- **Never hand-edit `dbgen/`** — it is sqlc output.
- **Never hand-edit `api/openapi/*.yaml` or `api/postman/`** — edit `api/openapi/src/` and run
  `make openapi`, which rebuilds both.
- **Do not read `.env` or `.secrets/`** into anything you write. Both are gitignored and hold real
  local key material.

## Finishing a change

```bash
go build ./... && go test -race ./... && make lint && git diff
make test-db      # if the change touched SQL, organization scoping or sign-in
```

## Tickets

Name the ticket in the commit or pull request title when there is one. Never put a ticket key or
tracker link in code, comments, tests, migrations, OpenAPI documents or Markdown docs: name the
thing instead.

## Escalate rather than proceed

Stop and report if a task would weaken a security control, bypass `EnforceOrganizationScope`, edit an
applied migration, change JWT claims or signing, change SCIM/SAML/webhook contracts, restructure the
chi route tree, or require modifying another repository.

Cross-repository impact: `qeet-id-files/TAD.md` §15.
