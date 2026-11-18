# GEMINI.md — qeet-id-server

**Read [AGENTS.md](AGENTS.md) first.** It is the model-neutral instruction file and the source of
truth for this repository. This file is a pointer and adds no architecture.

```text
GEMINI.md  →  AGENTS.md  →  docs/llm/*
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

Parent context: **L0** `qeetgroup/qeet-context` · **L1** `qeetgroup/qeet-id-context`.

## What this repository is

The Go backend of Qeet ID — a passkeys-first identity platform. Modular monolith, module
`github.com/qeetgroup/qeet-id-server`, five bounded contexts under `internal/`, one PostgreSQL
database, chi router, port 4001.

**All enforcement happens here.** Consoles and UIs present; this repository decides.

## Non-negotiables

1. **Organization scope comes from `httpx.RequireOrganization(r)`**, never from request input. Row-level
   security covers only organization-owned tables in organization-administration requests —
   elsewhere a missing `WHERE organization_id = $1` exposes another organization's data.
2. **Wiring belongs in `internal/bootstrap`.** `internal/platform` must not import a bounded context
   — a build-time test enforces it.
3. **A route without an OpenAPI entry fails CI.**
4. **Never edit an applied migration.** Add an `NNNN_*.{up,down}.sql` pair.
5. **Never weaken a security control**, including to make a test pass. Report the gap instead.
6. **Never hand-edit `dbgen/`** — it is sqlc output.
7. **Never hand-edit `api/openapi/*.yaml` or `api/postman/`** — edit `api/openapi/src/` and run `make openapi`.

## Commands

`make help · install · dev-secrets · dev · dev-observed · build · kill · db-up · db-down · db-reset ·
seed · seed-reset · migrate-down · test · test-db · lint · fmt · fmt-check · sqlc · sqlc-check ·
openapi · openapi-check · postman · ci · vuln · sast · secrets · scan-image · obs-up · obs-down`

That list is complete. **Do not invent targets.** `make lint` runs the same lint as CI.

## Before finishing

```bash
go build ./... && go test -race ./... && make lint && git diff
```
