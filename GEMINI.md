# GEMINI.md — qeet-id-server

**Read [AGENTS.md](AGENTS.md) first.** It is the model-neutral instruction file and the source of
truth for this repository. This file is a pointer and adds no architecture.

```text
GEMINI.md  →  AGENTS.md  →  docs/llm/*
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

Parent context: **L0** `qeetgroup/qeet-context` · **L1** `qeetgroup/qeet-id-context`.

## What this repository is

The Go backend of Qeet ID — a passkeys-first identity platform. Modular monolith, module
`github.com/qeetgroup/qeet-id-server`, five bounded contexts under `internal/`, one PostgreSQL
database, chi router, port 4001.

**All enforcement happens here.** Consoles and UIs present; this repository decides.

## Non-negotiables

1. **Tenant scope comes from `httpx.RequireTenant(r)`**, never from request input. There is **no
   RLS** — a missing `WHERE tenant_id = $1` exposes another tenant's data.
2. **Wiring belongs in `internal/bootstrap`.** `internal/platform` must not import a bounded context
   — a build-time test enforces it.
3. **A route without an OpenAPI entry fails CI.**
4. **Never edit an applied migration.** Add an `NNNN_*.{up,down}.sql` pair.
5. **Never weaken a security control**, including to make a test pass. Report the gap instead.
6. **Never hand-edit `dbgen/`** — it is sqlc output.

## Commands

`make install · dev-secrets · dev · build · test · test-integration · lint · bench · db-up · db-down ·
db-reset · migrate-up · migrate-down · seed · seed-reset · kill`

That list is complete. **Do not invent targets.** `make lint` runs `go vet` only; CI also runs
`golangci-lint`.

## Before finishing

```bash
go build ./... && go test -race ./... && make lint && git diff
make test-integration      # if a route changed
```
