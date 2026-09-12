# AGENTS.md — qeet-id-server

**The model-neutral instruction file for coding agents working in this repository.**
Model-specific adapters ([CLAUDE.md](CLAUDE.md), [GEMINI.md](GEMINI.md),
[.github/copilot-instructions.md](.github/copilot-instructions.md)) point here. This file is the
source of truth; they add nothing architectural.

---

## What this repository is

`qeet-id-server` is the **Go backend of Qeet ID** — a passkeys-first identity and access platform.
It owns the API, all business logic, and **all enforcement**. Module
`github.com/qeetgroup/qeet-id-server`. Single deployable binary, modular monolith, one PostgreSQL
database.

**It is the only place in Qeet ID where a security decision is made.** Consoles and UIs present;
this repository decides.

## Context hierarchy — read upward before working downward

```text
qeet-context      L0   organization standards   security · domain · API · engineering
      ↓
qeet-id-context   L1   product architecture     flows · repositories · contracts
      ↓
qeet-id-server    L2   THIS REPOSITORY          implementation
      ↓
source                 L3/L4                    actual behaviour
```

**This repository does not restate L0 or L1.** When a task needs organization or product
understanding, read those repositories. When it needs to know *how this backend implements
something*, read the files below.

## Read before changing code

| File | For |
|---|---|
| [qeet-repo.yml](qeet-repo.yml) | Machine-readable identity — start here |
| [docs/llm/architecture-map.md](docs/llm/architecture-map.md) | "Where is X?" — fastest path to a file |
| [docs/llm/context.md](docs/llm/context.md) | How the backend actually works |
| [docs/llm/subsystems.md](docs/llm/subsystems.md) | Subsystem map + **real filenames** per package |
| [docs/llm/boundaries.md](docs/llm/boundaries.md) | What this repo owns, and what it must not touch |
| [docs/llm/workflows.md](docs/llm/workflows.md) | Step-by-step for common changes |

Load the smallest set that answers your question. Most tasks need the architecture map plus one
section of the context document.

---

## Rules

### 1. Inspect before editing

**Never change code based on a filename or an assumption.** Read the file. Read its callers. This
repository has 77 packages and near-identical names in different contexts — `internal/access/risk/ipallow`
and `internal/access/threat/risk` are different things.

### 2. Follow the existing architecture

Reuse the established pattern before introducing an abstraction. Every domain package follows the
same shape: `queries.sql` + `sqlc.yaml` + generated `dbgen/`, plus Go files named after the
**domain** — `passkey.go`, `agent.go`, `oidc.go`. **The convention is `<domain>.go`, not
`service.go`/`repository.go`**: only four packages use layered names and only twelve have an
`http.go`. Check [docs/llm/subsystems.md](docs/llm/subsystems.md) for the real filenames before
looking for one.

### 3. Preserve package boundaries

Two rules are **enforced by a test** (`tests/architecture/arch_test.go`) and will fail CI:

- **R1** — `internal/platform/*` must not import a bounded context, `cmd/*`, or `internal/bootstrap`.
- **R2** — a bounded context must not import `cmd/*` or `internal/bootstrap`.

Cross-context imports are **not** currently enforced. Do not take that as permission — prefer
consumer-declared interfaces over importing another context's concrete types.

### 4. `internal/bootstrap` is the composition root

It is the only package that wires dependencies. New services, repositories, routes, middleware and
workers are wired **there**, not in the package that defines them.

### 5. Preserve API contracts

`api/openapi/` is the contract, split into five bounded-context documents. **A route added without
documenting it fails CI** — `tests/integration/coverage_test.go` asserts every mounted route appears
in a specification. Update the spec in the same change as the route.

### 6. Preserve tenant isolation — the highest-severity rule here

**Tenant scope comes from the authenticated principal. Never from a path, body, query or header.**

- Use `httpx.RequireTenant(r)`. It is the only trustworthy source.
- `httpx.EnforceTenantScope` compares any `{tenantID}` path parameter to the caller's own tenant.
- Every tenant-scoped query carries `WHERE tenant_id = $1`.
- **There is no PostgreSQL RLS.** Verified: zero policies across all 104 migrations. A missing
  predicate is a cross-tenant data exposure, not an error the database will catch.

**Restructuring the chi route tree is a security change.** The guard depends on chi's nested-route
matching; `internal/bootstrap/router.go` warns that flattening the routes makes it *silently fail
open*.

### 7. Never weaken a security control

Do not weaken authentication, authorization, CSRF or origin checks, token validation, session
handling, secret handling, cryptography, or tenant isolation — **including to make a test pass**.

If the implementation does not meet an L0 or L1 requirement, that is a **finding to report**, not a
standard to redefine. Record it against the product register in `qeet-id-context/DRIFT-REGISTER.md`.

Two behaviours look like bugs and are **deliberate, with ADRs**: the rate limiter fails **open** when
its store errors, and auth hooks default to **fail-open**. Do not "fix" either.

### 8. Migrations are immutable once applied

Never edit an existing migration. Add a new pair:

```text
internal/platform/database/migrations/NNNN_description.up.sql
internal/platform/database/migrations/NNNN_description.down.sql
```

Numbering continues from the highest present (currently `0107`; `0082` is absent and is not to be
reused). Migrations are embedded with `//go:embed` and applied on startup. Additive first —
expand, migrate, contract across releases.

### 9. Behaviour changes require tests

A new behaviour ships with a test. A bug fix ships with a test that fails before it. Anything
touching tenant scoping needs a test proving cross-tenant access is denied.

### 10. Do not commit secrets

`.env` and `.secrets/` exist locally and are gitignored. Never read them into a file you create,
never echo their contents, never add a real value to `.env.example` — placeholders only.

---

## Commands

Verified against the `Makefile`. **These are all of them — do not invent targets.**

```bash
make install          # go mod download
make dev              # run the API on :4001 (persistent JWT + SAML keys from .secrets/)
make dev-secrets      # generate local dev key material
make build            # go build -o bin/qeet-id ./cmd/api
make test             # go test ./...            (includes the architecture fitness test)
make test-integration # go test -tags integration ./tests/integration/...
make lint             # go vet ./...             (NOT golangci-lint — see below)
make bench            # k6 performance run
make db-up/db-down/db-reset      # docker compose: postgres :5001, nats :4222, mailpit :8025
make migrate-up/migrate-down     # one migration at a time
make seed/seed-reset             # demo data (development only)
make kill                        # free a stuck :4001
```

There is no `make help`, no `dev-*` variants beyond `dev-secrets`, and no `test-*` beyond
`test-integration`.

**`make lint` runs `go vet` only.** CI additionally runs `golangci-lint` v2.12.2 on new code, with
`errcheck`, `govet`, `staticcheck` and `misspell`. Passing `make lint` locally does not mean CI lint
will pass.

Single test: `go test ./internal/access/authentication/... -run TestName`

---

## What CI enforces

| Job | Runs |
|---|---|
| `test` | `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` — includes architecture fitness |
| `lint` | `golangci-lint` v2.12.2, new code only |
| `integration` | `go test -tags integration ./tests/integration/...` — **includes the OpenAPI route-coverage gate** |
| `vuln` | `govulncheck ./cmd/... ./internal/...` blocking, plus an advisory full-tree scan |
| `sast` | `gosec` — advisory, reports findings as a warning |
| `deploy` | On push to `main` only: build, deploy to AWS via OIDC, then tag |

---

## Before you finish

```bash
go build ./...
go test -race ./...        # architecture fitness runs here
make lint
git diff                   # no secrets, no unrelated changes, no generated junk
```

If the change touched a route: also run `make test-integration`, or CI will fail on route coverage.

---

## When to stop and escalate

Report rather than proceed if a task would:

- weaken any security control, or bypass `EnforceTenantScope`
- edit an already-applied migration
- change JWT claims, signing, or `kid` handling — this reaches **every Qeet product** and external
  relying parties
- change SCIM, SAML or webhook contracts — external consumers cannot be surveyed
- restructure the chi route tree
- require modifying another repository

For cross-repository impact, see `qeet-id-context/CHANGE-MATRIX.md`.
