# AGENTS.md — qeet-id-server

**The model-neutral instruction file for coding agents working in this repository.**
Model-specific adapters ([CLAUDE.md](CLAUDE.md), [GEMINI.md](GEMINI.md),
[.github/copilot-instructions.md](.github/copilot-instructions.md)) point here. This file is the
source of truth; they add nothing architectural.

---

## What this repository is

`qeet-id-server` is the **Go backend of Qeet ID** — a passkeys-first identity and access platform.
It owns the API, all business logic, and **all enforcement**. Module
`github.com/qeetgroup/qeet-id-server`. It is a modular monolith over one PostgreSQL database: the API
is the primary deployable and runs the background workers itself, with an optional standalone
scheduler entry point.

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
understanding, read those repositories. When it needs to know _how this backend implements
something_, read the files below.

## Read before changing code

| File                                                         | For                                             |
| ------------------------------------------------------------ | ----------------------------------------------- |
| [qeet-repo.yml](qeet-repo.yml)                               | Machine-readable identity — start here          |
| [docs/llm/architecture-map.md](docs/llm/architecture-map.md) | "Where is X?" — fastest path to a file          |
| [docs/llm/context.md](docs/llm/context.md)                   | How the backend actually works                  |
| [docs/llm/subsystems.md](docs/llm/subsystems.md)             | Subsystem map + **real filenames** per package  |
| [docs/llm/boundaries.md](docs/llm/boundaries.md)             | What this repo owns, and what it must not touch |
| [docs/llm/workflows.md](docs/llm/workflows.md)               | Step-by-step for common changes                 |

Load the smallest set that answers your question. Most tasks need the architecture map plus one
section of the context document.

---

## Rules

### 1. Inspect before editing

**Never change code based on a filename or an assumption.** Read the file. Read its callers. This
repository has over a hundred packages and near-identical names in different contexts — `internal/access/ipallow`
and `internal/access/threat/risk` are different things.

### 2. Follow the existing architecture

Reuse the established pattern before introducing an abstraction. Every domain package has the same
shape: `<package>.go` (package doc, Service, `New`), `http.go` (routes and handlers), `errors.go` (its
error codes), `queries.sql` (listed in the root `sqlc.yaml`) + generated `dbgen/`, and one file per
topic (`register.go`, `login.go`). Only three packages (rbac, organization, user) also have a `service.go` or `repository.go`: don't add one elsewhere. Check
[docs/llm/subsystems.md](docs/llm/subsystems.md) for the real filenames before looking for one.

**Names.** Three words say who holds what: an **account** is a person's sign-in, an **organization**
is a customer company, and an **application** is an app an organization connects. Use them in code,
SQL, comments and docs, with the one spelling "organization". Never add an `organization` name. The public
contract still says organization, and changes in one change of its own: the `/v1/organizations/{organizationID}/…`
paths, the `organization_id` JSON field and token claim, and the `organization.*` permission, event and error
names. Leave those strings alone until then. A Microsoft Entra directory is also called a tenant;
that is the provider's word and it stays (`allowed_idp_tenant_ids`).

### 3. Preserve package boundaries

Enforced by `depguard` in `golangci-lint` (`.golangci.yml`); each exception there carries its reason:

- **R1** — `internal/platform/*` must not import a bounded context, `cmd/*`, or `internal/bootstrap`.
- **R2** — a bounded context must not import `cmd/*` or `internal/bootstrap`.
- **R3** — `operations` and `developer` are leaf contexts: the others use only the plan gate
  (`operations/entitlements`) and in-app notices (`operations/notification`). The audit writer is
  `internal/platform/audit`.
- **R4** — `developer` uses those two and RBAC's scope check, never identity or federation.
- **R5** — `operations` depends on no other context (its tests may build fixtures with them).
- **R6** — `federation` builds on `access` and `identity`, never the other way round; `access` uses
  `identity` only for `domainverify` and `user`, `identity` uses `access` only for `auth` and `authpolicy`.

Depend on an interface, not another context's concrete types. An interface several packages need is declared once,
next to what satisfies it (`entitlements.PlanGate`, `PlanLimiter`, `SeatGuard`; `notification.Notifier`;
`ipallow.AddressPolicy`; `authpolicy.PasswordRules`; `postgres.Querier`); declare one in the consumer
only when no shared one fits.

### 4. `internal/bootstrap` is the composition root

It is the only package that wires dependencies, one file per context (`wire_<context>.go`). New
services, repositories, routes, middleware and workers are wired **there**, not in the package that
defines them. A service takes every dependency in its constructor, which refuses a missing one by
name, so the server doesn't start; there are no `Set…` methods and no nil-dependency branches. A
truly optional feature gets an explicit no-op chosen in bootstrap (e.g. `authpolicy.NoBreachCheck`).

### 5. Preserve API contracts

`api/openapi/` is the contract, split into five bounded-context documents. They are **generated**:
edit the sources in `api/openapi/src/` (one file per path) and run `make openapi`; `make openapi-check`
fails if a committed document differs from what its sources build, after linting them with the rules
in `api/openapi/src/redocly.yaml`. **A route added without
documenting it fails the test gate** — `internal/bootstrap/openapi_coverage_test.go` asserts every
mounted route appears in a specification, `openapi_valid_test.go` that every document is valid
OpenAPI 3.1, and `openapi_consistency_test.go` that the documents agree with each other (one
definition per component name, unique operationIds, every operation tagged, tags in their declared
order, the no-store and idempotency headers documented on exactly the routes that send them, every
list paged by cursor or capped with `truncated`). These tests run locally in `make ci`; the hosted Verify workflow runs them and `make openapi-check`
too, but no other tests.
Update the spec in the same change as the route. How the sources are laid out: `api/openapi/README.md`.

**URLs.** The organization always comes from the caller's token (`httpx.RequireOrganization`). A new
organization-administration route also names it in the path, `/v1/organizations/{organizationID}/…`
(`EnforceOrganizationScope` checks the two agree); a person's own routes live under `/v1/me/…`. The routes
that predate this rule and take the organization from the token alone are frozen in
`tokenScopedRoutes` (`internal/bootstrap/permissions_test.go`); don't add to that list.

**Compatibility from 1.0.** Changes are additive: a new route, a new optional request field, a new
response field, a new error code. Never remove or rename a field, change its type or meaning, make
an optional field required, or change a status code or an error code a client may branch on. To retire
something, mark it `deprecated: true` in the spec and answer with `Deprecation` (RFC 9745) and
`Sunset` (RFC 8594) headers for at least six months, then remove it only in a new major version
(`/v2`). Clients must ignore response fields they don't know.

### 6. Preserve organization isolation — the highest-severity rule here

**Organization scope comes from the authenticated principal. Never from a path, body, query or header.**

- Use `httpx.RequireOrganization(r)`. It is the only trustworthy source.
- `httpx.EnforceOrganizationScope` compares any `{organizationID}` path parameter to the caller's own organization.
- Every organization-scoped query carries `WHERE organization_id = $1`.
- **Row-level security is the second layer** (migration 0011). Organization-administration
  requests — routes whose policy needs a permission or a machine scope — run scoped to the caller's
  organization (`scopeOrganizationRoutes` in `bootstrap/router.go`), and the organization-owned
  tables show and accept only its rows. A person's own routes, background jobs, sign-in and the
  account-level tables (`accountLevelTables` in `migrations/runner_db_test.go`) run unscoped, so a
  missing predicate there is still a cross-organization data exposure. Code that acts across
  organizations by design calls `postgres.AcrossOrganizations`. The DB tests' `dbtest.Serve` scopes every
  request, so handler tests catch a cross-organization read. A new table with `organization_id` needs an
  `organization_isolation` policy in its migration; the schema test fails otherwise.

**Restructuring the chi route tree is a security change.** The guard depends on chi's nested-route
matching; `internal/bootstrap/router.go` warns that flattening the routes makes it _silently fail
open_.

### 7. Never weaken a security control

Do not weaken authentication, authorization, CSRF or origin checks, token validation, session
handling, secret handling, cryptography, or organization isolation — **including to make a test pass**.

If the implementation does not meet an L0 or L1 requirement, that is a **finding to report**, not a
standard to redefine. Record the product-level divergence in `qeet-id-context` and its
`CONTEXT-CHANGELOG.md`; do not cite the retired `DRIFT-REGISTER.md`.

Two behaviours look like bugs and are **deliberate, with ADRs**: the rate limiter fails **open** when
its store errors, and auth hooks default to **fail-open**. Do not "fix" either.

### 8. Migrations are immutable once applied

Never edit an existing migration. Add a new pair. (Until the first release ships, the owner may decide
to change a baseline file in place; every database is then recreated. Ask first. After that, never.)

```text
internal/platform/database/migrations/NNNN_description.up.sql
internal/platform/database/migrations/NNNN_description.down.sql
```

Numbering continues from the highest present (currently `0012`). `0001`–`0012` are the schema
baseline: one file per schema with every table in its final shape, written in November 2026 in
place of 243 incremental migrations, before any database held real data. A database the earlier
migrations built is refused at start as newer than this build: recreate it (`make db-reset`).
Migrations are embedded with `//go:embed` and applied on startup, by the server and the seed only:
the runner records the checksum of each file it applies (`public.schema_migration_checksums`) and
refuses a database whose applied migrations aren't recorded as the files this build carries: one built
before a baseline file was edited, one migrated with the `migrate` tool, or one migrated by a build
from before the records. To change your own unmerged migration after it ran: `make migrate-down`, then
`make dev`. Additive first —
expand, migrate, contract across releases. An index on a table that already exists is built with
`CREATE INDEX CONCURRENTLY`, alone in its file (a plain one blocks writes while it builds;
`TestNewIndexesDontLockTheirTable` enforces it). A migration waits at most 10s for a busy table,
then fails and runs again at the next start; a concurrent index build that gives up is left
half-applied for the manual recovery. A table with an `organization_id` gets an index leading on it
and a foreign key to `organization.organizations`, or a note beside it saying why it has none (an append-only
log, a record that outlives its organization).

### 9. Behaviour changes require tests

A new behaviour ships with a test. A bug fix ships with a test that fails before it. Anything
touching organization scoping needs a test proving cross-organization access is denied. The test database is the
schema alone: a test that depends on the built-in permissions or plans seeds them with the service's
own `SeedBuiltins`, which is what the server runs at start.

Test files are named after the code file they test, beside it: `foo_test.go` for tests without a
database and `foo_db_test.go` for tests that need PostgreSQL (first line `//go:build integration`).
Nothing else: no topic-named test files, no `*_integration_test.go`, no test folders inside a
package. `TestMain` and shared helpers live in `<package>_db_test.go` (or `<package>_test.go`), and
the test doubles a package's constructors take in `deps_test.go`;
`internal/platform/database/dbtest` is the one shared test helper package. Tests that span the whole
server live in `tests/` at the root (`architecture`, `contract`, `e2e`), and internal/bootstrap's
whole-server checks name their files for what they check. `tests/architecture` enforces these rules.

### 10. Do not commit secrets

`.env` and `.secrets/` exist locally and are gitignored. Never read them into a file you create,
never echo their contents, never add a real value to `.env.example` — placeholders only.

---

## Commands

Every target runs in Go (`cmd/devtool`), so it behaves the same on Windows, macOS and Linux. Without
`make`, run the same task as `go run ./cmd/devtool <task>`. **These are all of them — do not invent
targets** (`make help` lists them).

```bash
make install          # go mod download
make dev              # run the API on :4001 (persistent JWT + SAML keys from .secrets/)
make dev-observed     # make dev with JSON logs to bin/logs/api.log and traces to the local collector
make dev-secrets      # generate local dev key material
make build            # go build -o bin/qeet-id ./cmd/api
make test             # go test ./...
make test-db          # every test, database ones too, race detector on, one shared PostgreSQL (needs Docker)
make ci               # the full local gate: build, test-db, lint, fmt-check, sqlc-check, openapi-check, vuln, sast, secrets
make lint             # go vet + golangci-lint, as CI runs it
make fmt / fmt-check  # format every file (gofmt+goimports, Prettier, shfmt) / fail if one isn't formatted
make sqlc             # regenerate dbgen/ from queries.sql
make sqlc-check       # fail if dbgen/ is stale or a queries.sql is missing from sqlc.yaml
make openapi          # rebuild api/openapi/*.yaml from api/openapi/src, then api/postman from them (needs Bun)
make openapi-check    # lint the API sources; fail if a built document or the Postman collection is stale
make postman          # rebuild only the Postman collection and local environment in api/postman
make vuln / sast      # govulncheck / gosec
make secrets          # gitleaks over the history and the working tree (Docker)
make scan-image       # build the image and scan it and the Dockerfile with Trivy (Docker)
make load             # k6 load test of a running local server; fails when an SLO is missed
make dast / fuzz-api  # OWASP ZAP / Schemathesis against a running local server (changes data)
make sonar-up/sonar   # local SonarQube Community Build, then analyse with coverage (SONAR_TOKEN)
make db-up/db-down/db-reset      # docker compose: postgres :5001, nats :4222, mailpit :8025
make obs-up/obs-down             # local observability: Grafana :3300, Prometheus :9090, Loki, Tempo (observability/README.md)
make migrate-down                # roll one migration back; the server applies them at start
make seed/seed-reset             # demo data into an empty database / recreate the database, then seed (development only)
make kill                        # free a stuck :4001
```

**`make lint` runs the same lint as CI:** `go vet` plus `golangci-lint` v2.15.0 over the whole tree,
including the integration-tagged database tests, with the linters in `.golangci.yml`.

Single test: `go test ./internal/access/authentication/... -run TestName`

---

## Branches and releases

| Branch                 | What it is                                                                                                                         |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `develop`              | Where every change lands                                                                                                           |
| `main`                 | Production. It changes only by a merged release or hotfix branch (or to be brought level with `develop`)                           |
| `release/YEAR.MONTH.0` | The monthly release, cut from `develop` (e.g. `release/2027.1.0`). After the cut it takes fixes only, and is deleted once released |
| `hotfix/YEAR.MONTH.N`  | An urgent fix to that month's release, from `main`, counting from 1 (e.g. `hotfix/2027.1.1`)                                       |

Versions have no leading zeros (`2027.1.0`, not `2027.01.0`); `scripts/release/version.sh` is the
rule. A fix during testing is made on `develop` first, then copied to the release branch, so no fix
is lost from the next release. Test copies (`2027.1.0-rc.1`, `-rc.2` …) are numbered by
`qeet-id-kit`, never here.

## What CI enforces

| Workflow          | Runs                                                                                                                                                                                                                                                                                                                                   |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ci.yml` · Verify | On pull requests into `develop` and `main` (a release reaches `main` by one): compile (`go build ./...`, `go vet ./...`), format and lint (`golangci-lint` v2.15.0 on the whole tree, gofmt and goimports included), dependency audit (`govulncheck ./cmd/... ./internal/...`), secret scan (gitleaks over the pull request's commits) |
| `candidate.yml`   | On push to `release/**` or `hotfix/**`: publish `ghcr.io/qeetgroup/qeet-id-server:sha-<commit>` (amd64+arm64) with an SBOM and SLSA provenance attached, for the Qeet ID Kit (`qeet-id-kit`). Base images are pinned by digest and every action by commit SHA. Never computes an RC number                                             |
| `deploy.yml`      | On a merged `release/…` or `hotfix/…` pull request into `main`: copy that branch's tested candidate image to ECR as `vYEAR.MONTH.N` (never rebuilt), roll the host via OIDC and SSM, then tag. Any other push to `main` deploys nothing. A manual run with `rollback_to` rolls back                                                    |

The unit and database tests, the generated-SQL check and `gosec` are not in CI: they run locally
before every push (`make ci`). On release day, once the deploy is live: delete the release (or hotfix) branch and merge `main` into `develop`.
The tests include the OpenAPI route-coverage and document-validity gates and the static
guards: organization filter (`internal/platform/database/organizationguard`), pool use inside a transaction
(`…/txguard`), error-code statuses and `.env.example` completeness. An accepted `gosec` finding
needs `// #nosec <rule> -- <reason>` (`.gosec.json`).

---

## Before you finish

```bash
go build ./...
go test -race ./...        # includes the route-coverage gate and the static guards
make lint
make test-db               # if you touched SQL, organization scoping or sign-in
git diff                   # no secrets, no unrelated changes, no generated junk
```

Before a push to `develop`, a release or a hotfix branch, run the full local gate, `make ci`: CI
runs only Verify, which runs the API contract checks but no other tests, so the rest are yours to run.

---

## When to stop and escalate

Report rather than proceed if a task would:

- weaken any security control, or bypass `EnforceOrganizationScope`
- edit an already-applied migration
- change JWT claims, signing, or `kid` handling — this reaches **every Qeet product** and external
  relying parties
- change SCIM, SAML or webhook contracts — external consumers cannot be surveyed
- restructure the chi route tree
- require modifying another repository

For cross-repository impact, see `qeet-id-context/CHANGE-MATRIX.md`.
