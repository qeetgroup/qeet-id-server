# Contributing to Qeet ID

Thanks for considering a contribution. This guide covers branching, commits, code style, and how to add new features across the monorepo.

If you're reporting a security issue, please follow [SECURITY.md](./SECURITY.md) instead of opening an issue.

---

## Ground rules

- **Be kind, be specific.** Concrete repro steps and concrete diffs beat opinions every time.
- **One PR, one purpose.** Mixing refactors with feature work makes review painful — split them.
- **Tests for behaviour changes.** Bug fixes and new features need a regression test. Pure refactors that preserve behaviour don't.
- **No drive-by formatting.** Lint changes on lines you aren't otherwise touching belong in a separate PR.

---

## Filing issues

Work is tracked on the **"Qeet ID - Roadmap"** board ([github.com/orgs/qeetgroup/projects/24](https://github.com/orgs/qeetgroup/projects/24)). When you open an issue:

- **Title:** prefix with `[feat]`, `[fix]`, or `[chore]` (the issue templates do this for you).
- **Body:** use these three sections — **Context** (why / the gap), **Requirements** (what's needed), **Acceptance criteria** (`- [ ]` checkboxes that are specific and testable). Don't add a "References" section.
- **Labels:** a priority (`P0`–`P3`), an area (`area/backend|console|login|web|sdk|docs|deploy|infra|dx`), a type (`type/feature|bug|chore|…`), and a workstream (`ws/*`) where it fits.
- **Milestone:** pick the target release (`v1.0 — GA`, `v1.1 — Agent & MCP Fast-Follow`, `v1.2 — Standards & Federation`, `Infra & Deploy`, `Ops & Go-Live Hardening`, or `Post-GA Backlog`).
- **Before opening:** search existing issues and the code — the roadmap docs sometimes over-claim what's shipped. Agents/maintainers can use the `issue-tracker` subagent to create + reconcile these automatically.

Security issues do **not** go here — follow [SECURITY.md](./SECURITY.md).

---

## Development setup

See the [Quickstart in the root README](./README.md#quickstart). In short:

```bash
# Backend (from the repo root — single Go module)
make db-up && make migrate-up && make dev-backend

# Frontend (from the repo root — Bun workspace)
bun install && bun run dev
```

---

## Branching

| Branch | Purpose |
|---|---|
| `main` | Always-deployable. PRs land here. |
| `develop` | Integration branch for v1.0 work. PRs land here for now until we stabilise. |
| `feat/<short-slug>` | New feature work |
| `fix/<short-slug>` | Bug fix |
| `chore/<short-slug>` | Tooling, docs, dependencies |
| `refactor/<short-slug>` | Internal restructure with no behaviour change |

Branch from `develop` for v1.0 feature work. Branch from `main` for hotfixes that need to ship before v1.0.

---

## Commit messages

Conventional Commits flavour, kept short:

```
<type>(<scope>): <summary>

<optional body — explain WHY, not what>

<optional footer — refs / breaking changes>
```

**Types:** `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`.
**Scope:** module name — `auth`, `rbac`, `oidc`, `admin`, `docs`, `webhook`, etc.

Examples:

```
feat(passkey): implement WebAuthn registration ceremony
fix(auth): rotate refresh token on every use, not just expiry
docs(gap-analysis): mark SCIM Users endpoint as P0
```

Why this matters: commit history feeds the changelog. Vague commits → vague releases.

---

## Pull requests

1. **Fork or branch** from `develop`.
2. **Write the change** — keep it focused. If you find yourself touching > 10 files outside the scope, stop and ask whether this should be multiple PRs.
3. **Run the local checks** before opening the PR:

   ```bash
   # Backend (from the repo root)
   make test-backend && go vet ./...

   # Frontend (from the repo root)
   bun run typecheck && bun run lint && bun run test
   ```

4. **Open the PR** against `develop`. Fill in the template (`.github/PULL_REQUEST_TEMPLATE.md`).
5. **Address review feedback** by adding new commits — don't force-push until the reviewer asks.
6. **Squash on merge** unless the PR genuinely has multiple atomic commits worth preserving.

PRs need one approving review from a maintainer and a green CI run before merge.

---

## Adding a new backend module

Backend modules live under [domains/](./domains/), grouped by bounded context
(`identity` / `access` / `federation` / `developer` / `operations`); shared infra
is under [platform/](./platform/). Each module is a self-contained domain (e.g.
`domains/access/authentication`, `domains/access/authorization/rbac`,
`domains/federation/oidc`). Folder names are domain-oriented; the Go package
clause keeps its short name (e.g. folder `authentication` → `package auth`).

Convention:

```
domains/<context>/<module>/
├── <module>.go         Domain types + service + handler (small modules)
├── service.go          Business logic (larger modules)
├── http.go             HTTP handlers + route registration
├── repository.go       PostgreSQL access
└── domain.go           Pure domain types
```

Steps to add a module:

1. Create the package directory under the right `domains/<context>/`.
2. Add SQL migrations under `migrations/` with the next number — both `.up.sql` and `.down.sql`.
3. Add domain types, repository, service, and HTTP handlers.
4. Mount the routes in [platform/api/rest/router.go](./platform/api/rest/router.go).
5. Add tests next to the code (`*_test.go`).
6. Update [api/openapi/](./api/openapi/).

---

## Adding a frontend route or component

Admin console uses file-based routing under [apps/console/src/routes/](./apps/console/src/routes/). To add a screen:

1. Create the route file under `src/routes/_app/<feature>.tsx` (the `_app` layout adds the sidebar / auth gate).
2. Add the nav entry in [src/config/navigation.tsx](./apps/console/src/config/navigation.tsx).
3. Use components from the shared `@qeetrix/*` design system — only add new primitives there if reused across apps.
4. Wire data via TanStack Query against the backend API.
5. Add tests using Vitest + Testing Library.

For the marketing site ([apps/website](./apps/website/)) and hosted login ([apps/login](./apps/login/)), use Next.js file-based routing under each app's `src/app/`.

---

## Code style

- **Go:** gofmt-clean. `go vet` clean. Use the existing patterns in `platform/` (errors, logging, HTTP middleware).
- **TypeScript:** Biome-formatted. Biome lint clean. No `any` without a justification comment.
- **SQL:** lowercase keywords (`select`, not `SELECT`). Migrations are immutable once merged — don't edit them in place; write a new one.
- **Comments:** the [root README and CLAUDE-style guidance](./README.md) apply — only write a comment when the *why* is non-obvious. Don't restate what the code does.

---

## Documentation expectations

If your change affects:

| Change | Update |
|---|---|
| Backend API | [api/openapi/](./api/openapi/) |
| Architecture / conventions | [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) |
| Security posture | [SECURITY.md](./SECURITY.md) |
| End-user docs | standalone `qeet-docs` repo (docs.qeet.in) |
| Breaking API change | [CHANGELOG.md](./CHANGELOG.md) — note under "Unreleased / Breaking" |

---

## Releases

Releases follow SemVer. The maintainer cuts releases off `main` by tagging `vX.Y.Z` and publishing release notes derived from [CHANGELOG.md](./CHANGELOG.md).

Pre-1.0: minor versions may include breaking changes — document them clearly in the changelog.

---

## Code of conduct

By participating, you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md).

---

## Questions?

Open a [GitHub Discussion](https://github.com/qeetgroup/qeet-id/discussions) (once enabled) or reach out at `hello@qeet.in`.
