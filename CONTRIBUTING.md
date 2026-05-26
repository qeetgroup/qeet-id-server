# Contributing to Qeetid

Thanks for considering a contribution. This guide covers branching, commits, code style, and how to add new features across the monorepo.

If you're reporting a security issue, please follow [SECURITY.md](./SECURITY.md) instead of opening an issue.

---

## Ground rules

- **Be kind, be specific.** Concrete repro steps and concrete diffs beat opinions every time.
- **One PR, one purpose.** Mixing refactors with feature work makes review painful — split them.
- **Tests for behaviour changes.** Bug fixes and new features need a regression test. Pure refactors that preserve behaviour don't.
- **No drive-by formatting.** Lint changes on lines you aren't otherwise touching belong in a separate PR.

---

## Development setup

See the [Quickstart in the root README](./README.md#quickstart). In short:

```bash
# Backend
cd backend && docker compose up -d && make migrate-up && make run

# Frontend
cd frontend && pnpm install && pnpm dev
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
   # Backend
   cd backend && make test && go vet ./...

   # Frontend
   cd frontend && pnpm typecheck && pnpm lint && pnpm test
   ```

4. **Open the PR** against `develop`. Fill in the template (`.github/PULL_REQUEST_TEMPLATE.md`).
5. **Address review feedback** by adding new commits — don't force-push until the reviewer asks.
6. **Squash on merge** unless the PR genuinely has multiple atomic commits worth preserving.

PRs need one approving review from a maintainer and a green CI run before merge.

---

## Adding a new backend module

Backend modules live under [backend/internal/](./backend/internal/). Each is a self-contained domain (e.g. `auth`, `rbac`, `oidc`).

Convention:

```
backend/internal/<module>/
├── <module>.go         Domain types + service + handler (small modules)
├── service.go          Business logic (larger modules)
├── http.go             HTTP handlers + route registration
├── repository.go       PostgreSQL access
└── domain.go           Pure domain types
```

Steps to add a module:

1. Create the package directory under `backend/internal/`.
2. Add SQL migrations under `backend/migrations/` with the next number — both `.up.sql` and `.down.sql`.
3. Add domain types, repository, service, and HTTP handlers.
4. Mount the routes in [backend/internal/http/router.go](./backend/internal/http/router.go).
5. Add tests next to the code (`*_test.go`).
6. Update [backend/api/openapi.yaml](./backend/api/openapi.yaml).
7. Update [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md) and [documents/FEATURE-MATRIX.md](./documents/FEATURE-MATRIX.md).

---

## Adding a frontend route or component

Admin dashboard uses file-based routing under [frontend/apps/qeetid-admin/src/routes/](./frontend/apps/qeetid-admin/src/routes/). To add a screen:

1. Create the route file under `src/routes/_app/<feature>.tsx` (the `_app` layout adds the sidebar / auth gate).
2. Add the nav entry in [src/config/navigation.tsx](./frontend/apps/qeetid-admin/src/config/navigation.tsx).
3. Use components from [@qeetid/ui](./frontend/packages/qeetid-ui/) — only add new primitives there if reused across apps.
4. Wire data via TanStack Query against the backend API.
5. Add tests using Vitest + Testing Library.

For marketing (`qeetid-web`) and docs (`qeetid-docs`), use Next.js file-based routing under each app's `src/app/`.

---

## Code style

- **Go:** gofmt-clean. `go vet` clean. Use the existing patterns in `backend/internal/platform/` (errors, logging, HTTP middleware).
- **TypeScript:** Prettier-formatted. ESLint clean. No `any` without a justification comment.
- **SQL:** lowercase keywords (`select`, not `SELECT`). Migrations are immutable once merged — don't edit them in place; write a new one.
- **Comments:** the [root README and CLAUDE-style guidance](./README.md) apply — only write a comment when the *why* is non-obvious. Don't restate what the code does.

---

## Documentation expectations

If your change affects:

| Change | Update |
|---|---|
| Backend API | [backend/api/openapi.yaml](./backend/api/openapi.yaml) + relevant `docs/api/*.mdx` |
| New module or feature | [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md) + [documents/FEATURE-MATRIX.md](./documents/FEATURE-MATRIX.md) |
| Protocol implementation | [documents/PROTOCOL-STATUS.md](./documents/PROTOCOL-STATUS.md) |
| Security posture | [SECURITY.md](./SECURITY.md) and/or [documents/GAP-ANALYSIS.md](./documents/GAP-ANALYSIS.md) |
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

Open a [GitHub Discussion](https://github.com/qeetgroup/qeet-identity/discussions) (once enabled) or reach out at `hello@qeetid.com`.
