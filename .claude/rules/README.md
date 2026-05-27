# .claude/rules/ — topic-scoped project rules

Each file here is a focused set of rules for one slice of the codebase. They expand on [../CLAUDE.md](../../CLAUDE.md) (which stays high-level so it loads fast) and on the implementation-status docs under [documents/](../../documents/).

Read the relevant file before touching code in that slice. Slash commands and the [qeetid-reviewer agent](../agents/qeetid-reviewer.md) reference these rules by path.

## Index

| File | When to read |
|---|---|
| [backend.md](./backend.md) | Editing anything under `backend/internal/`. Module shape, error handling, logging, transactions. |
| [frontend.md](./frontend.md) | Editing anything under `frontend/`. Apps, shared UI, routing, styling. |
| [database.md](./database.md) | Writing or reviewing a migration, or any SQL. Schemas, tenancy, soft-delete, audit, outbox. |
| [security.md](./security.md) | Touching auth, tokens, cookies, passwords, MFA, passkeys, sessions, crypto, or anything in `internal/auth`, `internal/mfa`, `internal/passkey`, `internal/social`, `internal/oidc`. |
| [api.md](./api.md) | Adding, removing, or changing any HTTP handler. OpenAPI + Postman discipline. |
| [testing.md](./testing.md) | Writing tests, deciding whether a change needs a test, or running the API suite. |
| [git-workflow.md](./git-workflow.md) | Commits, branches, PRs, what to keep out of a commit. |
| [docs.md](./docs.md) | Updating anything under `documents/`. What counts as "done". |

## Conventions for these rule files

- Bullet form, not prose. Each rule is one line where possible.
- Lead with the rule, end with the *why* in parentheses if non-obvious.
- Cite a concrete file path when a rule references existing code.
- No timestamps inside the rule text — these files are the living spec; git history is the changelog.
- If a rule changes, edit it here and update [../CLAUDE.md](../../CLAUDE.md) only if the high-level summary still fits.
