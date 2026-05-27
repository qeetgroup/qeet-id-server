# .claude/ — Claude Code configuration for this repo

This folder holds project-level configuration that Claude Code (and any other Anthropic-SDK agent) picks up automatically. It pairs with the top-level [CLAUDE.md](../CLAUDE.md), which is the AI-facing project guide.

## What's in here

| Path | Purpose | Committed? |
|---|---|---|
| `settings.json` | Permission allow/deny lists, default env vars. Applied to every assistant session in this repo. | yes |
| `settings.local.json` | Personal overrides (extra allowlist entries, your own env). | **no — gitignored** |
| `commands/` | Repo-specific slash commands (`/routes`, `/migration-new`, …). | yes |
| `agents/` | Repo-specific subagents Claude can delegate to (e.g. `qeetid-reviewer`). | yes |
| `rules/` | Topic-scoped rule files (backend, frontend, database, security, …). Referenced from [CLAUDE.md](../CLAUDE.md) and from commands/agents. | yes |
| `skills/` | Multi-phase procedures with auto-triggered descriptions ([add-endpoint](./skills/add-endpoint/SKILL.md), [release-readiness](./skills/release-readiness/SKILL.md), [gap-fill](./skills/gap-fill/SKILL.md)). | yes |

## How `settings.json` is scoped

- **Allow:** safe read-only or dev-loop commands — `make *`, `go test`, `pnpm *`, `git status/diff/log`, `gh pr view`, `lsof`, `grep`, `find`, etc. — so Claude doesn't prompt for each one.
- **Deny:** anything that can destroy work or leak secrets:
  - `rm -rf`, `git push --force`, `git reset --hard`, `git config`
  - migration `down` and `make db-reset` / `db-wipe` (these drop schemas)
  - reads / writes to `.env*`, `*.pem`, `*.key`, `secrets/**`
  - edits to already-merged migrations (`0001`…`0029`) — never rewrite history; write a new migration
- **Env:** `QEETID_DB_URL` and `QEETID_API_BASE` match the dev defaults in the [Makefile](../Makefile).

## Adjusting locally

Add personal allowlist entries to `.claude/settings.local.json` — it won't be committed. Example:

```json
{
  "permissions": {
    "allow": ["Bash(psql:*)", "Bash(open http://localhost:*)"]
  }
}
```

## Adding a new slash command

Drop a `name.md` file in `commands/`. The first line should be a short description; everything after that is the prompt. See existing commands for the pattern.

## See also

- [CLAUDE.md](../CLAUDE.md) — project guide for AI assistants
- [CONTRIBUTING.md](../CONTRIBUTING.md) — human contributor guide
- [documents/IMPLEMENTATION-STATUS.md](../documents/IMPLEMENTATION-STATUS.md) — authoritative feature status
