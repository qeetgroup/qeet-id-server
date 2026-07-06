# qeet-id `.claude/` — automation

Two parts: a **product-manager** agent that finds feature gaps, and a **6-agent delivery pipeline** that builds them.

## Implementation pipeline (agents/)

Turns a `FEATURE-PROPOSALS.md` row into shipped, tested, security-reviewed code. Full flow + "definition of done" in **[PIPELINE.md](PIPELINE.md)**.

| Agent | Role |
|---|---|
| [`agents/feature-architect.md`](agents/feature-architect.md) | Proposal → `docs/specs/<slug>.md` (data model, migration plan, API surface, security/tenant notes, task breakdown). No code. |
| [`agents/backend-engineer.md`](agents/backend-engineer.md) | Go domain pkg (domain/repo/service/http) + migration pair + OpenAPI + router wiring; gates on build/vet/test + arch test. |
| [`agents/frontend-engineer.md`](agents/frontend-engineer.md) | React apps (console/login/website) on `@qeetrix/*` + SDK updates; gates on pnpm typecheck/lint/build. |
| [`agents/qa-test-engineer.md`](agents/qa-test-engineer.md) | Unit + testcontainers integration + Postman + Vitest; never weakens tests. |
| [`agents/security-reviewer.md`](agents/security-reviewer.md) | IAM threat-model audit of the diff (tenant isolation, authz, tokens, CSRF…). **Read-only.** |
| [`agents/docs-writer.md`](agents/docs-writer.md) | Updates docs/OpenAPI + closes the loop (proposal → `done`, updates `ROADMAP.md`). |
| [`agents/devops-engineer.md`](agents/devops-engineer.md) | Deploy/release: Helm chart, Compose, Dockerfiles, CI/CD, migration rollout. Validates with helm lint/template + docker build; **never deploys/pushes**. |

Reuse the existing `/code-review`, `/verify`, `/simplify` skills + `code-architect` plugin — don't duplicate them. Agents implement in the working tree and run tests, but **don't commit** — you review & commit.

## Product-manager competitive-intelligence agent

> **👉 New here? Read [HOW-TO-RUN.md](HOW-TO-RUN.md) — plain-English steps (incl. a double-click launcher).**

An on-demand agent that maps the **entire internet** of identity/auth/authz/IAM/CIAM/PAM/IGA
platforms — actively discovering players/tools/standards beyond any fixed list — inventories
**every** capability the market offers, and writes a comprehensive feature catalog + prioritized
proposals into the PRD hub so Qeet ID can support every feature worth having. You run it
**manually whenever you want** (no schedule).

| File | Role |
|---|---|
| [`agents/product-manager.md`](agents/product-manager.md) | The agent: persona, landscape (seed list + active discovery), 10-dim capability taxonomy, full-sweep vs scoped run modes, methodology, output contract. Invoke on-demand with the `product-manager` subagent, or via the scheduler below. |
| [`scripts/run-product-manager.sh`](scripts/run-product-manager.sh) | Headless runner (`claude -p`) the scheduler calls. Also usable for a manual dry-run. |
| [`scheduling/com.qeet.product-manager.plist`](scheduling/com.qeet.product-manager.plist) | launchd job — 09:00 / 13:00 / 20:00 **local (IST)**. |
| [`settings.json`](settings.json) | Tool allowlist (WebSearch/WebFetch/etc.) so interactive on-demand runs aren't prompt-heavy. |

**Outputs** (in the non-git PRD hub, not this repo):
- `../../qeet-files/qeet-id/FEATURE-CATALOG.md` — **master capability inventory** (every feature the landscape offers × who ships it × Qeet ID has/lacks). Grows toward complete coverage.
- `../../qeet-files/qeet-id/FEATURE-PROPOSALS.md` — deduped, prioritized backlog (the gaps).
- `../../qeet-files/qeet-id/COMPETITIVE-INTEL.md` — dated rolling research log.
- `../ROADMAP.md` is the **read-only golden source** the agent dedupes against.

### Run it manually (this is how it's used — no schedule)
Default is a **comprehensive full sweep** of the whole landscape; you can scope to one focus to save time/cost:
```bash
# comprehensive full sweep across the entire landscape (default)
bash qeet-id/.claude/scripts/run-product-manager.sh

# scope to one focus: auth | enterprise | agent | pam | decentralized
bash qeet-id/.claude/scripts/run-product-manager.sh agent

# deeper run on a stronger model
PM_MODEL=opus bash qeet-id/.claude/scripts/run-product-manager.sh enterprise

# watch it / read results
tail -f qeet-id/.claude/logs/run-*.log
open ../../qeet-files/qeet-id/FEATURE-CATALOG.md
```
It runs to completion in the foreground (a sweep takes a few minutes) and writes to `qeet-files/qeet-id/`. Requires the Full Disk Access grant below (the binaries already have it).

### Optional: re-enable a recurring schedule (NOT installed)
Not active — you chose manual-only. If you ever want it back, a launchd template is kept at `scheduling/com.qeet.product-manager.plist` (fires 09:00/13:00/20:00 IST):
```bash
cp qeet-id/.claude/scheduling/com.qeet.product-manager.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/com.qeet.product-manager.plist   # install
launchctl unload -w ~/Library/LaunchAgents/com.qeet.product-manager.plist # uninstall
```

### Notes & caveats
- **macOS Full Disk Access is REQUIRED** (the workspace is under `~/Desktop`, which macOS protects from background launchd agents). Without it the scheduled run fails with exit `126` / `Operation not permitted` in `launchd.err.log` and writes nothing. One-time fix:
  1. System Settings → **Privacy & Security → Full Disk Access** → click **+**.
  2. In the picker press **⌘⇧G**, enter `/bin/bash`, Add, toggle **ON**.
  3. **+** again, ⌘⇧G, enter `/Users/a3097640/.local/bin/claude`, Add, toggle **ON**.
  4. Re-test: `launchctl start com.qeet.product-manager`, then confirm `launchd.err.log` is clean and a new `logs/run-*.log` appeared.
  (Interactive/on-demand runs from your Terminal work without this — only the unattended launchd trigger needs it. Re-add the `claude` entry after a major claude version bump if scheduled runs start failing.)
- **Local only:** launchd fires only while the Mac is awake/online. A run missed during sleep is coalesced and runs once on next wake. For always-on reliability, port to a cloud `/schedule` routine that commits into this git repo (it cannot write to the non-git `qeet-files/`).
- **Headless permissions:** the runner passes `--permission-mode acceptEdits --allowedTools "…"`; print mode never prompts, so any tool it needs must be in that list. If a tool is silently denied, add it (or use `--dangerously-skip-permissions` in the script as a last resort — your machine, scoped research task).
- **Auth/env:** the plist sets `PATH` (claude at `/Users/a3097640/.local/bin` + node) and `HOME` so the headless `claude` finds your existing login. If you move/upgrade the claude binary or change machines, update the plist `PATH` and `scripts/run-product-manager.sh` `CLAUDE_BIN`.
- **Cost control:** scheduled runs default to `sonnet` and a single rotating focus per run (not a full sweep). `.claude/logs/` is gitignored.
