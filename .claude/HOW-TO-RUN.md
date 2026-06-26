# How to use the Qeet ID agents

There are **two stages**, run by two sets of agents:

1. **Find feature ideas** — the **product-manager** agent researches the *whole* identity/auth/iam/ciam
   market (every site it can find, not just a fixed list) and writes a feature catalog +
   proposals into your PRD hub. → **Part 1** (a script you run).
2. **Build a feature** — a 6-agent **delivery pipeline** turns one of those proposals into
   tested, security-reviewed code. → **Part 2** (you chat with Claude).

═══════════════════════════════════════════════════════════════

# Part 1 — Find feature ideas (product-manager)

This agent researches the **entire internet** of identity/auth/IAM/CIAM platforms — discovering
new players and features beyond any fixed list — and writes a master feature catalog + ranked
ideas into your PRD hub, so Qeet ID can support every feature worth having. You run it
**whenever you want** — there's no schedule.

It writes to:
- `~/Desktop/QG/qeet-files/qeet-id/FEATURE-CATALOG.md` — master capability inventory (every feature × who ships it × Qeet ID has/lacks)
- `~/Desktop/QG/qeet-files/qeet-id/FEATURE-PROPOSALS.md` — prioritized feature backlog (the gaps)
- `~/Desktop/QG/qeet-files/qeet-id/COMPETITIVE-INTEL.md` — dated research log

---

## ⭐ Easiest way — double-click (no typing)

1. In **Finder**, go to: `Desktop → QG → qeet-id → .claude → scripts`
   - (`.claude` is a hidden folder. If you don't see it, press **⌘ + Shift + .** to show hidden files.)
2. Double-click **`Run Qeet PM.command`**.
3. A black Terminal window opens and asks **what to research** — type `1`–`4` (or just press **Enter** for "Everything") and hit Enter.
4. Wait a few minutes. You'll see activity scroll by; when it says **"All done"**, you're finished.
5. Open the result files (links above) to read the findings.

> First time only: macOS may say *"cannot be opened because it is from an unidentified developer."*
> Fix: **right-click** the file → **Open** → **Open** (you only do this once).

---

## Alternative — one line in Terminal

1. Open **Terminal** (press **⌘ + Space**, type `Terminal`, press Enter).
2. Copy–paste this line and press Enter:
   ```bash
   bash ~/Desktop/QG/qeet-id/.claude/scripts/run-product-manager.sh
   ```
3. Wait a few minutes. It prints a summary when done.
4. Read the findings:
   ```bash
   open ~/Desktop/QG/qeet-files/qeet-id/FEATURE-CATALOG.md
   open ~/Desktop/QG/qeet-files/qeet-id/FEATURE-PROPOSALS.md
   ```

### Research just one topic (faster / cheaper)
Add one word at the end:
```bash
bash ~/Desktop/QG/qeet-id/.claude/scripts/run-product-manager.sh auth
bash ~/Desktop/QG/qeet-id/.claude/scripts/run-product-manager.sh enterprise
bash ~/Desktop/QG/qeet-id/.claude/scripts/run-product-manager.sh agent
```
| word | covers |
|---|---|
| `auth` | passkeys/WebAuthn, passwordless, MFA, social & enterprise login |
| `enterprise` | SSO (SAML/OIDC), SCIM, orgs/multi-tenancy, RBAC/ReBAC, compliance |
| `agent` | AI-agent identity, MCP, token exchange, SDKs, pricing, new entrants |
| *(nothing)* | all three (a full sweep) |

### Want a deeper, sharper analysis?
Put `PM_MODEL=opus` in front (slower, costs more, higher quality):
```bash
PM_MODEL=opus bash ~/Desktop/QG/qeet-id/.claude/scripts/run-product-manager.sh agent
```

---

## What to expect

- **It looks quiet for a few minutes.** That's normal — it's reading the web. It prints a summary at the end.
- **Run it as often (or rarely) as you like.** The market moves slowly — once a week or before planning is plenty.
- **Let one run finish before starting another.**
- Each run **adds** to the two files (newest entry on top) and **avoids repeating** ideas it already logged or that Qeet ID already has.

## If it fails

- **`Operation not permitted`** → macOS needs **Full Disk Access** for the workspace (it lives under `~/Desktop`). Grant it once: **System Settings → Privacy & Security → Full Disk Access → +** and add **`/bin/bash`** and **`/Users/a3097640/.local/bin/claude`**, toggle both ON. (Already done? Then ignore this.)
- **Nothing written / errors** → check the latest log:
  ```bash
  ls -t ~/Desktop/QG/qeet-id/.claude/logs/run-*.log | head -1 | xargs cat
  ```

## Don't want to use Terminal at all?
Just ask Claude (in this repo) — say **"run the product-manager agent"** — and it'll do the sweep for you.

═══════════════════════════════════════════════════════════════

# Part 2 — Build a feature (the 6-agent pipeline)

Once the product-manager has filled `FEATURE-PROPOSALS.md`, this team turns a proposal into
real, tested, security-reviewed code. **You don't run a script for this — you chat with Claude**
and it drives the agents. (Full details: [PIPELINE.md](PIPELINE.md).)

### Step 1 — open Claude in the qeet-id folder
In a Terminal:
```bash
cd ~/Desktop/QG/qeet-id
claude
```
(Or open the folder in the Claude Code VS Code extension / desktop app.) Opening it **inside
`qeet-id`** is what makes the build agents available.

### Step 2 — pick a proposal
Open `~/Desktop/QG/qeet-files/qeet-id/FEATURE-PROPOSALS.md` and note an ID, e.g. **FP-013**.

### Step 3 — ask Claude to run the pipeline
Paste a request like this and let it work through the stages:

> Build **FP-013** from FEATURE-PROPOSALS.md. Use the **feature-architect** agent to write the
> spec, then **backend-engineer** (and **frontend-engineer** if there's UI) to implement it,
> then **qa-test-engineer** for tests, then **security-reviewer** to audit it, then
> **docs-writer** to update docs. Stop before committing so I can review.

You can also go one step at a time (recommended the first few times), e.g.:
- *"Use the feature-architect agent to spec FP-013."* → review the spec in `docs/specs/`
- *"Now use the backend-engineer agent to implement that spec."*
- *"Now the qa-test-engineer agent."* … *"Now the security-reviewer agent."*

### What each agent does (one line each)
| Agent | Does |
|---|---|
| **feature-architect** | writes the plan → `docs/specs/<feature>.md` (no code) |
| **backend-engineer** | Go code + database migration + API |
| **frontend-engineer** | the React UI (console / login / website) |
| **qa-test-engineer** | writes & runs the tests |
| **security-reviewer** | checks for security holes (read-only) |
| **docs-writer** | updates docs + marks the proposal **done** |

### Important to know
- **The agents do NOT commit to git** — they leave the changes for you to review. When you're
  happy, you (or ask Claude to) commit.
- **Run one feature at a time.** A full feature can take a while.
- **You don't need to memorize agent names** — you can just say *"build FP-013 end to end and
  stop before committing,"* and Claude will pick the right agents in order.
- If you only changed your mind about *what* to build, re-run Part 1 first to refresh the proposals.
