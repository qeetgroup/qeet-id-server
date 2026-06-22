#!/usr/bin/env bash
# Headless runner for the Qeet ID product-manager competitive-intelligence agent.
# Invoked by launchd (com.qeet.product-manager) at 09:00 / 13:00 / 20:00 IST,
# or run manually for a dry-run. Writes findings into qeet-files/qeet-id/.
set -euo pipefail

QG="/Users/a3097640/Desktop/QG"
# Absolute path to the claude binary (launchd's env is minimal; don't rely on PATH).
CLAUDE_BIN="${CLAUDE_BIN:-/Users/a3097640/.local/bin/claude}"
MODEL="${PM_MODEL:-sonnet}"            # override with PM_MODEL=opus for a deep run

# Optional focus arg for manual runs at any time: auth | enterprise | agent | all (default: all).
case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
  auth|enduser|end-user)          FOCUS="Auth & end-user (passkeys/WebAuthn, passwordless, MFA/adaptive/step-up, social & enterprise federation, breached-password)";;
  enterprise|authz|authorization) FOCUS="Enterprise & authorization (SSO SAML/OIDC, SCIM, directory/HRIS sync, orgs/multi-tenancy, RBAC/ReBAC/ABAC/FGA, compliance)";;
  agent|ai|mcp|dx|platform)       FOCUS="AI-agent identity, DX & platform (agent/workload identity, MCP auth, token exchange/delegation, token vaulting, SDKs, hosted/embeddable UI, pricing, new entrants)";;
  ""|all)                         FOCUS="ALL THREE areas in one light pass: (1) auth & end-user, (2) enterprise & authorization, (3) AI-agent identity / DX / platform";;
  *)                              FOCUS="${1}";;   # pass through a custom focus string
esac
LOGDIR="$QG/qeet-id/.claude/logs"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/run-$(date +%Y%m%d-%H%M%S).log"

PROMPT="Use the product-manager subagent to run a competitive-intelligence sweep. Focus: ${FOCUS}.
First read qeet-files/qeet-id/QEET-ID-STATUS.md to dedupe against what Qeet ID already has, then research the live market for that focus and update qeet-files/qeet-id/COMPETITIVE-INTEL.md and qeet-files/qeet-id/FEATURE-PROPOSALS.md exactly per your output contract. Cite primary sources. If nothing material changed, say so and add nothing."

cd "$QG/qeet-id"                       # cwd = project so the product-manager agent is discovered
echo "=== product-manager run $(date '+%Y-%m-%d %H:%M:%S %Z') (focus=${FOCUS%% (*}, model=$MODEL) ===" >> "$LOG"

TOOLS="WebSearch,WebFetch,Read,Grep,Glob,Write,Edit,Bash"
if [ -t 1 ]; then
  # Run from a Terminal (interactive): show live progress on screen AND save to the log.
  echo "Researching '${FOCUS%% (*}' — this takes a few minutes. Leave this window open…"
  echo
  "$CLAUDE_BIN" -p "$PROMPT" --model "$MODEL" --permission-mode acceptEdits --verbose \
    --add-dir "$QG/qeet-files" --allowedTools "$TOOLS" 2>&1 | tee -a "$LOG"
  echo
  echo "✅ Done. Findings written to:"
  echo "   $QG/qeet-files/qeet-id/COMPETITIVE-INTEL.md"
  echo "   $QG/qeet-files/qeet-id/FEATURE-PROPOSALS.md"
else
  # Run unattended (launchd/cron): write only to the log file.
  exec "$CLAUDE_BIN" -p "$PROMPT" --model "$MODEL" --permission-mode acceptEdits \
    --add-dir "$QG/qeet-files" --allowedTools "$TOOLS" >> "$LOG" 2>&1
fi
