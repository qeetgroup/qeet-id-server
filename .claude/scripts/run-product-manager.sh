#!/usr/bin/env bash
# Headless runner for the Qeet ID product-manager competitive-intelligence agent.
# Invoked by launchd (com.qeet.product-manager) at 09:00 / 13:00 / 20:00 IST,
# or run manually for a dry-run. Writes findings into qeet-files/qeet-id/.
set -euo pipefail

QG="/Users/a3097640/Desktop/QG"
# Absolute path to the claude binary (launchd's env is minimal; don't rely on PATH).
CLAUDE_BIN="${CLAUDE_BIN:-/Users/a3097640/.local/bin/claude}"
MODEL="${PM_MODEL:-sonnet}"            # override with PM_MODEL=opus for a deep run

# Optional focus arg for manual runs. Default (no arg / "all" / "full") = COMPREHENSIVE FULL SWEEP
# of the whole landscape. Scoped focuses below are for cost/time control only.
case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
  auth|enduser|end-user)          FOCUS="Auth & end-user (passkeys/WebAuthn, passwordless, MFA/adaptive/step-up, social & enterprise federation, breached-password)";;
  enterprise|authz|authorization) FOCUS="Enterprise & authorization (SSO SAML/OIDC, SCIM, directory/HRIS sync, orgs/multi-tenancy, RBAC/ReBAC/ABAC/FGA, compliance)";;
  agent|ai|mcp|dx|platform)       FOCUS="AI-agent identity, DX & platform (agent/workload identity, MCP auth, token exchange/delegation, token vaulting, SDKs, hosted/embeddable UI, pricing, new entrants)";;
  pam|iga|governance|privileged)  FOCUS="Privileged access & identity governance (PAM: JIT/time-bound access, session recording, credential brokering; IGA: access requests/approvals, access reviews/certifications, SoD, least-privilege analytics)";;
  decentralized|ssi|vc|wallet)    FOCUS="Decentralized & verifiable identity (W3C Verifiable Credentials, DIDs, EUDI/mDL wallets, selective disclosure, reusable identity/KYC)";;
  ""|all|full|sweep)              FOCUS="COMPREHENSIVE FULL SWEEP across the ENTIRE landscape — all taxonomy dimensions (1-10) plus active discovery of new players/tools/standards. Aim for completeness of the feature catalog, not a light pass.";;
  *)                              FOCUS="${1}";;   # pass through a custom focus string
esac
LOGDIR="$QG/qeet-id/.claude/logs"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/run-$(date +%Y%m%d-%H%M%S).log"

PROMPT="Use the product-manager subagent to map the identity/auth/authz/IAM/CIAM market. Focus: ${FOCUS}.
Research the WHOLE internet of similar platforms — actively discover players/tools/standards beyond your seed list, not just known names. First read ROADMAP.md to dedupe against what Qeet ID already has, then update all three outputs exactly per your output contract: qeet-files/qeet-id/FEATURE-CATALOG.md (the master capability inventory — extend coverage toward complete), qeet-files/qeet-id/FEATURE-PROPOSALS.md (the prioritized gaps), and qeet-files/qeet-id/COMPETITIVE-INTEL.md (dated log). Cite primary sources. Goal: Qeet ID should support every feature worth having."

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
  echo "   $QG/qeet-files/qeet-id/FEATURE-CATALOG.md     (master capability inventory)"
  echo "   $QG/qeet-files/qeet-id/FEATURE-PROPOSALS.md   (prioritized gaps)"
  echo "   $QG/qeet-files/qeet-id/COMPETITIVE-INTEL.md   (dated research log)"
else
  # Run unattended (launchd/cron): write only to the log file.
  exec "$CLAUDE_BIN" -p "$PROMPT" --model "$MODEL" --permission-mode acceptEdits \
    --add-dir "$QG/qeet-files" --allowedTools "$TOOLS" >> "$LOG" 2>&1
fi
