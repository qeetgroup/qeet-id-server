#!/bin/bash
# Double-click this file in Finder to run the Qeet ID product-manager competitive sweep.
# (No Terminal knowledge needed — it opens a window, asks what to research, and runs.)
clear
echo "════════════════════════════════════════════════"
echo "   Qeet ID — Product Manager competitive sweep"
echo "════════════════════════════════════════════════"
echo
echo "What should it research?"
echo "   1) Everything  (all areas)          [default]"
echo "   2) Auth & end-user                  (passkeys, MFA, passwordless, social/SSO)"
echo "   3) Enterprise & authorization       (SSO, SCIM, orgs, RBAC/ReBAC, compliance)"
echo "   4) AI-agent identity & developer    (agents, MCP, token exchange, SDKs, pricing)"
echo
read -r -p "Type 1-4 then Enter (or just press Enter for 1): " choice
case "$choice" in
  2) FOCUS=auth ;;
  3) FOCUS=enterprise ;;
  4) FOCUS=agent ;;
  *) FOCUS=all ;;
esac
echo
bash "/Users/a3097640/Desktop/QG/qeet-id/.claude/scripts/run-product-manager.sh" "$FOCUS"
echo
read -r -p "All done — press Enter to close this window."
