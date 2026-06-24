#!/usr/bin/env bash
# Verify the API health endpoint responds and returns a known-good structure.
# Exit 0 = healthy, non-zero = unhealthy.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:4001}"

echo "Checking ${BASE_URL}/healthz ..."
response=$(curl -sf --max-time 5 "${BASE_URL}/healthz") || {
  echo "FAIL: /healthz unreachable"
  exit 1
}

status=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
if [ "$status" != "ok" ]; then
  echo "FAIL: unexpected status '${status}'"
  echo "$response"
  exit 1
fi

echo "Checking ${BASE_URL}/readyz ..."
curl -sf --max-time 5 "${BASE_URL}/readyz" >/dev/null || {
  echo "FAIL: /readyz returned non-200 (DB likely unreachable)"
  exit 1
}

version=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version','unknown'))" 2>/dev/null || echo "unknown")
echo "OK — version: ${version}"
