#!/usr/bin/env bash
# Post-deploy smoke test: login + token refresh.
# Needs a running backend with the demo seed applied.
# Exit 0 = smoke test passed, non-zero = failure.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:4001}"
EMAIL="${SMOKE_EMAIL:-sneha@qeet.in}"
PASSWORD="${SMOKE_PASSWORD:-Password123!}"

echo "Smoke test against ${BASE_URL}"

# 1. Login
echo "1. Login..."
login_response=$(curl -sf --max-time 10 -X POST "${BASE_URL}/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}") || {
  echo "FAIL: login request failed"
  exit 1
}

access_token=$(echo "$login_response" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo "")
refresh_token=$(echo "$login_response" | python3 -c "import sys,json; print(json.load(sys.stdin)['refresh_token'])" 2>/dev/null || echo "")
user_id=$(echo "$login_response" | python3 -c "import sys,json; print(json.load(sys.stdin)['user_id'])" 2>/dev/null || echo "")

if [ -z "$access_token" ]; then
  echo "FAIL: no access_token in login response"
  echo "$login_response"
  exit 1
fi
echo "   OK — got access_token"

# 2. Authenticated request
# There is no GET /v1/users/me endpoint (QID-10) — the backend routes
# /v1/users/{id} and would try to parse the literal "me" as a UUID, returning
# 400 "invalid id". Use the user_id from the login response instead, matching
# the workaround the console's own lib/auth.ts already uses.
echo "2. Authenticated profile fetch..."
curl -sf --max-time 5 "${BASE_URL}/v1/users/${user_id}" \
  -H "Authorization: Bearer ${access_token}" >/dev/null || {
  echo "FAIL: /v1/users/{id} failed"
  exit 1
}
echo "   OK"

# 3. Token refresh
echo "3. Token refresh..."
refresh_response=$(curl -sf --max-time 5 -X POST "${BASE_URL}/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"${refresh_token}\"}") || {
  echo "FAIL: token refresh failed"
  exit 1
}

new_token=$(echo "$refresh_response" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo "")
if [ -z "$new_token" ]; then
  echo "FAIL: no access_token in refresh response"
  exit 1
fi
echo "   OK"

echo ""
echo "Smoke test PASSED ✓"
