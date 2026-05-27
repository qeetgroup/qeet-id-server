#!/usr/bin/env bash
# Newman runner for the qeet-identity Postman collection.
#
# Usage:
#   ./run.sh                          # full run against http://localhost:4001
#   ./run.sh --base http://localhost:4000
#   ./run.sh --folder Auth            # run one folder
#   ./run.sh --folder Auth --folder Tenants  # run multiple folders (repeat flag)
#   ./run.sh --ci                     # JUnit + HTML reports under ./reports
#   ./run.sh --bail                   # stop on first failure
#   ./run.sh --skip-501               # skip routes whose name starts with [501]
#
# Requires: node >= 18. Newman is fetched on demand via npx.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTION="$DIR/qeet-identity.postman_collection.json"
ENVIRONMENT="$DIR/qeet-identity.postman_environment.json"

BASE_URL=""
BAIL=""
CI_MODE=0
SKIP_501=0
FOLDERS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)       BASE_URL="$2"; shift 2 ;;
    --folder)     FOLDERS+=("$2"); shift 2 ;;
    --bail)       BAIL="--bail"; shift ;;
    --ci)         CI_MODE=1; shift ;;
    --skip-501)   SKIP_501=1; shift ;;
    -h|--help)    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

if [[ ! -f "$COLLECTION" ]]; then
  echo "collection not found: $COLLECTION" >&2; exit 1
fi
if [[ ! -f "$ENVIRONMENT" ]]; then
  echo "environment not found: $ENVIRONMENT" >&2; exit 1
fi

CMD=(npx --yes newman@6 run "$COLLECTION" -e "$ENVIRONMENT")

if [[ -n "$BASE_URL" ]]; then
  CMD+=(--env-var "baseUrl=$BASE_URL")
fi

for f in "${FOLDERS[@]:-}"; do
  [[ -z "$f" ]] && continue
  CMD+=(--folder "$f")
done

[[ -n "$BAIL" ]] && CMD+=("$BAIL")

if [[ $CI_MODE -eq 1 ]]; then
  mkdir -p "$DIR/reports"
  CMD+=(--reporters cli,junit,htmlextra
        --reporter-junit-export "$DIR/reports/junit.xml"
        --reporter-htmlextra-export "$DIR/reports/report.html"
        --reporter-htmlextra-title "Qeet Identity API")
fi

if [[ $SKIP_501 -eq 1 ]]; then
  # Newman doesn't support skipping by name pattern directly; emit a tmp collection
  # with the [501] requests stripped. Requires jq.
  if ! command -v jq >/dev/null 2>&1; then
    echo "--skip-501 needs jq (brew install jq)" >&2; exit 1
  fi
  TMP="$(mktemp -t qeet-postman.XXXXXX).json"
  jq '
    .item |= map(
      .item |= map(select((.name // "") | startswith("[501]") | not))
    )
  ' "$COLLECTION" > "$TMP"
  trap 'rm -f "$TMP"' EXIT
  # Replace collection arg.
  CMD=("${CMD[@]/$COLLECTION/$TMP}")
fi

echo "+ ${CMD[*]}"
exec "${CMD[@]}"
