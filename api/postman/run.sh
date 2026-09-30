#!/usr/bin/env bash
# Newman runner for the qeet-id Postman collection.
#
# Usage:
#   ./run.sh                          # full run against http://localhost:4001
#   ./run.sh --base http://localhost:4001
#   ./run.sh --folder "03 Auth"       # run one folder (bare "Auth" also resolves)
#   ./run.sh --folder "03 Auth" --folder "09 Tenants"  # multiple (repeat flag)
#   ./run.sh --ci                     # JUnit + HTML reports under ./reports
#   ./run.sh --bail                   # stop on first failure
#   ./run.sh --skip-501               # skip [501]-tagged routes (NN prefix ok)
#
# Requires: Bun. Newman is fetched on demand via bunx.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTION="$DIR/qeet-id.postman_collection.json"
ENVIRONMENT="$DIR/qeet-id.postman_environment.json"

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

# Resolve a --folder argument to its numbered display name (e.g. Auth -> "03 Auth").
# Folders in the collection are numbered ("01 Health", "03 Auth", …); this lets old
# commands that pass the bare name keep working. Already-numbered or unknown names are
# passed through verbatim. Needs jq for the lookup; without jq, the arg is used as-is.
normalize_folder() {
  local arg="$1"
  if [[ "$arg" =~ ^[0-9][0-9][[:space:]] ]]; then
    printf '%s' "$arg"; return
  fi
  if command -v jq >/dev/null 2>&1; then
    local match
    match="$(jq -r --arg a "$arg" \
      '[ .item[].name | select(test("^[0-9][0-9] ") and (.[3:] == $a)) ] | .[0] // empty' \
      "$COLLECTION" 2>/dev/null || true)"
    if [[ -n "$match" ]]; then printf '%s' "$match"; return; fi
  fi
  printf '%s' "$arg"
}

CMD=(bunx newman@6 run "$COLLECTION" -e "$ENVIRONMENT")

if [[ -n "$BASE_URL" ]]; then
  CMD+=(--env-var "baseUrl=$BASE_URL")
fi

for f in "${FOLDERS[@]:-}"; do
  [[ -z "$f" ]] && continue
  CMD+=(--folder "$(normalize_folder "$f")")
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
      .item |= map(select((.name // "") | test("^(?:[0-9]{2} +)?\\[501\\]") | not))
    )
  ' "$COLLECTION" > "$TMP"
  trap 'rm -f "$TMP"' EXIT
  # Replace collection arg.
  CMD=("${CMD[@]/$COLLECTION/$TMP}")
fi

echo "+ ${CMD[*]}"
exec "${CMD[@]}"
