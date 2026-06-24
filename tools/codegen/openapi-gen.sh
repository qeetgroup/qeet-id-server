#!/usr/bin/env bash
# Generate TypeScript types for the JS SDK from the OpenAPI contract.
#
# The contract is split into five bounded-context files under api/openapi/.
# openapi-typescript wants a single document, so we merge the five into a
# temporary bundle (via the openapi-split tool), generate from it, and discard
# the bundle — no monolith is committed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${REPO_ROOT}/sdk/js/sdk/src/generated/schema.ts"

if ! command -v openapi-typescript &>/dev/null; then
  echo "openapi-typescript not found — install with: pnpm add -g openapi-typescript"
  exit 1
fi

TMP="$(mktemp -t qeet-id-openapi.XXXXXX.yaml)"
trap 'rm -f "$TMP"' EXIT

echo "Merging api/openapi/*.yaml → bundle"
(cd "$REPO_ROOT" && go run ./tools/openapi-split merge) > "$TMP"

echo "Generating TypeScript types"
mkdir -p "$(dirname "$OUT")"
openapi-typescript "$TMP" --output "$OUT"
echo "Done → ${OUT}"
