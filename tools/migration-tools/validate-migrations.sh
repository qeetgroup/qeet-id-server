#!/usr/bin/env bash
# Validate migration files: check pairing and contiguous sequence numbers.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIGRATIONS_DIR="${REPO_ROOT}/internal/platform/database/migrations"

errors=0

# Check every .up.sql has a matching .down.sql
for up in "$MIGRATIONS_DIR"/*.up.sql; do
  down="${up%.up.sql}.down.sql"
  if [ ! -f "$down" ]; then
    echo "ERROR: missing down migration for $(basename "$up")"
    errors=$((errors + 1))
  fi
done

# Check every .down.sql has a matching .up.sql
for down in "$MIGRATIONS_DIR"/*.down.sql; do
  up="${down%.down.sql}.up.sql"
  if [ ! -f "$up" ]; then
    echo "ERROR: missing up migration for $(basename "$down")"
    errors=$((errors + 1))
  fi
done

# Check sequence is contiguous
prev=0
for up in $(ls "$MIGRATIONS_DIR"/*.up.sql 2>/dev/null | sort); do
  seq=$(basename "$up" | cut -d_ -f1)
  expected=$(printf "%04d" $((prev + 1)))
  if [ "$seq" != "$expected" ]; then
    echo "ERROR: gap in migration sequence — expected ${expected}, found ${seq}"
    errors=$((errors + 1))
  fi
  prev=$((10#$seq))
done

if [ "$errors" -eq 0 ]; then
  echo "OK — ${prev} migration(s) validated"
else
  echo "FAILED — ${errors} error(s)"
  exit 1
fi
