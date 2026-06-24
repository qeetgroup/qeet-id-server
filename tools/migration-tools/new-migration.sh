#!/usr/bin/env bash
# Create a new migration pair with the next sequence number.
# Usage: ./tools/migration-tools/new-migration.sh <name>
# Example: ./tools/migration-tools/new-migration.sh add_widget_table
set -euo pipefail

NAME="${1:-}"
if [ -z "$NAME" ]; then
  echo "Usage: $0 <migration_name>"
  echo "Example: $0 add_widget_table"
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIGRATIONS_DIR="${REPO_ROOT}/platform/database/migrations"

# Find the next sequence number
LAST=$(ls "$MIGRATIONS_DIR"/*.up.sql 2>/dev/null | sort | tail -1 | xargs basename | cut -d_ -f1)
if [ -z "$LAST" ]; then
  NEXT="0001"
else
  NEXT=$(printf "%04d" $((10#$LAST + 1)))
fi

UP="${MIGRATIONS_DIR}/${NEXT}_${NAME}.up.sql"
DOWN="${MIGRATIONS_DIR}/${NEXT}_${NAME}.down.sql"

cat > "$UP" << EOF
-- Migration ${NEXT}: ${NAME}
-- Up

EOF

cat > "$DOWN" << EOF
-- Migration ${NEXT}: ${NAME}
-- Down

EOF

echo "Created:"
echo "  ${UP}"
echo "  ${DOWN}"
