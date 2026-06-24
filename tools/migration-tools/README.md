# tools/migration-tools

Helpers for creating and validating database migrations.

## Create a new migration pair

```bash
./tools/migration-tools/new-migration.sh add_widget_table
# creates:
#   platform/database/migrations/0063_add_widget_table.up.sql
#   platform/database/migrations/0063_add_widget_table.down.sql
```

The script auto-increments the sequence number from the latest existing migration.

## Validate migrations

```bash
./tools/migration-tools/validate-migrations.sh
# checks:
#   - every .up.sql has a matching .down.sql
#   - sequence numbers are contiguous with no gaps
#   - no file has been modified after being applied (detect accidental edits)
```

## Check migration status

```bash
# Against local dev DB
./tools/migration-tools/status.sh

# Against a specific DB
DB_URL=postgres://... ./tools/migration-tools/status.sh
```
