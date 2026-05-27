---
description: Scaffold a new golang-migrate up/down migration pair with the next sequence number.
---

Create a new migration pair under `backend/migrations/`. Read [../rules/database.md](../rules/database.md) first — the migration rules in there are binding.

Input: `$ARGUMENTS` is the snake_case migration name (e.g. `add_user_recovery_codes`). If empty, ask the user for the name before proceeding.

Steps:

1. List `backend/migrations/` and find the highest existing four-digit prefix (e.g. `0029`). The new prefix is that number + 1, zero-padded to 4 digits.
2. Create two files:
   - `backend/migrations/<NNNN>_<name>.up.sql`
   - `backend/migrations/<NNNN>_<name>.down.sql`
3. Seed the `.up.sql` with a leading `-- <NNNN>: <human-readable summary>` comment and a placeholder `BEGIN;` / `COMMIT;` block. Seed `.down.sql` with the inverse skeleton (drop / revert).
4. Remind the user to:
   - Keep DDL inside the transaction.
   - Add `tenant_id` to any new business table (see [CLAUDE.md](../../CLAUDE.md) — Database conventions).
   - Update [backend/api/openapi.yaml](../../backend/api/openapi.yaml) if the schema change is user-visible.
   - **Never edit a merged migration** — only edit these two new files.
5. Do **not** run `make migrate-up` yet. Show the user the new file paths and let them review the SQL first.
