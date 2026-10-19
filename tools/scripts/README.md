# tools/scripts

Utility scripts for common development and operations tasks.

| Script | Purpose |
|---|---|
| `health-check.sh` | Verify the API is healthy (used in CI + deploy smoke tests) |
| `smoke-test.sh` | Lightweight post-deploy verification (login + token refresh) |
| `db-dump.sh` | Dump the dev database schema for review |
| `gen-secret.sh` | Generate a random secret value (JWT_SECRET, CSRF_KEY, etc.) |
| `group-hierarchy-check.sql` | List groups nested under another organization's group, or in a loop (read-only; run before migration 0136) |
| `api-keys-acting-for-people.sql` | List live API keys that act for a person, and whether that person is in the key's organization (read-only; review once) |

## Usage

```bash
# Check local backend is healthy
./tools/scripts/health-check.sh

# Smoke test against staging
BASE_URL=https://api.id.qeet.in ./tools/scripts/smoke-test.sh

# Generate a new 32-byte secret
./tools/scripts/gen-secret.sh
```
