# Database Operations Runbook

## Migration management

### Apply all pending migrations (development)

```bash
make migrate-up
# Or directly:
migrate -source file://migrations -database $DATABASE_URL up
```

### Apply a specific number of steps

```bash
make migrate-up N=1    # apply 1 migration
# Or:
migrate -source file://migrations -database $DATABASE_URL up 1
```

### Roll back (development only)

**Never roll back migrations in production** without a thorough data assessment. Rolling back may lose data written by the new schema.

```bash
make migrate-down       # roll back 1 step
make migrate-down-all   # roll back everything (wipes all data)
```

### Check current migration version

```bash
migrate -source file://migrations -database $DATABASE_URL version
```

### Fix a dirty migration state

If a migration fails mid-run, golang-migrate marks the version as "dirty" and refuses to apply further migrations until it's resolved:

```bash
# Identify the dirty version
migrate -source file://migrations -database $DATABASE_URL version
# Output: 0042 (dirty)

# Force-set to the last clean version (the migration BEFORE the dirty one)
make migrate-force V=0041
# Or:
migrate -source file://migrations -database $DATABASE_URL force 0041

# Then investigate and fix the failed migration, then re-apply
make migrate-up
```

### Adding a new migration

```bash
# Create migration files
touch platform/database/platform/database/migrations/0063_my_change.up.sql
touch platform/database/platform/database/migrations/0063_my_change.down.sql
```

**Rules:**
- Never edit an applied migration — add a new pair
- Number sequentially (next after current highest)
- Name descriptively (snake_case)
- Always write a `down.sql` that reverses the `up.sql`
- Test `down.sql` locally before committing

---

## Emergency database access

### Development

```bash
make db-psql    # opens psql shell in the Postgres Docker container
```

### Production (Kubernetes)

```bash
# Find the migration Job pod (it has psql available)
kubectl get pods -n qeet-id | grep migrate

# Exec into the pod
kubectl exec -it -n qeet-id <migrate-pod-name> -- psql $DATABASE_URL
```

Or use a dedicated bastion/jump host with psql access to the managed DB.

---

## Backup and restore

### Backup (full dump)

```bash
pg_dump $DATABASE_URL \
  --format=custom \
  --compress=9 \
  --file=qeet-id-$(date +%Y%m%d-%H%M%S).dump
```

### Backup (schema-only, for documentation)

```bash
pg_dump $DATABASE_URL \
  --schema-only \
  --file=qeet-id-schema-$(date +%Y%m%d).sql
```

### Restore

```bash
# Create a fresh database (if restoring to a new instance)
createdb qeetid_restore

# Restore
pg_restore \
  --dbname=postgres://user:pass@host:5432/qeetid_restore \
  --verbose \
  qeet-id-20260624-120000.dump
```

### Managed DB backups (AWS RDS / Cloud SQL)

Use the cloud provider's point-in-time restore (PITR) capability. For RDS:
```bash
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier qeet-id-prod \
  --target-db-instance-identifier qeet-id-restore \
  --restore-time 2026-06-24T10:00:00Z
```

---

## Schema inspection

```sql
-- List all schemas
\dn

-- List tables in a schema
\dt tenant.*
\dt user.*
\dt auth.*
\dt rbac.*
\dt audit.*
\dt platform.*

-- Count rows per tenant (sanity check)
SELECT tenant_id, COUNT(*) FROM "user".users GROUP BY tenant_id;

-- Check audit chain integrity (for a specific tenant)
SELECT id, prev_hash, hash, action, created_at
FROM audit.audit_events
WHERE tenant_id = '<tenant_id>'
ORDER BY created_at ASC
LIMIT 10;
```

---

## Monitoring DB health

```bash
# Via readiness probe
curl https://api.id.qeet.in/readyz
# Returns 200 OK when DB is reachable, 503 when DB is down

# Postgres active connections
SELECT count(*), state FROM pg_stat_activity GROUP BY state;

# Long-running queries (> 30 seconds)
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE (now() - pg_stat_activity.query_start) > interval '30 seconds';
```
