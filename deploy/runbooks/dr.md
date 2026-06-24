# Disaster Recovery Runbook

## RTO / RPO targets

| Scenario | Recovery Time Objective | Recovery Point Objective |
|---|---|---|
| Single pod crash | < 30s (K8s auto-restart) | 0 (stateless) |
| Full deployment rollback | < 5m (helm rollback) | 0 (DB unchanged) |
| DB corruption (recent) | < 30m (PITR restore) | < 5m (WAL lag) |
| Region failure | < 4h (manual failover to secondary region) | < 1h (cross-region replica lag) |

## Scenario 1: Pod/deployment failure

Kubernetes restarts pods automatically. If pods are crash-looping:

```bash
kubectl -n qeet-id logs deploy/qeet-id --previous | tail -50
# Almost always a config.Validate() failure — fix the env var and redeploy
helm rollback qeet-id -n qeet-id  # if a bad release caused it
```

## Scenario 2: Database corruption / accidental data loss

**Step 1: Identify the point-in-time target**

Check the audit log timestamp of the last good event before the corruption.

**Step 2: Create a PITR restore (AWS RDS)**

```bash
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier qeet-id-prod \
  --target-db-instance-identifier qeet-id-prod-restore-$(date +%Y%m%d) \
  --restore-time "2026-06-24T10:00:00Z" \
  --db-subnet-group-name qeet-id-prod \
  --vpc-security-group-ids sg-... \
  --no-publicly-accessible
```

**Step 3: Validate the restore**

```bash
# Connect to restored instance and verify data
psql "postgres://postgres:...@qeet-id-prod-restore-....rds.amazonaws.com/qeet_id"
SELECT count(*) FROM "user".users;
SELECT max(created_at) FROM audit.audit_events;
```

**Step 4: Verify audit chain integrity**

```bash
# Against restored DB
GET /v1/audit/verify  # should return { "valid": true }
```

**Step 5: Switch application to restored DB**

Update `DB_URL` secret to point to the restored instance. Deploy.

**Step 6: Verify and clean up**

After confirming the restored DB is healthy, rename instances and delete the corrupted one.

## Scenario 3: Redis failure

Redis stores only rate-limit state (ephemeral). On Redis failure:
- Rate limiter fails open (traffic continues, limits unenforced temporarily)
- No data loss

Restore Redis:
```bash
# Provision new ElastiCache cluster (or restart existing)
# Update REDIS_URL secret
# Redeploy (rate limits resume immediately)
```

## Scenario 4: Region failure

Qeet ID does not currently have active-active multi-region. Manual failover procedure:

1. Promote the read replica in the secondary region to primary (RDS → Promote Read Replica)
2. Update `DB_URL` in Secrets Manager in the secondary region
3. Push container images to ECR in the secondary region
4. Apply Helm chart / kustomize overlays in the secondary region cluster
5. Update DNS to point to the secondary region load balancer
6. Verify health probes pass in the new region

**Restore point:** The secondary region replica has a typical lag of < 5 minutes. Events written to the primary in the last 5 minutes before the failure may not be present on the replica.

## Backup verification (quarterly drill)

```bash
# 1. Restore to a scratch instance
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier qeet-id-prod \
  --target-db-instance-identifier qeet-id-drill-$(date +%Y%m%d) \
  --use-latest-restorable-time

# 2. Point a staging deploy at the restored DB
# 3. Run smoke tests: make test-api FOLDER=Auth
# 4. Verify audit chain: GET /v1/audit/verify
# 5. Record RTO/RPO actuals
# 6. Delete scratch instance
aws rds delete-db-instance \
  --db-instance-identifier qeet-id-drill-$(date +%Y%m%d) \
  --skip-final-snapshot
```
