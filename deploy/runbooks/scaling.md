# Scaling Runbook

## Horizontal scaling (Kubernetes)

The Qeet ID API is stateless — scale replicas freely. The Helm chart includes an HPA:

```bash
# Current replica count
kubectl get deploy qeet-id -n qeet-id

# Manual scale
kubectl scale deploy qeet-id -n qeet-id --replicas=5

# Check HPA settings
kubectl get hpa qeet-id -n qeet-id
```

**Important with multiple replicas:** Rate limiting requires Redis for global consistency. Without Redis, each replica maintains its own independent bucket — effective per-IP limit becomes `configured_rate × replica_count`.

Enable Redis:
```bash
# Add REDIS_URL to secrets
aws secretsmanager put-secret-value \
  --secret-id "qeet-id/prod/REDIS_URL" \
  --secret-string "redis://your-elasticache-endpoint:6379"
```

## DB connection pool tuning

The pgx connection pool is configured via:

| Variable | Default | Description |
|---|---|---|
| `DB_MAX_CONNS` | 20 | Maximum open connections |
| `DB_MIN_CONNS` | 2 | Minimum idle connections |
| `DB_MAX_CONN_LIFETIME` | 30m | Maximum connection lifetime |
| `DB_MAX_CONN_IDLE_TIME` | 5m | Maximum idle time |

Formula: `DB_MAX_CONNS = (2 × replica_count) + 5` is a reasonable starting point. RDS `max_connections` defaults to ~87 for `db.t4g.medium` — ensure `DB_MAX_CONNS × replica_count < max_connections`.

## Vertical scaling (RDS)

Scale RDS instance class with minimal downtime (Multi-AZ failover):

```bash
aws rds modify-db-instance \
  --db-instance-identifier qeet-id-prod \
  --db-instance-class db.r8g.xlarge \
  --apply-immediately
```

Multi-AZ failover takes ~60s. The readiness probe (`/readyz`) will show failures during failover; pods will stop receiving traffic and resume automatically when the new primary is available.

## Caching strategy

Qeet ID does not use Redis for application-level caching (only rate limiting). If query performance becomes a bottleneck:

1. Check slow query log on RDS (Performance Insights → Top SQL)
2. Add indexes via a new migration
3. Consider read replicas for read-heavy audit log queries
