# Deployment Runbooks

Operational procedures for deploying and running Qeet ID in production.

| Runbook | When to use |
|---|---|
| [operations.md](operations.md) | Main ops reference: build, release, deploy, rollback, migrations, key rotation, backup/DR, incident response |
| [secrets.md](secrets.md) | Generating and rotating all production secrets |
| [scaling.md](scaling.md) | Horizontal/vertical scaling, Redis setup, DB connection tuning |
| [dr.md](dr.md) | Disaster recovery procedures (region failover, PITR restore, data integrity) |

For developer-facing runbooks (incident response by feature, monitoring setup, database operations), see [`../../docs/runbooks/`](../../docs/runbooks/).
