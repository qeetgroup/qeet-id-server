# deploy/

Deployment artifacts for Qeet ID. The backend ships as a distroless container
([../Dockerfile](../Dockerfile)); schema migrations ship as a
separate one-shot image ([../Dockerfile.migrate](../Dockerfile.migrate)).

| Path | Use |
| --- | --- |
| [compose/](compose/) | Hardened **Docker Compose** stack (TLS via Caddy, Postgres, Redis, migration one-shot). Staging / single-host. |
| [helm/qeet-id/](helm/qeet-id/) | **Helm chart** — production target. Deployment/Service/Ingress/HPA/PDB + pre-upgrade migration Job; AWS External Secrets + IRSA; ServiceMonitor. `values-{staging,prod}.yaml`. |
| [observability/](observability/) | Prometheus scrape config + alert rules, Grafana dashboard, OTel Collector config. |
| [RUNBOOK.md](RUNBOOK.md) | Build/release flow, deploy, rollback, migrations, key rotation, backup/DR, incident response. |

## Quick reference
- **Images** (pushed by `release.yml`, signed with cosign + SBOM/provenance):
  `ghcr.io/qeetgroup/qeet-id` and `ghcr.io/qeetgroup/qeet-id-migrate`.
- **Release flow**: conventional commits → release-please tag `vX.Y.Z` → signed images. See RUNBOOK.
- **Boot gate**: the app refuses to start outside `SERVICE_ENV=dev` unless every production
  invariant in `config.Validate()` is satisfied (see RUNBOOK → Required secrets).
- **Secrets**: AWS KMS-wrapped vault DEK (`SECRETS_PROVIDER=aws-kms`) or a static `SECRETS_KEY`.
