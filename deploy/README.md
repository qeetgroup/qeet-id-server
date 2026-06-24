# deploy/

Deployment artifacts for Qeet ID. The backend ships as a distroless container
([../Dockerfile](../Dockerfile)); schema migrations ship as a separate one-shot image
([../Dockerfile.migrate](../Dockerfile.migrate)).

| Path | Use |
| --- | --- |
| [local/](local/) | **Local dev** — Docker Compose for Postgres only (port 5001). Used by `make db-up`. |
| [docker/](docker/) | **Container builds** — build scripts and docs; Dockerfiles stay at repo root (single Go module build context). |
| [compose/](compose/) | Hardened **Docker Compose** stack (TLS via Caddy, Postgres, Redis, migration one-shot). Staging / single-host. |
| [kubernetes/](kubernetes/) | **Kustomize** — raw Kubernetes manifests (base + staging/prod overlays). Alternative to Helm. |
| [helm/qeet-id/](helm/qeet-id/) | **Helm chart** — production target. Deployment/Service/Ingress/HPA/PDB + pre-upgrade migration Job; AWS External Secrets + IRSA; ServiceMonitor. `values-{staging,prod}.yaml`. |
| [terraform/](terraform/) | **AWS IaC** — RDS PostgreSQL, ECR, KMS CMK, Secrets Manager (staging + prod environments). |
| [observability/](observability/) | Prometheus scrape config + alert rules, Grafana dashboard, OTel Collector config. |
| [runbooks/](runbooks/) | Ops playbooks: secrets generation, JWT rotation, scaling, disaster recovery. |

## Quick reference

- **Images** (pushed by `release.yml`, signed with cosign + SBOM/provenance):
  `ghcr.io/qeetgroup/qeet-id` and `ghcr.io/qeetgroup/qeet-id-migrate`.
- **Release flow**: conventional commits → release-please tag `vX.Y.Z` → signed images. See [runbooks/operations.md](runbooks/operations.md).
- **Boot gate**: the app refuses to start outside `SERVICE_ENV=dev` unless every production
  invariant in `config.Validate()` is satisfied.
- **Secrets**: AWS KMS-wrapped vault DEK (`SECRETS_PROVIDER=aws-kms`) or a static `SECRETS_KEY`.
  Generation and rotation procedures: [runbooks/secrets.md](runbooks/secrets.md).

## Deploy paths

```
Local dev     → deploy/local/   (Docker Compose, Postgres only)
Staging       → deploy/compose/ (Docker Compose + Caddy TLS + Redis)
                OR
              → deploy/kubernetes/ overlays/staging/ (kustomize)
Production    → deploy/helm/    (Helm chart + AWS External Secrets)
              → deploy/terraform/ (AWS infra provisioning)
```
