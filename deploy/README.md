# deploy/

Deployment artifacts, organized **by environment** on top of a shared,
env-agnostic **base**. Promotion is consistent across `dev → test → stage → prod`:
the base never changes between environments; only the per-environment config does.

```
deploy/
├── base/                         shared, environment-agnostic
│   ├── docker/                   Dockerfile (app) + Dockerfile.migrate + build.sh
│   ├── helm/qeet-id/             Helm chart (templates + default values.yaml)
│   ├── kubernetes/base/          kustomize base (Deployment/Service/Job/…)
│   ├── terraform/                root module + modules/ (rds, ecr, kms, secrets)
│   └── observability/            Prometheus, Grafana, OTel Collector
├── environments/
│   ├── dev/                      local dev — Postgres-only Compose (used by `make db-up`)
│   ├── test/                     test DB Compose + notes (CI is the real test env)
│   ├── stage/                    values.yaml · kubernetes/ overlay · terraform.tfvars
│   └── prod/                     values.yaml · kubernetes/ overlay · terraform.tfvars · compose/ (single-host stack)
└── runbooks/                     operations, secrets, scaling, disaster recovery
```

## Why base + environments

The Helm chart, Terraform modules, and Dockerfiles are **the same** for every
environment — duplicating them per env is a maintenance trap. So they live once
under `base/`, and each environment supplies only its **config** (Helm values,
kustomize patches, tfvars, compose). This keeps environments provably consistent
and the diff between stage and prod small and reviewable.

## Build (images)

The build **context is the repo root** (the Go module + `platform/database/migrations`
are needed at build time); the Dockerfiles live under `base/docker/`.

```bash
./deploy/base/docker/build.sh dev        # builds app + migrate images
# or directly:
docker build -f deploy/base/docker/Dockerfile         -t qeet-id .
docker build -f deploy/base/docker/Dockerfile.migrate -t qeet-id-migrate .
```

CI/release publish cosign-signed images: `ghcr.io/qeetgroup/qeet-id` and `…/qeet-id-migrate`.

## Run, by environment

```bash
# dev — Postgres only; app tiers run on the host via `make dev`
make db-up      # docker compose -f deploy/environments/dev/docker-compose.yml up -d

# test — persistent test DB on :5002 (CI is the authoritative test env)
docker compose -f deploy/environments/test/docker-compose.yml up -d

# stage / prod — Helm (chart in base/, values per env)
helm upgrade --install qeet-id deploy/base/helm/qeet-id \
  -f deploy/environments/stage/values.yaml -n qeet-id-staging
helm upgrade --install qeet-id deploy/base/helm/qeet-id \
  -f deploy/environments/prod/values.yaml  -n qeet-id

# stage / prod — kustomize alternative (overlay references base/)
kubectl apply -k deploy/environments/prod/kubernetes/

# prod — single-host Compose stack (Caddy TLS + Postgres + Redis + migrate one-shot)
docker compose -f deploy/environments/prod/compose/docker-compose.prod.yml up -d

# AWS infra (per env)
terraform -chdir=deploy/base/terraform apply \
  -var-file=../../environments/prod/terraform.tfvars
```

## More

- **Operations / rollback / DR / key rotation** → [runbooks/](runbooks/)
- **Observability** (Prometheus scrape, alerts, Grafana, OTel) → [base/observability/](base/observability/)
- **Boot gate**: the app refuses to start outside `SERVICE_ENV=dev` unless every
  invariant in `config.Validate()` is satisfied — see [runbooks/secrets.md](runbooks/secrets.md).
