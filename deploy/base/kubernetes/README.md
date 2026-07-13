# Kubernetes Manifests (Kustomize)

Raw Kubernetes manifests for teams that prefer `kubectl apply` + kustomize over Helm. For production deployments with full lifecycle management (rollbacks, upgrades, secrets), prefer the [Helm chart](../helm/qeet-id/).

## Structure

```
kubernetes/
├── base/               ← common resources (all environments inherit)
│   ├── namespace.yaml
│   ├── serviceaccount.yaml
│   ├── configmap.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── migration-job.yaml
│   └── kustomization.yaml
└── overlays/
    ├── staging/        ← staging-specific patches
    │   ├── kustomization.yaml
    │   └── patch-replicas.yaml
    └── prod/           ← production-specific patches
        ├── kustomization.yaml
        ├── patch-replicas.yaml
        ├── patch-resources.yaml
        └── ingress.yaml
```

## Usage

### Deploy to staging

```bash
kubectl apply -k deploy/environments/stage/kubernetes/
```

### Deploy to production

```bash
kubectl apply -k deploy/environments/prod/kubernetes/
```

### Diff before applying

```bash
kubectl diff -k deploy/environments/prod/kubernetes/
```

## Secrets

Secrets are not managed by these manifests — never commit secrets to git. Provision them separately:

```bash
kubectl create secret generic qeet-id-secrets \
  --namespace qeet-id \
  --from-literal=DB_URL="postgres://..." \
  --from-literal=JWT_SIGNING_KEY="$(cat signing.pem)" \
  --from-literal=JWT_SECRET="$(openssl rand -base64 48)" \
  --from-literal=CSRF_KEY="$(openssl rand -base64 32)"
```

Or use External Secrets Operator with the Helm chart for a managed approach.

## Run migrations

Migrations run as a Kubernetes Job before the Deployment:

```bash
# Apply migration job manually
kubectl apply -f deploy/base/kubernetes/base/migration-job.yaml -n qeet-id

# Wait for completion
kubectl wait --for=condition=complete job/qeet-id-migrate -n qeet-id --timeout=120s

# Then apply the deployment
kubectl apply -k deploy/environments/prod/kubernetes/
```
