# Terraform — AWS Infrastructure

Terraform configuration for provisioning the AWS infrastructure required by Qeet ID in production.

## Structure

```
terraform/
├── modules/
│   ├── rds/          ← PostgreSQL on Amazon RDS
│   ├── ecr/          ← Elastic Container Registry (image hosting)
│   ├── kms/          ← KMS key for secrets vault DEK
│   └── secrets/      ← AWS Secrets Manager entries
├── environments/
│   ├── staging/      ← staging.tfvars + backend config
│   └── prod/         ← prod.tfvars + backend config
├── main.tf
├── variables.tf
└── outputs.tf
```

## Prerequisites

- Terraform ≥ 1.7
- AWS CLI configured with credentials for the target account
- S3 bucket + DynamoDB table for Terraform state (create once per account)

## State backend

State is stored in S3 with DynamoDB locking. Initialize once:

```bash
cd deploy/base/terraform
terraform init \
  -backend-config="bucket=qeet-id-tfstate-<env>" \
  -backend-config="key=qeet-id/terraform.tfstate" \
  -backend-config="region=ap-south-1" \
  -backend-config="dynamodb_table=qeet-id-tfstate-lock"
```

## Deploy

```bash
# Plan
terraform plan -var-file=environments/prod/terraform.tfvars

# Apply
terraform apply -var-file=environments/prod/terraform.tfvars
```

## Modules

### `modules/rds`
- PostgreSQL 16 on RDS (Multi-AZ in prod, single-AZ in staging)
- `db.t4g.medium` (staging) / `db.r8g.large` (prod)
- Automated backups, 7-day PITR retention
- Encryption at rest (KMS)
- Private subnet only (no public access)

### `modules/ecr`
- Private ECR repositories: `qeet-id` and `qeet-id-migrate`
- Image scanning on push
- Lifecycle policy: keep last 30 tagged images

### `modules/kms`
- Symmetric CMK for secrets vault DEK encryption (`SECRETS_PROVIDER=aws-kms`)
- Key rotation enabled (annual)
- Key policy: restricted to qeet-id EKS pod role via IRSA

### `modules/secrets`
- AWS Secrets Manager entries for all production secrets
- External Secrets Operator reads these and syncs to Kubernetes Secrets
- Secret names follow pattern: `qeet-id/{env}/{key}`

## Required variables

| Variable | Description | Example |
|---|---|---|
| `aws_region` | AWS region | `ap-south-1` |
| `environment` | Environment name | `prod` |
| `db_password` | RDS master password | (use AWS Secrets Manager) |
| `vpc_id` | VPC to deploy into | `vpc-...` |
| `private_subnet_ids` | Private subnet IDs (list) | `["subnet-...", "subnet-..."]` |
| `eks_node_role_arn` | EKS node IAM role ARN | `arn:aws:iam::...` |

## Outputs

After `terraform apply`:

| Output | Description |
|---|---|
| `rds_endpoint` | RDS instance endpoint (put in `DB_URL`) |
| `ecr_repository_url` | ECR URL for image pushes |
| `kms_key_arn` | KMS key ARN (put in `KMS_KEY_ID`) |
| `secrets_manager_prefix` | Base path for Secrets Manager entries |
