output "rds_endpoint" {
  description = "RDS instance endpoint — use in DB_URL: postgres://postgres:<password>@<endpoint>/qeet_id"
  value       = module.rds.endpoint
  sensitive   = true
}

output "ecr_repository_urls" {
  description = "ECR repository URLs for pushing images"
  value = {
    api     = module.ecr.repository_url_api
    migrate = module.ecr.repository_url_migrate
  }
}

output "kms_key_arn" {
  description = "KMS key ARN — set as KMS_KEY_ID environment variable"
  value       = module.kms.key_arn
}

output "secrets_manager_prefix" {
  description = "Base path for AWS Secrets Manager entries"
  value       = "qeet-id/${var.environment}"
}
