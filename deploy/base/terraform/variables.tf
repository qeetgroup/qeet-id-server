variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "ap-south-1"
}

variable "environment" {
  description = "Environment name (staging or prod)"
  type        = string
  validation {
    condition     = contains(["staging", "prod"], var.environment)
    error_message = "environment must be 'staging' or 'prod'"
  }
}

variable "vpc_id" {
  description = "VPC ID to deploy RDS and other resources into"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for RDS subnet group"
  type        = list(string)
}

variable "db_password" {
  description = "RDS master password (use AWS Secrets Manager in prod, not tfvars)"
  type        = string
  sensitive   = true
}

variable "eks_node_role_arn" {
  description = "IAM role ARN for EKS nodes (granted KMS decrypt permission)"
  type        = string
}
