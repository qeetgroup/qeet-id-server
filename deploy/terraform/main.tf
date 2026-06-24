terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Configured via -backend-config flags during `terraform init`
    # bucket         = "qeet-id-tfstate-<env>"
    # key            = "qeet-id/terraform.tfstate"
    # region         = "ap-south-1"
    # dynamodb_table = "qeet-id-tfstate-lock"
    encrypt = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "qeet-id"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

module "rds" {
  source = "./modules/rds"

  environment        = var.environment
  vpc_id             = var.vpc_id
  private_subnet_ids = var.private_subnet_ids
  db_password        = var.db_password
  kms_key_arn        = module.kms.key_arn
  multi_az           = var.environment == "prod"
  instance_class     = var.environment == "prod" ? "db.r8g.large" : "db.t4g.medium"
}

module "ecr" {
  source = "./modules/ecr"

  environment = var.environment
}

module "kms" {
  source = "./modules/kms"

  environment       = var.environment
  eks_node_role_arn = var.eks_node_role_arn
}

module "secrets" {
  source = "./modules/secrets"

  environment = var.environment
  kms_key_arn = module.kms.key_arn
}
