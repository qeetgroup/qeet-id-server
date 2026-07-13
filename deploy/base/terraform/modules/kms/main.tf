# KMS key for Qeet ID secrets vault DEK encryption

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "vault" {
  description             = "qeet-id-${var.environment} secrets vault DEK"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootAccess"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowQeetIDPods"
        Effect = "Allow"
        Principal = { AWS = var.eks_node_role_arn }
        Action   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "vault" {
  name          = "alias/qeet-id-${var.environment}-vault"
  target_key_id = aws_kms_key.vault.key_id
}
