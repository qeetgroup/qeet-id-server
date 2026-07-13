# RDS PostgreSQL instance for Qeet ID

resource "aws_db_subnet_group" "this" {
  name       = "qeet-id-${var.environment}"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "qeet-id-${var.environment}"
  }
}

resource "aws_security_group" "rds" {
  name        = "qeet-id-rds-${var.environment}"
  description = "Allow PostgreSQL from qeet-id EKS nodes"
  vpc_id      = var.vpc_id

  ingress {
    description = "PostgreSQL from EKS nodes"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    # Restrict to EKS node security group in a real deployment
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "this" {
  identifier = "qeet-id-${var.environment}"

  engine         = "postgres"
  engine_version = "16"
  instance_class = var.instance_class

  db_name  = "qeet_id"
  username = "postgres"
  password = var.db_password

  # Storage
  allocated_storage     = var.environment == "prod" ? 100 : 20
  max_allocated_storage = var.environment == "prod" ? 1000 : 100
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  # Networking
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false

  # Availability
  multi_az = var.multi_az

  # Backups
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  deletion_protection     = var.environment == "prod"

  # Performance Insights
  performance_insights_enabled = true

  skip_final_snapshot = var.environment != "prod"
  final_snapshot_identifier = var.environment == "prod" ? "qeet-id-prod-final" : null

  tags = {
    Name = "qeet-id-${var.environment}"
  }
}
