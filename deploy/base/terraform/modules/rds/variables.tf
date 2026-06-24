variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "db_password" { type = string; sensitive = true }
variable "kms_key_arn" { type = string }
variable "multi_az" { type = bool; default = false }
variable "instance_class" { type = string; default = "db.t4g.medium" }
