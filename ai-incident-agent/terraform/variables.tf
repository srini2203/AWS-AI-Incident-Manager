variable "project_name" {
  type    = string
  default = "aws-ai-incident-agent"
}
variable "environment" {
  type    = string
  default = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}
variable "aws_region" {
  type    = string
  default = "ap-south-1"
}
variable "application_state_bucket" {
  type    = string
  default = "three-tier-ha-aws-643681787444-ap-south-1-tfstate"
}
variable "application_state_key" {
  type    = string
  default = "three-tier-ha-aws/terraform.tfstate"
}
variable "application_state_region" {
  type    = string
  default = "ap-south-1"
}
variable "lambda_runtime" {
  type    = string
  default = "python3.12"
}
variable "lambda_architecture" {
  type    = string
  default = "x86_64"
  validation {
    condition     = contains(["x86_64", "arm64"], var.lambda_architecture)
    error_message = "Lambda architecture must be x86_64 or arm64."
  }
}
variable "lambda_memory_size" {
  type    = number
  default = 1024
  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory must be between 128 and 10240 MB."
  }
}
variable "lambda_timeout_seconds" {
  type    = number
  default = 180
  validation {
    condition     = var.lambda_timeout_seconds >= 1 && var.lambda_timeout_seconds <= 900
    error_message = "Lambda timeout must be between 1 and 900 seconds."
  }
}
variable "lambda_reserved_concurrency" {
  type    = number
  default = 5
}
variable "log_retention_days" {
  type    = number
  default = 30
}
variable "bedrock_model_id" {
  type    = string
  default = "apac.amazon.nova-micro-v1:0"
}
variable "bedrock_max_tokens" {
  type    = number
  default = 1800
}
variable "bedrock_temperature" {
  type    = number
  default = 0.1
}
variable "enable_bedrock_guardrails" {
  type    = bool
  default = true
}
variable "cloudwatch_log_groups" {
  type    = list(string)
  default = ["/aws/ec2/three-tier-app"]
}
variable "sns_topic_name" {
  type    = string
  default = "aws-ai-incident-notifications"
}
variable "notification_email" {
  type    = string
  default = ""
}
variable "approval_table_name" {
  type    = string
  default = "aws-ai-incident-approvals"
}
variable "approval_ttl_hours" {
  type    = number
  default = 24
}
variable "approval_jwt_issuer" {
  type = string
}
variable "approval_jwt_audience" {
  type = list(string)
}
variable "approval_authorization_scopes" {
  type    = list(string)
  default = ["approvals:write"]
}
variable "approver_groups" {
  type    = list(string)
  default = ["IncidentApprovers"]
}
variable "api_throttling_rate_limit" {
  type    = number
  default = 5
}
variable "api_throttling_burst_limit" {
  type    = number
  default = 10
}
