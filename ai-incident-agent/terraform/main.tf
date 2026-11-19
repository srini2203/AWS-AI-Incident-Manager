data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "terraform_remote_state" "application" {
  backend = "s3"
  config = {
    bucket = var.application_state_bucket
    key    = var.application_state_key
    region = var.application_state_region
  }
}

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Component   = "ai-incident-agent"
  }

  vpc_id                       = data.terraform_remote_state.application.outputs.vpc_id
  private_app_subnet_ids       = data.terraform_remote_state.application.outputs.private_app_subnet_ids
  private_app_route_table_ids  = data.terraform_remote_state.application.outputs.private_app_route_table_ids
  application_target_group_arn = data.terraform_remote_state.application.outputs.app_target_group_arn
}
