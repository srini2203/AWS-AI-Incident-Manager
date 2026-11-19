resource "aws_cloudwatch_log_group" "incident" {
  name              = "/aws/lambda/${var.project_name}-incident"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_group" "approval" {
  name              = "/aws/lambda/${var.project_name}-approval"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_lambda_function" "incident" {
  function_name = "${var.project_name}-incident"
  description   = "Investigates AWS incidents using diagnostics and Amazon Bedrock"

  filename         = "${path.module}/../dist/incident-agent.zip"
  source_code_hash = filebase64sha256("${path.module}/../dist/incident-agent.zip")

  role          = aws_iam_role.incident.arn
  handler       = "handlers.incident_handler.lambda_handler"
  runtime       = var.lambda_runtime
  architectures = [var.lambda_architecture]

  memory_size = var.lambda_memory_size
  timeout     = var.lambda_timeout_seconds

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  ephemeral_storage {
    size = 1024
  }

  vpc_config {
    subnet_ids         = local.private_app_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      APP_NAME                            = var.project_name
      APP_ENV                             = var.environment
      ANALYZER_MODE = "bedrock"
      DIAGNOSTICS_MODE = "aws"
      BEDROCK_MODEL_ID                    = var.bedrock_model_id
      BEDROCK_MAX_TOKENS                  = tostring(var.bedrock_max_tokens)
      BEDROCK_TEMPERATURE                 = tostring(var.bedrock_temperature)
      BEDROCK_TOP_P                       = "0.9"
      BEDROCK_RETRY_ATTEMPTS              = "3"
      BEDROCK_CONNECT_TIMEOUT_SECONDS     = "5"
      BEDROCK_READ_TIMEOUT_SECONDS        = "60"
      BEDROCK_MAX_EVIDENCE_CHARS          = "30000"
      ENABLE_BEDROCK_GUARDRAILS            = tostring(var.enable_bedrock_guardrails)
      BEDROCK_GUARDRAIL_ID                = var.enable_bedrock_guardrails ? aws_bedrock_guardrail.incident[0].guardrail_id : ""
      BEDROCK_GUARDRAIL_VERSION = var.enable_bedrock_guardrails ? aws_bedrock_guardrail_version.incident[0].version : ""
      CLOUDWATCH_LOG_GROUPS               = join(",", var.cloudwatch_log_groups)
      CLOUDWATCH_LOG_LOOKBACK_MINUTES     = "15"
      CLOUDWATCH_LOG_QUERY_TIMEOUT_SECONDS = "30"
      MAX_LOG_ENTRIES                     = "200"
      MAX_LOG_ENTRY_LENGTH                = "4000"
      METRICS_LOOKBACK_MINUTES            = "15"
      METRIC_PERIOD_SECONDS               = "60"
      MAX_METRIC_DATAPOINTS               = "100"
      TARGET_GROUP_ARN                    = local.application_target_group_arn
      SNS_TOPIC_ARN                       = aws_sns_topic.incidents.arn
      ENABLE_SNS_NOTIFICATIONS            = "true"
      APPROVAL_TABLE_NAME                 = aws_dynamodb_table.approvals.name
      APPROVAL_TTL_HOURS                  = tostring(var.approval_ttl_hours)
      APPROVER_GROUPS                     = join(",", var.approver_groups)
      AUDIT_LOG_LEVEL                     = "INFO"
      LAMBDA_TIMEOUT_SECONDS              = tostring(var.lambda_timeout_seconds)
      AWS_API_TIMEOUT_SECONDS             = "10"
      INVESTIGATION_MAX_CONCURRENCY       = "4"
      PROMPT_VERSION                      = "1.0"
      APPROVAL_API_URL = aws_apigatewayv2_api.approval.api_endpoint
    }
  }

  logging_config {
    log_format            = "JSON"
    application_log_level = "INFO"
    system_log_level      = "WARN"
    log_group             = aws_cloudwatch_log_group.incident.name
  }

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags

  depends_on = [
    aws_iam_role_policy.incident_permissions,
    aws_cloudwatch_log_group.incident
  ]
}

resource "aws_lambda_function" "approval" {
  function_name = "${var.project_name}-approval"
  description   = "Processes authenticated human approval decisions"

  filename         = "${path.module}/../dist/incident-agent.zip"
  source_code_hash = filebase64sha256("${path.module}/../dist/incident-agent.zip")

  role          = aws_iam_role.approval.arn
  handler       = "handlers.approval_handler.lambda_handler"
  runtime       = var.lambda_runtime
  architectures = [var.lambda_architecture]

  memory_size = 512
  timeout     = 30

  reserved_concurrent_executions = 3

  vpc_config {
    subnet_ids         = local.private_app_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      APP_NAME             = var.project_name
      APP_ENV              = var.environment
      APPROVAL_TABLE_NAME  = aws_dynamodb_table.approvals.name
      APPROVAL_TTL_HOURS   = tostring(var.approval_ttl_hours)
      APPROVER_GROUPS      = join(",", var.approver_groups)
      ENABLE_SNS_NOTIFICATIONS = "false"
      AUDIT_LOG_LEVEL      = "INFO"
      AWS_API_TIMEOUT_SECONDS = "10"
    }
  }

  logging_config {
    log_format            = "JSON"
    application_log_level = "INFO"
    system_log_level      = "WARN"
    log_group             = aws_cloudwatch_log_group.approval.name
  }

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags

  depends_on = [
    aws_iam_role_policy.approval_permissions,
    aws_cloudwatch_log_group.approval
  ]
}