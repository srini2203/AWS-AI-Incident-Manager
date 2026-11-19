output "incident_lambda_arn" {
  description = "ARN of the incident investigation Lambda"
  value       = aws_lambda_function.incident.arn
}

output "approval_lambda_arn" {
  description = "ARN of the human approval Lambda"
  value       = aws_lambda_function.approval.arn
}

output "approval_api_endpoint" {
  description = "JWT-protected approval API endpoint"
  value       = aws_apigatewayv2_api.approval.api_endpoint
}

output "incident_event_rule_arn" {
  description = "EventBridge rule ARN for CloudWatch alarm events"
  value       = aws_cloudwatch_event_rule.incident_alarm.arn
}

output "incident_sns_topic_arn" {
  description = "SNS topic ARN for incident notifications"
  value       = aws_sns_topic.incidents.arn
}

output "approval_table_name" {
  description = "DynamoDB approval table name"
  value       = aws_dynamodb_table.approvals.name
}

output "cloudtrail_arn" {
  description = "CloudTrail audit trail ARN"
  value       = aws_cloudtrail.audit.arn
}

output "cloudtrail_bucket_name" {
  description = "S3 bucket containing CloudTrail audit logs"
  value       = aws_s3_bucket.cloudtrail.id
}

output "bedrock_guardrail_arn" {
  description = "Bedrock Guardrail ARN when Guardrails are enabled"
  value       = var.enable_bedrock_guardrails ? aws_bedrock_guardrail.incident[0].guardrail_arn : null
}
