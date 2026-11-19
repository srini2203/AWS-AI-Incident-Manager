resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/${var.project_name}-approval"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_apigatewayv2_api" "approval" {
  name          = "${var.project_name}-approval-api"
  protocol_type = "HTTP"

  description = "Authenticated API for human approval of AWS incident remediation"

  tags = local.common_tags
}

resource "aws_apigatewayv2_authorizer" "approval_jwt" {
  api_id          = aws_apigatewayv2_api.approval.id
  authorizer_type = "JWT"
  name            = "${var.project_name}-jwt-authorizer"

  identity_sources = [
    "$request.header.Authorization"
  ]

  jwt_configuration {
    audience = var.approval_jwt_audience
    issuer   = var.approval_jwt_issuer
  }
}

resource "aws_apigatewayv2_integration" "approval" {
  api_id                 = aws_apigatewayv2_api.approval.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.approval.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}

resource "aws_apigatewayv2_route" "approval_decision" {
  api_id    = aws_apigatewayv2_api.approval.id
  route_key = "POST /approvals/{approval_id}"

  target = "integrations/${aws_apigatewayv2_integration.approval.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.approval_jwt.id

  authorization_scopes = var.approval_authorization_scopes
}

resource "aws_apigatewayv2_stage" "approval" {
  api_id      = aws_apigatewayv2_api.approval.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn

    format = jsonencode({
      requestId       = "$context.requestId"
      requestTime     = "$context.requestTime"
      httpMethod      = "$context.httpMethod"
      routeKey        = "$context.routeKey"
      status          = "$context.status"
      responseLength  = "$context.responseLength"
      sourceIp        = "$context.identity.sourceIp"
      authorizerError = "$context.authorizer.error"
    })
  }

  default_route_settings {
    throttling_burst_limit = var.api_throttling_burst_limit
    throttling_rate_limit  = var.api_throttling_rate_limit
    detailed_metrics_enabled = true
  }

  tags = local.common_tags
}

resource "aws_lambda_permission" "approval_api" {
  statement_id  = "AllowAuthenticatedApprovalApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approval.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.approval.execution_arn}/*/POST/approvals/*"
}