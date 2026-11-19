data "aws_prefix_list" "dynamodb" {
  name = "com.amazonaws.${var.aws_region}.dynamodb"
}

resource "aws_security_group" "lambda" {
  name        = "${var.project_name}-lambda-sg"
  description = "Security group for incident and approval Lambda functions"
  vpc_id      = local.vpc_id
  tags        = local.common_tags
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.project_name}-endpoints-sg"
  description = "Security group for private AWS service endpoints"
  vpc_id      = local.vpc_id
  tags        = local.common_tags
}

resource "aws_vpc_security_group_egress_rule" "lambda_to_endpoints" {
  security_group_id            = aws_security_group.lambda.id
  referenced_security_group_id = aws_security_group.vpc_endpoints.id
  description                  = "HTTPS access to private AWS interface endpoints"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "lambda_to_dynamodb" {
  security_group_id = aws_security_group.lambda.id
  prefix_list_id    = data.aws_prefix_list.dynamodb.id
  description       = "HTTPS access to the DynamoDB gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_lambda" {
  security_group_id            = aws_security_group.vpc_endpoints.id
  referenced_security_group_id = aws_security_group.lambda.id
  description                  = "HTTPS access from incident agent Lambda functions"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

locals {
  interface_endpoint_services = toset([
    "logs",
    "monitoring",
    "elasticloadbalancing",
    "bedrock-runtime",
    "sns"
  ])
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoint_services

  vpc_id              = local.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.private_app_subnet_ids
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.value}-endpoint"
  })

  depends_on = [aws_vpc_security_group_ingress_rule.endpoints_from_lambda]
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = local.vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = local.private_app_route_table_ids

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action = [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem"
      ]
      Resource = [aws_dynamodb_table.approvals.arn]
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-dynamodb-endpoint"
  })
}
