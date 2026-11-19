resource "aws_cloudwatch_event_rule" "incident_alarm" {
  name        = "${var.project_name}-alarm-events"
  description = "Routes CloudWatch alarm state changes to the AI incident agent"

  event_pattern = jsonencode({
    source = [
      "aws.cloudwatch"
    ]

    "detail-type" = [
      "CloudWatch Alarm State Change"
    ]

    detail = {
      state = {
        value = [
          "ALARM"
        ]
      }
    }
  })

  tags = local.common_tags
}

resource "aws_sqs_queue" "event_dlq" {
  name                      = "${var.project_name}-event-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  tags                      = local.common_tags
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.event_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AllowEventBridgeDelivery"
        Effect = "Allow"

        Principal = {
          Service = "events.amazonaws.com"
        }

        Action = [
          "sqs:SendMessage"
        ]

        Resource = aws_sqs_queue.event_dlq.arn

        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.incident_alarm.arn
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "incident_lambda" {
  rule      = aws_cloudwatch_event_rule.incident_alarm.name
  target_id = "incident-triage-lambda"
  arn       = aws_lambda_function.incident.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 5
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
  }

  depends_on = [
    aws_sqs_queue_policy.event_dlq
  ]
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeIncidentInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.incident.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.incident_alarm.arn
}