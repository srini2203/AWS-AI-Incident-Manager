resource "aws_sns_topic" "incidents" {
  name              = var.sns_topic_name
  kms_master_key_id = "alias/aws/sns"
  tags              = local.common_tags
}

resource "aws_sns_topic_policy" "incidents" {
  arn = aws_sns_topic.incidents.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowAccountManagement"
      Effect = "Allow"
      Principal = {
        AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
      }
      Action = [
        "SNS:GetTopicAttributes",
        "SNS:SetTopicAttributes",
        "SNS:ListSubscriptionsByTopic",
        "SNS:Subscribe",
        "SNS:Publish"
      ]
      Resource = aws_sns_topic.incidents.arn
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.incidents.arn
  protocol  = "email"
  endpoint  = var.notification_email
}
