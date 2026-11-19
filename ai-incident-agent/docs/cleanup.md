# Cleanup Guide

The AI incident agent creates billable resources, including interface VPC endpoints, Lambda functions, API Gateway, CloudTrail storage, DynamoDB, SNS and Bedrock inference usage.

## Destroy the agent stack

From ai-incident-agent/terraform, review and run:

\`\`\`bash
terraform plan -destroy
terraform destroy
\`\`\`

Do not destroy the existing three-tier application stack as part of agent cleanup. The two Terraform states are separate.

## CloudTrail S3 bucket

The CloudTrail bucket uses force_destroy=false to protect audit records. After the trail is stopped and Terraform removes the trail and bucket policy, inspect the bucket and decide whether audit records must be retained. If retention is no longer required and policy permits deletion, empty all object versions and delete markers before removing the bucket.

## Verify remaining resources

Check for agent Lambda functions, VPC endpoints, API Gateway, SNS topic/subscriptions, DynamoDB table, EventBridge rule, SQS DLQ, CloudTrail trail, S3 bucket and retained CloudWatch log groups.

## State safety

Keep the Terraform state bucket and state files until teardown is confirmed. Do not delete the shared state bucket because it also stores the existing three-tier application's Terraform state.
