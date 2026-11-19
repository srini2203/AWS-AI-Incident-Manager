# Changelog

## [2.0.0] - AI Incident Triage Architecture

- Added a separate Terraform stack for an AI incident triage agent while reusing the existing three-tier VPC and application subnets.
- Added EventBridge-triggered Lambda investigation workflow.
- Added read-only CloudWatch metrics, Logs Insights and ALB target-health collection.
- Added Amazon Bedrock Converse inference through a configurable inference profile.
- Added Bedrock Guardrails, evidence redaction and untrusted-log handling.
- Added SNS incident notifications and JWT-authenticated human approval workflow backed by DynamoDB.
- Added CloudTrail management-event logging and S3 audit storage.
- Added AI agent tests, architecture documentation, security documentation, deployment instructions and cleanup instructions.
- The AI agent source and Terraform configuration require account-specific configuration and deployment; their presence does not mean a live deployment has been validated.

## [1.0.0] - Locked

- Initial architecture: VPC (three tiers, two Availability Zones), ALB and ASG, RDS Multi-AZ, Secrets Manager, IAM roles, CloudWatch and SNS.
- Terraform written flat for readability at the original project scope.
- Console screenshots from hands-on AWS study added and mapped to Terraform files.
