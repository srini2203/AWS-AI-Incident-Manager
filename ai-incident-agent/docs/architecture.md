# AI Incident Triage Architecture

## Purpose

The agent investigates CloudWatch alarm events for the existing three-tier AWS application. It gathers read-only telemetry, uses Amazon Bedrock for evidence-based diagnosis, sends reports through SNS and records human approval decisions in DynamoDB.

## Request flow

1. CloudWatch emits an alarm state-change event.
2. EventBridge matches alarms entering ALARM and invokes the incident Lambda.
3. The event parser normalizes the event into an Incident model.
4. Diagnostics collect CloudWatch metrics, CloudWatch Logs Insights results and ALB target health.
5. Evidence is bounded and redacted before inference.
6. Amazon Bedrock Converse is called through the configured inference profile.
7. Bedrock Guardrails inspect input and output when enabled.
8. The analyzer validates the JSON response and creates an IncidentAnalysis.
9. The agent publishes the incident report to SNS and writes structured audit events to CloudWatch Logs.
10. Proposed infrastructure changes require a separate, authenticated approval request. Approval decisions are stored in DynamoDB and do not execute remediation.

## AWS resources

- Incident and approval Lambda functions.
- EventBridge rule and encrypted SQS dead-letter queue.
- Bedrock Guardrail and inference-profile invocation.
- SNS notification topic.
- DynamoDB approval table with TTL and point-in-time recovery.
- API Gateway HTTP API with JWT authorization.
- Interface VPC endpoints for CloudWatch Logs, CloudWatch monitoring, ELBv2, Bedrock Runtime and SNS.
- DynamoDB gateway VPC endpoint.
- CloudTrail multi-region management-event trail with S3 log storage.

## Network design

The agent reuses the existing VPC and private application subnets. Lambda security groups allow HTTPS egress to the configured interface endpoints and DynamoDB prefix list. There is no inbound Lambda access path. Application infrastructure and AI-agent Terraform states are separate.

## Trust boundaries

Application logs are untrusted data. They are never treated as instructions. Evidence is redacted, length-limited and labeled with trust boundaries before being sent to Bedrock. The agent has no remediation execution role or write permissions to EC2, Auto Scaling, RDS or load-balancer configuration.

## Local mode

The local CLI defaults to mock diagnostics and mock analysis. Mock output is illustrative, marked as mock, and does not call AWS or Bedrock.
