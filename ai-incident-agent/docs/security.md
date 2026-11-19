# Security Design

## Identity and permissions

The incident and approval Lambdas use separate IAM roles. The incident role has read-only permissions for CloudWatch metrics, configured Logs Insights groups and load-balancer target health. It may invoke Bedrock, apply the configured Guardrail and publish to the incident SNS topic. The approval role can read and conditionally update only the approval DynamoDB table.

No static AWS credentials are stored in the application. Lambda execution roles provide temporary credentials.

## Network controls

Both Lambda functions execute in the existing private application subnets. Lambda security groups permit HTTPS to the configured AWS interface endpoints and DynamoDB gateway endpoint. No inbound security group rule is required. The existing application VPC is reused and is not recreated by the agent stack.

## AI and evidence security

- Application logs and incident text are untrusted input.
- The evidence sanitizer bounds payload size and redacts likely credentials and personal identifiers.
- The Bedrock system prompt instructs the model to ignore instructions embedded in evidence.
- Bedrock Guardrails apply prompt-attack and sensitive-information controls.
- Model output is parsed and schema-validated before it becomes an incident report.
- Model output is advisory analysis, not authorization to modify infrastructure.

Guardrails and redaction reduce risk but do not guarantee perfect detection of secrets or prompt injection. Avoid sending highly sensitive payloads to the model and keep application logging free of credentials.

## Approval controls

Approval decisions are accepted through an API Gateway JWT authorizer with a required scope. The application additionally checks configured approver groups. DynamoDB conditional updates ensure a pending approval can transition only once and only before expiry. No remediation executor is included.

The identity provider must issue the configured issuer, audience, scope and approver-group claims. Validate exact claim names against the chosen provider before deployment.

## Audit and retention

CloudTrail records multi-region management events in a versioned, private S3 bucket. Lambda audit events are emitted as structured JSON to CloudWatch Logs. Configure retention and access controls according to the operating environment.
