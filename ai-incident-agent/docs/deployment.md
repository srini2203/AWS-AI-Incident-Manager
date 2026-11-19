# Deployment Guide

## Prerequisites

- AWS CLI authenticated with a dedicated deployment identity, not root credentials.
- Terraform 1.10 or later.
- Python 3.12.
- Existing three-tier Terraform state in the configured S3 backend.
- Bedrock access enabled for the configured APAC Nova Micro inference profile in the account.
- An OIDC/JWT identity provider for approval requests.

## 1. Publish application outputs

The root terraform/outputs.tf exposes the private application subnet IDs, private application route-table IDs and ALB target group ARN. From the existing root terraform directory, run terraform init using its existing backend, review the plan and apply the output changes. Do not replace existing infrastructure unexpectedly.

## 2. Configure the agent

From ai-incident-agent/terraform, copy terraform.tfvars.example to terraform.tfvars. Set the real JWT issuer and audience, application CloudWatch log group names, notification email if required, and environment-specific values. Do not commit terraform.tfvars.

Ensure the CloudWatch log groups listed in cloudwatch_log_groups exist and that the Lambda role is scoped to those exact groups.

## 3. Build the Lambda package

From ai-incident-agent using Python 3.12:

\`\`\`powershell
Remove-Item -Recurse -Force package, dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force package, dist | Out-Null
python -m pip install -r requirements.txt --target package
Copy-Item -Recurse app package/app
Copy-Item -Recurse handlers package/handlers
python -c "import shutil; shutil.make_archive('dist/incident-agent', 'zip', 'package')"
\`\`\`

The resulting file must be ai-incident-agent/dist/incident-agent.zip. The Lambda package root must contain app/ and handlers/.

## 4. Deploy the agent infrastructure

From ai-incident-agent/terraform:

\`\`\`bash
terraform init
terraform fmt -recursive
terraform validate
terraform plan
\`\`\`

Review resource creation and estimated charges, especially interface VPC endpoints, CloudTrail storage, Lambda, SNS and Bedrock inference. Apply only after review:

\`\`\`bash
terraform apply
\`\`\`

## 5. Configure identity and notifications

Configure the identity provider to issue JWTs with the expected issuer, audience, approvals:write scope and configured approver group claim. API Gateway validates issuer, audience and scope; the Lambda validates the approver group.

If an email subscription is configured, confirm the SNS subscription from the email AWS sends. An unconfirmed subscription does not receive notifications.

## 6. Bedrock configuration

The default model ID is apac.amazon.nova-micro-v1:0. Confirm that the inference profile is available and invocation is enabled for the AWS account. The account must have sufficient inference quota. The code uses Converse and does not bypass service quotas.

## 7. Local invocation

The CLI defaults to mock diagnostics and mock analysis. For real calls set ANALYZER_MODE=bedrock and DIAGNOSTICS_MODE=aws, configure AWS credentials and set APP_ENV=development. Local real invocations require permissions equivalent to the incident Lambda role.

## 8. Cost and teardown

This deployment creates billable AWS resources. See cleanup.md before applying and remove the stack when it is no longer required. The CloudTrail bucket is configured with force_destroy=false.
