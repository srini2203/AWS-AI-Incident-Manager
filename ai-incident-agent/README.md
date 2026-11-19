# AI Incident Triage Agent

A Python-based incident investigation workflow for the existing three-tier AWS application. CloudWatch alarm events are routed through EventBridge to Lambda. The agent gathers read-only metrics, logs and load-balancer target health, validates and redacts the evidence, requests Amazon Bedrock analysis, and publishes incident reports through SNS.

## Local development

The defaults are deliberately offline and do not call AWS or Bedrock:

- \`ANALYZER_MODE=mock\`
- \`DIAGNOSTICS_MODE=mock\`

Create a Python 3.12 environment, install dependencies and run the test suite:

\`\`\`bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -p "test_*.py" -v
\`\`\`

On PowerShell, activate with \`.venv\\Scripts\\Activate.ps1\`.

Run an example EventBridge event:

\`\`\`bash
python main.py tests/fixtures/cloudwatch-alarm.json --output reports/incident.json
\`\`\`

The mock report is clearly labeled and is not a real AWS diagnosis.

## Live AWS mode

For AWS diagnostics and Bedrock inference, set:

\`\`\`text
ANALYZER_MODE=bedrock
DIAGNOSTICS_MODE=aws
APP_ENV=development
\`\`\`

Provide the appropriate AWS identity and environment variables from \`.env.example\`. Bedrock inference requires model access, a supported inference profile and sufficient account quota. The Lambda deployment is configured for live mode by Terraform.

## Deploy

The AI stack has its own Terraform state in \`terraform/\`. It reuses the VPC, private application subnets, route tables and ALB target group outputs from the existing root \`terraform/\` state. Complete the deployment sequence in [docs/deployment.md](docs/deployment.md) and review the charges before applying.

## Security boundary

The agent is read-only with respect to the application infrastructure. It does not have permission to modify EC2, Auto Scaling, RDS or load-balancer configuration. Human approval decisions are authenticated and stored, but an approval does not execute remediation.
