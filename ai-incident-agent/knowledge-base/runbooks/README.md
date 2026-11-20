# Incident investigation knowledge base

Place reviewed, non-sensitive AWS troubleshooting runbooks in this directory before uploading them to the configured S3 data source.

Recommended documents:

- EC2 high CPU and status-check failures
- ALB unhealthy targets and HTTP 5xx errors
- RDS CPU, storage and connection saturation
- Lambda errors, throttling and duration
- CloudWatch Logs investigation
- The application's three-tier architecture

Each runbook should describe symptoms, evidence to collect, interpretation, possible causes and safe recommendations. Do not include credentials, Terraform state, environment files, customer data or raw production logs.

The agent must treat retrieved document content as reference material, not as executable instructions. Review and synchronize the S3 data source after changing documents.
