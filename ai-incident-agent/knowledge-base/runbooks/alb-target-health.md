# Runbook: Application Load Balancer unhealthy targets

## Symptoms
- CloudWatch alarms for HealthyHostCount, UnHealthyHostCount, HTTPCode_Target_5XX_Count, or elevated TargetResponseTime.
- Application Load Balancer reports one or more targets as unhealthy.

## Evidence to collect
- Target group target health state and reason codes.
- Healthy and unhealthy target counts over the incident window.
- ALB target 5xx, ELB 5xx, request count, and target response-time metrics.
- Application logs around the first failed health check.
- Recent deployment, listener, target group, security group, and health-check configuration changes.

## Interpretation
- Connection errors often indicate network reachability, listener port, or security group issues.
- Health-check response-code mismatches can indicate an incorrect path, port, protocol, or application response.
- A rising target 5xx count with healthy targets can indicate application-level failures rather than target registration failure.
- A simultaneous drop in healthy targets and request volume may indicate a wider application outage.

## Safe recommendations
- Compare target health reason codes with the configured health-check path, port, protocol, and matcher.
- Verify the application process is listening on the expected port and review its startup logs.
- Review security group rules and network ACLs for the load balancer-to-target path.
- Compare the incident start time with deployments and configuration changes.
- Do not deregister targets, change routing, restart services, or deploy fixes without an approved change.

## Limitations
- A healthy target does not prove the application is functioning correctly for every request.
- Correlate ALB metrics with application logs and downstream database metrics before assigning root cause.
