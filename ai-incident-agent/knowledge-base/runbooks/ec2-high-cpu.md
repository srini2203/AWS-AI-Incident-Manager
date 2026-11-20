# Runbook: EC2 high CPU or status-check alarm

## Symptoms
- CPUUtilization remains elevated or exceeds the configured alarm threshold.
- StatusCheckFailed, StatusCheckFailed_Instance, or StatusCheckFailed_System becomes non-zero.
- Application latency or request failures increase during the same interval.

## Evidence to collect
- CPUUtilization time series and instance status-check metrics.
- EC2 instance ID, instance type, availability zone, and alarm timestamp.
- Application and system logs around the incident window.
- Memory, disk, process, and network telemetry when available through the approved monitoring agent.
- Recent deployment, scaling, scheduled-job, or configuration changes.

## Interpretation
- Sustained CPU saturation can be caused by traffic growth, inefficient queries, runaway processes, background jobs, or an undersized instance.
- An instance status-check failure points to an instance or underlying host/network issue and should not be inferred from CPU alone.
- A brief CPU spike without correlated latency or errors may not explain a user-visible incident.

## Safe recommendations
- Correlate CPU spikes with request volume, application logs, and deployment timestamps.
- Identify the process or workload consuming CPU using approved host telemetry.
- Review autoscaling activity and capacity headroom.
- Escalate persistent instance status-check failures to the infrastructure owner.
- Do not stop, reboot, resize, or replace instances without human approval.

## Limitations
- CloudWatch CPU metrics alone cannot identify the responsible process.
- Memory and disk pressure require additional telemetry if those metrics are not already published.
