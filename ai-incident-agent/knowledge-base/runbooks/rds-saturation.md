# Runbook: RDS CPU, storage, or connection saturation

## Symptoms
- CPUUtilization, FreeStorageSpace, FreeableMemory, DatabaseConnections, or ReadLatency/WriteLatency alarms.
- Application logs show connection timeouts, pool exhaustion, slow queries, or database errors.

## Evidence to collect
- RDS metrics over the incident window and the preceding baseline.
- Database engine, instance class, storage type, and configured connection limits.
- Application logs and connection-pool metrics around the first failure.
- Performance Insights or database monitoring evidence when enabled.
- Recent schema changes, query releases, batch jobs, or traffic changes.

## Interpretation
- High DatabaseConnections can indicate a connection leak, oversized application pools, or increased concurrency.
- High CPU and latency together may indicate expensive queries or insufficient database capacity.
- Falling FreeStorageSpace can cause write failures even when CPU is normal.
- High read/write latency should be correlated with I/O and storage metrics before attributing it to CPU.

## Safe recommendations
- Identify the top database waits and query patterns using approved monitoring.
- Compare application pool sizes and concurrency with database connection capacity.
- Review slow-query logs and recent application releases.
- Check storage headroom and growth rate.
- Do not fail over, reboot, resize, kill sessions, or modify database parameters without human approval.

## Limitations
- Aggregate CloudWatch metrics do not identify a specific SQL statement.
- Query-level diagnosis requires database-native telemetry and appropriate access.
