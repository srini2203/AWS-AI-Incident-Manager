# Runbook: AWS Lambda errors, throttling, and duration

## Symptoms
- Errors, Throttles, Duration, ConcurrentExecutions, or IteratorAge alarms.
- Downstream API failures or delayed asynchronous event processing.

## Evidence to collect
- Lambda Errors, Invocations, Throttles, Duration percentiles, and ConcurrentExecutions.
- Function version, alias, runtime, memory, timeout, and concurrency configuration.
- CloudWatch application logs and request IDs for failed invocations.
- Downstream service throttling, latency, and error metrics.
- Recent deployment, dependency, environment-variable, or event-source changes.

## Interpretation
- Rising Errors with normal Throttles may indicate application exceptions or downstream failures.
- Throttles indicate concurrency or account-level limits rather than necessarily faulty application code.
- Duration approaching the configured timeout can indicate slow dependencies, insufficient memory, or increased workload.
- IteratorAge growth for stream sources indicates processing is falling behind.

## Safe recommendations
- Group errors by exception type and correlate them with request IDs.
- Check whether duration increases coincide with downstream latency.
- Review reserved concurrency, account concurrency, and event-source batch settings.
- Compare the failing version with the last known healthy deployment.
- Do not change concurrency, roll back, or deploy code without human approval.

## Limitations
- Error counts do not identify root cause without exception logs.
- Downstream metrics may be required to distinguish local from dependency failures.
