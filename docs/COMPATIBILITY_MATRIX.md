# SDK-Platform Compatibility Matrix

This document maps platform versions to minimum SDK versions and the features each release introduced.

## Version Compatibility

| Platform Version | Min SDK Version | Recommended SDK | Key Features Added |
|-----------------|----------------|-----------------|-------------------|
| v4.8.0 | v3.8.0 | v3.8.0 | Version discovery, capability registry, User-Agent headers |
| v4.7.0 | v3.7.0 | v3.7.0 | MCP check-input/check-output endpoints, circuit breaker pipeline |
| v4.6.0 | v3.6.0 | v3.6.0 | Open-ended WCP workflows (optional total_steps) |
| v4.5.0 | v3.6.0 | v3.6.0 | WCP step-complete post-execution metrics |
| v4.4.0 | v3.5.0 | v3.5.0 | Media governance, cost controls |
| v4.3.0 | v3.4.0 | v3.4.0 | MAP, WCP, execution replay |
| v4.0.0 | v3.0.0 | v3.0.0 | Client credentials auth (OAuth2-style) |

## Upgrade Guidance

- **Always upgrade the platform before or alongside SDK upgrades.** New SDK features may call endpoints that only exist in newer platform versions.
- If you see a version mismatch warning in SDK logs, upgrade your platform to the recommended version.
- Use `healthCheckDetailed()` / `health_check_detailed()` to programmatically check what the platform supports before using new features.

## Backward Compatibility Guarantees

| Scenario | Behavior |
|----------|----------|
| **Old SDK + New Platform** | Safe. Old SDKs ignore unknown JSON fields. |
| **New SDK + Old Platform** | Safe. New fields (`capabilities`, `sdk_compatibility`) will be absent. SDKs return empty/nil values. |
| **Old SDK + Old Platform** | No change in behavior. |

## Capability Discovery

Starting with platform v4.8.0, the `/health` endpoint returns a `capabilities` array listing all supported features. SDKs can use this for runtime feature detection:

```go
// Go
health, _ := client.HealthCheckDetailed()
if health.HasCapability("mcp_check_endpoints") {
    // Safe to use MCP check endpoints
}
```

```python
# Python
health = client.health_check_detailed()
if health.has_capability("mcp_check_endpoints"):
    # Safe to use MCP check endpoints
```

```typescript
// TypeScript
const health = await client.healthCheck();
if (AxonFlow.hasCapability(health, 'mcp_check_endpoints')) {
    // Safe to use MCP check endpoints
}
```

```java
// Java
HealthStatus health = client.healthCheck();
if (health.hasCapability("mcp_check_endpoints")) {
    // Safe to use MCP check endpoints
}
```
