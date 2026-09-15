# SQL Injection Scanning
> Deprecated in v11.0.0: the legacy policy write routes answer 409 LEGACY_POLICY_WRITE_FROZEN on an application-role deployment; use the typed policy routes instead. This material is rewritten or deleted in v11.1.0.


AxonFlow provides built-in SQL injection (SQLi) detection for MCP connector responses to protect against data exfiltration and manipulation attacks.

## Overview

SQL injection scanning monitors responses from MCP connectors for patterns that indicate SQL injection attempts. This protects against scenarios where:

- Malicious data injected into databases is returned in query results
- LLM-generated queries inadvertently include injection payloads
- External data sources contain compromised content

## Scanning Modes

AxonFlow offers three scanning modes to balance security and performance:

| Mode | Description | Edition | Performance |
|------|-------------|---------|-------------|
| `off` | Scanning disabled | Community | N/A |
| `basic` | Pattern-based regex detection | Community | <1ms |
| `advanced` | Heuristic analysis with confidence scoring | Enterprise | <10ms |

### Basic Mode (Community)

Basic mode uses compiled regex patterns to detect common SQL injection techniques:

- **Union-based injection** - `UNION SELECT` statements for data extraction
- **Boolean-blind injection** - `OR 1=1` and similar always-true conditions
- **Time-based blind injection** - `SLEEP()`, `WAITFOR DELAY`, `PG_SLEEP()`
- **Stacked queries** - `DROP TABLE`, `DELETE FROM`, `INSERT INTO`
- **Comment injection** - SQL commands after `--`, `/**/`, or `#`
- **Error-based injection** - `EXTRACTVALUE`, `UPDATEXML`

### Advanced Mode (Enterprise)

Advanced mode extends basic detection with:

- **Heuristic analysis** for obfuscation detection
- **Confidence scoring** (0.0-1.0) to reduce false positives
- **Context-aware detection** that recognizes documentation/code blocks
- **Multi-stage pipeline** for comprehensive analysis

## Configuration

### Default Configuration

```yaml
sqli:
  input_mode: basic      # Scan user inputs
  response_mode: basic   # Scan connector responses
  block_on_detection: false  # Monitoring mode (set true to enforce blocking)
  log_detections: true
  audit_trail_enabled: true
  max_content_length: 1048576  # 1MB
```

> **Note:** By default, SQL injection scanning runs in **monitoring mode** - detections are logged but responses are not blocked. This allows you to validate detection accuracy in your environment before enabling enforcement. Set `block_on_detection: true` to enable blocking.

### Per-Connector Configuration

```yaml
sqli:
  response_mode: basic
  connector_overrides:
    # Disable for trusted internal cache
    redis_cache:
      enabled: false
    # Use advanced mode for sensitive data
    postgresql_main:
      response_mode: advanced
```

### Programmatic Configuration

```go
import "axonflow/platform/agent/sqli"

cfg := sqli.DefaultConfig().
    WithResponseMode(sqli.ModeBasic).
    WithBlockOnDetection(true).
    WithConnectorOverride("redis", sqli.ConnectorConfig{
        Enabled: false,
    })

middleware, err := sqli.NewScanningMiddleware(
    sqli.WithMiddlewareConfig(cfg),
)
```

### Environment Variable Configuration

For Docker and containerized deployments, configure SQL injection scanning using environment variables:

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `SQLI_SCANNER_MODE` | `off`, `basic`, `advanced` | `basic` | Sets the scanning mode for both input and response |

> **Removed in v11 (#3961):** `SQLI_ACTION` and `SQLI_BLOCK_MODE` no longer set the action taken on a detection. A deployment that still sets either keeps running: the agent logs a boot `WARN [agent] detection posture env var ignored: ...` line and increments `axonflow_ignored_posture_env_total{name="SQLI_ACTION"}` (or `name="SQLI_BLOCK_MODE"`) on `/prometheus`. The action is the one stored on the matching `security-sqli` policy; see [Response Handling](#response-handling) for how to change it.

**Example: docker-compose.yml**

```yaml
services:
  axonflow-agent:
    environment:
      # Scanning mode: off, basic, advanced
      SQLI_SCANNER_MODE: ${SQLI_SCANNER_MODE:-basic}
```

**Usage Examples:**

```bash
# Default: basic scanning; the stored policy action decides the outcome
docker compose up -d

# Disable scanning entirely
SQLI_SCANNER_MODE=off docker compose up -d

# Use advanced scanning (Enterprise only)
SQLI_SCANNER_MODE=advanced docker compose up -d
```

> **Note:** An invalid `SQLI_SCANNER_MODE` value is logged and falls back to `basic`.

## Detection Categories

| Category | Severity | Description |
|----------|----------|-------------|
| `stacked_queries` | Critical | Can modify or delete data |
| `dangerous_query` | Critical | DDL operations (DROP, TRUNCATE, ALTER, CREATE USER, GRANT) |
| `union_based` | High | Can extract sensitive data |
| `time_based` | High | Confirms SQL injection vulnerability |
| `boolean_blind` | Medium | May have false positives |
| `error_based` | Medium | Error message extraction |
| `comment_injection` | Medium | Query manipulation |
| `generic` | Low | General suspicious patterns |

## Response Handling

When SQL injection is detected, the outcome is the action stored on the matching `security-sqli` policy, unless the organization has recorded an `sqli` detection-posture override, which replaces it. Every shipped `sys_sqli_*` row stores `warn` for both the request and the response phase, so **out of the box a detection is recorded and the request proceeds**. On the gateway pre-check the request is `approved: true` and the matched `sys_sqli_*` policy id is listed in `policies`.

To block SQL injection, either:

- record the organization override (Enterprise): `PUT /api/v1/detection-posture/sqli` with body `{"action":"block"}` on the customer portal API (session auth, `sso:configure` permission; audited to `admin_audit_log`). Agents apply it within `AXONFLOW_DETECTION_OVERRIDE_TTL_SECONDS` (default 60 seconds); or
- change the policy's action: create a system-policy override (`POST /api/v1/system-policies/{id}/override`, Enterprise). Editing the tenant policy was the other way before v11; in v11 the legacy policy tables are read-only to the application roles (`migrations/core/172`), so that edit answers `409 LEGACY_POLICY_WRITE_FROZEN`.

Community SaaS (try.getaxonflow.com) warns until its provisioning writes an override (#4017). See [Policy Actions and Detection-Posture Overrides](../governance/policy-action-authority.md) for the per-plane detail.

### Block (`sqli=block` override, or a policy whose action is `block`)

Returns HTTP 403 Forbidden and rejects the request:
```json
{
  "success": false,
  "error": "Response blocked: potential SQL injection detected (pattern: union_select)"
}
```

### Warn (shipped default)

Records the detection but allows the request through. Useful for:
- Initial deployment to assess false positive rates
- Testing detection patterns before enabling enforcement
- Environments where availability is prioritized over strict blocking

Example log output:
```
[SQLi] WARNING: SQL injection attempt detected but not blocked (warn mode): pattern=union_select, category=union_based
```

## Audit Trail

When `audit_trail_enabled: true`, detections are logged to the audit queue:

```json
{
  "type": "sqli_detection",
  "timestamp": "2025-12-14T15:30:00Z",
  "severity": "high",
  "connector_name": "postgresql_main",
  "scan_type": "response",
  "pattern": "union_select",
  "category": "union_based",
  "confidence": 0.95,
  "blocked": true
}
```

## Compliance Integration

SQL injection scanning supports compliance requirements:

- **EU AI Act Art. 15**: Accuracy logging for AI system outputs
- **RBI FREE-AI**: Data integrity monitoring for financial AI
- **SEBI AIF**: Security audit trail for investment platforms

## Best Practices

1. **Enable scanning by default** - Use `basic` mode for all connectors initially
2. **Tune per-connector** - Disable for trusted internal services
3. **Use advanced mode** for sensitive data stores in Enterprise edition
4. **Monitor audit logs** for detection patterns and false positives
5. **Set appropriate thresholds** - Adjust confidence threshold for advanced mode

## Performance Impact

| Mode | Average Latency | P99 Latency | Throughput Impact |
|------|-----------------|-------------|-------------------|
| `off` | 0ms | 0ms | 0% |
| `basic` | <1ms | 2ms | <1% |
| `advanced` | 3-5ms | 10ms | 2-5% |

## Metrics

The middleware exposes metrics for monitoring:

```go
metrics := sqli.GetGlobalMiddleware().GetMetrics()
// metrics.ScansTotal - Total scans performed
// metrics.DetectionsTotal - Total detections
// metrics.BlockedTotal - Total blocked responses
```

## Troubleshooting

### False Positives

If legitimate SQL content is being blocked:

1. Check if content contains SQL-like patterns (documentation, logs)
2. Consider using `advanced` mode for better context awareness
3. Disable scanning for specific connectors with known safe data

### Performance Issues

If scanning adds unacceptable latency:

1. Reduce `max_content_length` to limit scanned data
2. Disable scanning for high-throughput connectors
3. Use `basic` mode instead of `advanced`

## Related Documentation

- [Row-Level Security](row-level-security.md)
- [MCP Connector Development](../guides/connector-development.md)
- [Compliance Guide](https://docs.getaxonflow.com/docs/compliance/overview/)
