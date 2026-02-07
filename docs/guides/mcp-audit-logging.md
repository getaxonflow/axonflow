# MCP Audit Logging

This guide explains how AxonFlow captures audit logs for all MCP (Model Context Protocol) connector operations. Every query and execute operation is automatically logged to provide a complete audit trail for compliance and security analysis.

## Overview

MCP audit logging captures policy evaluation results at three phases:

1. **Request Phase**: Before the query reaches the connector
   - SQLi detection and blocking
   - PII blocking (when configured to block vs redact)
   - Dangerous operation detection

2. **Response Phase**: After the connector returns data
   - PII redaction (emails, SSNs, phone numbers, etc.)
   - Redacted field paths for compliance reporting

3. **Exfiltration Phase**: Data volume checks
   - Row count limits
   - Data volume limits
   - Time-window aggregation (Enterprise)

## Audit Table Schema

All MCP operations are logged to the `mcp_query_audits` table:

```sql
CREATE TABLE mcp_query_audits (
    id UUID PRIMARY KEY,
    audit_id VARCHAR(64) UNIQUE NOT NULL,     -- Correlates with SDK PolicyInfo
    tenant_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    connector_name VARCHAR(100) NOT NULL,      -- postgres, mysql, etc.
    operation VARCHAR(50) NOT NULL,            -- query, insert, update, delete

    -- Privacy: Raw statement NOT stored, only hash
    statement_hash VARCHAR(64),                -- SHA256 hash

    -- Request phase results
    request_blocked BOOLEAN DEFAULT false,
    request_block_reason TEXT,
    request_policies_evaluated INT DEFAULT 0,
    request_matched_policies TEXT[],           -- Policy IDs that matched

    -- Response phase results
    response_redacted BOOLEAN DEFAULT false,
    response_redactions_count INT DEFAULT 0,
    response_redacted_fields TEXT[],           -- JSONPath of redacted fields

    -- Exfiltration detection
    exfil_rows_returned INT,
    exfil_exceeded BOOLEAN DEFAULT false,
    exfil_limit_type VARCHAR(20),              -- row_count, data_volume

    -- Final result
    row_count INT,
    duration_ms BIGINT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
```

## Configuration

MCP audit logging is enabled by default. Configure the audit mode in your environment:

```yaml
# axonflow.yaml
audit:
  mode: compliance    # compliance (sync) or performance (async)
  fallback_path: /var/log/axonflow/audit-fallback.log
```

| Mode | Behavior | Use Case |
|------|----------|----------|
| `compliance` | Synchronous writes, guaranteed durability | Regulated environments (SEBI, RBI, EU AI Act) |
| `performance` | Async writes with batching | High-throughput applications |

## Querying Audit Logs

### Daily Summary

```sql
SELECT
    DATE_TRUNC('day', created_at) AS date,
    connector_name,
    COUNT(*) AS total_queries,
    COUNT(*) FILTER (WHERE request_blocked = true) AS blocked,
    COUNT(*) FILTER (WHERE response_redacted = true) AS redacted,
    COUNT(*) FILTER (WHERE exfil_exceeded = true) AS exfil_violations,
    AVG(duration_ms) AS avg_duration_ms
FROM mcp_query_audits
WHERE tenant_id = 'your-tenant'
GROUP BY DATE_TRUNC('day', created_at), connector_name
ORDER BY date DESC;
```

### Security Incident Investigation

Find all blocked SQLi attempts:

```sql
SELECT
    created_at,
    client_id,
    user_id,
    connector_name,
    request_block_reason,
    statement_hash
FROM mcp_query_audits
WHERE request_blocked = true
  AND request_block_reason LIKE '%SQL injection%'
ORDER BY created_at DESC
LIMIT 100;
```

### PII Redaction Report

Track what fields are being redacted:

```sql
SELECT
    connector_name,
    UNNEST(response_redacted_fields) AS redacted_field,
    COUNT(*) AS redaction_count
FROM mcp_query_audits
WHERE response_redacted = true
  AND created_at > NOW() - INTERVAL '7 days'
GROUP BY connector_name, redacted_field
ORDER BY redaction_count DESC;
```

### Exfiltration Attempts

Identify potential data exfiltration:

```sql
SELECT
    created_at,
    client_id,
    user_id,
    connector_name,
    exfil_limit_type,
    exfil_rows_returned
FROM mcp_query_audits
WHERE exfil_exceeded = true
ORDER BY created_at DESC
LIMIT 50;
```

## SDK Integration

The SDK's `ConnectorResponse` includes `PolicyInfo` that matches the audit entry:

```go
result, err := client.MCPQuery(ctx, axonflow.MCPQueryRequest{
    Connector: "postgres",
    Statement: "SELECT email FROM users",
})

if result.PolicyInfo != nil {
    fmt.Printf("Policies evaluated: %d\n", result.PolicyInfo.PoliciesEvaluated)
    fmt.Printf("Redacted fields: %v\n", result.PolicyInfo.RedactedFields)
}
```

The `audit_id` in the database can be used to correlate SDK responses with audit entries.

## Gateway vs Proxy Mode

MCP audit logging works identically in both Gateway and Proxy modes:

| Mode | MCP Flow | Audit Table |
|------|----------|-------------|
| Gateway | SDK → Agent → Connector | `mcp_query_audits` |
| Proxy | SDK → Orchestrator → Agent → Connector | `mcp_query_audits` |

## Compliance Requirements

### SEBI (India)

- 7-year retention for audit logs
- Use compliance mode for synchronous writes
- Enable statement hashing for privacy

### RBI (India)

- Real-time audit trail for AI decisions
- Track PII handling in financial data
- Exfiltration detection for fraud prevention

### EU AI Act

- Article 12: Automatic logging for high-risk AI systems
- Track human involvement in AI-assisted decisions
- Export capabilities for regulatory audits

## Summary View

Use the built-in summary view for quick analysis:

```sql
SELECT * FROM mcp_query_audit_summary
WHERE tenant_id = 'your-tenant'
ORDER BY date DESC
LIMIT 30;
```

This view provides daily aggregates by tenant and connector.

## Maintenance

### Cleanup Old Records

For non-regulated environments, you may want to purge old audit records:

```sql
-- Delete records older than 90 days
DELETE FROM mcp_query_audits
WHERE created_at < NOW() - INTERVAL '90 days'
  AND tenant_id = 'your-tenant';
```

For regulated environments, configure archive-to-S3 or similar before deletion.

## Examples

See the [MCP Audit Examples](/examples/mcp-audit/) for working code in:
- HTTP (cURL)
- Go
- Python
- TypeScript
- Java
