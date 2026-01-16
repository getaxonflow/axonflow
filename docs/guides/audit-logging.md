# Audit Logging Architecture

This guide provides a comprehensive overview of AxonFlow's audit logging system, covering all audit tables, their purposes, and how they work together to provide a complete compliance trail.

## Overview

AxonFlow maintains multiple audit tables to capture different types of operations:

| Table | Purpose | Mode |
|-------|---------|------|
| `gateway_contexts` | Pre-check contexts for Gateway Mode | Gateway |
| `llm_call_audits` | LLM call details in Gateway Mode | Gateway |
| `agent_audit_logs` | Agent actions (legacy) | Both |
| `orchestrator_audit_logs` | Orchestrator actions | Proxy |
| `mcp_query_audits` | MCP connector operations | Both |

## Audit Tables

### 1. Gateway Mode Audits

When using Gateway Mode, clients perform a pre-check before making LLM calls, then report back for audit.

#### `gateway_contexts`

Stores pre-check contexts that link policy approval to the audit trail.

```sql
CREATE TABLE gateway_contexts (
    id UUID PRIMARY KEY,
    context_id VARCHAR(64) UNIQUE NOT NULL,  -- Links to llm_call_audits
    client_id VARCHAR(255) NOT NULL,
    user_token_hash VARCHAR(64),              -- SHA256 hash (privacy)
    query_hash VARCHAR(64),                   -- SHA256 hash (privacy)
    data_sources TEXT[],                      -- MCP connectors accessed
    policies_evaluated TEXT[],                -- Policies evaluated
    approved BOOLEAN NOT NULL,
    block_reason TEXT,
    expires_at TIMESTAMP NOT NULL,            -- 5-minute validity window
    created_at TIMESTAMP
);
```

**Key Fields:**
- `context_id`: Unique identifier returned to SDK, used to link audit records
- `user_token_hash`: Privacy-preserving hash of user token
- `approved`: Whether the request passed policy evaluation
- `expires_at`: Context is only valid for a short window

#### `llm_call_audits`

Stores audit records for LLM calls made by clients in Gateway Mode.

```sql
CREATE TABLE llm_call_audits (
    id UUID PRIMARY KEY,
    audit_id VARCHAR(64) UNIQUE NOT NULL,
    context_id VARCHAR(64) REFERENCES gateway_contexts(context_id),
    client_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,            -- openai, anthropic, etc.
    model VARCHAR(100) NOT NULL,
    prompt_tokens INT,
    completion_tokens INT,
    total_tokens INT,
    latency_ms BIGINT,
    estimated_cost_usd DECIMAL(10, 6),
    response_summary_hash VARCHAR(64),
    metadata JSONB,
    created_at TIMESTAMP
);
```

**Key Fields:**
- `context_id`: Links back to the gateway_contexts pre-check
- `provider`/`model`: Which LLM was used
- `estimated_cost_usd`: Cost tracking for budgets
- `latency_ms`: Performance monitoring

### 2. MCP Connector Audits

All MCP connector operations are logged with policy evaluation results.

#### `mcp_query_audits`

Captures query and execute operations on MCP connectors.

```sql
CREATE TABLE mcp_query_audits (
    id UUID PRIMARY KEY,
    audit_id VARCHAR(64) UNIQUE NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    connector_name VARCHAR(100) NOT NULL,
    operation VARCHAR(50) NOT NULL,           -- query, execute, etc.
    statement_hash VARCHAR(64),               -- SHA256 hash (privacy)

    -- Request phase (pre-execution)
    request_blocked BOOLEAN DEFAULT false,
    request_block_reason TEXT,
    request_policies_evaluated INT DEFAULT 0,
    request_matched_policies TEXT[],

    -- Response phase (post-execution)
    response_redacted BOOLEAN DEFAULT false,
    response_redactions_count INT DEFAULT 0,
    response_redacted_fields TEXT[],          -- JSONPath of redacted fields

    -- Exfiltration detection
    exfil_rows_returned INT,
    exfil_exceeded BOOLEAN DEFAULT false,
    exfil_limit_type VARCHAR(20),

    -- Result
    row_count INT,
    duration_ms BIGINT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ
);
```

**Key Fields:**
- `statement_hash`: SHA256 hash of the SQL statement (privacy-preserving)
- `request_blocked`: Whether the query was blocked before execution
- `request_block_reason`: Why it was blocked (e.g., "Detects DROP TABLE statement")
- `response_redacted`: Whether PII was redacted from the response
- `response_redacted_fields`: JSONPath of redacted fields (e.g., `$.users[*].ssn`)
- `exfil_exceeded`: Whether exfiltration limits were exceeded

### 3. Legacy Audit Tables

#### `agent_audit_logs`

Basic agent action logging.

```sql
CREATE TABLE agent_audit_logs (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255),
    client_id VARCHAR(100),
    action VARCHAR(100),
    resource TEXT,
    timestamp TIMESTAMP
);
```

#### `orchestrator_audit_logs`

Basic orchestrator action logging.

```sql
CREATE TABLE orchestrator_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    org_id VARCHAR(255),
    service_id VARCHAR(100) NOT NULL,
    action VARCHAR(255) NOT NULL,
    resource TEXT,
    timestamp TIMESTAMP WITH TIME ZONE
);
```

## Audit Modes

AxonFlow supports two audit modes, configured via the `AUDIT_MODE` environment variable:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `compliance` | Synchronous writes, guaranteed durability | Regulated environments (SEBI, RBI, EU AI Act) |
| `performance` | Async writes with batching | High-throughput applications |

### Compliance Mode

In compliance mode, audit writes are synchronous:
- Every policy violation is written immediately
- Database failures cause request failures
- Suitable for regulated environments

```yaml
environment:
  AUDIT_MODE: compliance
```

### Performance Mode

In performance mode, audit writes are asynchronous:
- Writes are queued and batched
- Fallback to file if queue overflows
- Recovery on restart

```yaml
environment:
  AUDIT_MODE: performance
  AUDIT_FALLBACK_PATH: /var/log/axonflow/audit-fallback.jsonl
```

## Privacy Considerations

AxonFlow protects sensitive data in audit logs:

| Field | Storage | Purpose |
|-------|---------|---------|
| User Token | SHA256 hash | Privacy-preserving linkage |
| SQL Statement | SHA256 hash | Audit without storing raw queries |
| Query Content | SHA256 hash | Reproducibility without exposure |
| Response Data | Not stored | Only metadata captured |

## Querying Audit Logs

### Daily Summary (MCP)

```sql
SELECT
    DATE_TRUNC('day', created_at) AS date,
    connector_name,
    COUNT(*) AS total_queries,
    COUNT(*) FILTER (WHERE request_blocked = true) AS blocked,
    COUNT(*) FILTER (WHERE response_redacted = true) AS redacted,
    COUNT(*) FILTER (WHERE exfil_exceeded = true) AS exfil_violations
FROM mcp_query_audits
WHERE tenant_id = 'your-tenant'
GROUP BY 1, 2
ORDER BY date DESC;
```

### LLM Cost Summary (Gateway)

```sql
SELECT * FROM llm_cost_summary
WHERE client_id = 'your-client'
ORDER BY date DESC
LIMIT 30;
```

### Security Incident Investigation

Find blocked SQLi attempts:

```sql
SELECT
    created_at,
    client_id,
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
GROUP BY 1, 2
ORDER BY redaction_count DESC;
```

## Compliance Mapping

| Regulation | Requirement | AxonFlow Feature |
|------------|-------------|------------------|
| **SEBI** | 7-year audit retention | Compliance mode + archive |
| **RBI** | Real-time AI decision audit | Synchronous writes |
| **EU AI Act** | Article 12: Automatic logging | All audit tables |
| **HIPAA** | PHI access logging | MCP audit with PII tracking |

## Retention and Cleanup

### Configuring Retention

For non-regulated environments:

```sql
-- Delete MCP audits older than 90 days
DELETE FROM mcp_query_audits
WHERE created_at < NOW() - INTERVAL '90 days';

-- Clean up expired gateway contexts
SELECT cleanup_expired_gateway_contexts();
```

For regulated environments, archive before deletion:
1. Export to S3/object storage
2. Verify archive integrity
3. Delete from database

### Summary Views

Pre-built views for quick analysis:

- `llm_cost_summary`: Daily LLM cost aggregates
- `mcp_query_audit_summary`: Daily MCP operation summaries

## SDK Integration

### Gateway Mode SDK

```typescript
// Pre-check before LLM call
const context = await client.getPolicyApprovedContext({
  query: userQuery,
  userId: currentUser.id
});

if (!context.approved) {
  throw new Error(context.blockReason);
}

// Make LLM call directly
const response = await openai.chat.completions.create({...});

// Report back for audit
await client.auditLLMCall({
  contextId: context.contextId,
  provider: 'openai',
  model: 'gpt-4',
  promptTokens: response.usage.prompt_tokens,
  completionTokens: response.usage.completion_tokens
});
```

### MCP Connector SDK

```go
result, err := client.MCPQuery(ctx, axonflow.MCPQueryRequest{
    Connector: "postgres",
    Statement: "SELECT email FROM users",
})

// PolicyInfo contains audit correlation ID
if result.PolicyInfo != nil {
    fmt.Printf("Audit ID: %s\n", result.PolicyInfo.AuditID)
    fmt.Printf("Policies evaluated: %d\n", result.PolicyInfo.PoliciesEvaluated)
}
```

## Architecture Diagram

```
Gateway Mode:
  SDK -> getPolicyApprovedContext() -> gateway_contexts
  SDK -> LLM Provider (direct)
  SDK -> auditLLMCall() -> llm_call_audits

Proxy Mode:
  SDK -> Orchestrator -> orchestrator_audit_logs
  SDK -> Agent -> agent_audit_logs

MCP (Both Modes):
  SDK -> Agent MCP Handler -> mcp_query_audits
```

## See Also

- [MCP Audit Logging](./mcp-audit-logging.md) - Detailed MCP audit configuration
- [Gateway Mode](./gateway-mode.md) - Gateway Mode setup
- [Proxy Mode](./proxy-mode.md) - Proxy Mode setup
