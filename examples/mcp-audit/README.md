# MCP Audit Logging Examples

These examples demonstrate the MCP (Model Context Protocol) audit logging feature in AxonFlow. Every MCP connector query and execute operation is automatically logged to the `mcp_query_audits` table with full policy evaluation details.

## What Gets Audited

Each MCP operation creates an audit entry capturing:

| Phase | What's Logged |
|-------|---------------|
| **Request** | SQLi detection, PII blocking, matched policies |
| **Response** | PII redaction, redacted field paths |
| **Exfiltration** | Row counts, volume limits exceeded |
| **Result** | Success/failure, error messages, duration |

## Audit Entry Fields

The `mcp_query_audits` table stores:

```sql
audit_id                    -- Unique identifier for this audit entry
tenant_id, client_id, user_id -- Who made the request
connector_name, operation   -- What was requested (query/execute)
statement_hash              -- SHA256 hash of statement (privacy)
request_blocked             -- If request was blocked
request_block_reason        -- Why it was blocked
request_policies_evaluated  -- Number of policies checked
request_matched_policies    -- Which policies matched
response_redacted           -- If response was redacted
response_redactions_count   -- Number of fields redacted
response_redacted_fields    -- Paths of redacted fields (e.g., $.users[*].ssn)
exfil_rows_returned         -- Rows in response
exfil_exceeded              -- If exfiltration limit was hit
exfil_limit_type            -- row_count or data_volume
row_count, duration_ms      -- Final metrics
success, error_message      -- Result
created_at                  -- Timestamp
```

## Running the Examples

### Prerequisites

```bash
# Start AxonFlow
docker compose up -d

# Verify services are running
curl http://localhost:8080/health
```

### HTTP (cURL)

```bash
cd http
chmod +x mcp-audit.sh
./mcp-audit.sh
```

### Go

```bash
cd go
go run main.go
```

### Python

```bash
cd python
pip install -r requirements.txt
python main.py
```

### TypeScript

```bash
cd typescript
npm install
npx tsx index.ts
```

### Java

```bash
cd java
mvn exec:java -q
```

## Verifying Audit Entries

After running any example, verify the audit entries in the database:

```bash
docker compose exec postgres psql -U axonflow -d axonflow -c "
SELECT
    audit_id,
    connector_name,
    operation,
    request_blocked,
    response_redacted,
    exfil_exceeded,
    success,
    duration_ms
FROM mcp_query_audits
ORDER BY created_at DESC
LIMIT 10;
"
```

For detailed policy information:

```bash
docker compose exec postgres psql -U axonflow -d axonflow -c "
SELECT
    audit_id,
    request_policies_evaluated,
    request_matched_policies,
    response_redacted_fields
FROM mcp_query_audits
WHERE request_blocked = true OR response_redacted = true
ORDER BY created_at DESC
LIMIT 5;
"
```

## Use Cases

### Compliance Reporting

Query blocked requests for compliance dashboards:

```sql
SELECT
    DATE_TRUNC('day', created_at) as date,
    COUNT(*) as total_queries,
    COUNT(*) FILTER (WHERE request_blocked = true) as blocked,
    COUNT(*) FILTER (WHERE response_redacted = true) as redacted
FROM mcp_query_audits
WHERE tenant_id = 'your-tenant'
GROUP BY DATE_TRUNC('day', created_at)
ORDER BY date DESC;
```

### Security Incident Investigation

Find all blocked SQLi attempts:

```sql
SELECT
    created_at,
    client_id,
    user_id,
    request_block_reason,
    statement_hash
FROM mcp_query_audits
WHERE request_blocked = true
  AND request_block_reason LIKE '%SQL injection%'
ORDER BY created_at DESC;
```

### Data Access Patterns

Analyze which connectors are most used:

```sql
SELECT
    connector_name,
    COUNT(*) as query_count,
    AVG(duration_ms) as avg_duration,
    SUM(row_count) as total_rows
FROM mcp_query_audits
GROUP BY connector_name
ORDER BY query_count DESC;
```
