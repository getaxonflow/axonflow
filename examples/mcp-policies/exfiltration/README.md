# MCP Exfiltration Detection Examples

Demonstrates AxonFlow's data exfiltration protection for MCP connectors (v3.2.0+).

## Overview

Exfiltration detection prevents large-scale data extraction through MCP queries by enforcing:

- **Row limits**: Maximum rows per query (default: 10,000)
- **Byte limits**: Maximum response size (default: 10MB)

When limits are exceeded, the query is blocked with a 403 response.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `MCP_EXFILTRATION_ENABLED` | `true` | Enable/disable exfiltration checks |
| `MCP_MAX_ROWS_PER_QUERY` | `10000` | Maximum rows per query |
| `MCP_MAX_BYTES_PER_QUERY` | `10485760` | Maximum response size in bytes (10MB) |

## Response Format

All MCP responses include `exfiltration_check` in `policy_info`:

```json
{
  "success": true,
  "data": [...],
  "policy_info": {
    "exfiltration_check": {
      "exceeded": false,
      "limit_type": "none",
      "rows_returned": 100,
      "row_limit": 10000,
      "bytes_returned": 15360,
      "byte_limit": 10485760
    }
  }
}
```

When blocked:

```json
{
  "success": false,
  "error": "Request blocked: exfiltration limit exceeded",
  "block_reason": "Row limit exceeded: 15000 rows exceeds limit of 10000",
  "policy_info": {
    "blocked": true,
    "exfiltration_check": {
      "exceeded": true,
      "limit_type": "rows",
      "rows_returned": 15000,
      "row_limit": 10000
    }
  }
}
```

## Examples

### HTTP

```bash
# Query within limits
./http/within-limits.sh

# Test row limit blocking (requires data or lower limit)
MCP_MAX_ROWS_PER_QUERY=5 docker-compose up -d
./http/row-limit-exceeded.sh
```

## Testing with Low Limits

To test exfiltration blocking without large datasets:

```bash
# Set a low row limit for testing
export MCP_MAX_ROWS_PER_QUERY=5

# Restart services
docker-compose down && docker-compose up -d

# Now any query returning >5 rows will be blocked
curl -X POST http://localhost:8080/mcp/resources/query \
  -H "Content-Type: application/json" \
  -d '{"connector": "postgres-main", "statement": "SELECT * FROM users"}'
```

## Use Cases

1. **Prevent bulk data extraction**: Block queries attempting to dump entire tables
2. **Protect against accidental exposure**: Limit damage from unintended broad queries
3. **Compliance**: Meet data handling requirements by limiting extraction volume
4. **Cost control**: Prevent expensive large-result queries

## See Also

- [MCP Policy Enforcement](/docs/mcp/policy-enforcement.md)
- [Dynamic Policy Evaluation](../dynamic/)
