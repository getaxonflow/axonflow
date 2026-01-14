# MCP Dynamic Policy Evaluation Examples

Demonstrates AxonFlow's dynamic policy evaluation for MCP connectors (v3.2.0+).

## Overview

Dynamic policy evaluation enables Orchestrator-based policy checks for MCP queries. This provides:

- **Rate limiting**: Limit requests per user/connector/time window
- **Budget controls**: Enforce spending limits for data access
- **Time-based access**: Restrict access by time of day/week
- **Role-based access**: Control access based on user roles

Dynamic policies are **opt-in** and disabled by default.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `MCP_DYNAMIC_POLICIES_ENABLED` | `false` | Enable/disable dynamic policy evaluation |
| `MCP_DYNAMIC_POLICIES_ENDPOINT` | `http://localhost:8081` | Orchestrator endpoint |
| `MCP_DYNAMIC_POLICIES_TIMEOUT` | `5s` | Timeout for Orchestrator calls |
| `MCP_DYNAMIC_POLICIES_GRACEFUL` | `true` | Continue if Orchestrator unavailable |
| `MCP_DYNAMIC_POLICIES_CONNECTORS` | `""` | Comma-separated connectors (empty = all) |

## Response Format

All MCP responses include `dynamic_policy_info` in `policy_info`:

```json
{
  "success": true,
  "data": [...],
  "policy_info": {
    "policies_evaluated": 142,
    "blocked": false,
    "dynamic_policy_info": {
      "policies_evaluated": 3,
      "orchestrator_reachable": true,
      "processing_time_ms": 12,
      "matched_policies": [
        {
          "policy_id": "rate-limit-1",
          "policy_name": "API Rate Limit",
          "policy_type": "rate-limit",
          "action": "allow"
        }
      ]
    }
  }
}
```

When blocked by dynamic policy:

```json
{
  "success": false,
  "error": "Request blocked by dynamic policy",
  "block_reason": "Rate limit exceeded: 200/200 requests in current window",
  "policy_info": {
    "blocked": true,
    "dynamic_policy_info": {
      "policies_evaluated": 3,
      "orchestrator_reachable": true,
      "processing_time_ms": 5,
      "matched_policies": [
        {
          "policy_id": "rate-limit-1",
          "policy_name": "API Rate Limit",
          "policy_type": "rate-limit",
          "action": "deny"
        }
      ]
    }
  }
}
```

## Examples

### HTTP

```bash
# Basic evaluation (shows dynamic_policy_info in response)
MCP_DYNAMIC_POLICIES_ENABLED=true docker-compose up -d
./http/basic-evaluation.sh

# Rate limit test (sends rapid requests)
./http/rate-limit-test.sh 20
```

## Enabling Dynamic Policies

```bash
# Enable via environment variable
export MCP_DYNAMIC_POLICIES_ENABLED=true

# Restart services
docker-compose down && docker-compose up -d

# Verify enabled
curl -s http://localhost:8080/mcp/resources/query \
  -H "Content-Type: application/json" \
  -d '{"connector": "postgres-main", "query": "SELECT 1"}' | \
  jq '.policy_info.dynamic_policy_info.enabled'
# Should return: true
```

## Graceful Degradation

When `MCP_DYNAMIC_POLICIES_GRACEFUL=true` (default), queries continue if Orchestrator is unavailable:

```json
{
  "policy_info": {
    "dynamic_policy_info": {
      "enabled": true,
      "evaluated": false,
      "error": "connection refused"
    }
  }
}
```

Set `MCP_DYNAMIC_POLICIES_GRACEFUL=false` to fail queries when Orchestrator is unavailable.

## Policy Types

| Type | Description | Example |
|------|-------------|---------|
| `rate-limit` | Limit requests per time window | 100 req/min per user |
| `budget` | Enforce spending limits | $50/day per team |
| `time-based` | Restrict by time | Business hours only |
| `role-based` | Control by user role | Admins only for sensitive data |

## Enterprise Features

Community edition supports dynamic policies with a 2-connector limit. Enterprise features include:

- Unlimited connectors
- ML-based anomaly detection
- Cross-tenant policy inheritance
- Custom policy scripting

## See Also

- [MCP Policy Enforcement](/docs/mcp/policy-enforcement.md)
- [Exfiltration Detection](../exfiltration/)
