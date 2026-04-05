# Workflow Policy Enforcement Examples

This directory contains examples demonstrating **Workflow Policy Enforcement** in AxonFlow.
Policy enforcement ensures that workflow steps and plan executions are evaluated against
configured policies before proceeding.

## Features Demonstrated

### MAP (Multi-Agent Planning) Policy Enforcement
- Policy evaluation before plan execution
- `PolicyInfo` field in execution response
- Blocked execution when policies deny (403 response)
- Risk score and applied policies tracking

### WCP (Workflow Control Plane) Policy Enforcement
- Policy evaluation at each step gate
- `policies_evaluated` - all policies checked
- `policies_matched` - policies that triggered the decision
- Detailed policy match info (policy_id, policy_name, action, reason)

## Available Examples

| Language | Directory | Description |
|----------|-----------|-------------|
| HTTP/curl | `http/` | Raw HTTP API examples |
| Go | `go/` | Go SDK example |
| Python | `python/` | Python SDK example |
| TypeScript | `typescript/` | TypeScript SDK example |
| Java | `java/` | Java SDK example |

## Prerequisites

1. AxonFlow running locally (default: `http://localhost:8080`)
2. Valid client credentials

## Environment Variables

```bash
# Required
export AXONFLOW_ENDPOINT="http://localhost:8080"
export AXONFLOW_CLIENT_ID="your-client-id"
export AXONFLOW_CLIENT_SECRET="your-client-secret"

# Optional (for MAP examples)
export AXONFLOW_AGENT_URL="http://localhost:8080"
```

## Running Examples

### HTTP (curl)
```bash
cd http
chmod +x workflow-policy.sh
./workflow-policy.sh
```

### Go
```bash
cd go
go run main.go
```

### Python
```bash
cd python
pip install axonflow
python main.py
```

### TypeScript
```bash
cd typescript
npm install
npx tsx main.ts
```

### Java
```bash
cd java
mvn compile exec:java -q
```

## Expected Output

### MAP Policy Allowed
```json
{
  "success": true,
  "plan_id": "plan_abc123",
  "policy_info": {
    "allowed": true,
    "applied_policies": ["pii-detection", "sqli-prevention"],
    "risk_score": 0.15,
    "processing_time_ms": 5
  }
}
```

### MAP Policy Blocked
```json
{
  "success": false,
  "error": "Policy blocked MAP execution",
  "policy_info": {
    "allowed": false,
    "applied_policies": ["sqli-prevention"],
    "risk_score": 0.95
  }
}
```

### WCP Step Gate with Policy Info
```json
{
  "decision": "allow",
  "step_id": "step-1",
  "policies_evaluated": [
    {"policy_id": "pol-1", "policy_name": "pii-detection", "action": "allow"},
    {"policy_id": "pol-2", "policy_name": "sqli-prevention", "action": "allow"}
  ],
  "policies_matched": []
}
```

## Related Documentation

- [Workflow Control Plane Guide](https://docs.getaxonflow.com/docs/orchestration/wcp/overview/)
- [Policy Configuration](https://docs.getaxonflow.com/docs/orchestration/wcp/policy-configuration/)
- [API Reference](../../docs/api/orchestrator-api.yaml)

## Issues

- Issue #1019: EPIC - Workflow Policy Enforcement
- Issue #1020: MAP Policy Enforcement
- Issue #1021: WCP Policy Enforcement
