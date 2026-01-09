# MCP Policy Enforcement Examples

This directory contains examples demonstrating MCP (Model Context Protocol) policy enforcement with phase-aware blocking and redaction.

## Overview

AxonFlow enforces policies at two phases:

1. **REQUEST Phase**: Evaluates incoming queries and blocks malicious patterns (SQLi, dangerous operations)
2. **RESPONSE Phase**: Scans connector responses and redacts sensitive data (PII)

## Policy Behavior

| Phase | Categories | Action |
|-------|------------|--------|
| REQUEST | security-sqli, security-dangerous | Block with 403 |
| RESPONSE | pii-* | Redact sensitive fields |

## Response Fields

All MCP responses now include policy enforcement metadata:

```json
{
  "success": true,
  "data": [...],
  "redacted": true,
  "redacted_fields": ["data.rows[0].ssn", "data.rows[0].credit_card"],
  "policy_info": {
    "policies_evaluated": 15,
    "blocked": false,
    "redactions_applied": 2,
    "processing_time_ms": 3,
    "matched_policies": [
      {"policy_id": "pii-us-ssn", "category": "pii-us", "severity": "critical", "action": "redact"}
    ]
  }
}
```

## Examples

Each example demonstrates:

1. **Request Blocking**: SQLi pattern in query returns 403
2. **Response Redaction**: PII in connector data is redacted
3. **Clean Query**: No PII/SQLi passes through unmodified
4. **Policy Info**: Inspection of policy evaluation metadata

### Running Examples

Prerequisites:
```bash
docker compose up -d
```

#### Go
```bash
cd go
go run main.go
```

#### TypeScript
```bash
cd typescript
npm install
npx ts-node index.ts
```

#### Python
```bash
cd python
pip install -r requirements.txt
python main.py
```

#### Java
```bash
cd java
mvn compile exec:java
```

#### HTTP (curl)
```bash
cd http
./request-blocked.sh
./response-redacted.sh
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_ENDPOINT` | `http://localhost:8080` | AxonFlow Agent endpoint |
| `AXONFLOW_CLIENT_ID` | `demo` | Client ID for authentication |
| `AXONFLOW_CLIENT_SECRET` | `demo` | Client secret for authentication |

## Related Documentation

- [MCP Policy Enforcement Guide](../../docs/mcp/policy-enforcement.md)
- [ADR-022: MCP Policy Enforcement](../../technical-docs/architecture-decisions/ADR-022-mcp-policy-enforcement.md)
- [Issues #963, #975](https://github.com/getaxonflow/axonflow-enterprise/issues/963)
