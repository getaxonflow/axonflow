# Audit Logging Examples

Demonstrates AxonFlow's audit logging capabilities for compliance and monitoring.

## What This Example Shows

AxonFlow provides comprehensive audit trails for AI interactions:

| Feature | Description |
|---------|-------------|
| Pre-check Logging | Records policy evaluations before LLM calls |
| LLM Call Auditing | Logs provider, model, tokens, latency |
| Tool Call Auditing | Records non-LLM tool calls (API, MCP, functions) |
| Context Tracking | Links pre-check to audit via context ID |
| Search & Query | Query audit logs by user, time, client |

## Gateway Mode Workflow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Pre-Check  │────▶│   LLM Call   │────▶│   Audit     │
│  (Policies) │     │ (Your Code)  │     │   (Log)     │
└─────────────┘     └──────────────┘     └─────────────┘
       │                   │                    │
       └───────────────────┴────────────────────┘
                    Context ID links all steps
```

## Prerequisites

```bash
# Start AxonFlow
cd /path/to/axonflow
docker compose up -d

# Set API key for LLM calls
export OPENAI_API_KEY=sk-your-key-here

# For authenticated environments, provide client credentials and a JWT user token
export AXONFLOW_CLIENT_ID=local-test
export AXONFLOW_CLIENT_SECRET=<license-or-client-secret>
export AXONFLOW_USER_TOKEN=<jwt-token>
```

## Run Examples

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
npx ts-node index.ts
```

### Java
```bash
cd java
mvn compile exec:java
```

### HTTP (curl)
```bash
cd http
chmod +x audit-logging.sh
./audit-logging.sh
```

## Expected Output

Each example demonstrates the complete Gateway Mode workflow:
1. Pre-check returns context ID and approval status
2. Your code makes the LLM call (using OpenAI in these examples)
3. Audit logs the interaction with token usage and latency
4. Final output shows governance overhead vs LLM latency

## SDK + HTTP Coverage

This example set covers the audit methods from issues `#878` and `#1260`:

| Capability | Go | Python | TypeScript | Java | HTTP |
|------------|----|--------|------------|------|------|
| Pre-check (`getPolicyApprovedContext`) | ✅ | ✅ | ✅ | ✅ | ✅ (`POST /api/policy/pre-check`) |
| Audit write (`auditLLMCall`) | ✅ | ✅ | ✅ | ✅ | ✅ (`POST /api/audit/llm-call`) |
| Tool call audit (`auditToolCall`) | ✅ | ✅ | ✅ | ✅ | ✅ (`POST /api/v1/audit/tool-call`) |
| Audit search (`SearchAuditLogs` / equivalent) | ✅ | ✅ | ✅ | ✅ | ✅ (`POST /api/v1/audit/search`) |
| Tenant logs (`GetAuditLogsByTenant` / equivalent) | ✅ | ✅ | ✅ | ✅ | ✅ (`GET /api/v1/audit/tenant/{tenant_id}`) |

## Audit Log Fields

Each audit entry includes:
- `context_id` - Links to original pre-check
- `user_token` - User identifier
- `client_id` - Application identifier
- `provider` - LLM provider (openai, anthropic, etc.)
- `model` - Model used (gpt-4, claude-3, etc.)
- `token_usage` - Prompt, completion, total tokens
- `latency_ms` - LLM call duration
- `timestamp` - When the call was made

## Querying Audit Logs

Search audit logs via the Agent API:

```bash
# Search by user and date range
curl -X POST http://localhost:8080/api/v1/audit/search \
  -H "Content-Type: application/json" \
  -u demo:demo-secret \
  -d '{
    "user_email": "user@example.com",
    "start_time": "2025-01-01T00:00:00Z",
    "end_time": "2025-01-31T23:59:59Z",
    "limit": 100
  }'

# Get tenant audit logs
curl -u demo:demo-secret http://localhost:8080/api/v1/audit/tenant/demo
```

## Next Steps

- [Gateway Mode](../integrations/gateway-mode/) - Full Gateway Mode examples
- [Proxy Mode](../integrations/proxy-mode/) - Let AxonFlow make LLM calls
- [Policies](../policies/) - Create custom policies
