# Audit Logging Examples

Demonstrates AxonFlow's audit logging capabilities for compliance and monitoring.

## What This Example Shows

AxonFlow provides comprehensive audit trails for AI interactions:

| Feature | Description |
|---------|-------------|
| Pre-check Logging | Records policy evaluations before LLM calls |
| LLM Call Auditing | Logs provider, model, tokens, latency |
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

Use the Orchestrator API to search audit logs:

```bash
# Search by user and date range
curl -X POST http://localhost:8081/api/v1/audit/search \
  -H "Content-Type: application/json" \
  -d '{
    "user_email": "user@example.com",
    "start_time": "2025-01-01T00:00:00Z",
    "end_time": "2025-01-31T23:59:59Z",
    "limit": 100
  }'

# Get tenant audit logs
curl http://localhost:8081/api/v1/audit/tenant/demo
```

## Next Steps

- [Gateway Mode](../integrations/gateway-mode/) - Full Gateway Mode examples
- [Proxy Mode](../integrations/proxy-mode/) - Let AxonFlow make LLM calls
- [Policies](../policies/) - Create custom policies
