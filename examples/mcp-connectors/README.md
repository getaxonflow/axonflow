# MCP Connector Examples - Orchestrator Routing

These examples test the **full MCP connector flow** through the orchestrator:

```
SDK -> Orchestrator (port 8081) -> Agent (port 8080) -> Connector
```

This is different from direct agent calls and exercises the internal service
authentication between orchestrator and agent.

## Prerequisites

Start AxonFlow:

```bash
# Community mode
docker compose up -d

# Or Enterprise mode
docker compose -f docker-compose.yml -f docker-compose.enterprise.yml up -d
```

## Running the Examples

### Go

```bash
cd go
go run main.go
```

### TypeScript

```bash
cd typescript
npx ts-node index.ts
```

### Python

```bash
cd python
pip install requests
python main.py
```

### Java (Java 11+)

```bash
cd java
java McpConnectorExample.java
```

## What These Examples Test

1. **Orchestrator Routing**: Sends `request_type: "mcp-query"` to orchestrator
2. **Internal Service Auth**: Orchestrator uses internal credentials to call agent
3. **Connector Query**: Agent executes query via postgres connector
4. **Response Flow**: Data flows back through orchestrator to SDK

## Expected Output

```
==============================================
MCP Connector Example - Orchestrator Routing
==============================================
Orchestrator URL: http://localhost:8081

Test 1: Query postgres connector via orchestrator...
SUCCESS: MCP query through orchestrator worked!
  Request ID: mcp-test-1234567890
  Processing Time: 50ms
  Rows returned: 1
  Connector: postgres

Test 2: Query 'database' connector (alias for postgres)...
SUCCESS: Database alias connector worked!

==============================================
All MCP connector tests PASSED!
==============================================
```

## Troubleshooting

**"Invalid client" error**: The orchestrator-to-agent authentication is not working.
Check that PR #814 fix is applied.

**"Connection refused"**: AxonFlow is not running. Run `docker compose up -d`.

**"Connector not found"**: The postgres connector is not configured. Check
`config/axonflow.yaml` has the postgres connector enabled.
