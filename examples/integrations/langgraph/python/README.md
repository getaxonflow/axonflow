# LangGraph + AxonFlow MCP Tool Interceptor (Python SDK)

This example demonstrates how to enforce AxonFlow policies around MCP tool calls in a LangGraph workflow using `AxonFlowLangGraphAdapter.mcp_tool_interceptor()`.

## Features

- **MCP Tool Interception**: Policy enforcement around every MCP tool call
- **Input Policy Checks**: SQLi detection, PII blocking, dangerous query prevention
- **Output Policy Checks**: PII redaction, exfiltration limits
- **Pluggable Connector Types**: Custom mapping from MCP request to policy connector
- **Configurable Operation Type**: `"execute"` (default) or `"query"` for read-only tools

## Prerequisites

- Python 3.9+
- AxonFlow running locally (`docker compose up`)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the example
python main.py
```

## How It Works

### MCP Tool Interceptor Flow

```
┌──────────────────┐
│  MCP Tool Call    │
│  (e.g., SQL query)│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌─────────┐
│ mcp_check_input  │────►│ BLOCKED │  (SQLi, PII, policy violation)
│ (input policies) │     └─────────┘
└────────┬─────────┘
         │ allowed
         ▼
┌──────────────────┐
│  handler()       │  (execute the actual MCP tool)
│  (tool execution)│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌──────────┐
│ mcp_check_output │────►│ REDACTED │  (PII in results replaced)
│ (output policies)│     └──────────┘
└────────┬─────────┘
         │ allowed
         ▼
┌──────────────────┐
│  Return result   │
│  (or redacted)   │
└──────────────────┘
```

### Usage with MultiServerMCPClient

```python
from axonflow import AxonFlow
from axonflow.adapters import AxonFlowLangGraphAdapter, MCPInterceptorOptions

async with AxonFlow(endpoint="http://localhost:8080") as client:
    adapter = AxonFlowLangGraphAdapter(client, "my-workflow")

    # Default: operation="execute", connector_type="{server}.{tool}"
    mcp_client = MultiServerMCPClient(
        {"postgres": {"url": "...", "transport": "http"}},
        tool_interceptors=[adapter.mcp_tool_interceptor()],
    )

    # For read-only tools
    opts = MCPInterceptorOptions(operation="query")
    mcp_client = MultiServerMCPClient(
        {"readonly-db": {"url": "...", "transport": "http"}},
        tool_interceptors=[adapter.mcp_tool_interceptor(opts)],
    )

    # Custom connector type mapping
    opts = MCPInterceptorOptions(
        connector_type_fn=lambda req: req.server_name,
    )
```

## Expected Output

```
LangGraph + AxonFlow MCP Tool Interceptor Example
============================================================

Running MCP interceptor tests...

============================================================
[Test 1] Safe MCP Tool Call - Should be allowed
============================================================
   PASS: Tool call returned a result
   PASS: Result contains rows
   PASS: Row count is 2 (got 2)

============================================================
[Test 2] SQL Injection in MCP Tool Args - Should be blocked
============================================================
   Blocked: SQL injection detected in query
   PASS: SQL injection tool call was blocked
   PASS: Block reason mentions SQL injection or policy block

============================================================
[Test 5] Custom Connector Type Derivation
============================================================
   PASS: Custom connector type tool call succeeded

============================================================
Test Summary
============================================================
ALL TESTS PASSED
============================================================
```

## Related Examples

- [Go SDK Example](../go/) - LangGraph integration in Go
- [TypeScript SDK Example](../typescript/) - LangGraph integration in TypeScript
- [Workflow Control Adapter](../../../workflow-control/python/langgraph_example.py) - WCP step gates
- [MCP Policy Check Endpoints](../../../mcp-policies/check-endpoints/) - Standalone policy checks
