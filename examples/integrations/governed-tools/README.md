# GovernedTool: Framework-Agnostic Tool Governance

Demonstrates `GovernedTool` — wraps any LangChain `BaseTool` with AxonFlow input/output governance. Works with LangGraph, LangChain AgentExecutor, CrewAI, AutoGen, and any framework that accepts `BaseTool` instances.

## Prerequisites

- AxonFlow running locally (`docker compose up -d`)
- Python 3.10+
- `pip install axonflow langchain-core`

## Examples

### HTTP (curl)

Tests the underlying `mcp_check_input` and `mcp_check_output` endpoints that `GovernedTool` calls internally:

```bash
cd http
bash test_governed_tools.sh
```

### Python: Comprehensive E2E

Tests all governance scenarios: clean calls, SQLi blocked, PII detection, output redaction, custom connector types, govern_tools helper:

```bash
cd python
pip install -r requirements.txt
python main.py
```

## How It Works

```
User → Agent → GovernedTool.invoke(input)
                    │
                    ├── mcp_check_input(connector_type, args)
                    │     → BLOCK if policy violated (tool never runs)
                    │
                    ├── wrapped_tool.invoke(input)
                    │     → actual tool execution
                    │
                    └── mcp_check_output(connector_type, result)
                          → BLOCK if exfiltration/policy violated
                          → REDACT if PII detected (clean result returned)
                          → ALLOW (original result returned)
```

## Key Difference from tool_output_wrapper

| Feature | `GovernedTool` | `tool_output_wrapper` |
|---------|---------------|----------------------|
| **Works with** | Any framework (BaseTool) | LangGraph ToolNode only |
| **Integration** | `govern_tools(tools, client)` | `ToolNode(awrap_tool_call=wrapper)` |
| **Governs** | Input + output | Input + output |
| **Best for** | LangChain, CrewAI, AutoGen, any BaseTool consumer | LangGraph-specific pipelines |
