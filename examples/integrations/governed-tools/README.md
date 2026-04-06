# GovernedTool: Framework-Agnostic Tool Governance

Demonstrates `GovernedTool` -- wraps any tool with AxonFlow input/output governance. Works with LangGraph, LangChain AgentExecutor, CrewAI, AutoGen, Vercel AI SDK, and any framework that accepts tool-shaped objects.

## Prerequisites

- AxonFlow running locally (`docker compose up -d`)

## Examples

### HTTP (curl)

Tests the underlying `mcp_check_input` and `mcp_check_output` endpoints that `GovernedTool` calls internally:

```bash
cd http
bash test_governed_tools.sh
```

### Python

Tests all governance scenarios: clean calls, SQLi blocked, PII detection, output redaction, custom connector types, govern_tools helper:

```bash
cd python
pip install -r requirements.txt
python main.py
```

### TypeScript

Uses `GovernedTool` and `governTools` from `@axonflow/sdk` with standard `ToolDefinition` objects:

```bash
cd typescript
npm install
npx ts-node src/index.ts
```

### Go

Uses `GovernTool` and `GovernTools` from the Go SDK with the `axonflow.Tool` interface:

```bash
cd go
go run main.go
```

### Java

Wraps tool calls with `mcpCheckInput`/`mcpCheckOutput` for governed execution:

```bash
cd java
mvn compile exec:java
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
