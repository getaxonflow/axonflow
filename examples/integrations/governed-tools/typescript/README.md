# GovernedTool Example -- TypeScript

Demonstrates `GovernedTool` wrapping standard `ToolDefinition` objects with AxonFlow input/output governance. Works with any framework that accepts tools with `name`, `description`, and `invoke()`.

## Prerequisites

- AxonFlow running locally (`docker compose up -d`)
- Node.js 18+

## Run

```bash
npm install
npx ts-node src/index.ts
```

## Tests

1. Clean tool call (policies evaluated, tool executes)
2. SQL injection blocked (tool never runs)
3. PII in tool input (detected/blocked)
4. PII in tool output (detected/redacted)
5. Custom connector type derivation
6. Read-only tool with `operation="query"`
7. `governTools()` multi-tool wrapping
8. Metadata and toString preservation
