# GovernedTool Example -- Go

Demonstrates `GovernedTool` wrapping standard `axonflow.Tool` interface implementations with AxonFlow input/output governance. Works with any framework that accepts the Tool interface.

## Prerequisites

- AxonFlow running locally (`docker compose up -d`)
- Go 1.21+

## Run

```bash
go run main.go
```

## Tests

1. Clean tool call (policies evaluated, tool executes)
2. SQL injection blocked (tool never runs)
3. PII in tool input (detected/blocked)
4. PII in tool output (detected/redacted)
5. Custom connector type derivation
6. Read-only tool with `operation="query"`
7. `GovernTools()` multi-tool wrapping
8. Metadata and String() preservation
