# GovernedTool Example -- Java

Demonstrates governed tool execution by wrapping standard tool calls with AxonFlow `mcpCheckInput`/`mcpCheckOutput` policy enforcement. Tests the underlying policy engine behavior: PII detection, SQLi blocking, output redaction.

## Prerequisites

- AxonFlow running locally (`docker compose up -d`)
- Java 11+
- Maven

## Run

```bash
mvn compile exec:java
```

## Tests

1. Clean tool call (policies evaluated, tool executes)
2. SQL injection blocked (tool never runs)
3. PII in tool input (detected/blocked)
4. PII in tool output (detected/redacted)
5. Custom connector type derivation
6. Read-only tool with `operation="query"`
7. Multi-tool wrapping
8. Metadata and representation
