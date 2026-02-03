# Multi-Agent Planning (MAP) Examples

These examples demonstrate how to use AxonFlow's Multi-Agent Planning (MAP) feature across all supported SDKs.

## Prerequisites

- AxonFlow Agent running (default: `http://localhost:8080`)
- SDK installed for your language

## Environment Variables

All examples support these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_AGENT_URL` | `http://localhost:8080` | AxonFlow Agent URL |
| `AXONFLOW_CLIENT_ID` | `demo` | Client ID for authentication |
| `AXONFLOW_CLIENT_SECRET` | `demo` | Client secret for authentication |

## Running the Examples

### Python

```bash
cd python
pip install -r requirements.txt
python main.py
```

### Go

```bash
cd go
go run main.go
```

### TypeScript

```bash
cd typescript
npm install
npm start
```

### Java

```bash
cd java
mvn compile exec:java
```

## What the Examples Do

Each example:
1. Connects to the AxonFlow Agent
2. Generates a multi-agent plan for a simple query
3. Displays the generated plan steps

## Expected Output

```
AxonFlow MAP Example - [Language]
==================================================

Query: Create a brief plan to greet a new user and ask how to help them
Domain: generic
--------------------------------------------------

✅ Plan Generated Successfully
Plan ID: plan_abc123
Steps: 3
  1. greet-user (llm-call)
  2. ask-how-to-help (llm-call)
  3. synthesize-results (llm-call)

==================================================
✅ [Language] MAP Test: PASS
```

## Policy Configuration for MAP

MAP plan generation and execution respects the same policy configuration as other AxonFlow operations. Each example includes a PII-containing plan query test that checks behavior based on the configured PII action:

| Variable | Default | Description |
|----------|---------|-------------|
| `PII_ACTION` | `redact` | Controls PII detection behavior globally |
| `GATEWAY_PII_ACTION` | (inherits `PII_ACTION`) | Override for gateway mode |

When `GATEWAY_PII_ACTION=block`, plan generation with PII data (e.g., SSN) will be blocked. When set to `log`, PII is detected and logged but the plan proceeds. The default `redact` mode flags PII for downstream redaction by the Orchestrator.

## Learn More

- [MAP Documentation](https://docs.getaxonflow.com/docs/orchestration/overview)
- [SDK Documentation](https://docs.getaxonflow.com/docs/sdk/overview)
