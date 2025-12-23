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

## Learn More

- [MAP Documentation](https://docs.getaxonflow.com/docs/orchestration/overview)
- [SDK Documentation](https://docs.getaxonflow.com/docs/sdk/overview)
