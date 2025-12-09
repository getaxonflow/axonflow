# Example 1: Simple Sequential Workflow

This example shows the most basic AxonFlow workflow: send a query to an LLM and get a response.

## What You'll Learn

- How to connect to AxonFlow
- How to send a simple query
- How to handle the response

## Running

```bash
cp .env.example .env
# Add your API key to .env
go run main.go
```

## Expected Output

```
✅ Connected to AxonFlow
📤 Sending query: What is the capital of France?
📥 Response: The capital of France is Paris.
✅ Workflow completed successfully
```

## How It Works

1. **Initialize Client:** Connect to AxonFlow agent (http://localhost:8080)
2. **Send Query:** Submit natural language query
3. **Receive Response:** AxonFlow routes to LLM and returns result

The agent handles:
- Policy enforcement (PII redaction, content filtering)
- LLM routing (selects best provider)
- Response processing

## Next Steps

- Try Example 2 to see parallel execution
- Modify the query to test different prompts
- Check `docker-compose logs axonflow-agent` to see policy enforcement in action
