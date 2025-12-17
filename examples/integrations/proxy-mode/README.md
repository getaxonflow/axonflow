# Proxy Mode Examples

**Simplest integration** - Send queries to AxonFlow, get governed responses back.

## What is Proxy Mode?

Proxy Mode routes ALL your LLM calls through AxonFlow:

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  Your App   │─────▶│  AxonFlow   │─────▶│  LLM API    │
│             │      │  (Policy +  │      │  (OpenAI)   │
│             │◀─────│   Routing)  │◀─────│             │
└─────────────┘      └─────────────┘      └─────────────┘
```

**Benefits:**
- Zero LLM API key management in your app
- Automatic policy enforcement
- Automatic audit logging
- Built-in retry and failover
- Single endpoint for all LLM providers

**Trade-offs:**
- All traffic goes through AxonFlow
- Less control over LLM parameters
- Higher latency than Gateway Mode

## Quick Start

### 1. Start AxonFlow

```bash
docker compose up -d
```

### 2. Choose your language

#### TypeScript

```bash
cd typescript
npm install
npm start
```

#### Go

```bash
cd go
go run main.go
```

#### Python

```bash
cd python
pip install -r requirements.txt
python main.py
```

## Usage

### Single Query

```typescript
// TypeScript
const response = await client.executeQuery({
  query: "What is AI governance?",
  userToken: "user-123",
  requestType: "chat",
  context: { department: "engineering" },
});

if (response.blocked) {
  console.log(`Blocked: ${response.blockReason}`);
} else {
  console.log(`Response: ${response.result}`);
}
```

```go
// Go
response, err := client.ExecuteQuery(
    "user-123",
    "What is AI governance?",
    "chat",
    map[string]interface{}{"department": "engineering"},
)
if response.Blocked {
    fmt.Printf("Blocked: %s\n", response.BlockReason)
} else {
    fmt.Printf("Response: %v\n", response.Result)
}
```

```python
# Python
response = await client.execute_query(
    user_token="user-123",
    query="What is AI governance?",
    request_type="chat",
    context={"department": "engineering"},
)
if response.blocked:
    print(f"Blocked: {response.block_reason}")
else:
    print(f"Response: {response.result}")
```

## Request Types

| Type | Description |
|------|-------------|
| `chat` | General chat/conversation |
| `sql` | SQL query generation |
| `multi-agent-plan` | Multi-agent workflow planning |
| `mcp-query` | MCP connector queries |

## Policy Enforcement

Same policies apply as Gateway Mode:

| Policy | What It Catches |
|--------|-----------------|
| SQL Injection | `SELECT * FROM users; DROP TABLE` |
| PII Detection | Social Security Numbers, Credit Cards |
| Prompt Injection | Attempts to override system prompts |
| RBAC | User permission violations |
| Rate Limiting | Excessive requests |

## Response Structure

```typescript
interface ClientResponse {
  success: boolean;
  data?: any;
  result?: string;
  blocked: boolean;
  blockReason?: string;
  policyInfo?: {
    policiesEvaluated: string[];
    staticChecks: string[];
    processingTime: string;
    tenantId: string;
  };
  metadata?: Record<string, any>;
  error?: string;
}
```

## Gateway vs Proxy Mode

| Feature | Gateway Mode | Proxy Mode |
|---------|--------------|------------|
| LLM API key | Your app | AxonFlow |
| LLM control | Full | Limited |
| Integration | 3 calls | 1 call |
| Latency | Lower | Higher |
| Complexity | Higher | Lower |
| Audit | Manual | Automatic |

**Choose Gateway Mode when:**
- You need full control over LLM parameters
- You want lowest possible latency
- You have specific streaming requirements

**Choose Proxy Mode when:**
- You want the simplest integration
- You don't want to manage LLM API keys
- You want automatic audit logging

## Files

```
proxy-mode/
├── typescript/
│   ├── src/index.ts
│   ├── package.json
│   ├── tsconfig.json
│   └── .env.example
├── go/
│   ├── main.go
│   ├── go.mod
│   └── .env.example
├── python/
│   ├── main.py
│   ├── requirements.txt
│   └── .env.example
└── README.md
```

## Next Steps

- [Gateway Mode](../gateway-mode/) - Lower latency, more control
- [LangChain Integration](../langchain/) - Use with LangChain
- [CrewAI Integration](../crewai/) - Multi-agent workflows
