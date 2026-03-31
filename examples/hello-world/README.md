# Hello World - AxonFlow

**The simplest AxonFlow example** - Get started in 5 minutes.

---

## Overview

This is the absolute minimum code needed to use AxonFlow. Perfect for:
- Learning the basics
- Testing your local AxonFlow deployment
- Understanding the request/response flow
- Verifying connectivity

**Time to complete:** 5 minutes
**Lines of code:** ~20 lines
**Prerequisites:** AxonFlow running locally (`docker compose up -d`)

---

## What It Does

1. Connects to your local AxonFlow agent
2. Sends a query through the governance layer
3. AxonFlow enforces policies (PII detection, rate limits, etc.)
4. Returns the response with audit metadata

---

## Quick Start

Make sure AxonFlow is running:

```bash
# From the repo root
docker compose ps   # Should show services as "healthy"
```

Then run any example:

### TypeScript

```bash
cd typescript
npm install
AGENT_URL=http://localhost:8080 npm start
```

### Python

```bash
cd python
pip install -r requirements.txt
AGENT_URL=http://localhost:8080 python main.py
```

### Go

```bash
cd go
AGENT_URL=http://localhost:8080 go run main.go
```

### Java

```bash
cd java
mvn compile exec:java
```

### HTTP (curl)

```bash
cd http
./hello-world.sh
```

---

## Code Examples

### TypeScript

```typescript
import { AxonFlow } from '@axonflow/sdk';

const ax = new AxonFlow({
  endpoint: process.env.AGENT_URL || 'http://localhost:8080'
});

async function main() {
  // Gateway Mode: Pre-check → Your LLM call → Audit
  const approval = await ax.preCheck({
    query: 'What is the capital of France?',
    userToken: 'demo-user',
    clientId: 'hello-world'
  });

  console.log('Approved:', approval.approved);
  console.log('Context ID:', approval.contextId);

  if (approval.approved) {
    // Make your LLM call here, then audit it
    await ax.audit({
      contextId: approval.contextId,
      model: 'gpt-4',
      success: true
    });
  }
}

main();
```

### Python

```python
import asyncio
from axonflow import AxonFlow

async def main():
    async with AxonFlow(endpoint="http://localhost:8080") as ax:
        # Gateway Mode: Pre-check → Your LLM call → Audit
        approval = await ax.pre_check(
            query="What is the capital of France?",
            user_token="demo-user",
            client_id="hello-world"
        )

        print(f"Approved: {approval.approved}")
        print(f"Context ID: {approval.context_id}")

        if approval.approved:
            # Make your LLM call here, then audit it
            await ax.audit(
                context_id=approval.context_id,
                model="gpt-4",
                success=True
            )

asyncio.run(main())
```

### Go

```go
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
    agentURL := os.Getenv("AGENT_URL")
    if agentURL == "" {
        agentURL = "http://localhost:8080"
    }

    client := axonflow.NewClient(agentURL)

    // Gateway Mode: Pre-check → Your LLM call → Audit
    approval, err := client.PreCheck(context.Background(), axonflow.PreCheckRequest{
        Query:     "What is the capital of France?",
        UserToken: "demo-user",
        ClientID:  "hello-world",
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("Approved:", approval.Approved)
    fmt.Println("Context ID:", approval.ContextID)
}
```

### HTTP (curl)

```bash
# Pre-check a query
curl -X POST http://localhost:8080/api/policy/pre-check \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What is the capital of France?",
    "user_token": "demo-user",
    "client_id": "hello-world"
  }'
```

---

## Expected Output

```json
{
  "approved": true,
  "context_id": "ctx_abc123",
  "policies_evaluated": ["pii_detection", "rate_limiting"],
  "latency_ms": 4
}
```

**Performance:** Policy evaluation typically takes 3-5ms.

---

## What Happens Under the Hood

```
1. Client sends query to Agent (:8080)
   ↓
2. Agent evaluates static policies (PII, SQLi, rate limits)
   ↓
3. Policy returns "approved: true"
   ↓
4. Agent returns context_id for audit tracking
   ↓
5. You make your LLM call (with your own client)
   ↓
6. You call audit() to complete the request lifecycle
   ↓
7. Audit log written to PostgreSQL
```

---

## Troubleshooting

### Connection Refused

```
Error: connect ECONNREFUSED 127.0.0.1:8080
```

**Solution:** Make sure AxonFlow is running:
```bash
docker compose ps        # Check status
docker compose up -d     # Start if needed
docker compose logs -f agent  # Check logs
```

### Services Not Healthy

```bash
# Wait for services to be healthy (~30 seconds after start)
docker compose ps

# If stuck, check logs
docker compose logs agent orchestrator
```

---

## Next Steps

- **[Support Demo](../support-demo/)** - Real-world customer support example with PII detection
- **[PII Detection](../pii-detection/)** - See how AxonFlow blocks sensitive data
- **[Gateway vs Proxy Mode](https://docs.getaxonflow.com/docs/sdk/choosing-a-mode/)** - Choose your integration pattern

---

## Files in This Example

```
hello-world/
├── README.md           # This file
├── go/
│   ├── go.mod
│   └── main.go
├── python/
│   ├── requirements.txt
│   └── main.py
├── typescript/
│   ├── package.json
│   └── index.ts
├── java/
│   ├── pom.xml
│   └── src/main/java/...
└── http/
    └── hello-world.sh
```
