# LLM Interceptors

AxonFlow interceptors wrap LLM provider clients (like OpenAI) with governance,
providing transparent policy enforcement without changing your existing code patterns.

## Features

- **Pre-check queries** against policies before LLM calls
- **Block requests** that violate policies
- **Audit responses** for compliance tracking
- **Transparent integration** - minimal code changes required

## Available Languages

| Language | Directory | SDK Version |
|----------|-----------|-------------|
| Go | [go/](./go/) | v1.14.0 |
| Python | [python/](./python/) | v0.10.1 |
| Java | [java/](./java/) | v1.8.0 |
| TypeScript | [typescript/](./typescript/) | v1.11.1 |

## Quick Start

### TypeScript (Gateway Mode - Recommended)

```typescript
import { AxonFlow, PolicyViolationError } from '@axonflow/sdk';
import OpenAI from 'openai';

const axonflow = new AxonFlow({ endpoint: 'http://localhost:8080' });
const openai = new OpenAI();

async function governedCall(query: string) {
  // Step 1: Pre-check policies
  const ctx = await axonflow.getPolicyApprovedContext({
    userToken: 'user-123',
    query,
  });

  if (!ctx.approved) {
    throw new PolicyViolationError(ctx.blockReason, ctx.policies?.[0]);
  }

  // Step 2: Make LLM call
  const response = await openai.chat.completions.create({
    model: 'gpt-3.5-turbo',
    messages: [{ role: 'user', content: query }],
  });

  // Step 3: Audit
  await axonflow.auditLLMCall({
    contextId: ctx.contextId,
    responseSummary: response.choices[0]?.message?.content?.substring(0, 100),
    provider: 'openai',
    model: 'gpt-3.5-turbo',
    tokenUsage: {
      promptTokens: response.usage?.prompt_tokens || 0,
      completionTokens: response.usage?.completion_tokens || 0,
      totalTokens: response.usage?.total_tokens || 0,
    },
    latencyMs: 250,
  });

  return response;
}
```

### Python

```python
from axonflow import AxonFlow
from axonflow.interceptors.openai import wrap_openai_client
from openai import OpenAI

axonflow = AxonFlow(agent_url="http://localhost:8080")
openai_client = OpenAI()
governed_client = wrap_openai_client(openai_client, axonflow, user_token="user-123")

# All calls through governed_client are policy-checked
response = governed_client.chat.completions.create(
    model="gpt-3.5-turbo",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

### Go

```go
import (
    axonflow "github.com/getaxonflow/axonflow-sdk-go"
    "github.com/getaxonflow/axonflow-sdk-go/interceptors"
)

client := axonflow.NewClient(axonflow.AxonFlowConfig{
    AgentURL: "http://localhost:8080",
})

wrappedCall := interceptors.WrapOpenAIFunc(openAICall, client, "user-123")

// All calls through wrappedCall are policy-checked
response, err := wrappedCall(ctx, req)
```

## Running Examples

Each example demonstrates:
1. Safe query (allowed through)
2. PII query (blocked by default policies)
3. SQL injection (blocked by security policies)

```bash
# Set environment variables
export AXONFLOW_AGENT_URL=http://localhost:8080
export OPENAI_API_KEY=your-key

# Run TypeScript
cd typescript && npm install && npm start

# Run Python
cd python && pip install -r requirements.txt && python main.py

# Run Go
cd go && go run main.go

# Run Java
cd java && mvn compile exec:java
```
