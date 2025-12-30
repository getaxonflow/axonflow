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
| Go | [go/](./go/) | v1.8.0 |
| Python | [python/](./python/) | v0.5.0 |
| Java | [java/](./java/) | v1.3.1 |
| TypeScript | [typescript/](./typescript/) | v1.6.0 |

## Quick Start

### TypeScript

```typescript
import { AxonFlow, wrapOpenAIClient } from '@axonflow/sdk';
import OpenAI from 'openai';

const axonflow = new AxonFlow({
  endpoint: 'http://localhost:8080',
});

const openai = new OpenAI();
const governedClient = wrapOpenAIClient(openai, axonflow, {
  userToken: 'user-123',
});

// All calls through governedClient are policy-checked
const response = await governedClient.chat.completions.create({
  model: 'gpt-3.5-turbo',
  messages: [{ role: 'user', content: 'Hello!' }],
});
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
