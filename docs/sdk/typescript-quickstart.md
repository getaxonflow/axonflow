# AxonFlow TypeScript SDK -- Quick Start Guide

**Last Updated:** February 2026

**SDK Version:** v3.2.0 | **Platform Version:** v4.1.0

---

## Prerequisites

- **Node.js 18+** (uses native `fetch`)
- An AxonFlow Agent running (locally via Docker or a remote deployment)
- Your `clientId` and `clientSecret` credentials (for enterprise deployments)

## 1. Install the SDK

```bash
npm install @axonflow/sdk
```

> **Note:** The published npm version is v2.3.0. The SDK source is at v3.2.0. To use v3.2.0 features (dynamic policy tiers, unified execution, etc.), build from source:
>
> ```bash
> git clone https://github.com/getaxonflow/axonflow-sdk-typescript.git
> cd axonflow-sdk-typescript
> npm install && npm run build && npm link
> # Then in your project:
> npm link @axonflow/sdk
> ```

## 2. Configure the Client

```typescript
import { AxonFlow } from '@axonflow/sdk';

const client = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT,       // e.g., "http://localhost:8080"
  clientId: process.env.AXONFLOW_CLIENT_ID,       // Your organization ID
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET, // Your license key
});
```

For Community Edition (self-hosted without authentication):

```typescript
const client = new AxonFlow({
  endpoint: 'http://localhost:8080',
});
```

## 3. Choose an Integration Mode

The SDK supports two modes. Pick the one that fits your architecture.

### Proxy Mode (Recommended for New Projects)

AxonFlow handles policy enforcement **and** LLM routing. Your application sends queries to AxonFlow, which forwards them to the configured LLM provider.

```typescript
import { AxonFlow, PolicyViolationError } from '@axonflow/sdk';

const client = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT,
  clientId: process.env.AXONFLOW_CLIENT_ID,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET,
});

async function chat(userMessage: string) {
  try {
    const response = await client.proxyLLMCall({
      userToken: 'user-123',
      query: userMessage,
      requestType: 'chat',
    });

    if (response.success) {
      console.log('Response:', response.data);
      console.log('Policies evaluated:', response.policyInfo?.policiesEvaluated);
    }
  } catch (error) {
    if (error instanceof PolicyViolationError) {
      console.error('Blocked by policy:', error.blockReason);
    } else {
      throw error;
    }
  }
}

await chat('What is the capital of France?');
```

### Gateway Mode (For Existing LLM Integrations)

Your application makes direct LLM calls. AxonFlow provides pre-call policy checks and post-call audit logging. This is ideal when you already have LangChain, CrewAI, or direct OpenAI/Anthropic integrations.

```typescript
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const client = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT,
  clientId: process.env.AXONFLOW_CLIENT_ID,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET,
});

async function chatWithGovernance(prompt: string) {
  // Step 1: Pre-check -- get policy approval
  const ctx = await client.getPolicyApprovedContext({
    userToken: 'user-123',
    query: prompt,
  });

  if (!ctx.approved) {
    throw new Error(`Query blocked: ${ctx.blockReason}`);
  }

  // Step 2: Make your own LLM call
  const start = Date.now();
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }],
  });
  const latencyMs = Date.now() - start;

  // Step 3: Audit the call
  await client.auditLLMCall({
    contextId: ctx.contextId,
    responseSummary: response.choices[0].message.content?.substring(0, 100) || '',
    provider: 'openai',
    model: 'gpt-4',
    tokenUsage: {
      promptTokens: response.usage?.prompt_tokens || 0,
      completionTokens: response.usage?.completion_tokens || 0,
      totalTokens: response.usage?.total_tokens || 0,
    },
    latencyMs,
  });

  return response.choices[0].message.content;
}
```

## 4. Test Policy Enforcement

Send a query that contains PII to verify that policies are working:

```typescript
// Proxy Mode -- PII is detected and handled by the Agent
try {
  const response = await client.proxyLLMCall({
    userToken: 'test-user',
    query: 'My SSN is 123-45-6789 and credit card is 4111-1111-1111-1111',
    requestType: 'chat',
  });

  // If PII_ACTION=redact (default), the response is processed with PII redacted
  console.log('Success:', response.success);
  console.log('Policies evaluated:', response.policyInfo?.policiesEvaluated);
} catch (error) {
  // If PII_ACTION=block, a PolicyViolationError is thrown
  if (error instanceof PolicyViolationError) {
    console.log('Blocked:', error.blockReason);
    console.log('Policies:', error.policies);
  }
}
```

```typescript
// Gateway Mode -- pre-check catches PII before LLM call
const ctx = await client.getPolicyApprovedContext({
  userToken: 'test-user',
  query: 'My SSN is 123-45-6789 and credit card is 4111-1111-1111-1111',
});

if (ctx.requiresRedaction) {
  console.log('PII detected, will be redacted:', ctx.policies);
}

if (!ctx.approved) {
  console.log('Blocked:', ctx.blockReason);
}
```

## 5. Verify Health

```typescript
const health = await client.healthCheck();
console.log('Agent status:', health.status);
// Output: "healthy", "degraded", or "unhealthy"

const orchHealth = await client.orchestratorHealthCheck();
console.log('Orchestrator status:', orchHealth.status);
```

## Common Integration Patterns

### Next.js API Route

```typescript
// app/api/chat/route.ts (App Router)
import { AxonFlow, PolicyViolationError } from '@axonflow/sdk';
import { NextResponse } from 'next/server';

const client = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT!,
  clientId: process.env.AXONFLOW_CLIENT_ID!,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET!,
});

export async function POST(request: Request) {
  const { prompt, userToken } = await request.json();

  try {
    const response = await client.proxyLLMCall({
      userToken,
      query: prompt,
      requestType: 'chat',
    });

    return NextResponse.json({ response: response.data });
  } catch (error) {
    if (error instanceof PolicyViolationError) {
      return NextResponse.json(
        { error: error.blockReason },
        { status: 403 }
      );
    }
    throw error;
  }
}
```

### Express Middleware

```typescript
import express from 'express';
import { AxonFlow, PolicyViolationError } from '@axonflow/sdk';

const app = express();
app.use(express.json());

const client = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT!,
  clientId: process.env.AXONFLOW_CLIENT_ID!,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET!,
});

app.post('/api/chat', async (req, res) => {
  const { prompt, userToken } = req.body;

  try {
    const response = await client.proxyLLMCall({
      userToken,
      query: prompt,
      requestType: 'chat',
    });

    res.json({ response: response.data });
  } catch (error) {
    if (error instanceof PolicyViolationError) {
      return res.status(403).json({ error: error.blockReason });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(3000);
```

### Gateway Mode with Express

```typescript
import express from 'express';
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

const app = express();
app.use(express.json());

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const client = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT!,
  clientId: process.env.AXONFLOW_CLIENT_ID!,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET!,
});

app.post('/api/chat', async (req, res) => {
  const { prompt, userToken } = req.body;

  const ctx = await client.getPolicyApprovedContext({ userToken, query: prompt });
  if (!ctx.approved) {
    return res.status(403).json({ error: ctx.blockReason });
  }

  const start = Date.now();
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }],
  });

  await client.auditLLMCall({
    contextId: ctx.contextId,
    responseSummary: response.choices[0].message.content?.substring(0, 100) || '',
    provider: 'openai',
    model: 'gpt-4',
    tokenUsage: {
      promptTokens: response.usage?.prompt_tokens || 0,
      completionTokens: response.usage?.completion_tokens || 0,
      totalTokens: response.usage?.total_tokens || 0,
    },
    latencyMs: Date.now() - start,
  });

  res.json({ response: response.choices[0].message.content });
});

app.listen(3000);
```

## Environment Variables

Set these in your `.env` file or deployment configuration:

| Variable | Description | Example |
|----------|-------------|---------|
| `AXONFLOW_ENDPOINT` | AxonFlow Agent URL | `http://localhost:8080` |
| `AXONFLOW_CLIENT_ID` | Organization/client identifier | `my-org` |
| `AXONFLOW_CLIENT_SECRET` | License key | `your-license-key` |
| `OPENAI_API_KEY` | LLM API key (Gateway Mode only) | `sk-...` |

## Troubleshooting

### "Request blocked by policy"

Your query triggered a policy violation. The `PolicyViolationError` contains `blockReason` and `policies` properties to identify which policy was triggered. Adjust your query or update your policies via the Orchestrator API.

### "Authentication failed"

Verify your `clientId` and `clientSecret` values. The SDK sends them as an `Authorization: Basic` header. For Community Edition deployments without authentication, omit both fields.

### Connection errors

Ensure the AxonFlow Agent is running and reachable at the configured `endpoint`. Test with:

```typescript
try {
  const health = await client.healthCheck();
  console.log('Agent is', health.status);
} catch (error) {
  console.error('Cannot reach Agent:', error.message);
}
```

### Timeout errors

The default timeout is 30 seconds. For Multi-Agent Planning (MAP) operations, the default is 120 seconds. Adjust via the `timeout` and `mapTimeout` config options:

```typescript
const client = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT,
  clientId: process.env.AXONFLOW_CLIENT_ID,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET,
  timeout: 60000,       // 60 seconds for standard requests
  mapTimeout: 300000,   // 5 minutes for MAP operations
});
```

## Deployment

The SDK works in any Node.js 18+ environment:

- Local development (localhost)
- Docker / Kubernetes
- Serverless (AWS Lambda, Vercel, etc.)
- Staging and production environments

No special deployment configuration is needed. All configuration is passed through the `AxonFlowConfig` constructor.

## Next Steps

- **Configure policies** using the [Policy Management API](typescript-specification.md#policy-management)
- **Set up Multi-Agent Planning** for complex multi-step workflows
- **Add cost controls** with budgets and usage tracking
- **Review audit logs** for compliance reporting

## Support

- Documentation: [https://docs.getaxonflow.com](https://docs.getaxonflow.com)
- Issues: [https://github.com/getaxonflow/axonflow-sdk-typescript/issues](https://github.com/getaxonflow/axonflow-sdk-typescript/issues)
- Email: support@axonflow.com

---

*For the full API reference, see [TypeScript Specification](typescript-specification.md). For architecture details, see [TypeScript Architecture](typescript-architecture.md).*
