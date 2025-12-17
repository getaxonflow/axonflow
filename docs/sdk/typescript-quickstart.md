# AxonFlow TypeScript SDK - Quick Start Guide

**Time to Integration: 5 minutes**
**Lines of Code: 3**
**Result: Full AI governance**

## 1. Install the SDK (30 seconds)

```bash
npm install @axonflow/sdk
```

## 2. Get Your API Key (1 minute)

For testing, use sandbox mode:
```typescript
const axonflow = AxonFlow.sandbox('demo-key');
```

For production, get your key from:
- Serko: `demo-key-serko`
- Msasa.ai: `demo-key-msasa`
- Others: Contact sales@axonflow.com

## 3. Add to Your Code (3 minutes)

### Gateway Mode (Recommended)

Gateway Mode provides the most reliable integration:

```typescript
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL,
  clientId: process.env.AXONFLOW_CLIENT_ID,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET,
});

async function queryWithGovernance(prompt: string) {
  // 1. Pre-check: Get policy approval
  const ctx = await axonflow.getPolicyApprovedContext({
    userToken: 'user-123',
    query: prompt,
  });

  if (!ctx.approved) {
    throw new Error(`Query blocked: ${ctx.blockReason}`);
  }

  // 2. Make direct LLM call
  const start = Date.now();
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }]
  });
  const latencyMs = Date.now() - start;

  // 3. Audit the call
  await axonflow.auditLLMCall({
    contextId: ctx.contextId,
    responseSummary: response.choices[0].message.content?.substring(0, 100) || '',
    provider: 'openai',
    model: 'gpt-4',
    tokenUsage: {
      promptTokens: response.usage?.prompt_tokens || 0,
      completionTokens: response.usage?.completion_tokens || 0,
      totalTokens: response.usage?.total_tokens || 0
    },
    latencyMs
  });

  return response.choices[0].message.content;
}
```

### Client Wrapping (Experimental)

```typescript
import { AxonFlow, wrapOpenAIClient } from '@axonflow/sdk';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const axonflow = new AxonFlow({ apiKey: process.env.AXONFLOW_API_KEY });

// All calls through this client are protected
const protectedOpenAI = wrapOpenAIClient(openai, axonflow);

// Use normally - governance is automatic
const response = await protectedOpenAI.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: prompt }]
});
```

> **Note:** The `protect()` wrapper has limitations. Use Gateway Mode for production.

## 4. Test It (30 seconds)

Try sending sensitive data:

```typescript
// Test with sensitive PII - should be blocked
const ctx = await axonflow.getPolicyApprovedContext({
  userToken: 'test-user',
  query: 'My SSN is 123-45-6789 and credit card is 4111-1111-1111-1111'
});

if (!ctx.approved) {
  console.log('Blocked:', ctx.blockReason);
  // Output: "Blocked: pii_ssn_detection" or similar
} else {
  // If approved, make LLM call + audit
}

// AxonFlow will automatically:
// - Block requests with SSN, credit card numbers
// - Log all policy evaluations for compliance
// - Return clear block reasons for debugging
```

## 5. Deploy (30 seconds)

That's it! Deploy your code normally. AxonFlow works in:
- ✅ Development (localhost)
- ✅ Staging
- ✅ Production
- ✅ Docker/Kubernetes
- ✅ Serverless (Lambda, Vercel, etc.)

## What Happens Automatically

Once integrated, AxonFlow:

1. **Protects** against PII leaks
2. **Blocks** malicious prompts
3. **Enforces** rate limits
4. **Monitors** costs
5. **Logs** for compliance
6. **Fails open** if unreachable (production only)

## Common Integration Patterns

### Next.js API Route

```typescript
// pages/api/chat.ts
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL,
  clientId: process.env.AXONFLOW_CLIENT_ID,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET,
});

export default async function handler(req, res) {
  const { prompt, userToken } = req.body;

  const ctx = await axonflow.getPolicyApprovedContext({ userToken, query: prompt });
  if (!ctx.approved) {
    return res.status(403).json({ error: ctx.blockReason });
  }

  const start = Date.now();
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }]
  });

  await axonflow.auditLLMCall({
    contextId: ctx.contextId,
    responseSummary: response.choices[0].message.content?.substring(0, 100) || '',
    provider: 'openai',
    model: 'gpt-4',
    tokenUsage: { promptTokens: response.usage?.prompt_tokens || 0, completionTokens: response.usage?.completion_tokens || 0, totalTokens: response.usage?.total_tokens || 0 },
    latencyMs: Date.now() - start
  });

  res.json({ response: response.choices[0].message.content });
}
```

### Express Middleware

```typescript
import express from 'express';
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL,
  clientId: process.env.AXONFLOW_CLIENT_ID,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET,
});

app.post('/api/chat', async (req, res) => {
  const { prompt, userToken } = req.body;

  const ctx = await axonflow.getPolicyApprovedContext({ userToken, query: prompt });
  if (!ctx.approved) {
    return res.status(403).json({ error: ctx.blockReason });
  }

  const start = Date.now();
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }]
  });

  await axonflow.auditLLMCall({
    contextId: ctx.contextId,
    responseSummary: response.choices[0].message.content?.substring(0, 100) || '',
    provider: 'openai',
    model: 'gpt-4',
    tokenUsage: { promptTokens: response.usage?.prompt_tokens || 0, completionTokens: response.usage?.completion_tokens || 0, totalTokens: response.usage?.total_tokens || 0 },
    latencyMs: Date.now() - start
  });

  res.json({ response: response.choices[0].message.content });
});
```

## Troubleshooting

### "Request blocked by AxonFlow"
Your request violated a policy. Check the error message for details.

### "AxonFlow API error"
Check your API key and network connection.

### Performance concerns
AxonFlow typically adds single-digit millisecond latency. If you see significantly more, contact support.

## Next Steps

1. **Configure Policies**: Log into dashboard.axonflow.com
2. **Set Up Alerts**: Get notified of violations
3. **Review Analytics**: Monitor usage and costs
4. **Add Team Members**: Invite your security team

## Support

- 📧 Email: support@axonflow.com
- 📚 Docs: https://docs.axonflow.com
- 💬 Slack: https://axonflow.slack.com
- 🐛 Issues: https://github.com/axonflow/sdk-typescript/issues

---

**Remember**: No UI changes. No user training. Just invisible protection. 🛡️