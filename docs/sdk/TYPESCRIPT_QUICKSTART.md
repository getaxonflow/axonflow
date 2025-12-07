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

### Option A: Wrap Individual Calls

```typescript
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const axonflow = new AxonFlow({ apiKey: process.env.AXONFLOW_API_KEY });

// Wrap your AI call with protect()
const response = await axonflow.protect(async () => {
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }]
  });
});
```

### Option B: Wrap the Entire Client

```typescript
import { AxonFlow, wrapOpenAIClient } from '@axonflow/sdk';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const axonflow = new AxonFlow({ apiKey: process.env.AXONFLOW_API_KEY });

// All calls through this client are now protected
const protectedOpenAI = wrapOpenAIClient(openai, axonflow);

// Use normally - governance is invisible
const response = await protectedOpenAI.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: prompt }]
});
```

## 4. Test It (30 seconds)

Try sending sensitive data:

```typescript
const response = await axonflow.protect(async () => {
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{
      role: 'user',
      content: 'My SSN is 123-45-6789 and credit card is 4111-1111-1111-1111'
    }]
  });
});

// AxonFlow will automatically:
// - Redact SSN → [SSN_REDACTED]
// - Redact credit card → [CARD_REDACTED]
// - Log for compliance
// - Continue the request safely
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

### React Component

```tsx
function ChatComponent() {
  const axonflow = new AxonFlow({ apiKey: 'your-key' });

  const handleSubmit = async (prompt: string) => {
    const response = await axonflow.protect(() =>
      fetch('/api/chat', {
        method: 'POST',
        body: JSON.stringify({ prompt })
      }).then(r => r.json())
    );

    return response;
  };
}
```

### Next.js API Route

```typescript
// pages/api/chat.ts
import { AxonFlow } from '@axonflow/sdk';

const axonflow = new AxonFlow({ apiKey: process.env.AXONFLOW_API_KEY });

export default async function handler(req, res) {
  const response = await axonflow.protect(() =>
    openai.chat.completions.create({
      model: 'gpt-4',
      messages: req.body.messages
    })
  );

  res.json(response);
}
```

### Express Middleware

```typescript
import { AxonFlow } from '@axonflow/sdk';

const axonflow = new AxonFlow({ apiKey: process.env.AXONFLOW_API_KEY });

app.post('/api/chat', async (req, res) => {
  try {
    const response = await axonflow.protect(() =>
      openai.chat.completions.create(req.body)
    );
    res.json(response);
  } catch (error) {
    res.status(403).json({ error: error.message });
  }
});
```

## Troubleshooting

### "Request blocked by AxonFlow"
Your request violated a policy. Check the error message for details.

### "AxonFlow API error"
Check your API key and network connection.

### Performance concerns
AxonFlow adds <10ms latency (9.5ms P99). If you see more, contact support.

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