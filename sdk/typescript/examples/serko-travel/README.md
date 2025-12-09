# Serko Travel Booking Demo

This demo shows how Serko can add AxonFlow governance to their travel booking AI assistant with just 3 lines of code.

## The Challenge

Serko's AI assistant handles:
- Customer personal information (names, passport numbers, etc.)
- Payment details
- Travel preferences and history
- Corporate travel policies

Without governance, there's risk of:
- PII exposure to AI providers
- Compliance violations (GDPR, PCI-DSS)
- Cost overruns from excessive AI usage
- Data leaks from prompt injection

## The Solution

AxonFlow provides invisible governance that:
- Redacts PII before sending to AI
- Enforces corporate travel policies
- Blocks malicious prompts
- Maintains audit trail for compliance

## Integration Example

```typescript
// Before: Unprotected AI call
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{
    role: 'user',
    content: `Book a flight for John Smith, passport A12345678,
              from Auckland to Sydney on March 15th`
  }]
});

// After: With AxonFlow (3 lines added)
import { AxonFlow } from '@axonflow/sdk';
const axonflow = new AxonFlow({ apiKey: 'demo-key-serko' });

const response = await axonflow.protect(async () => {
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{
      role: 'user',
      content: `Book a flight for John Smith, passport A12345678,
                from Auckland to Sydney on March 15th`
    }]
  });
});

// AxonFlow automatically:
// - Redacts "A12345678" → "[PASSPORT_REDACTED]"
// - Logs the request for compliance
// - Enforces rate limits
// - Blocks if violates policies
```

## Running the Demo

1. Install dependencies:
```bash
npm install
```

2. Set environment variables:
```bash
export OPENAI_API_KEY=your-openai-key
export AXONFLOW_API_KEY=demo-key-serko
```

3. Run the demo:
```bash
npm start
```

## What Happens Behind the Scenes

1. **Request Interception**: AxonFlow intercepts the OpenAI call
2. **Policy Evaluation**: Checks against Serko's configured policies (9.5ms)
3. **PII Detection**: Identifies passport number, names, etc.
4. **Redaction**: Replaces sensitive data with safe placeholders
5. **Execution**: Sends sanitized request to OpenAI
6. **Response Processing**: Ensures response doesn't contain leaked PII
7. **Audit Logging**: Records everything for compliance

## 30-Day Deployment Timeline

**Week 1**: Install SDK, configure basic policies
**Week 2**: Test in development environment
**Week 3**: Staging deployment with real workflows
**Week 4**: Production rollout
**Day 30**: Full production with all policies active

No UI changes. No user training. Just invisible protection.