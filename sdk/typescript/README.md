# AxonFlow SDK for TypeScript

Add invisible AI governance to your applications in 3 lines of code. No UI changes. No user training. Just drop-in enterprise protection.

## Installation

```bash
npm install @axonflow/sdk
```

## Quick Start

### Basic Usage

```typescript
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

// Initialize your AI client as usual
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Add AxonFlow governance (3 lines)
const axonflow = new AxonFlow({ apiKey: process.env.AXONFLOW_API_KEY });

// Wrap any AI call with protect()
const response = await axonflow.protect(async () => {
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: 'Process this customer data...' }]
  });
});
```

### Even Easier with Client Wrapping

```typescript
import { AxonFlow, wrapOpenAIClient } from '@axonflow/sdk';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const axonflow = new AxonFlow({ apiKey: process.env.AXONFLOW_API_KEY });

// Wrap the entire client - all calls are now protected
const protectedOpenAI = wrapOpenAIClient(openai, axonflow);

// Use normally - governance happens invisibly
const response = await protectedOpenAI.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Process this customer data...' }]
});
```

## React Example

```tsx
import { AxonFlow } from '@axonflow/sdk';
import { useState } from 'react';

const axonflow = new AxonFlow({ apiKey: 'your-key' });

function ChatComponent() {
  const [response, setResponse] = useState('');

  const handleSubmit = async (prompt: string) => {
    // Your existing OpenAI call, now protected
    const result = await axonflow.protect(async () => {
      return fetch('/api/openai', {
        method: 'POST',
        body: JSON.stringify({ prompt })
      }).then(r => r.json());
    });

    setResponse(result.text);
  };

  return (
    // Your existing UI - no changes needed
    <div>...</div>
  );
}
```

## Next.js API Route

```typescript
// pages/api/chat.ts
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const axonflow = new AxonFlow({ apiKey: process.env.AXONFLOW_API_KEY });

export default async function handler(req, res) {
  const { prompt } = req.body;

  try {
    // Protect the OpenAI call
    const response = await axonflow.protect(async () => {
      return openai.chat.completions.create({
        model: 'gpt-3.5-turbo',
        messages: [{ role: 'user', content: prompt }]
      });
    });

    res.json({ success: true, response });
  } catch (error) {
    // AxonFlow will block requests that violate policies
    res.status(403).json({ error: error.message });
  }
}
```

## Configuration Options

```typescript
const axonflow = new AxonFlow({
  apiKey: 'your-api-key',           // Required (use client_id from AxonFlow)

  // Optional settings
  mode: 'production',                // or 'sandbox' for testing
  endpoint: 'https://staging-eu.getaxonflow.com', // Default public endpoint
  tenant: 'your-tenant-id',         // For multi-tenant setups (use client_id)
  debug: true,                       // Enable debug logging

  // Retry configuration
  retry: {
    enabled: true,
    maxAttempts: 3,
    delay: 1000
  },

  // Cache configuration
  cache: {
    enabled: true,
    ttl: 60000  // 1 minute
  }
});
```

### VPC Private Endpoint (Low-Latency)

For customers running within AWS VPC, use the private endpoint for sub-10ms latency:

```typescript
const axonflow = new AxonFlow({
  apiKey: 'your-client-id',
  endpoint: 'https://10.0.2.67:8443',  // VPC private endpoint (EU)
  tenant: 'your-client-id',
  mode: 'production'
});
```

**Performance:**
- Public endpoint: ~100ms (internet routing)
- VPC private endpoint: <10ms P99 (intra-VPC routing)

**Note:** VPC endpoints require AWS VPC peering setup with AxonFlow infrastructure.

## Sandbox Mode (Testing)

```typescript
// Use sandbox mode for testing without affecting production
const axonflow = AxonFlow.sandbox('demo-key');

// Test with aggressive policies
const response = await axonflow.protect(async () => {
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{
      role: 'user',
      content: 'My SSN is 123-45-6789' // Will be blocked/redacted
    }]
  });
});
```

## What Gets Protected?

AxonFlow automatically:
- **Blocks** prompts containing sensitive data (PII, credentials, etc.)
- **Redacts** personal information from responses
- **Enforces** rate limits and usage quotas
- **Prevents** prompt injection attacks
- **Logs** all requests for compliance audit trails
- **Monitors** costs and usage patterns

## Error Handling

```typescript
try {
  const response = await axonflow.protect(() => openai.complete(prompt));
} catch (error) {
  if (error.message.includes('blocked by AxonFlow')) {
    // Request violated a policy
    console.log('Policy violation:', error.message);
  } else {
    // Other errors (network, API, etc.)
    console.error('API error:', error);
  }
}
```

## Production Best Practices

1. **Environment Variables**: Never hardcode API keys
   ```typescript
   const axonflow = new AxonFlow({
     apiKey: process.env.AXONFLOW_API_KEY
   });
   ```

2. **Fail Open**: In production, AxonFlow fails open if unreachable
   ```typescript
   // If AxonFlow is down, the original call proceeds
   // This ensures your app stays operational
   ```

3. **Tenant Isolation**: Use tenant IDs for multi-tenant apps
   ```typescript
   const axonflow = new AxonFlow({
     apiKey: 'your-key',
     tenant: getCurrentTenantId()
   });
   ```

## Support

- Documentation: https://docs.axonflow.com
- Email: support@axonflow.com
- GitHub: https://github.com/axonflow/sdk-typescript

## MCP Connector Marketplace

Integrate with external data sources using AxonFlow's MCP (Model Context Protocol) connectors:

### List Available Connectors

```typescript
const connectors = await axonflow.listConnectors();

connectors.forEach(conn => {
  console.log(`Connector: ${conn.name} (${conn.type})`);
  console.log(`  Description: ${conn.description}`);
  console.log(`  Installed: ${conn.installed}`);
  console.log(`  Capabilities: ${conn.capabilities.join(', ')}`);
});
```

### Install a Connector

```typescript
await axonflow.installConnector({
  connector_id: 'amadeus-travel',
  name: 'amadeus-prod',
  tenant_id: 'your-tenant-id',
  options: {
    environment: 'production'
  },
  credentials: {
    api_key: process.env.AMADEUS_API_KEY,
    api_secret: process.env.AMADEUS_API_SECRET
  }
});

console.log('Connector installed successfully!');
```

### Query a Connector

```typescript
// Query the Amadeus connector for flight information
const resp = await axonflow.queryConnector(
  'amadeus-prod',
  'Find flights from Paris to Amsterdam on Dec 15',
  {
    origin: 'CDG',
    destination: 'AMS',
    date: '2025-12-15'
  }
);

if (resp.success) {
  console.log('Flight data:', resp.data);
} else {
  console.error('Query failed:', resp.error);
}
```

## Multi-Agent Planning (MAP)

Generate and execute complex multi-step plans using AI agent orchestration:

### Generate a Plan

```typescript
// Generate a travel planning workflow
const plan = await axonflow.generatePlan(
  'Plan a 3-day trip to Paris with moderate budget',
  'travel'  // Domain hint (optional)
);

console.log(`Generated plan ${plan.planId} with ${plan.steps.length} steps`);
console.log(`Complexity: ${plan.complexity}, Parallel: ${plan.parallel}`);

plan.steps.forEach((step, i) => {
  console.log(`  Step ${i + 1}: ${step.name} (${step.type})`);
  console.log(`    Description: ${step.description}`);
  console.log(`    Agent: ${step.agent}`);
  if (step.dependsOn.length > 0) {
    console.log(`    Depends on: ${step.dependsOn.join(', ')}`);
  }
});
```

### Execute a Plan

```typescript
// Execute the generated plan
const execResp = await axonflow.executePlan(plan.planId);

console.log(`Plan Status: ${execResp.status}`);
console.log(`Duration: ${execResp.duration}`);

if (execResp.status === 'completed') {
  console.log(`Result:\n${execResp.result}`);

  // Access individual step results
  Object.entries(execResp.stepResults || {}).forEach(([stepId, result]) => {
    console.log(`  ${stepId}:`, result);
  });
} else if (execResp.status === 'failed') {
  console.error(`Error: ${execResp.error}`);
}
```

### Check Plan Status

```typescript
// For long-running plans, check status periodically
const status = await axonflow.getPlanStatus(plan.planId);

console.log(`Plan Status: ${status.status}`);
if (status.status === 'running') {
  console.log('Plan is still executing...');
}
```

### Complete Example: Trip Planning with MAP

```typescript
import { AxonFlow } from '@axonflow/sdk';

async function planTrip() {
  // Initialize client
  const axonflow = new AxonFlow({
    apiKey: process.env.AXONFLOW_API_KEY,
    debug: true
  });

  // 1. Generate multi-agent plan
  const plan = await axonflow.generatePlan(
    'Plan a 3-day trip to Paris for 2 people with moderate budget',
    'travel'
  );

  console.log(`✅ Generated plan with ${plan.steps.length} steps (parallel: ${plan.parallel})`);

  // 2. Execute the plan
  console.log('\n🚀 Executing plan...');
  const execResp = await axonflow.executePlan(plan.planId);

  // 3. Display results
  if (execResp.status === 'completed') {
    console.log(`\n✅ Plan completed in ${execResp.duration}`);
    console.log(`\n📋 Complete Itinerary:\n${execResp.result}`);
  } else {
    console.error(`\n❌ Plan failed: ${execResp.error}`);
  }
}

planTrip().catch(console.error);
```

## License

MIT