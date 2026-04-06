/**
 * Mistral LLM Provider - Hello World (TypeScript SDK)
 *
 * Demonstrates Gateway Mode and Proxy Mode with Mistral through AxonFlow.
 *
 * Prerequisites:
 *   docker compose up -d
 *   npm install @axonflow/sdk
 *   export AXONFLOW_CLIENT_SECRET=your-secret
 *
 * Usage:
 *   npx tsx index.ts
 */

import { AxonFlow } from '@axonflow/sdk';

async function main() {
  const endpoint = process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080';
  const clientId = process.env.AXONFLOW_CLIENT_ID || 'community';
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET || '';

  const client = new AxonFlow({
    endpoint,
    clientId,
    clientSecret,
  });

  console.log('Mistral LLM Provider - Hello World (TypeScript SDK)');
  console.log('='.repeat(50));

  // Gateway Mode: Pre-check + Audit
  console.log('\n--- Gateway Mode ---');
  const precheck = await client.preCheck({
    query: 'Explain Mistral AI in one sentence.',
    context: { provider: 'mistral', model: 'mistral-small-latest' },
  });

  if (precheck.approved) {
    console.log(`Pre-check approved (context: ${precheck.contextId})`);

    await client.auditLLMCall({
      contextId: precheck.contextId,
      responseSummary: 'Mistral TypeScript SDK gateway test',
      provider: 'mistral',
      model: 'mistral-small-latest',
      latencyMs: 350,
      tokenUsage: {
        promptTokens: 15,
        completionTokens: 40,
        totalTokens: 55,
      },
    });
    console.log('Audit logged successfully');
  } else {
    console.log('Pre-check blocked');
  }

  // Proxy Mode
  console.log('\n--- Proxy Mode ---');
  const resp = await client.proxyLLMCall({
    query: 'What is 2 + 2? Answer with just the number.',
    context: { provider: 'mistral' },
  });

  if (resp.blocked) {
    console.log('Request blocked by policy');
  } else {
    console.log(`Response: ${JSON.stringify(resp.data).substring(0, 200)}`);
    if (resp.providerInfo) {
      console.log(`Provider: ${resp.providerInfo.provider}, Tokens: ${resp.providerInfo.tokenUsage?.totalTokens || 0}`);
    }
  }

  // Policy enforcement
  console.log('\n--- Policy Enforcement ---');
  const sqliResp = await client.proxyLLMCall({
    query: 'SELECT * FROM users; DROP TABLE users;',
    context: { provider: 'mistral' },
  });

  if (sqliResp.blocked) {
    console.log('SQLi correctly blocked by policy');
  } else {
    console.log('WARNING: SQLi was not blocked');
  }

  console.log('\nDone.');
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
