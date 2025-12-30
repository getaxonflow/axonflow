/**
 * AxonFlow LLM Interceptor Example - TypeScript
 *
 * Demonstrates how to wrap LLM provider clients with AxonFlow governance
 * using interceptors. This provides transparent policy enforcement without
 * changing your existing LLM call patterns.
 *
 * Interceptors automatically:
 * - Pre-check queries against policies before LLM calls
 * - Block requests that violate policies
 * - Audit LLM responses for compliance tracking
 *
 * Requirements:
 *   npm install @axonflow/sdk openai
 *
 * Usage:
 *   export AXONFLOW_AGENT_URL=http://localhost:8080
 *   export OPENAI_API_KEY=your-openai-key
 *   npx ts-node src/index.ts
 */

import { AxonFlow, wrapOpenAIClient, PolicyViolationError } from '@axonflow/sdk';
import OpenAI from 'openai';

async function main() {
  console.log('AxonFlow LLM Interceptor Example - TypeScript');
  console.log('='.repeat(60));
  console.log();

  // Initialize AxonFlow client
  const axonflow = new AxonFlow({
    endpoint: process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080',
    licenseKey: process.env.AXONFLOW_LICENSE_KEY,
  });

  // Initialize OpenAI client
  const openaiClient = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
  });

  // Wrap OpenAI client with AxonFlow governance
  // All calls through this client will be policy-checked automatically
  const governedClient = wrapOpenAIClient(openaiClient, axonflow, {
    userToken: 'user-123',
  });

  console.log('Testing LLM Interceptor with OpenAI');
  console.log('-'.repeat(60));
  console.log();

  // Example 1: Safe query (should pass)
  console.log('Example 1: Safe Query');
  console.log('-'.repeat(40));
  await runTest(governedClient, 'What is the capital of France?');
  console.log();

  // Example 2: Query with PII (should be blocked by default policies)
  console.log('Example 2: Query with PII (Expected: Blocked)');
  console.log('-'.repeat(40));
  await runTest(governedClient, 'Process refund for SSN 123-45-6789');
  console.log();

  // Example 3: SQL injection attempt (should be blocked)
  console.log('Example 3: SQL Injection (Expected: Blocked)');
  console.log('-'.repeat(40));
  await runTest(governedClient, 'SELECT * FROM users WHERE 1=1; DROP TABLE users;--');
  console.log();

  console.log('='.repeat(60));
  console.log('TypeScript LLM Interceptor Test: COMPLETE');
}

async function runTest(client: OpenAI, query: string): Promise<void> {
  console.log(`Query: ${query}`);

  try {
    const response = await client.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [{ role: 'user', content: query }],
      max_tokens: 100,
    });

    console.log('Status: APPROVED');
    if (response.choices[0]?.message?.content) {
      console.log(`Response: ${response.choices[0].message.content}`);
    }
  } catch (error) {
    if (error instanceof PolicyViolationError) {
      console.log('Status: BLOCKED');
      console.log(`Reason: ${error.message}`);
    } else if (error instanceof Error) {
      console.log(`Error: ${error.message}`);
    } else {
      console.log(`Error: ${error}`);
    }
  }
}

main().catch(console.error);
