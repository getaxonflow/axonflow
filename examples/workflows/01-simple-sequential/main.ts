/**
 * Example 1: Simple Sequential Workflow - TypeScript
 *
 * This example shows the most basic AxonFlow workflow: send a query to an LLM and get a response.
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow } from '@axonflow/sdk';

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

async function main() {
  // Get AxonFlow configuration from environment
  const agentUrl = process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080';
  const clientId = process.env.AXONFLOW_CLIENT_ID;
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    console.error('AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set');
    process.exit(1);
  }

  // Create AxonFlow client
  const client = new AxonFlow({
    endpoint: agentUrl,
    clientId,
    clientSecret,
  });

  console.log('Connected to AxonFlow');

  // Define a simple query
  const query = 'What is the capital of France?';
  console.log(`Sending query: ${query}`);

  try {
    // Send query to AxonFlow
    const response = await client.proxyLLMCall({
      userToken: 'user-123',
      query: query,
      requestType: 'chat',
      context: {
        model: 'gpt-4',
      },
    });

    // Print response
    console.log(`Response: ${JSON.stringify(response.data)}`);

    // Assertions - validate actual response structure and content
    console.log('\n--- Assertions ---');
    assertCheck(response !== null && response !== undefined, 'Response object exists');
    assertCheck(response.data !== null && response.data !== undefined, 'Response has data field');
    assertCheck(!response.blocked, 'Response is not blocked');
    assertCheck(
      response.blocked === false || response.blockReason === undefined || response.blockReason === '',
      'No block reason when not blocked'
    );

    // Validate response content contains expected answer
    const responseText = JSON.stringify(response.data).toLowerCase();
    assertCheck(
      responseText.includes('paris') || responseText.includes('france'),
      'Response mentions Paris or France (expected answer)'
    );

    // Validate response metadata
    assertCheck(
      response.requestId !== undefined && response.requestId !== '',
      'Response has a request ID for tracing'
    );

    console.log('\nWorkflow completed successfully');
  } catch (error) {
    console.error(`Query failed: ${error}`);
    process.exit(1);
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
