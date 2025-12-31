/**
 * Example 1: Simple Sequential Workflow - TypeScript
 *
 * This example shows the most basic AxonFlow workflow: send a query to an LLM and get a response.
 */

import { AxonFlow } from '@axonflow/sdk';

async function main() {
  // Get AxonFlow configuration from environment
  const agentUrl = process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080';
  const licenseKey = process.env.AXONFLOW_LICENSE_KEY;

  if (!licenseKey) {
    console.error('❌ AXONFLOW_LICENSE_KEY must be set');
    process.exit(1);
  }

  // Create AxonFlow client
  const client = new AxonFlow({
    endpoint: agentUrl,
    licenseKey: licenseKey,
  });

  console.log('✅ Connected to AxonFlow');

  // Define a simple query
  const query = 'What is the capital of France?';
  console.log(`📤 Sending query: ${query}`);

  try {
    // Send query to AxonFlow
    const response = await client.executeQuery({
      userToken: 'user-123',
      query: query,
      requestType: 'chat',
      context: {
        model: 'gpt-4',
      },
    });

    // Print response
    console.log(`📥 Response: ${JSON.stringify(response.data)}`);
    console.log('✅ Workflow completed successfully');
  } catch (error) {
    console.error(`❌ Query failed: ${error}`);
    process.exit(1);
  }
}

main();
