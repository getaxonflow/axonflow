/**
 * Example 3: Conditional Logic Workflow - TypeScript
 *
 * Demonstrates if/else branching based on API responses.
 */

import { AxonFlow } from '@axonflow/sdk';

async function main() {
  const agentUrl = process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080';
  const licenseKey = process.env.AXONFLOW_LICENSE_KEY;

  if (!licenseKey) {
    console.error('❌ AXONFLOW_LICENSE_KEY must be set');
    process.exit(1);
  }

  const client = new AxonFlow({
    endpoint: agentUrl,
    licenseKey: licenseKey,
  });

  console.log('✅ Connected to AxonFlow');

  // Step 1: Search for flights
  const searchQuery = 'Find round-trip flights from New York to Paris for next week';
  console.log('📤 Searching for flights to Paris...');

  try {
    const searchResponse = await client.executeQuery({
      userToken: 'user-123',
      query: searchQuery,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });

    console.log('✅ Received search results');

    const result = JSON.stringify(searchResponse.data).toLowerCase();

    // Step 2: Conditional logic based on search results
    if (result.includes('no flights') || result.includes('not available')) {
      // Fallback path - no flights available
      console.log('⚠️  No flights found for selected dates');
      console.log('💡 Trying alternative dates...');

      const altQuery = 'Find flights from New York to Paris for the following week instead';
      const altResponse = await client.executeQuery({
        userToken: 'user-123',
        query: altQuery,
        requestType: 'chat',
        context: { model: 'gpt-4' },
      });

      console.log('📥 Alternative Options:');
      console.log(altResponse.data);
      console.log('✅ Workflow completed with fallback');
      return;
    }

    // Success path - flights found
    console.log('💡 Flights found! Analyzing best option...');
    console.log(searchResponse.data);

    // Step 3: Proceed to booking recommendation
    const bookQuery = 'Based on the search results above, what would be the recommended booking?';
    console.log('\n📤 Getting booking recommendation...');

    const bookResponse = await client.executeQuery({
      userToken: 'user-123',
      query: bookQuery,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });

    console.log('📥 Booking Recommendation:');
    console.log(bookResponse.data);
    console.log('\n✅ Workflow completed successfully');
    console.log('💡 Tip: This example demonstrates if/else branching based on API responses');
  } catch (error) {
    console.error(`❌ Query failed: ${error}`);
    process.exit(1);
  }
}

main();
