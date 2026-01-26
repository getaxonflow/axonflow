/**
 * Example 3: Conditional Logic Workflow - TypeScript
 *
 * Demonstrates if/else branching based on API responses.
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
  const agentUrl = process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080';
  const clientId = process.env.AXONFLOW_CLIENT_ID;
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    console.error('AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set');
    process.exit(1);
  }

  const client = new AxonFlow({
    endpoint: agentUrl,
    clientId,
    clientSecret,
  });

  console.log('Connected to AxonFlow');

  // Step 1: Search for flights
  const searchQuery = 'Find round-trip flights from New York to Paris for next week';
  console.log('Searching for flights to Paris...');

  let stepsExecuted = 0;
  let pathTaken = '';

  try {
    const searchResponse = await client.proxyLLMCall({
      userToken: 'user-123',
      query: searchQuery,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });

    stepsExecuted++;
    console.log('Received search results');

    // Initial assertions on search response
    console.log('\n--- Search Response Assertions ---');
    assertCheck(searchResponse !== null && searchResponse !== undefined, 'Search response exists');
    assertCheck(!searchResponse.blocked, 'Search response is not blocked');
    assertCheck(
      searchResponse.data !== null && searchResponse.data !== undefined,
      'Search response has data'
    );

    const result = JSON.stringify(searchResponse.data).toLowerCase();

    // Step 2: Conditional logic based on search results
    if (result.includes('no flights') || result.includes('not available')) {
      // Fallback path - no flights available
      pathTaken = 'fallback';
      console.log('No flights found for selected dates');
      console.log('Trying alternative dates...');

      const altQuery = 'Find flights from New York to Paris for the following week instead';
      const altResponse = await client.proxyLLMCall({
        userToken: 'user-123',
        query: altQuery,
        requestType: 'chat',
        context: { model: 'gpt-4' },
      });

      stepsExecuted++;

      console.log('Alternative Options:');
      console.log(altResponse.data);

      // Assertions for fallback path
      console.log('\n--- Fallback Path Assertions ---');
      assertCheck(altResponse !== null && altResponse !== undefined, 'Alternative response exists');
      assertCheck(!altResponse.blocked, 'Alternative response is not blocked');
      assertCheck(
        altResponse.data !== null && altResponse.data !== undefined,
        'Alternative response has data'
      );

      console.log('Workflow completed with fallback');
    } else {
      // Success path - flights found
      pathTaken = 'success';
      console.log('Flights found! Analyzing best option...');
      console.log(searchResponse.data);

      // Step 3: Proceed to booking recommendation
      const bookQuery = 'Based on the search results above, what would be the recommended booking?';
      console.log('\nGetting booking recommendation...');

      const bookResponse = await client.proxyLLMCall({
        userToken: 'user-123',
        query: bookQuery,
        requestType: 'chat',
        context: { model: 'gpt-4' },
      });

      stepsExecuted++;

      console.log('Booking Recommendation:');
      console.log(bookResponse.data);

      // Assertions for success path
      console.log('\n--- Success Path Assertions ---');
      assertCheck(bookResponse !== null && bookResponse !== undefined, 'Booking response exists');
      assertCheck(!bookResponse.blocked, 'Booking response is not blocked');
      assertCheck(
        bookResponse.data !== null && bookResponse.data !== undefined,
        'Booking response has data'
      );

      // Validate booking recommendation content
      const bookingText = JSON.stringify(bookResponse.data).toLowerCase();
      assertCheck(
        bookingText.includes('recommend') ||
          bookingText.includes('book') ||
          bookingText.includes('option') ||
          bookingText.includes('flight'),
        'Booking response contains recommendation content'
      );

      console.log('\nWorkflow completed successfully');
    }

    // Final assertions on workflow execution
    console.log('\n--- Workflow Assertions ---');
    assertCheck(stepsExecuted >= 2, `At least 2 steps executed (got ${stepsExecuted})`);
    assertCheck(pathTaken !== '', 'A conditional path was taken');
    assertCheck(
      pathTaken === 'success' || pathTaken === 'fallback',
      `Valid path taken: ${pathTaken}`
    );

    console.log('Tip: This example demonstrates if/else branching based on API responses');
  } catch (error) {
    console.error(`Query failed: ${error}`);
    process.exit(1);
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
