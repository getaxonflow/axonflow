/**
 * Example 4: Travel Booking with Fallbacks - TypeScript
 *
 * Demonstrates intelligent fallback patterns: try premium options first,
 * fall back to alternatives if unavailable.
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
  console.log('Planning trip to Tokyo with intelligent fallbacks...\n');

  let flightOption = '';
  let hotelOption = '';
  let apiCallCount = 0;
  let flightFallbackUsed = false;
  let hotelFallbackUsed = false;

  try {
    // STEP 1: Try direct flights first
    console.log('Step 1: Searching for direct flights from San Francisco to Tokyo...');
    const flightResp1 = await client.proxyLLMCall({
      userToken: 'user-123',
      query: 'Find direct flights from San Francisco to Tokyo next month',
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });
    apiCallCount++;

    // Assertions for initial flight search
    console.log('\n--- Flight Search Assertions ---');
    assertCheck(flightResp1 !== null && flightResp1 !== undefined, 'Flight search response exists');
    assertCheck(!flightResp1.blocked, 'Flight search is not blocked');
    assertCheck(
      flightResp1.data !== null && flightResp1.data !== undefined,
      'Flight search has data'
    );

    const flightResult = JSON.stringify(flightResp1.data).toLowerCase();

    if (flightResult.includes('no direct flights') || flightResult.includes('not available')) {
      flightFallbackUsed = true;
      console.log('No direct flights available');
      console.log('Step 2 (Fallback): Trying connecting flights...');

      const flightResp2 = await client.proxyLLMCall({
        userToken: 'user-123',
        query: 'Find connecting flights from San Francisco to Tokyo with 1 stop',
        requestType: 'chat',
        context: { model: 'gpt-4' },
      });
      apiCallCount++;

      assertCheck(flightResp2 !== null && flightResp2 !== undefined, 'Fallback flight response exists');
      assertCheck(!flightResp2.blocked, 'Fallback flight search is not blocked');

      const fallbackResult = JSON.stringify(flightResp2.data).toLowerCase();
      if (fallbackResult.includes('no flights')) {
        console.log('No connecting flights available either');
        console.log('Recommendation: Try different dates or airports');

        // Assertions before early exit
        console.log('\n--- Early Exit Assertions ---');
        assertCheck(apiCallCount >= 2, `Made at least 2 API calls (got ${apiCallCount})`);
        assertCheck(flightFallbackUsed, 'Flight fallback was attempted');
        process.exit(failures.length > 0 ? 1 : 0);
      }

      flightOption = 'Connecting flight (1 stop)';
      console.log('Found connecting flight option');
    } else {
      flightOption = 'Direct flight';
      console.log('Found direct flight');
    }

    console.log();

    // STEP 2: Try 5-star hotels first
    console.log('Step 3: Searching for 5-star hotels in Tokyo city center...');
    const hotelResp1 = await client.proxyLLMCall({
      userToken: 'user-123',
      query: 'Find 5-star hotels in Tokyo Shibuya district',
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });
    apiCallCount++;

    // Assertions for initial hotel search
    console.log('\n--- Hotel Search Assertions ---');
    assertCheck(hotelResp1 !== null && hotelResp1 !== undefined, 'Hotel search response exists');
    assertCheck(!hotelResp1.blocked, 'Hotel search is not blocked');
    assertCheck(hotelResp1.data !== null && hotelResp1.data !== undefined, 'Hotel search has data');

    const hotelResult = JSON.stringify(hotelResp1.data).toLowerCase();

    if (hotelResult.includes('fully booked') || hotelResult.includes('no availability')) {
      hotelFallbackUsed = true;
      console.log('5-star hotels fully booked');
      console.log('Step 4 (Fallback): Trying 4-star hotels...');

      const hotelResp2 = await client.proxyLLMCall({
        userToken: 'user-123',
        query: 'Find 4-star hotels in Tokyo with good reviews',
        requestType: 'chat',
        context: { model: 'gpt-4' },
      });
      apiCallCount++;

      assertCheck(hotelResp2 !== null && hotelResp2 !== undefined, 'Fallback hotel response exists');
      assertCheck(!hotelResp2.blocked, 'Fallback hotel search is not blocked');

      const fallbackResult = JSON.stringify(hotelResp2.data).toLowerCase();
      if (fallbackResult.includes('no availability')) {
        console.log('4-star hotels also unavailable');
        console.log('Recommendation: Try Airbnb or alternative districts');

        // Assertions before early exit
        console.log('\n--- Early Exit Assertions ---');
        assertCheck(apiCallCount >= 3, `Made at least 3 API calls (got ${apiCallCount})`);
        assertCheck(hotelFallbackUsed, 'Hotel fallback was attempted');
        process.exit(failures.length > 0 ? 1 : 0);
      }

      hotelOption = '4-star hotel (fallback)';
      console.log('Found 4-star hotel alternative');
    } else {
      hotelOption = '5-star hotel';
      console.log('Found 5-star hotel');
    }

    console.log();

    // STEP 3: Generate final itinerary
    console.log('Generating complete itinerary with selected options...');
    const itineraryQuery = `Create a 7-day Tokyo itinerary with ${flightOption} and ${hotelOption} accommodation. Include top attractions, restaurants, and transportation tips.`;

    const itineraryResp = await client.proxyLLMCall({
      userToken: 'user-123',
      query: itineraryQuery,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });
    apiCallCount++;

    console.log('\nYour Tokyo Itinerary:');
    console.log('='.repeat(60));
    console.log(itineraryResp.data);
    console.log('='.repeat(60));

    // Final assertions
    console.log('\n--- Final Assertions ---');
    assertCheck(itineraryResp !== null && itineraryResp !== undefined, 'Itinerary response exists');
    assertCheck(!itineraryResp.blocked, 'Itinerary generation is not blocked');
    assertCheck(
      itineraryResp.data !== null && itineraryResp.data !== undefined,
      'Itinerary has data'
    );

    // Validate itinerary content
    const itineraryText = JSON.stringify(itineraryResp.data).toLowerCase();
    assertCheck(
      itineraryText.includes('tokyo') || itineraryText.includes('japan'),
      'Itinerary mentions Tokyo/Japan'
    );
    assertCheck(
      itineraryText.includes('day') || itineraryText.includes('itinerary'),
      'Itinerary contains day-by-day structure'
    );

    // Validate workflow state
    assertCheck(flightOption !== '', 'Flight option was selected');
    assertCheck(hotelOption !== '', 'Hotel option was selected');
    assertCheck(apiCallCount >= 3, `Made at least 3 API calls (got ${apiCallCount})`);

    console.log('\nTravel booking workflow completed successfully!');
    console.log(`Booked: ${flightOption} + ${hotelOption}`);
    console.log(`Total API calls: ${apiCallCount}`);
    console.log(`Fallbacks used: Flight=${flightFallbackUsed}, Hotel=${hotelFallbackUsed}`);
  } catch (error) {
    console.error(`Query failed: ${error}`);
    process.exit(1);
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
