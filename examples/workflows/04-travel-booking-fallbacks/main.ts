/**
 * Example 4: Travel Booking with Fallbacks - TypeScript
 *
 * Demonstrates intelligent fallback patterns: try premium options first,
 * fall back to alternatives if unavailable.
 */

import { AxonFlow } from '@axonflow/sdk';

async function main() {
  const agentUrl = process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080';
  const clientId = process.env.AXONFLOW_CLIENT_ID;
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    console.error('❌ AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set');
    process.exit(1);
  }

  const client = new AxonFlow({
    endpoint: agentUrl,
    clientId,
    clientSecret,
  });

  console.log('✅ Connected to AxonFlow');
  console.log('📤 Planning trip to Tokyo with intelligent fallbacks...\n');

  let flightOption = '';
  let hotelOption = '';

  try {
    // STEP 1: Try direct flights first
    console.log('🔍 Step 1: Searching for direct flights from San Francisco to Tokyo...');
    const flightResp1 = await client.proxyLLMCall({
      userToken: 'user-123',
      query: 'Find direct flights from San Francisco to Tokyo next month',
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });

    const flightResult = JSON.stringify(flightResp1.data).toLowerCase();

    if (flightResult.includes('no direct flights') || flightResult.includes('not available')) {
      console.log('⚠️  No direct flights available');
      console.log('📤 Step 2 (Fallback): Trying connecting flights...');

      const flightResp2 = await client.proxyLLMCall({
        userToken: 'user-123',
        query: 'Find connecting flights from San Francisco to Tokyo with 1 stop',
        requestType: 'chat',
        context: { model: 'gpt-4' },
      });

      const fallbackResult = JSON.stringify(flightResp2.data).toLowerCase();
      if (fallbackResult.includes('no flights')) {
        console.log('⚠️  No connecting flights available either');
        console.log('💡 Recommendation: Try different dates or airports');
        return;
      }

      flightOption = 'Connecting flight (1 stop)';
      console.log('✅ Found connecting flight option');
    } else {
      flightOption = 'Direct flight';
      console.log('✅ Found direct flight');
    }

    console.log();

    // STEP 2: Try 5-star hotels first
    console.log('🔍 Step 3: Searching for 5-star hotels in Tokyo city center...');
    const hotelResp1 = await client.proxyLLMCall({
      userToken: 'user-123',
      query: 'Find 5-star hotels in Tokyo Shibuya district',
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });

    const hotelResult = JSON.stringify(hotelResp1.data).toLowerCase();

    if (hotelResult.includes('fully booked') || hotelResult.includes('no availability')) {
      console.log('⚠️  5-star hotels fully booked');
      console.log('📤 Step 4 (Fallback): Trying 4-star hotels...');

      const hotelResp2 = await client.proxyLLMCall({
        userToken: 'user-123',
        query: 'Find 4-star hotels in Tokyo with good reviews',
        requestType: 'chat',
        context: { model: 'gpt-4' },
      });

      const fallbackResult = JSON.stringify(hotelResp2.data).toLowerCase();
      if (fallbackResult.includes('no availability')) {
        console.log('⚠️  4-star hotels also unavailable');
        console.log('💡 Recommendation: Try Airbnb or alternative districts');
        return;
      }

      hotelOption = '4-star hotel (fallback)';
      console.log('✅ Found 4-star hotel alternative');
    } else {
      hotelOption = '5-star hotel';
      console.log('✅ Found 5-star hotel');
    }

    console.log();

    // STEP 3: Generate final itinerary
    console.log('📋 Generating complete itinerary with selected options...');
    const itineraryQuery = `Create a 7-day Tokyo itinerary with ${flightOption} and ${hotelOption} accommodation. Include top attractions, restaurants, and transportation tips.`;

    const itineraryResp = await client.proxyLLMCall({
      userToken: 'user-123',
      query: itineraryQuery,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });

    console.log('\n📥 Your Tokyo Itinerary:');
    console.log('='.repeat(60));
    console.log(itineraryResp.data);
    console.log('='.repeat(60));
    console.log('\n✅ Travel booking workflow completed successfully!');
    console.log(`💡 Booked: ${flightOption} + ${hotelOption}`);
  } catch (error) {
    console.error(`❌ Query failed: ${error}`);
    process.exit(1);
  }
}

main();
