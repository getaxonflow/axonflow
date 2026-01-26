/**
 * Example 2: Parallel Execution Workflow - TypeScript
 *
 * Demonstrates how AxonFlow MAP (Multi-Agent Plan) automatically parallelizes independent tasks.
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

  // Complex query that benefits from parallelization
  const query =
    'Plan a 3-day trip to Paris including: (1) round-trip flights from New York, ' +
    '(2) hotel recommendations in the city center, and (3) top 5 tourist attractions to visit';

  console.log('Planning trip to Paris...');
  console.log('MAP will detect independent tasks and execute them in parallel');

  const startTime = Date.now();

  try {
    // Send query to AxonFlow (uses MAP for parallelization)
    const response = await client.proxyLLMCall({
      userToken: 'user-123',
      query: query,
      requestType: 'multi-agent-plan', // Use MAP for parallel execution
      context: { model: 'gpt-4' },
    });

    const duration = (Date.now() - startTime) / 1000;

    console.log(`Parallel execution completed in ${duration.toFixed(1)}s`);
    console.log('Trip Plan:');
    console.log(response.result);
    console.log();

    // Assertions - validate MAP response structure and content
    console.log('--- Assertions ---');
    assertCheck(response !== null && response !== undefined, 'Response object exists');
    assertCheck(!response.blocked, 'Response is not blocked');

    // Validate response has result field (MAP responses use result)
    assertCheck(
      response.result !== null && response.result !== undefined,
      'Response has result field for MAP execution'
    );

    // Validate that response content covers all three requested topics
    const resultText = JSON.stringify(response.result || response.data).toLowerCase();
    assertCheck(
      resultText.includes('flight') || resultText.includes('airline') || resultText.includes('jfk'),
      'Response includes flight information'
    );
    assertCheck(
      resultText.includes('hotel') || resultText.includes('accommodation') || resultText.includes('stay'),
      'Response includes hotel recommendations'
    );
    assertCheck(
      resultText.includes('eiffel') ||
        resultText.includes('louvre') ||
        resultText.includes('attraction') ||
        resultText.includes('museum'),
      'Response includes tourist attractions'
    );

    // Validate execution time is reasonable for parallel execution
    assertCheck(duration < 120, `Execution completed within reasonable time (${duration.toFixed(1)}s < 120s)`);

    // Validate request tracking
    assertCheck(
      response.requestId !== undefined && response.requestId !== '',
      'Response has request ID for tracing'
    );

    console.log('\nWorkflow completed successfully');
    console.log('Tip: MAP automatically parallelized the flight, hotel, and attractions search');
  } catch (error) {
    console.error(`Query failed: ${error}`);
    process.exit(1);
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
