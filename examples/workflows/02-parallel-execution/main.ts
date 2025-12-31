/**
 * Example 2: Parallel Execution Workflow - TypeScript
 *
 * Demonstrates how AxonFlow MAP (Multi-Agent Plan) automatically parallelizes independent tasks.
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

  // Complex query that benefits from parallelization
  const query =
    'Plan a 3-day trip to Paris including: (1) round-trip flights from New York, ' +
    '(2) hotel recommendations in the city center, and (3) top 5 tourist attractions to visit';

  console.log('📤 Planning trip to Paris...');
  console.log('🔄 MAP will detect independent tasks and execute them in parallel');

  const startTime = Date.now();

  try {
    // Send query to AxonFlow (uses MAP for parallelization)
    const response = await client.executeQuery({
      userToken: 'user-123',
      query: query,
      requestType: 'multi-agent-plan', // Use MAP for parallel execution
      context: { model: 'gpt-4' },
    });

    const duration = (Date.now() - startTime) / 1000;

    console.log(`⏱️  Parallel execution completed in ${duration.toFixed(1)}s`);
    console.log('📥 Trip Plan:');
    console.log(response.result);
    console.log();
    console.log('✅ Workflow completed successfully');
    console.log('💡 Tip: MAP automatically parallelized the flight, hotel, and attractions search');
  } catch (error) {
    console.error(`❌ Query failed: ${error}`);
    process.exit(1);
  }
}

main();
