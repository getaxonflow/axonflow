/**
 * AxonFlow MAP (Multi-Agent Planning) Example - TypeScript SDK
 */

import { AxonFlow } from '@axonflow/sdk';

async function main(): Promise<void> {
  console.log('AxonFlow MAP Example - TypeScript');
  console.log('==================================================');
  console.log();

  // Initialize client - uses environment variables or defaults for self-hosted
  const axonflow = new AxonFlow({
    agentUrl: process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080',
    clientId: process.env.AXONFLOW_CLIENT_ID || 'demo',
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || 'demo',
    debug: true,
  });

  // Simple query for testing
  const query = 'Create a brief plan to greet a new user and ask how to help them';
  const domain = 'generic';

  console.log(`Query: ${query}`);
  console.log(`Domain: ${domain}`);
  console.log('--------------------------------------------------');
  console.log();

  try {
    // Generate a plan
    const plan = await axonflow.generatePlan(query, domain);

    console.log('✅ Plan Generated Successfully');
    console.log(`Plan ID: ${plan.planId}`);
    console.log(`Steps: ${plan.steps?.length || 0}`);

    if (plan.steps) {
      plan.steps.forEach((step, i) => {
        console.log(`  ${i + 1}. ${step.name} (${step.type})`);
      });
    }

    console.log();
    console.log('==================================================');
    console.log('✅ TypeScript MAP Test: PASS');
  } catch (error) {
    console.error(`❌ Error: ${error}`);
    console.log();
    console.log('==================================================');
    console.log('❌ TypeScript MAP Test: FAIL');
    process.exit(1);
  }
}

main();
