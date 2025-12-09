import { AxonFlowClient } from '@axonflow/sdk';

// Initialize AxonFlow client
const client = new AxonFlowClient({
  endpoint: process.env.AXONFLOW_ENDPOINT || 'https://YOUR_AGENT_ENDPOINT',
  licenseKey: process.env.AXONFLOW_LICENSE_KEY || 'YOUR_LICENSE_KEY',
  organizationId: process.env.AXONFLOW_ORG_ID || 'my-org',
  insecureSkipVerify: true  // For self-signed certs in development
});

async function main() {
  try {
    console.log('🔌 Connecting to AxonFlow...');

    // Send query with simple policy
    const response = await client.executeQuery({
      query: 'What is the capital of France?',
      policy: `
        package axonflow.policy
        default allow = true
      `
    });

    // Display results
    console.log('✅ Query successful!');
    console.log('Response:', response.result);
    console.log('Latency:', response.metadata.latency_ms + 'ms');
    console.log('Policy Decision:', response.metadata.policy_decision);

  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  }
}

main();
