/**
 * AxonFlow Policy Management - Create Custom Policy
 *
 * This example demonstrates how to create a custom static policy
 * using the AxonFlow TypeScript SDK.
 *
 * Static policies are pattern-based rules that detect:
 * - PII (personally identifiable information)
 * - SQL injection attempts
 * - Sensitive data patterns
 */

import { AxonFlow } from '@axonflow/sdk';

async function main() {
  // Initialize the client
  // For self-hosted Community, no auth needed when running locally
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080',
  });

  console.log('AxonFlow Policy Management - Create Custom Policy');
  console.log('='.repeat(60));

  try {
    // Create a custom PII detection policy
    // This policy detects email addresses from a specific domain
    console.log('\n1. Creating custom email detection policy...');

    const policy = await client.createStaticPolicy({
      name: 'Custom Email Pattern',
      description: 'Detects email addresses in specific company format',
      category: 'pii-global',
      pattern: '[a-zA-Z0-9._%+-]+@company\\.com',
      severity: 'medium',  // Valid values: critical, high, medium, low
      enabled: true,
      action: 'warn',
    });

    console.log(`   Created policy: ${policy.id}`);
    console.log(`   Name: ${policy.name}`);
    console.log(`   Tier: ${policy.tier}`);  // Will be 'tenant' for custom policies
    console.log(`   Category: ${policy.category}`);
    console.log(`   Pattern: ${policy.pattern}`);

    // Test the pattern before using in production
    console.log('\n2. Testing the pattern...');

    const testResult = await client.testPattern(
      policy.pattern,
      ['john@company.com', 'jane@gmail.com', 'test@company.com', 'invalid-email']
    );

    console.log(`   Pattern valid: ${testResult.valid}`);
    console.log('\n   Test results:');

    testResult.matches.forEach((match) => {
      const icon = match.matched ? '\u2713' : '\u2717';
      console.log(`   ${icon} "${match.input}" ${match.matched ? '-> MATCH' : ''}`);
    });

    // Retrieve the created policy
    console.log('\n3. Retrieving created policy...');

    const retrieved = await client.getStaticPolicy(policy.id);
    console.log(`   Retrieved: ${retrieved.name}`);
    console.log(`   Version: ${retrieved.version || 1}`);

    // Clean up - delete the test policy
    console.log('\n4. Cleaning up (deleting test policy)...');
    await client.deleteStaticPolicy(policy.id);
    console.log('   Deleted successfully');

    console.log('\n' + '='.repeat(60));
    console.log('Example completed successfully!');

  } catch (error) {
    if (error instanceof Error) {
      console.error('\nError:', error.message);

      // Provide helpful error messages
      if (error.message.includes('ECONNREFUSED')) {
        console.error('\nHint: Make sure AxonFlow is running:');
        console.error('  docker compose up -d');
      }
    }
    process.exit(1);
  }
}

main();
