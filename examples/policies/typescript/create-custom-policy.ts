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
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow } from '@axonflow/sdk';

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
  }
}

async function main() {
  // Initialize the client with clientId for X-Tenant-ID header
  // Policy management APIs require tenant identification
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080',
    clientId: process.env.AXONFLOW_CLIENT_ID || 'demo-tenant',
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

    assertCheck(typeof policy.id === 'string' && policy.id.length > 0, 'Policy has valid ID');
    assertCheck(policy.name === 'Custom Email Pattern', 'Policy name matches input');
    assertCheck(policy.tier === 'tenant', 'Custom policy has tenant tier');
    assertCheck(policy.category === 'pii-global', 'Policy category matches input');
    assertCheck(policy.action === 'warn', 'Policy action is warn');
    assertCheck(policy.severity === 'medium', 'Policy severity is medium');
    assertCheck(policy.enabled === true, 'Policy is enabled');

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

    assertCheck(testResult.valid === true, 'Pattern is valid regex');
    assertCheck(testResult.matches.length === 4, 'All 4 test inputs were evaluated');
    // john@company.com and test@company.com should match, others should not
    assertCheck(testResult.matches[0].matched === true, 'john@company.com matches pattern');
    assertCheck(testResult.matches[1].matched === false, 'jane@gmail.com does not match pattern');
    assertCheck(testResult.matches[2].matched === true, 'test@company.com matches pattern');
    assertCheck(testResult.matches[3].matched === false, 'invalid-email does not match pattern');

    // Retrieve the created policy
    console.log('\n3. Retrieving created policy...');

    const retrieved = await client.getStaticPolicy(policy.id);
    console.log(`   Retrieved: ${retrieved.name}`);
    console.log(`   Version: ${retrieved.version || 1}`);

    assertCheck(retrieved.id === policy.id, 'Retrieved policy ID matches created policy');
    assertCheck(retrieved.name === policy.name, 'Retrieved policy name matches created policy');
    assertCheck(retrieved.pattern === policy.pattern, 'Retrieved policy pattern matches created policy');

    // Clean up - delete the test policy
    console.log('\n4. Cleaning up (deleting test policy)...');
    await client.deleteStaticPolicy(policy.id);
    console.log('   Deleted successfully');
    assertCheck(true, 'Policy deleted successfully');

    // Verify policy is deleted by trying to retrieve it
    try {
      await client.getStaticPolicy(policy.id);
      assertCheck(false, 'Deleted policy should not be retrievable');
    } catch {
      assertCheck(true, 'Deleted policy is no longer retrievable (expected error)');
    }

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
    failures.push(`Unexpected error: ${error instanceof Error ? error.message : error}`);
  }

  // Final assertion summary
  console.log('\n' + '='.repeat(60));
  console.log('Assertion Summary');
  console.log('='.repeat(60));
  if (failures.length === 0) {
    console.log('All assertions passed!');
  } else {
    console.log(`${failures.length} assertion(s) failed:`);
    failures.forEach((f) => console.log(`  - ${f}`));
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
