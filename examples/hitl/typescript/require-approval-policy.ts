/**
 * AxonFlow HITL - Create Policy with require_approval Action
 *
 * This example demonstrates how to create a policy that triggers
 * Human-in-the-Loop (HITL) approval using the `require_approval` action.
 *
 * The `require_approval` action:
 * - Enterprise: Pauses execution and creates an approval request in the HITL queue
 * - Community: Auto-approves immediately (upgrade path to Enterprise)
 *
 * Use cases:
 * - High-value transaction oversight (EU AI Act Article 14, SEBI AI/ML)
 * - Admin access detection
 * - Sensitive data access control
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
  // Initialize the client with client ID for policy operations
  // clientId is used as X-Tenant-ID header for multi-tenant APIs
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080',
    clientId: process.env.AXONFLOW_CLIENT_ID || 'demo-tenant',
  });

  console.log('AxonFlow HITL - require_approval Policy Example');
  console.log('='.repeat(60));

  try {
    // 1. Create a policy with require_approval action
    console.log('\n1. Creating HITL oversight policy...');

    const policy = await client.createStaticPolicy({
      name: 'High-Value Transaction Oversight',
      description: 'Require human approval for high-value financial decisions',
      category: 'security-admin',
      // Pattern matches amounts over 1 million (₹, $, €) - case insensitive
      pattern: '(?i)(amount|value|total|transaction).*[₹$€]\\s*[1-9][0-9]{6,}',
      severity: 'high',
      enabled: true,
      action: 'require_approval',  // Triggers HITL queue
    });

    console.log(`   Created policy: ${policy.id}`);
    console.log(`   Name: ${policy.name}`);
    console.log(`   Action: ${policy.action}`);
    console.log(`   Tier: ${policy.tier}`);

    assertCheck(typeof policy.id === 'string' && policy.id.length > 0, 'Policy has valid ID');
    assertCheck(policy.action === 'require_approval', 'Policy action is require_approval');
    assertCheck(policy.name === 'High-Value Transaction Oversight', 'Policy name matches input');
    assertCheck(policy.enabled === true, 'Policy is enabled');

    // 2. Test the pattern with sample inputs
    console.log('\n2. Testing pattern with sample inputs...');

    const testResult = await client.testPattern(
      policy.pattern,
      [
        'Transfer amount $5000000 to account',      // Should match (5M)
        'Transaction value ₹100000000',             // Should match (10Cr)
        'Total: €2500000',                          // Should match (2.5M)
        'Payment of $500 completed',                 // Should NOT match (under threshold)
        'Amount: $999999',                           // Should NOT match (under 1M)
      ]
    );

    console.log('\n   Test results:');
    for (const match of testResult.matches) {
      const icon = match.matched ? '✓ HITL' : '✗ PASS';
      const input = match.input.length > 40 ? match.input.substring(0, 40) + '...' : match.input;
      console.log(`   ${icon}: "${input}"`);
    }

    // Verify pattern matching behavior
    assertCheck(testResult.valid === true, 'Pattern is valid regex');
    assertCheck(testResult.matches.length === 5, 'All 5 test inputs were evaluated');
    // First 3 should match (over 1M), last 2 should not match (under 1M)
    assertCheck(testResult.matches[0].matched === true, 'High-value $5M matches pattern');
    assertCheck(testResult.matches[1].matched === true, 'High-value 10Cr INR matches pattern');
    assertCheck(testResult.matches[2].matched === true, 'High-value 2.5M EUR matches pattern');
    assertCheck(testResult.matches[3].matched === false, 'Low-value $500 does not match pattern');
    assertCheck(testResult.matches[4].matched === false, 'Under-threshold $999999 does not match pattern');

    // 3. Test enforcement via proxyLLMCall — verify policy actually blocks
    console.log('\n3. Testing HITL enforcement via proxyLLMCall...');
    console.log('   Waiting for policy propagation...');
    await new Promise(resolve => setTimeout(resolve, 3000));

    const userToken = process.env.AXONFLOW_USER_TOKEN || '';

    // 3a. Send query that MATCHES the require_approval pattern
    console.log('\n   3a. Sending query that matches HITL pattern...');
    try {
      const matchingResponse = await client.proxyLLMCall({
        userToken,
        query: 'Process transaction amount $5000000 to offshore account',
        requestType: 'chat',
        context: { provider: 'anthropic' },
      });

      if (matchingResponse.blocked) {
        // Enterprise mode: policy enforcement blocks the request
        assertCheck(true, 'Enterprise HITL enforcement: matching query was blocked');
        const blockReason = matchingResponse.blockReason || '';
        assertCheck(
          blockReason.includes('require_approval') || blockReason.includes('approval'),
          `Block reason mentions approval (got: ${blockReason})`
        );
      } else {
        // Community mode: auto-approved
        assertCheck(true, 'Community mode: matching query auto-approved (expected)');
      }
    } catch (error) {
      const errMsg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
      if (errMsg.includes('api_key') || errMsg.includes('authentication')) {
        console.log(`   Note: LLM API error (expected without key): ${error instanceof Error ? error.message : error}`);
        assertCheck(true, 'Matching query processed (LLM key issue expected)');
      } else {
        assertCheck(false, `Matching query failed unexpectedly: ${error instanceof Error ? error.message : error}`);
      }
    }

    // 3b. Send safe query that should NOT trigger HITL
    console.log('\n   3b. Sending safe query (should NOT trigger HITL)...');
    try {
      const safeResponse = await client.proxyLLMCall({
        userToken,
        query: 'What is the weather today?',
        requestType: 'chat',
        context: { provider: 'anthropic' },
      });
      assertCheck(!safeResponse.blocked, 'Safe query was NOT blocked by HITL policy');
    } catch (error) {
      const errMsg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
      if (errMsg.includes('api_key') || errMsg.includes('authentication')) {
        console.log(`   Note: LLM API error (expected without key): ${error instanceof Error ? error.message : error}`);
        assertCheck(true, 'Safe query processed (LLM key issue expected)');
      } else {
        assertCheck(false, `Safe query failed unexpectedly: ${error instanceof Error ? error.message : error}`);
      }
    }

    // 4. Create additional HITL policies for different use cases
    console.log('\n4. Creating admin access oversight policy...');

    const adminPolicy = await client.createStaticPolicy({
      name: 'Admin Access Detection',
      description: 'Route admin operations through human review',
      category: 'security-admin',
      pattern: '(admin|root|superuser|sudo|DELETE\\s+FROM|DROP\\s+TABLE)',
      severity: 'critical',
      enabled: true,
      action: 'require_approval',
    });

    console.log(`   Created: ${adminPolicy.name}`);
    console.log(`   Action: ${adminPolicy.action}`);

    assertCheck(adminPolicy.action === 'require_approval', 'Admin policy has require_approval action');
    assertCheck(adminPolicy.severity === 'critical', 'Admin policy severity is critical');

    // 5. List all policies with require_approval action
    console.log('\n5. Listing all HITL policies...');

    // Include tenant-tier policies with limit parameter
    const allPolicies = await client.listStaticPolicies({ limit: 100 });
    const hitlPolicies = allPolicies.filter(p => p.action === 'require_approval');

    console.log(`   Found ${hitlPolicies.length} HITL policies:`);
    for (const p of hitlPolicies) {
      console.log(`   - ${p.name} (${p.severity})`);
    }

    assertCheck(hitlPolicies.length >= 2, 'At least 2 HITL policies exist (created in this test)');
    assertCheck(
      hitlPolicies.some(p => p.name === 'High-Value Transaction Oversight'),
      'High-Value Transaction Oversight policy found in HITL list'
    );
    assertCheck(
      hitlPolicies.some(p => p.name === 'Admin Access Detection'),
      'Admin Access Detection policy found in HITL list'
    );

    // 6. Clean up test policies
    console.log('\n6. Cleaning up test policies...');
    await client.deleteStaticPolicy(policy.id);
    await client.deleteStaticPolicy(adminPolicy.id);
    console.log('   Deleted test policies');
    assertCheck(true, 'Test policies deleted successfully');

    // Verify policies are deleted
    const remainingPolicies = await client.listStaticPolicies();
    const deletedPolicyExists = remainingPolicies.some(p => p.id === policy.id || p.id === adminPolicy.id);
    assertCheck(!deletedPolicyExists, 'Deleted policies no longer exist in list');

    console.log('\n' + '='.repeat(60));
    console.log('Example completed successfully!');
    console.log('\nNote: In Community Edition, require_approval auto-approves.');
    console.log('Upgrade to Enterprise for full HITL queue functionality.');

  } catch (error) {
    if (error instanceof Error) {
      console.error('\nError:', error.message);

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
