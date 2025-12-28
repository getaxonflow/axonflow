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
 */

import { AxonFlow } from '@axonflow/sdk';

async function main() {
  // Initialize the client with tenant ID for policy operations
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080',
    tenant: process.env.AXONFLOW_TENANT || 'demo-tenant',
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
      // Pattern matches amounts over 1 million (₹, $, €)
      pattern: '(amount|value|total|transaction).*[₹$€]\\s*[1-9][0-9]{6,}',
      severity: 'high',
      enabled: true,
      action: 'require_approval',  // Triggers HITL queue
    });

    console.log(`   Created policy: ${policy.id}`);
    console.log(`   Name: ${policy.name}`);
    console.log(`   Action: ${policy.action}`);
    console.log(`   Tier: ${policy.tier}`);

    // 2. Test the pattern with sample inputs
    console.log('\n2. Testing pattern with sample inputs...');

    const testResult = await client.testPattern(
      policy.pattern,
      [
        'Transfer amount $5,000,000 to account',    // Should match (5M)
        'Transaction value ₹10,00,00,000',          // Should match (10Cr)
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

    // 3. Create additional HITL policies for different use cases
    console.log('\n3. Creating admin access oversight policy...');

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

    // 4. List all policies with require_approval action
    // Filter by tenant tier to get our custom policies (system policies are on first page)
    console.log('\n4. Listing all HITL policies...');

    const allPolicies = await client.listStaticPolicies({ tier: 'tenant' });
    const hitlPolicies = allPolicies.filter(p => p.action === 'require_approval');

    console.log(`   Found ${hitlPolicies.length} HITL policies:`);
    for (const p of hitlPolicies) {
      console.log(`   - ${p.name} (${p.severity})`);
    }

    // 5. Clean up test policies
    console.log('\n5. Cleaning up test policies...');
    await client.deleteStaticPolicy(policy.id);
    await client.deleteStaticPolicy(adminPolicy.id);
    console.log('   Deleted test policies');

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
    process.exit(1);
  }
}

main();
