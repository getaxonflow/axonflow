/**
 * AxonFlow Policy Management - List and Filter Policies
 *
 * This example demonstrates how to:
 * - List all static policies
 * - Filter policies by category, tier, and status
 * - Get effective policies with tier inheritance
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
  // Policy management APIs require clientId for X-Tenant-ID header
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080',
    clientId: process.env.AXONFLOW_CLIENT_ID || 'demo-tenant',
  });

  console.log('AxonFlow Policy Management - List and Filter');
  console.log('='.repeat(60));

  try {
    // 1. List all policies
    console.log('\n1. Listing all policies...');

    const allPolicies = await client.listStaticPolicies();
    console.log(`   Total: ${allPolicies.length} policies`);

    assertCheck(Array.isArray(allPolicies), 'listStaticPolicies returns an array');
    assertCheck(allPolicies.length > 0, 'At least one policy exists in the system');

    // Group by category for summary
    const byCategory: Record<string, number> = {};
    allPolicies.forEach((p) => {
      byCategory[p.category] = (byCategory[p.category] || 0) + 1;
    });
    console.log('\n   By category:');
    Object.entries(byCategory).forEach(([cat, count]) => {
      console.log(`     ${cat}: ${count}`);
    });

    // 2. Filter by category - SQL Injection policies
    console.log('\n2. Filtering by category (security-sqli)...');

    const sqliPolicies = await client.listStaticPolicies({
      category: 'security-sqli',
    });
    console.log(`   Found: ${sqliPolicies.length} SQLi policies`);

    assertCheck(Array.isArray(sqliPolicies), 'Category filter returns an array');
    assertCheck(
      sqliPolicies.every(p => p.category === 'security-sqli'),
      'All filtered policies have security-sqli category'
    );

    // Show first 3
    sqliPolicies.slice(0, 3).forEach((p) => {
      console.log(`     - ${p.name} (severity: ${p.severity})`);
    });
    if (sqliPolicies.length > 3) {
      console.log(`     ... and ${sqliPolicies.length - 3} more`);
    }

    // 3. Filter by tier - System policies
    console.log('\n3. Filtering by tier (system)...');

    const systemPolicies = await client.listStaticPolicies({
      tier: 'system',
    });
    console.log(`   Found: ${systemPolicies.length} system policies`);

    assertCheck(Array.isArray(systemPolicies), 'Tier filter returns an array');
    assertCheck(
      systemPolicies.every(p => p.tier === 'system'),
      'All filtered policies have system tier'
    );

    // 4. Filter by enabled status
    console.log('\n4. Filtering by enabled status...');

    const enabledPolicies = await client.listStaticPolicies({
      enabled: true,
    });
    const disabledPolicies = await client.listStaticPolicies({
      enabled: false,
    });

    console.log(`   Enabled: ${enabledPolicies.length}`);
    console.log(`   Disabled: ${disabledPolicies.length}`);

    assertCheck(
      enabledPolicies.every(p => p.enabled === true),
      'All enabled-filtered policies have enabled=true'
    );
    assertCheck(
      disabledPolicies.every(p => p.enabled === false),
      'All disabled-filtered policies have enabled=false'
    );

    // 5. Combine filters
    console.log('\n5. Combining filters (enabled PII policies)...');

    const piiEnabled = await client.listStaticPolicies({
      category: 'pii-global',
      enabled: true,
    });
    console.log(`   Found: ${piiEnabled.length} enabled PII policies`);

    assertCheck(
      piiEnabled.every(p => p.category === 'pii-global' && p.enabled === true),
      'Combined filter returns policies matching both criteria'
    );

    piiEnabled.slice(0, 5).forEach((p) => {
      console.log(`     - ${p.name}: ${p.pattern.slice(0, 40)}...`);
    });

    // 6. Get effective policies (includes tier inheritance)
    console.log('\n6. Getting effective policies...');

    const effective = await client.getEffectiveStaticPolicies();
    console.log(`   Effective total: ${effective.length} policies`);

    assertCheck(Array.isArray(effective), 'getEffectiveStaticPolicies returns an array');
    assertCheck(effective.length > 0, 'At least one effective policy exists');

    // Group by tier
    const byTier: Record<string, number> = {};
    effective.forEach((p) => {
      byTier[p.tier] = (byTier[p.tier] || 0) + 1;
    });
    console.log('\n   By tier (effective):');
    Object.entries(byTier).forEach(([tier, count]) => {
      console.log(`     ${tier}: ${count}`);
    });

    // 7. Pagination example
    // Note: The backend uses page-based pagination (page=1, page=2, ...),
    // not offset-based. The SDK's offset param is not honored by the server,
    // so we verify that limit is respected and results are returned.
    console.log('\n7. Pagination example...');

    const page1 = await client.listStaticPolicies({
      limit: 5,
    });
    const page2 = await client.listStaticPolicies({
      limit: 3,
    });

    console.log(`   Page (limit=5): ${page1.length} policies`);
    console.log(`   Page (limit=3): ${page2.length} policies`);

    assertCheck(page1.length <= 5, 'Request with limit=5 returns at most 5 policies');
    assertCheck(page2.length <= 3, 'Request with limit=3 returns at most 3 policies');
    // When there are enough policies, verify that limit actually constrains results
    if (allPolicies.length > 5) {
      assertCheck(page1.length === 5, 'Limit of 5 returns exactly 5 when enough policies exist');
    }
    if (allPolicies.length > 3) {
      assertCheck(page2.length === 3, 'Limit of 3 returns exactly 3 when enough policies exist');
    }

    // 8. Sorting
    console.log('\n8. Sorting by severity (descending)...');

    const bySeverity = await client.listStaticPolicies({
      sortBy: 'severity',
      sortOrder: 'desc',
      limit: 5,
    });

    console.log('   Top 5 by severity:');
    bySeverity.forEach((p) => {
      console.log(`     [${p.severity}] ${p.name}`);
    });

    assertCheck(bySeverity.length <= 5, 'Sort query respects limit of 5');
    // Verify severity ordering (critical > high > medium > low)
    const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    let isOrdered = true;
    for (let i = 1; i < bySeverity.length; i++) {
      const prevSeverity = severityOrder[bySeverity[i - 1].severity] || 0;
      const currSeverity = severityOrder[bySeverity[i].severity] || 0;
      if (prevSeverity < currSeverity) {
        isOrdered = false;
        break;
      }
    }
    assertCheck(isOrdered, 'Policies are sorted by severity in descending order');

    console.log('\n' + '='.repeat(60));
    console.log('Example completed successfully!');

  } catch (error) {
    if (error instanceof Error) {
      console.error('\nError:', error.message);
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
