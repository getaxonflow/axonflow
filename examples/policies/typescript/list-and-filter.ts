/**
 * AxonFlow Policy Management - List and Filter Policies
 *
 * This example demonstrates how to:
 * - List all static policies
 * - Filter policies by category, tier, and status
 * - Get effective policies with tier inheritance
 */

import { AxonFlow } from '@axonflow/sdk';

async function main() {
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080',
  });

  console.log('AxonFlow Policy Management - List and Filter');
  console.log('='.repeat(60));

  try {
    // 1. List all policies
    console.log('\n1. Listing all policies...');

    const allPolicies = await client.listStaticPolicies();
    console.log(`   Total: ${allPolicies.length} policies`);

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

    // 5. Combine filters
    console.log('\n5. Combining filters (enabled PII policies)...');

    const piiEnabled = await client.listStaticPolicies({
      category: 'pii-global',
      enabled: true,
    });
    console.log(`   Found: ${piiEnabled.length} enabled PII policies`);

    piiEnabled.slice(0, 5).forEach((p) => {
      console.log(`     - ${p.name}: ${p.pattern.slice(0, 40)}...`);
    });

    // 6. Get effective policies (includes tier inheritance)
    console.log('\n6. Getting effective policies...');

    const effective = await client.getEffectiveStaticPolicies();
    console.log(`   Effective total: ${effective.length} policies`);

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
    console.log('\n7. Pagination example...');

    const page1 = await client.listStaticPolicies({
      limit: 5,
      offset: 0,
    });
    const page2 = await client.listStaticPolicies({
      limit: 5,
      offset: 5,
    });

    console.log(`   Page 1: ${page1.length} policies`);
    console.log(`   Page 2: ${page2.length} policies`);

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

    console.log('\n' + '='.repeat(60));
    console.log('Example completed successfully!');

  } catch (error) {
    if (error instanceof Error) {
      console.error('\nError:', error.message);
    }
    process.exit(1);
  }
}

main();
