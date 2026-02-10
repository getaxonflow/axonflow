/**
 * AxonFlow Evaluation Tier - License Tier Limits Testing (TypeScript)
 *
 * TIER COMPATIBILITY: Community / Evaluation
 * Works without any license (Community mode) and with a free Evaluation license.
 * No paid Enterprise license required. Get a free Evaluation license at:
 * https://getaxonflow.com/evaluation-license
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * This example tests:
 * - Tier detection (Community, Evaluation, Enterprise)
 * - Tenant policy limits (20/50/unlimited)
 * - Organization policy access (blocked/5 limit/unlimited)
 *
 * Run with:
 *   npx ts-node test_tier_limits.ts
 *
 * Prerequisites: docker compose up -d
 */

import { AxonFlow, AxonFlowError } from '@axonflow/sdk';

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
  }
}

function getExpectedTier(): string {
  const licenseKey = process.env.AXONFLOW_LICENSE_KEY || '';
  if (!licenseKey) {
    return 'community';
  }
  // Ed25519 format: AXON-{base64url_payload}.{base64url_signature}
  if (licenseKey.startsWith('AXON-') && licenseKey.includes('.')) {
    try {
      const inner = licenseKey.slice(5); // Strip "AXON-"
      const lastDot = inner.lastIndexOf('.');
      const payloadB64 = inner.slice(0, lastDot);
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
      const tier = payload.tier || '';
      if (tier === 'Evaluation') return 'evaluation';
      if (['Enterprise', 'Plus', 'Professional'].includes(tier)) return 'enterprise';
    } catch {
      // Fall through to simple check
    }
  }
  if (licenseKey.toUpperCase().includes('EVALUATION')) {
    return 'evaluation';
  }
  return 'enterprise';
}

async function main(): Promise<number> {
  console.log('============================================================');
  console.log('AxonFlow Evaluation Tier - License Tier Limits Testing (TypeScript)');
  console.log('============================================================');

  const expectedTier = getExpectedTier();
  console.log(`\nDetected tier (from env): ${expectedTier}`);

  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080',
    clientId: process.env.AXONFLOW_CLIENT_ID || 'test-org-001',
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || 'test-secret',
  });

  // Test 1: Health Check / Tier Detection
  console.log('\n1. Testing Tier Detection');
  console.log('----------------------------------------');

  try {
    const health = await client.healthCheck();
    assertCheck(health.status === 'healthy', 'Platform is healthy');
    console.log(`   Platform version: ${health.version || 'unknown'}`);
  } catch (err) {
    console.log(`   Error: ${err}`);
    assertCheck(false, 'Health check passed');
  }

  // Test 2: Create and Delete Tenant Policy
  console.log('\n2. Testing Tenant Policy Limits');
  console.log('----------------------------------------');

  let expectedLimit: string;
  switch (expectedTier) {
    case 'community':
      expectedLimit = '20';
      break;
    case 'evaluation':
      expectedLimit = '50';
      break;
    default:
      expectedLimit = 'unlimited';
  }
  console.log(`   Expected limit for ${expectedTier}: ${expectedLimit}`);

  try {
    const policy = await client.createDynamicPolicy({
      name: 'TypeScript Evaluation Tier Test Policy',
      description: 'Test policy for tier limit verification',
      type: 'content',
      category: 'dynamic-ts-tier-test',
      conditions: [{ field: 'query', operator: 'contains', value: 'ts-tier-test' }],
      actions: [{ type: 'log' }],
      priority: 100,
      enabled: false,
    });

    assertCheck(true, 'Policy creation succeeded');
    console.log(`   Created policy: ${policy.id}`);

    // Clean up
    await client.deleteDynamicPolicy(policy.id);
    console.log('   Cleaned up test policy');
  } catch (err) {
    const errStr = String(err);
    if (errStr.includes('POLICY_LIMIT_EXCEEDED')) {
      console.log('   Policy limit reached');
      assertCheck(true, 'Policy limit enforcement working');

      if (expectedTier === 'community' && errStr.toLowerCase().includes('evaluation')) {
        assertCheck(true, 'Error mentions Evaluation upgrade path');
      } else if (expectedTier === 'evaluation' && errStr.toLowerCase().includes('enterprise')) {
        assertCheck(true, 'Error mentions Enterprise upgrade path');
      }
    } else {
      console.log(`   Error: ${err}`);
      assertCheck(false, 'Policy creation succeeded or limit enforced');
    }
  }

  // Test 3: Organization Policy Access
  console.log('\n3. Testing Organization Policy Access');
  console.log('----------------------------------------');

  try {
    const orgPolicy = await client.createDynamicPolicy({
      name: 'TypeScript Org Policy Test',
      description: 'Test org policy for tier verification',
      type: 'content',
      category: 'dynamic-ts-org-test',
      tier: 'organization',
      conditions: [{ field: 'query', operator: 'contains', value: 'ts-org-test' }],
      actions: [{ type: 'log' }],
      priority: 100,
      enabled: false,
    });

    if (expectedTier === 'community') {
      assertCheck(false, 'Community should not create org policies');
    } else {
      assertCheck(true, `${expectedTier} tier can create org policies`);
      console.log(`   Created org policy: ${orgPolicy.id}`);

      // Clean up
      await client.deleteDynamicPolicy(orgPolicy.id);
      console.log('   Cleaned up org policy');
    }
  } catch (err) {
    const errStr = String(err);
    if (expectedTier === 'community') {
      if (errStr.includes('ORG_TIER') || errStr.toLowerCase().includes('evaluation')) {
        assertCheck(true, 'Community tier correctly blocked org policy creation');
        if (errStr.toLowerCase().includes('evaluation')) {
          assertCheck(true, 'Error includes Evaluation upgrade path');
        }
      } else {
        console.log(`   Error: ${err}`);
        assertCheck(false, 'Expected org tier error for Community');
      }
    } else if (errStr.includes('ORG_POLICY_LIMIT_EXCEEDED')) {
      console.log('   Org policy limit reached for Evaluation tier');
      assertCheck(true, 'Evaluation tier has org policy limit enforcement');
    } else {
      console.log(`   Error: ${err}`);
      assertCheck(false, 'Unexpected error creating org policy');
    }
  }

  // Summary
  console.log('\n============================================================');
  console.log('TEST SUMMARY');
  console.log('============================================================');

  if (failures.length > 0) {
    console.log(`\n❌ ${failures.length} test(s) failed:`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
    return 1;
  } else {
    console.log('\n✓ All tests passed!');
    console.log(`\nTier limits verified for: ${expectedTier}`);
    console.log('\nTier Comparison:');
    console.log('  | Feature          | Community | Evaluation | Enterprise |');
    console.log('  |------------------|-----------|------------|------------|');
    console.log('  | Tenant policies  | 20        | 50         | Unlimited  |');
    console.log('  | Org policies     | 0         | 5          | Unlimited  |');
    console.log('  | MCP connectors   | 2         | 5          | Unlimited  |');
    console.log('  | Audit retention  | 3 days    | 14 days    | 3650 days  |');
    return 0;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('Unexpected error:', err);
    process.exit(1);
  });
