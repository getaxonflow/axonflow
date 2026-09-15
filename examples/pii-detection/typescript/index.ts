/**
 * AxonFlow PII Detection - TypeScript SDK
 *
 * This example demonstrates and VALIDATES AxonFlow's PII detection:
 * - US Social Security Numbers (SSN)
 * - Credit Card numbers
 * - India PAN (Permanent Account Number)
 * - India Aadhaar numbers
 * - Email addresses
 * - Phone numbers
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Default Behavior (v11):
 *
 *   The stored action of each matched PII policy decides. On the request side
 *   (this pre-check) the shipped SSN, credit card, PAN and Aadhaar policies store
 *   action_request=warn: the request is APPROVED and the matched policy ids are
 *   returned with it. Their stored response action is redact, so redaction
 *   happens on the response side. Environment variables no longer set detection
 *   actions. To change an outcome, record an organization override (Enterprise
 *   customer portal: PUT /api/v1/detection-posture/pii {"action":"block"}) or
 *   change the policy's action.
 *
 * Run with: npx ts-node index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow } from '@axonflow/sdk';

interface TestCase {
  name: string;
  query: string;
  expectDetect: boolean;
}

const failures: string[] = [];

function getEnv(key: string, defaultVal: string): string {
  return process.env[key] || defaultVal;
}

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
  }
}

async function main(): Promise<void> {
  console.log('AxonFlow PII Detection - TypeScript SDK');
  console.log('='.repeat(40));
  console.log();
  console.log('Stored policy actions decide: request-side PII warns (approved, policy recorded)');
  console.log();

  const axonflow = new AxonFlow({
    endpoint: getEnv('AXONFLOW_ENDPOINT', 'http://localhost:8080'),
    clientId: getEnv('AXONFLOW_CLIENT_ID', 'demo'),
    clientSecret: getEnv('AXONFLOW_CLIENT_SECRET', 'demo'),
    debug: getEnv('AXONFLOW_DEBUG', '') === 'true',
  });

  // PII test cases
  // expectDetect: true = critical PII (a policy matches; stored request action is warn)
  // expectDetect: false = non-critical or no PII (approved, no redaction flag)
  const testCases: TestCase[] = [
    {
      name: 'Safe Query (No PII)',
      query: 'What is the capital of France?',
      expectDetect: false,
    },
    {
      name: 'US Social Security Number (Critical PII)',
      query: 'Process refund for customer with SSN 123-45-6789',
      expectDetect: true,
    },
    {
      name: 'Credit Card Number (Critical PII)',
      query: 'Charge card 4111-1111-1111-1111 for $99.99',
      expectDetect: true,
    },
    {
      name: 'India PAN (Critical PII)',
      query: 'Verify PAN number ABCPD1234E for tax filing',
      expectDetect: true,
    },
    {
      name: 'India Aadhaar (Critical PII)',
      query: 'Link Aadhaar 2345 6789 0123 to account',
      expectDetect: true,
    },
    {
      name: 'Email Address (Non-Critical PII)',
      query: 'Send invoice to john.doe@gmail.com',
      expectDetect: false, // Medium severity - logged but not flagged
    },
    {
      name: 'Phone Number (Non-Critical PII)',
      query: 'Call customer at +1-555-123-4567',
      expectDetect: false, // Medium severity - logged but not flagged
    },
  ];

  for (let i = 0; i < testCases.length; i++) {
    const test = testCases[i];
    console.log(`Test ${i + 1}: ${test.name}`);
    const queryPreview =
      test.query.length > 60 ? test.query.substring(0, 60) + '...' : test.query;
    console.log(`  Query: ${queryPreview}`);

    let result;
    try {
      result = await axonflow.getPolicyApprovedContext({
        userToken: 'pii-detection-user',
        query: test.query,
      });
    } catch (error) {
      console.log(`   \u274C FATAL: getPolicyApprovedContext failed: ${error}`);
      process.exit(1);
    }

    // Validate context ID (UUID format)
    assertCheck(result.contextId !== '', 'contextId is not empty');

    // Check if request was approved
    if (result.approved) {
      if (result.requiresRedaction) {
        console.log('   Status: APPROVED (requires redaction)');
      } else {
        console.log('   Status: APPROVED');
      }
    } else {
      // Blocked only when an organization override or a policy edit sets block
      console.log('   Status: BLOCKED');
      console.log(`   Reason: ${result.blockReason}`);
    }
    const policies = result.policies || [];
    if (policies.length > 0) {
      console.log(`   Policies: ${policies.join(', ')}`);
    }

    // Verify expected behavior against the shipped stored actions
    if (test.expectDetect) {
      assertCheck(result.approved, 'Request approved (stored request action is warn, not block)');
      assertCheck(policies.length > 0, 'Critical PII detected (policy matched)');
    } else {
      assertCheck(
        !result.requiresRedaction && result.approved,
        'No critical PII detected, request approved'
      );
    }

    console.log();
  }

  console.log('='.repeat(40));
  if (failures.length === 0) {
    console.log('\u2713 ALL TESTS PASSED');
    console.log();
    console.log('PII types validated:');
    console.log('  - Safe query (no PII)');
    console.log('  - US SSN (critical)');
    console.log('  - Credit card (critical)');
    console.log('  - India PAN (critical)');
    console.log('  - India Aadhaar (critical)');
    console.log('  - Email (non-critical)');
    console.log('  - Phone (non-critical)');
  } else {
    console.log(`\u274C ${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => {
      console.log(`   - ${f}`);
    });
    process.exit(1);
  }
}

main();
