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
 * Default Behavior (Issue #891):
 *   PII detection defaults to "redact" mode - requests are APPROVED but flagged
 *   with requiresRedaction=true for downstream redaction by the Orchestrator.
 *   Set PII_ACTION=block to restore blocking behavior.
 *
 * Run with: npx ts-node index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow } from '@axonflow/sdk';

interface TestCase {
  name: string;
  query: string;
  expectRedact: boolean;
}

const failures: string[] = [];

function getEnv(key: string, defaultVal: string): string {
  return process.env[key] || defaultVal;
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    failures.push(message);
    console.log(`   \u274C FAIL: ${message}`);
  } else {
    console.log(`   \u2713 PASS: ${message}`);
  }
}

async function main(): Promise<void> {
  console.log('AxonFlow PII Detection - TypeScript SDK');
  console.log('='.repeat(40));
  console.log();
  console.log('Default Mode: redact (PII flagged for redaction, not blocked)');
  console.log();

  const axonflow = new AxonFlow({
    endpoint: getEnv('AXONFLOW_ENDPOINT', 'http://localhost:8080'),
    clientId: getEnv('AXONFLOW_CLIENT_ID', 'demo'),
    clientSecret: getEnv('AXONFLOW_CLIENT_SECRET', 'demo'),
    debug: getEnv('AXONFLOW_DEBUG', '') === 'true',
  });

  // PII test cases
  // expectRedact: true = critical PII (requiresRedaction=true)
  // expectRedact: false = non-critical or no PII (logged but not flagged)
  const testCases: TestCase[] = [
    {
      name: 'Safe Query (No PII)',
      query: 'What is the capital of France?',
      expectRedact: false,
    },
    {
      name: 'US Social Security Number (Critical PII)',
      query: 'Process refund for customer with SSN 123-45-6789',
      expectRedact: true,
    },
    {
      name: 'Credit Card Number (Critical PII)',
      query: 'Charge card 4111-1111-1111-1111 for $99.99',
      expectRedact: true,
    },
    {
      name: 'India PAN (Critical PII)',
      query: 'Verify PAN number ABCDE1234F for tax filing',
      expectRedact: true,
    },
    {
      name: 'India Aadhaar (Critical PII)',
      query: 'Link Aadhaar 2345 6789 0123 to account',
      expectRedact: true,
    },
    {
      name: 'Email Address (Non-Critical PII)',
      query: 'Send invoice to john.doe@gmail.com',
      expectRedact: false, // Medium severity - logged but not flagged
    },
    {
      name: 'Phone Number (Non-Critical PII)',
      query: 'Call customer at +1-555-123-4567',
      expectRedact: false, // Medium severity - logged but not flagged
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

    // Validate context ID
    assert(result.contextId !== '', 'contextId is not empty');
    assert(result.contextId.startsWith('ctx_'), "contextId has correct prefix 'ctx_'");

    // Check if request was approved
    if (result.approved) {
      if (result.requiresRedaction) {
        console.log('   Status: APPROVED (requires redaction)');
      } else {
        console.log('   Status: APPROVED');
      }
    } else {
      // Request was blocked (only if PII_ACTION=block)
      console.log('   Status: BLOCKED');
      console.log(`   Reason: ${result.blockReason}`);
    }

    // Get actual redaction status (blocked also counts as "requires handling")
    const actualRequiresRedaction = result.requiresRedaction || !result.approved;

    // Verify expected behavior
    if (test.expectRedact) {
      assert(actualRequiresRedaction, 'Critical PII detected and flagged for redaction');
    } else {
      assert(
        !actualRequiresRedaction && result.approved,
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
