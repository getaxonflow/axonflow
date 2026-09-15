/**
 * AxonFlow Policy Configuration - TypeScript SDK
 *
 * This example demonstrates and VALIDATES policy configuration using the pre-check API.
 * This example sends test queries through the pre-check API
 * (getPolicyApprovedContext) and checks that the Agent responds according to the
 * shipped policy actions.
 *
 * v11: the stored policy action decides. Environment variables no longer set
 * detection actions (PII_ACTION, SQLI_ACTION and their GATEWAY_/MCP_ variants are
 * ignored, with a boot WARN). The shipped request-phase actions exercised here:
 *   sys_pii_ssn, sys_pii_credit_card = warn (approved, policy id in policies)
 *   sys_sqli_*                       = warn (approved, policy id in policies)
 *
 * To change an outcome, record an organization override (customer portal API,
 * Enterprise: PUT /api/v1/detection-posture/{pii|sqli} with {"action":"block"})
 * or change the policy's action. This example validates the shipped actions with
 * no override recorded.
 *
 * Still read from the environment (a non-action knob, must match Agent config):
 *   GATEWAY_STATIC_POLICIES_ENABLED = true | false (default: true)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Run with: npx ts-node index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow } from '@axonflow/sdk';

const failures: string[] = [];

function getEnv(key: string, defaultVal: string): string {
  return process.env[key] || defaultVal;
}

function hasPolicyPrefix(policies: string[] | undefined, prefix: string): boolean {
  return (policies ?? []).some((p) => p.startsWith(prefix));
}

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

async function main(): Promise<void> {
  console.log('AxonFlow Per-Mode Policy Configuration - TypeScript SDK');
  console.log('='.repeat(55));
  console.log();

  // The pre-check API uses the Gateway engine. Detection actions come from the
  // stored policy rows (no org override recorded), not from the environment.
  const policiesEnabled = getEnv('GATEWAY_STATIC_POLICIES_ENABLED', 'true').toLowerCase();

  console.log('Expected actions: shipped stored actions (PII warn at request phase, SQLi warn)');
  console.log(`Static policies enabled: ${policiesEnabled}`);
  console.log();

  const axonflow = new AxonFlow({
    endpoint: getEnv('AXONFLOW_ENDPOINT', 'http://localhost:8080'),
    clientId: getEnv('AXONFLOW_CLIENT_ID', 'demo'),
    clientSecret: getEnv('AXONFLOW_CLIENT_SECRET', ''),
    debug: getEnv('AXONFLOW_DEBUG', '') === 'true',
  });

  // -----------------------------------------------------------
  // Test 1: Safe query -- should always be approved
  // -----------------------------------------------------------
  console.log('Test 1: Safe Query (No PII, No SQLi)');
  console.log('-'.repeat(37));

  let result;
  try {
    result = await axonflow.getPolicyApprovedContext({
      userToken: 'policy-config-user',
      query: 'What is the current date?',
    });
  } catch (error) {
    console.log(`   FATAL: Policy check failed: ${error}`);
    process.exit(1);
  }

  assertCheck(result.approved, 'Safe query is approved');
  assertCheck(result.contextId !== '', 'Context ID is returned');
  console.log();

  // -----------------------------------------------------------
  // Test 2: PII query (SSN) -- sys_pii_ssn stores warn for the request phase
  // -----------------------------------------------------------
  console.log("Test 2: PII Query (SSN '123-45-6789')");
  console.log('-'.repeat(38));
  console.log('  Expected action: warn (stored)');

  try {
    result = await axonflow.getPolicyApprovedContext({
      userToken: 'policy-config-user',
      query: 'Process refund for SSN 123-45-6789',
    });
  } catch (error) {
    console.log(`   FATAL: Policy check failed: ${error}`);
    process.exit(1);
  }

  if (policiesEnabled === 'false') {
    // When static policies are disabled, everything passes through
    assertCheck(result.approved, 'PII query approved (static policies disabled)');
    assertCheck((result.policies?.length ?? 0) === 0, 'No policies matched (static policies disabled)');
  } else {
    // warn approves the request and reports the matched policy
    assertCheck(result.approved, 'PII query approved with a warning (stored action: warn)');
    assertCheck(hasPolicyPrefix(result.policies, 'sys_pii_'), 'PII policy detected (sys_pii_* in policies)');
    console.log(`   Policies: ${result.policies?.join(', ')}`);
    if (!result.approved) {
      console.log(`   Block reason: ${result.blockReason} (an org pii=block override or an edited policy action is in force)`);
    }
  }
  console.log();

  // -----------------------------------------------------------
  // Test 3: SQLi query -- every sys_sqli_* policy stores warn
  // -----------------------------------------------------------
  console.log('Test 3: SQL Injection (UNION SELECT)');
  console.log('-'.repeat(37));
  console.log('  Expected action: warn (stored)');

  try {
    result = await axonflow.getPolicyApprovedContext({
      userToken: 'policy-config-user',
      query: 'SELECT name FROM employees UNION SELECT password FROM admin',
    });
  } catch (error) {
    console.log(`   FATAL: Policy check failed: ${error}`);
    process.exit(1);
  }

  if (policiesEnabled === 'false') {
    assertCheck(result.approved, 'SQLi query approved (static policies disabled)');
  } else {
    // SQL injection warns by default; it is not blocked
    assertCheck(result.approved, 'SQLi query approved with a warning (stored action: warn)');
    assertCheck(hasPolicyPrefix(result.policies, 'sys_sqli_'), 'SQLi policy detected (sys_sqli_* in policies)');
    console.log(`   Policies: ${result.policies?.join(', ')}`);
    if (!result.approved) {
      console.log(`   Block reason: ${result.blockReason} (an org sqli=block override or an edited policy action is in force)`);
    }
  }
  console.log();

  // -----------------------------------------------------------
  // Test 4: Credit card PII -- validates PII detection breadth
  // -----------------------------------------------------------
  console.log('Test 4: Credit Card PII');
  console.log('-'.repeat(23));

  try {
    result = await axonflow.getPolicyApprovedContext({
      userToken: 'policy-config-user',
      query: 'Charge card 4111-1111-1111-1111 for $50',
    });
  } catch (error) {
    console.log(`   FATAL: Policy check failed: ${error}`);
    process.exit(1);
  }

  if (policiesEnabled === 'false') {
    assertCheck(result.approved, 'Credit card query approved (static policies disabled)');
  } else {
    // sys_pii_credit_card stores warn for the request phase
    assertCheck(result.approved, 'Credit card approved with a warning (stored action: warn)');
    assertCheck(hasPolicyPrefix(result.policies, 'sys_pii_'), 'Credit card PII detected (sys_pii_* in policies)');
  }
  console.log();

  // -----------------------------------------------------------
  // Summary
  // -----------------------------------------------------------
  console.log('='.repeat(55));
  if (failures.length === 0) {
    console.log('ALL TESTS PASSED');
    console.log();
    console.log('Policy configuration validated:');
    console.log(`  shipped stored actions (PII warn, SQLi warn), enabled=${policiesEnabled}`);
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => {
      console.log(`   - ${f}`);
    });
    process.exit(1);
  }
}

main();
