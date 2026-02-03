/**
 * AxonFlow Policy Configuration - TypeScript SDK
 *
 * This example demonstrates and VALIDATES policy configuration using the pre-check API.
 * AxonFlow's static policies can be configured using environment variables.
 * This example validates the CURRENT configuration by sending test queries through
 * the pre-check API (getPolicyApprovedContext) and checking that the Agent responds
 * according to the configured policy actions.
 *
 * Environment variables (must match Agent-side config):
 *   PII_ACTION   = block | redact | warn | log  (default: redact)
 *   SQLI_ACTION  = block | warn | log           (default: block)
 *   GATEWAY_STATIC_POLICIES_ENABLED = true | false (default: true)
 *
 * Mode-specific overrides (higher precedence):
 *   GATEWAY_PII_ACTION, GATEWAY_SQLI_ACTION
 *
 * IMPORTANT: Changing policy behavior requires restarting the AxonFlow Agent with
 * different env vars. This example validates behavior for the CURRENT configuration.
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

  // Read expected policy actions (must match Agent-side config)
  // Pre-check API uses the Gateway engine, so read Gateway-specific overrides first
  const piiAction = getEnv('GATEWAY_PII_ACTION', getEnv('PII_ACTION', 'redact')).toLowerCase();
  const sqliAction = getEnv('GATEWAY_SQLI_ACTION', getEnv('SQLI_ACTION', 'block')).toLowerCase();
  const policiesEnabled = getEnv('GATEWAY_STATIC_POLICIES_ENABLED', 'true').toLowerCase();

  console.log(`Expected PII_ACTION:  ${piiAction}`);
  console.log(`Expected SQLI_ACTION: ${sqliAction}`);
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
  // Test 2: PII query (SSN) -- behavior depends on PII_ACTION
  // -----------------------------------------------------------
  console.log("Test 2: PII Query (SSN '123-45-6789')");
  console.log('-'.repeat(38));
  console.log(`  Expected action: ${piiAction}`);

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
    switch (piiAction) {
      case 'block':
        assertCheck(!result.approved, 'PII query blocked (PII_ACTION=block)');
        assertCheck(!!result.blockReason, 'Block reason provided');
        if (result.blockReason) {
          console.log(`   Block reason: ${result.blockReason}`);
        }
        break;
      case 'redact':
        // In redact mode, request phase approves but flags PII
        assertCheck(result.approved, 'PII query approved in request phase (PII_ACTION=redact)');
        assertCheck((result.policies?.length ?? 0) > 0, 'PII policies detected');
        console.log(`   Policies: ${result.policies?.join(', ')}`);
        break;
      case 'warn':
        assertCheck(result.approved, 'PII query approved (PII_ACTION=warn)');
        assertCheck((result.policies?.length ?? 0) > 0, 'PII policies detected for warning');
        break;
      case 'log':
        assertCheck(result.approved, 'PII query approved (PII_ACTION=log)');
        break;
      default:
        console.log(`   Unknown PII_ACTION: ${piiAction}`);
        failures.push(`Unknown PII_ACTION: ${piiAction}`);
    }
  }
  console.log();

  // -----------------------------------------------------------
  // Test 3: SQLi query -- behavior depends on SQLI_ACTION
  // -----------------------------------------------------------
  console.log('Test 3: SQL Injection (UNION SELECT)');
  console.log('-'.repeat(37));
  console.log(`  Expected action: ${sqliAction}`);

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
    switch (sqliAction) {
      case 'block':
        assertCheck(!result.approved, 'SQLi query blocked (SQLI_ACTION=block)');
        assertCheck(!!result.blockReason, 'Block reason provided');
        if (result.blockReason) {
          console.log(`   Block reason: ${result.blockReason}`);
        }
        break;
      case 'warn':
        assertCheck(result.approved, 'SQLi query approved with warning (SQLI_ACTION=warn)');
        break;
      case 'log':
        assertCheck(result.approved, 'SQLi query approved (SQLI_ACTION=log)');
        break;
      default:
        console.log(`   Unknown SQLI_ACTION: ${sqliAction}`);
        failures.push(`Unknown SQLI_ACTION: ${sqliAction}`);
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
    switch (piiAction) {
      case 'block':
        assertCheck(!result.approved, 'Credit card blocked (PII_ACTION=block)');
        break;
      case 'redact':
        assertCheck(result.approved, 'Credit card approved for redaction (PII_ACTION=redact)');
        assertCheck((result.policies?.length ?? 0) > 0, 'Credit card PII detected');
        break;
      case 'warn':
      case 'log':
        assertCheck(result.approved, `Credit card approved (PII_ACTION=${piiAction})`);
        break;
    }
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
    console.log(`  PII_ACTION=${piiAction}, SQLI_ACTION=${sqliAction}, enabled=${policiesEnabled}`);
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => {
      console.log(`   - ${f}`);
    });
    process.exit(1);
  }
}

main();
