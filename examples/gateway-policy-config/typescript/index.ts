/**
 * AxonFlow Gateway Policy Configuration - TypeScript SDK
 *
 * This example demonstrates and VALIDATES per-mode Gateway policy configuration.
 * This example sends test queries through the Gateway mode API
 * (getPolicyApprovedContext + proxyLLMCall) and checks that the Agent responds
 * according to the shipped policy actions.
 *
 * v11: the stored policy action decides. GATEWAY_PII_ACTION, GATEWAY_SQLI_ACTION,
 * PII_ACTION and SQLI_ACTION no longer set an action (ignored, with a boot WARN).
 * The shipped request-phase actions exercised here:
 *   sys_pii_ssn = warn (approved, policy id in policies)
 *   sys_sqli_*  = warn (approved, policy id in policies)
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
    console.log(`   \u2713 PASS: ${message}`);
  } else {
    console.log(`   \u274C FAIL: ${message}`);
    failures.push(message);
  }
}

async function main(): Promise<void> {
  console.log('AxonFlow Gateway Policy Configuration - TypeScript SDK');
  console.log('='.repeat(54));
  console.log();

  // Detection actions come from the stored policy rows (no org override
  // recorded), not from the environment.
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
  // Test 1: Safe query -- always approved
  // -----------------------------------------------------------
  console.log('Test 1: Safe Query Pre-Check');
  console.log('-'.repeat(28));

  let result;
  try {
    result = await axonflow.getPolicyApprovedContext({
      userToken: '',
      query: 'What are the best practices for deploying AI models?',
    });
  } catch (error) {
    console.log(`   \u274C FATAL: getPolicyApprovedContext failed: ${error}`);
    process.exit(1);
  }

  assertCheck(result.approved, 'Safe query is approved');
  assertCheck(result.contextId !== undefined && result.contextId !== '', 'Context ID returned');
  console.log();

  // -----------------------------------------------------------
  // Test 2: PII query (SSN) -- sys_pii_ssn stores warn for the request phase
  // -----------------------------------------------------------
  console.log("Test 2: PII Query (SSN '123-45-6789')");
  console.log('-'.repeat(38));
  console.log('  Expected action: warn (stored)');

  try {
    result = await axonflow.getPolicyApprovedContext({
      userToken: '',
      query: 'Look up the customer with SSN 123-45-6789 and return their balance',
    });
  } catch (error) {
    console.log(`   \u274C FATAL: Pre-check failed: ${error}`);
    process.exit(1);
  }

  if (policiesEnabled === 'false') {
    assertCheck(result.approved, 'PII approved (static policies disabled)');
    assertCheck(
      !result.policies || result.policies.length === 0,
      'No policies matched (disabled)'
    );
  } else {
    // warn approves the request and reports the matched policy
    assertCheck(result.approved, 'PII approved with a warning (stored action: warn)');
    assertCheck(hasPolicyPrefix(result.policies, 'sys_pii_'), 'PII policy detected (sys_pii_* in policies)');
    if (result.policies) {
      console.log(`   Policies: ${result.policies}`);
    }
    if (!result.approved) {
      console.log(`   Block reason: ${result.blockReason} (an org pii=block override or an edited policy action is in force)`);
    }
  }
  console.log();

  // -----------------------------------------------------------
  // Test 3: SQLi query -- every sys_sqli_* policy stores warn
  // -----------------------------------------------------------
  console.log('Test 3: SQLi Query (UNION SELECT)');
  console.log('-'.repeat(34));
  console.log('  Expected action: warn (stored)');

  try {
    result = await axonflow.getPolicyApprovedContext({
      userToken: '',
      query: 'Run this: SELECT name FROM users UNION SELECT password FROM admin_users',
    });
  } catch (error) {
    console.log(`   \u274C FATAL: Pre-check failed: ${error}`);
    process.exit(1);
  }

  if (policiesEnabled === 'false') {
    assertCheck(result.approved, 'SQLi approved (static policies disabled)');
  } else {
    // SQL injection warns by default; it is not blocked
    assertCheck(result.approved, 'SQLi approved with a warning (stored action: warn)');
    assertCheck(hasPolicyPrefix(result.policies, 'sys_sqli_'), 'SQLi policy detected (sys_sqli_* in policies)');
    if (result.policies) {
      console.log(`   Policies: ${result.policies}`);
    }
    if (!result.approved) {
      console.log(`   Block reason: ${result.blockReason} (an org sqli=block override or an edited policy action is in force)`);
    }
  }
  console.log();

  // -----------------------------------------------------------
  // Test 4: ProxyLLMCall -- end-to-end governed LLM call
  // -----------------------------------------------------------
  console.log('Test 4: ProxyLLMCall (End-to-End)');
  console.log('-'.repeat(33));

  let llmResp;
  try {
    llmResp = await axonflow.proxyLLMCall({
      userToken: '',
      query: 'Explain cloud computing in one sentence.',
      requestType: 'chat',
    });
  } catch (error) {
    console.log(`   \u274C FATAL: proxyLLMCall failed: ${error}`);
    process.exit(1);
  }

  assertCheck(llmResp.success, 'ProxyLLMCall succeeded');
  assertCheck(!llmResp.blocked, 'Safe LLM call was not blocked');
  // LLM response text is in result or data.data (nested)
  let responseText = llmResp.result || '';
  if (!responseText && llmResp.data && typeof llmResp.data === 'object') {
    responseText = (llmResp.data as any).data || '';
  }
  assertCheck(responseText !== '', 'LLM response is not empty');
  if (responseText) {
    console.log(`   Response: ${responseText.substring(0, 80)}...`);
  }
  console.log();

  // -----------------------------------------------------------
  // Summary
  // -----------------------------------------------------------
  console.log('='.repeat(54));
  if (failures.length === 0) {
    console.log('\u2713 ALL TESTS PASSED');
    console.log();
    console.log('Gateway policy config validated:');
    console.log(`  shipped stored actions (PII warn, SQLi warn), enabled=${policiesEnabled}`);
  } else {
    console.log(`\u274C ${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => {
      console.log(`   - ${f}`);
    });
    process.exit(1);
  }
}

main();
