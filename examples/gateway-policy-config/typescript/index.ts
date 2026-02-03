/**
 * AxonFlow Gateway Policy Configuration - TypeScript SDK
 *
 * This example demonstrates and VALIDATES per-mode Gateway policy configuration.
 * AxonFlow's static policies can be configured per-mode using environment variables.
 * This example validates the CURRENT configuration by sending test queries through
 * the Gateway mode API (getPolicyApprovedContext + proxyLLMCall) and checking that
 * the Agent responds according to the configured policy actions.
 *
 * Environment variables (must match Agent-side config):
 *   GATEWAY_PII_ACTION   = block | redact | log  (default: redact)
 *   GATEWAY_SQLI_ACTION  = block | warn | log    (default: block)
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

function getEnvWithFallback(key: string, fallbackKey: string, defaultVal: string): string {
  return process.env[key] || process.env[fallbackKey] || defaultVal;
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

  // Read expected policy actions (with fallback keys, matching Go version)
  const piiAction = getEnvWithFallback('GATEWAY_PII_ACTION', 'PII_ACTION', 'redact').toLowerCase();
  const sqliAction = getEnvWithFallback('GATEWAY_SQLI_ACTION', 'SQLI_ACTION', 'block').toLowerCase();
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
  // Test 2: PII query (SSN) -- depends on GATEWAY_PII_ACTION
  // -----------------------------------------------------------
  console.log("Test 2: PII Query (SSN '123-45-6789')");
  console.log('-'.repeat(38));
  console.log(`  Expected action: ${piiAction}`);

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
    switch (piiAction) {
      case 'block':
        assertCheck(!result.approved, 'PII blocked (GATEWAY_PII_ACTION=block)');
        assertCheck(
          result.blockReason !== undefined && result.blockReason !== '',
          'Block reason provided'
        );
        if (result.blockReason) {
          console.log(`   Block reason: ${result.blockReason}`);
        }
        break;
      case 'redact':
        assertCheck(result.approved, 'PII approved for redaction (GATEWAY_PII_ACTION=redact)');
        assertCheck(
          result.policies !== undefined && result.policies.length > 0,
          'PII policies detected'
        );
        if (result.policies) {
          console.log(`   Policies: ${result.policies}`);
        }
        break;
      case 'warn':
        assertCheck(result.approved, 'PII approved with warning (GATEWAY_PII_ACTION=warn)');
        assertCheck(
          result.policies !== undefined && result.policies.length > 0,
          'PII policies detected'
        );
        break;
      case 'log':
        assertCheck(result.approved, 'PII approved (GATEWAY_PII_ACTION=log)');
        break;
      default:
        console.log(`   \u274C Unknown GATEWAY_PII_ACTION: ${piiAction}`);
        failures.push(`Unknown GATEWAY_PII_ACTION: ${piiAction}`);
    }
  }
  console.log();

  // -----------------------------------------------------------
  // Test 3: SQLi query -- depends on GATEWAY_SQLI_ACTION
  // -----------------------------------------------------------
  console.log('Test 3: SQLi Query (UNION SELECT)');
  console.log('-'.repeat(34));
  console.log(`  Expected action: ${sqliAction}`);

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
    switch (sqliAction) {
      case 'block':
        assertCheck(!result.approved, 'SQLi blocked (GATEWAY_SQLI_ACTION=block)');
        assertCheck(
          result.blockReason !== undefined && result.blockReason !== '',
          'Block reason provided'
        );
        if (result.blockReason) {
          console.log(`   Block reason: ${result.blockReason}`);
        }
        break;
      case 'warn':
        assertCheck(result.approved, 'SQLi approved with warning (GATEWAY_SQLI_ACTION=warn)');
        break;
      case 'log':
        assertCheck(result.approved, 'SQLi approved (GATEWAY_SQLI_ACTION=log)');
        break;
      default:
        console.log(`   \u274C Unknown GATEWAY_SQLI_ACTION: ${sqliAction}`);
        failures.push(`Unknown GATEWAY_SQLI_ACTION: ${sqliAction}`);
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
    console.log(`  PII_ACTION=${piiAction}, SQLI_ACTION=${sqliAction}, enabled=${policiesEnabled}`);
  } else {
    console.log(`\u274C ${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => {
      console.log(`   - ${f}`);
    });
    process.exit(1);
  }
}

main();
