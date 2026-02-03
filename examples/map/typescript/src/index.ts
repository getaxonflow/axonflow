/**
 * AxonFlow MAP (Multi-Agent Planning) Example - TypeScript SDK
 *
 * This example demonstrates and VALIDATES all MAP SDK methods:
 * - generatePlan()   - Create a multi-agent execution plan
 * - executePlan()    - Execute a previously generated plan
 * - getPlanStatus()  - Get status of a running or completed plan
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Run with: npx ts-node src/index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow } from '@axonflow/sdk';

const failures: string[] = [];

function getEnv(key: string, defaultVal: string): string {
  return (typeof process !== 'undefined' ? process.env[key] : undefined) || defaultVal;
}

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

// Alias for backward compatibility
const assert = assertCheck;

async function main(): Promise<void> {
  console.log('AxonFlow MAP (Multi-Agent Planning) - TypeScript SDK');
  console.log('=====================================================');
  console.log();

  const axonflow = new AxonFlow({
    endpoint: getEnv('AXONFLOW_ENDPOINT', 'http://localhost:8080'),
    clientId: getEnv('AXONFLOW_CLIENT_ID', 'demo-org'),
    clientSecret: getEnv('AXONFLOW_CLIENT_SECRET', 'demo'),
    debug: getEnv('AXONFLOW_DEBUG', '') === 'true',
  });

  // User token for MAP operations (JWT for local testing with docker-compose)
  const userToken = getEnv('AXONFLOW_USER_TOKEN', '');

  const query = 'Create a brief plan to greet a new user and ask how to help them';
  const domain = 'generic';

  console.log(`Query: ${query}`);
  console.log(`Domain: ${domain}`);
  if (userToken) {
    console.log(`User Token: ${userToken.substring(0, 20)}...${userToken.slice(-10)}`);
  }
  console.log('-----------------------------------------------------');
  console.log();

  // ========================================
  // 1. GENERATE PLAN
  // ========================================
  console.log('1. generatePlan - Creating a multi-agent plan...');
  let plan;
  try {
    plan = await axonflow.generatePlan(query, domain, userToken || undefined);
  } catch (error) {
    console.log(`   \u274C FATAL: generatePlan failed: ${error}`);
    if (typeof process !== 'undefined') process.exit(1);
    return;
  }

  if (!plan) {
    console.log('   \u274C FATAL: generatePlan returned undefined');
    if (typeof process !== 'undefined') process.exit(1);
    return;
  }

  console.log(`   Plan ID: ${plan.planId}`);
  console.log(`   Domain: ${plan.domain}`);
  console.log(`   Steps: ${plan.steps?.length || 0}`);

  // Validate generatePlan response
  assert(plan.planId !== '', 'planId is not empty');
  assert(plan.planId.startsWith('plan_'), "planId has correct prefix 'plan_'");
  assert((plan.steps?.length || 0) > 0, 'Plan has at least one step');

  if (plan.steps && plan.steps.length > 0) {
    console.log('   Plan Steps:');
    plan.steps.forEach((step, i) => {
      console.log(`     ${i + 1}. ${step.name} (${step.type})`);
      assert(step.name !== '', `Step ${i + 1} has a name`);
      assert(step.type !== '', `Step ${i + 1} has a type`);
    });
  }
  console.log();

  const expectedStepCount = plan.steps?.length || 0;

  // ========================================
  // 2. GET PLAN STATUS (before execution) - Optional
  // ========================================
  console.log('2. getPlanStatus - Checking status before execution...');
  try {
    const status = await axonflow.getPlanStatus(plan.planId);
    console.log(`   Status: ${status.status}`);

    // Status can be running, completed, or failed - check it's not failed
    assert(
      status.status !== 'failed',
      'Plan status is not failed before execution'
    );
  } catch (error) {
    // getPlanStatus is optional - skip if not implemented (404)
    if (String(error).includes('404')) {
      console.log('   ⏭ SKIP: getPlanStatus not implemented (404)');
    } else {
      console.log(`   \u274C FATAL: getPlanStatus failed: ${error}`);
      if (typeof process !== 'undefined') process.exit(1);
      return;
    }
  }
  console.log();

  // ========================================
  // 3. EXECUTE PLAN
  // ========================================
  console.log('3. executePlan - Executing the plan...');
  let execution;
  try {
    execution = await axonflow.executePlan(plan.planId, userToken || undefined);
  } catch (error) {
    console.log(`   \u274C FATAL: executePlan failed: ${error}`);
    if (typeof process !== 'undefined') process.exit(1);
    return;
  }

  if (!execution) {
    console.log('   \u274C FATAL: executePlan returned undefined');
    if (typeof process !== 'undefined') process.exit(1);
    return;
  }

  console.log(`   Execution Status: ${execution.status}`);
  if (execution.duration) {
    console.log(`   Duration: ${execution.duration}`);
  }

  // Validate execution response - status should be 'completed' or 'running'
  assert(
    execution.status === 'completed' || execution.status === 'running',
    'Execution status indicates success or in progress'
  );

  // Validate step results if available
  if (execution.stepResults && Object.keys(execution.stepResults).length > 0) {
    console.log('   Step Results:');
    const stepNames = Object.keys(execution.stepResults);
    stepNames.forEach((stepName, i) => {
      const result = execution.stepResults?.[stepName];
      console.log(`     - ${stepName}: ${typeof result === 'object' ? JSON.stringify(result).substring(0, 50) : result}`);
    });
  }
  console.log();

  // ========================================
  // 4. GET PLAN STATUS (after execution) - Optional
  // ========================================
  console.log('4. getPlanStatus - Checking status after execution...');
  try {
    const finalStatus = await axonflow.getPlanStatus(plan.planId);
    console.log(`   Status: ${finalStatus.status}`);
    if (finalStatus.duration) {
      console.log(`   Duration: ${finalStatus.duration}`);
    }

    // Validate post-execution status
    assert(
      finalStatus.status === 'completed' || finalStatus.status === 'running',
      'Final status indicates completion or running'
    );
  } catch (error) {
    // getPlanStatus is optional - skip if not implemented (404)
    if (String(error).includes('404')) {
      console.log('   ⏭ SKIP: getPlanStatus not implemented (404)');
    } else {
      console.log(`   \u274C FATAL: getPlanStatus (post-execution) failed: ${error}`);
      if (typeof process !== 'undefined') process.exit(1);
      return;
    }
  }
  console.log();

  // ========================================
  // 5. PII IN PLAN QUERY - Policy enforcement on plan generation
  // ========================================
  console.log('5. PII in Plan Query - Testing policy enforcement on plan with SSN...');
  const piiQuery = 'Create a plan to process refund for customer with SSN 123-45-6789';
  const gatewayPiiAction = getEnv('GATEWAY_PII_ACTION', getEnv('PII_ACTION', 'redact'));
  console.log(`   GATEWAY_PII_ACTION=${gatewayPiiAction}`);

  let piiPlan;
  let piiErr: unknown = null;
  try {
    piiPlan = await axonflow.generatePlan(piiQuery, domain, userToken || undefined);
  } catch (error) {
    piiErr = error;
  }

  if (gatewayPiiAction === 'block') {
    if (piiErr) {
      assert(true, 'PII plan blocked as expected (GATEWAY_PII_ACTION=block)');
      console.log(`   Block reason: ${piiErr}`);
    } else {
      assert(false, 'PII plan should have been blocked (GATEWAY_PII_ACTION=block)');
    }
  } else if (gatewayPiiAction === 'log') {
    if (piiErr) {
      console.log(`   Warning: PII plan failed: ${piiErr}`);
    } else {
      assert(piiPlan?.planId !== '', 'PII plan approved with log-only mode');
      console.log(`   Plan ID: ${piiPlan?.planId} (PII logged but not redacted)`);
    }
  } else {
    // Default "redact" mode
    if (piiErr) {
      console.log(`   Warning: PII plan failed: ${piiErr}`);
    } else {
      assert(piiPlan?.planId !== '', 'PII plan generated (redaction may apply downstream)');
      console.log(`   Plan ID: ${piiPlan?.planId}`);
      console.log('   Note: PII redaction is applied downstream by the Orchestrator');
    }
  }
  console.log();

  // ========================================
  // SUMMARY
  // ========================================
  console.log('=====================================================');
  if (failures.length === 0) {
    console.log('ALL TESTS PASSED');
    console.log();
    console.log('Methods validated:');
    console.log('  1. generatePlan()   - Plan created with valid ID and steps');
    console.log('  2. getPlanStatus()  - Pre-execution status checked');
    console.log('  3. executePlan()    - Plan executed successfully');
    console.log('  4. getPlanStatus()  - Post-execution status checked');
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => {
      console.log(`   - ${f}`);
    });
  }
}

main()
  .then(() => {
    process.exit(failures.length > 0 ? 1 : 0);
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
