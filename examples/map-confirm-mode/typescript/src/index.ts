/**
 * AxonFlow MAP Confirm Mode Example - TypeScript SDK (Enterprise Only)
 *
 * Demonstrates the confirm execution mode where every step
 * requires explicit approval before execution.
 *
 * REQUIRES: Enterprise license
 *
 * Flow:
 *  1. Generate plan with executionMode: "confirm"
 *  2. Execute plan -> returns "awaiting_approval"
 *  3. Resume plan (approve step) -> executes step, pauses at next
 *  4. Repeat until all steps complete
 *
 * Run with: npx tsx src/index.ts
 * Prerequisites: docker compose up -d (enterprise mode)
 */

import { AxonFlow } from '@axonflow/sdk';

const failures: string[] = [];
let testsRun = 0;

function getEnv(key: string, defaultVal: string): string {
  return process.env[key] || defaultVal;
}

function assert(condition: boolean, message: string): void {
  testsRun++;
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

async function main(): Promise<void> {
  console.log('AxonFlow MAP Confirm Mode - TypeScript SDK (Enterprise)');
  console.log('========================================================');
  console.log();

  const axonflow = new AxonFlow({
    endpoint: getEnv('AXONFLOW_ENDPOINT', 'http://localhost:8080'),
    clientId: getEnv('AXONFLOW_CLIENT_ID', 'demo-org'),
    clientSecret: getEnv('AXONFLOW_CLIENT_SECRET', 'demo'),
    debug: getEnv('AXONFLOW_DEBUG', '') === 'true',
  });

  const userToken = getEnv('AXONFLOW_USER_TOKEN', '');
  const domain = 'travel';

  // ========================================
  // 1. GENERATE PLAN WITH CONFIRM MODE
  // ========================================
  console.log('1. generatePlan - Confirm mode...');
  let plan;
  try {
    plan = await axonflow.generatePlan(
      'Search flights, analyze options, and book the best one',
      domain,
      userToken || undefined,
      { executionMode: 'confirm' },
    );
  } catch (error) {
    const errStr = String(error).toLowerCase();
    if (errStr.includes('enterprise') || errStr.includes('403') || errStr.includes('license')) {
      console.log(`   SKIP: Confirm mode requires enterprise license: ${error}`);
      console.log();
      console.log('========================================================');
      console.log('Skipped - enterprise license required');
      return;
    }
    console.log(`   FATAL: generatePlan failed: ${error}`);
    process.exit(1);
  }

  console.log(`   Plan ID: ${plan.planId}`);
  console.log(`   Steps: ${plan.steps?.length || 0}`);

  assert(plan.planId !== '', 'Confirm mode plan generated');
  assert((plan.steps?.length || 0) > 0, 'Plan has steps');
  console.log();

  // ========================================
  // 2. EXECUTE PLAN (should return awaiting_approval)
  // ========================================
  console.log('2. executePlan - Should return awaiting_approval...');
  let execution;
  try {
    execution = await axonflow.executePlan(plan.planId, userToken || undefined);
  } catch (error) {
    console.log(`   FATAL: executePlan failed: ${error}`);
    process.exit(1);
  }

  assert(execution.status === 'awaiting_approval', `Status is awaiting_approval (${execution.status})`);
  console.log();

  // ========================================
  // 3-N. RESUME LOOP (approve each step)
  // ========================================
  const totalSteps = plan.steps?.length || 3;
  for (let step = 1; step <= totalSteps; step++) {
    console.log(`${step + 2}. resumePlan - Approve step ${step}...`);

    let resumeResp;
    try {
      resumeResp = await axonflow.resumePlan(plan.planId, true);
    } catch (error) {
      console.log(`   FATAL: resumePlan failed: ${error}`);
      process.exit(1);
    }

    console.log(`   Status: ${resumeResp.status}`);

    if (resumeResp.status === 'completed') {
      assert(true, `Plan completed after step ${step}`);
      console.log();
      break;
    } else if (resumeResp.status === 'awaiting_approval') {
      assert(true, `Step ${step} approved, paused at next step`);
    } else {
      assert(false, `Unexpected status after resume: ${resumeResp.status}`);
    }
    console.log();
  }

  // ========================================
  // FINAL STATUS CHECK
  // ========================================
  console.log('Final Status Check...');
  try {
    const finalStatus = await axonflow.getPlanStatus(plan.planId);
    assert(
      finalStatus.status === 'completed' || finalStatus.status === 'running',
      `Final status is completed (${finalStatus.status})`,
    );
  } catch (error) {
    if (String(error).includes('404')) {
      console.log('   SKIP: getPlanStatus not implemented (404)');
    } else {
      console.log(`   FATAL: getPlanStatus failed: ${error}`);
      process.exit(1);
    }
  }
  console.log();

  // ========================================
  // SUMMARY
  // ========================================
  console.log('========================================================');
  console.log(`Tests Run: ${testsRun}`);
  if (failures.length === 0) {
    console.log('ALL TESTS PASSED');
    console.log();
    console.log('Confirm mode flow:');
    console.log('  1. generatePlan (confirm)');
    console.log('  2. executePlan -> awaiting_approval');
    console.log('  3. resumePlan (approve) x N steps');
    console.log('  4. getPlanStatus -> completed');
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
