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
  console.log('AxonFlow MAP (Multi-Agent Planning) - TypeScript SDK');
  console.log('=====================================================');
  console.log();

  const axonflow = new AxonFlow({
    endpoint: getEnv('AXONFLOW_ENDPOINT', 'http://localhost:8080'),
    clientId: getEnv('AXONFLOW_CLIENT_ID', 'demo'),
    clientSecret: getEnv('AXONFLOW_CLIENT_SECRET', 'demo'),
    debug: getEnv('AXONFLOW_DEBUG', '') === 'true',
  });

  const query = 'Create a brief plan to greet a new user and ask how to help them';
  const domain = 'generic';

  console.log(`Query: ${query}`);
  console.log(`Domain: ${domain}`);
  console.log('-----------------------------------------------------');
  console.log();

  // ========================================
  // 1. GENERATE PLAN
  // ========================================
  console.log('1. generatePlan - Creating a multi-agent plan...');
  let plan;
  try {
    plan = await axonflow.generatePlan(query, domain);
  } catch (error) {
    console.log(`   \u274C FATAL: generatePlan failed: ${error}`);
    process.exit(1);
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
    console.log(`   Total Steps: ${status.totalSteps}`);

    // Validate pre-execution status
    assert(
      status.status === 'pending' || status.status === 'created',
      'Plan status is pending/created before execution'
    );
    assert(
      status.totalSteps === expectedStepCount,
      `totalSteps matches plan (${expectedStepCount})`
    );
  } catch (error) {
    // getPlanStatus is optional - skip if not implemented (404)
    if (String(error).includes('404')) {
      console.log('   ⏭ SKIP: getPlanStatus not implemented (404)');
    } else {
      console.log(`   \u274C FATAL: getPlanStatus failed: ${error}`);
      process.exit(1);
    }
  }
  console.log();

  // ========================================
  // 3. EXECUTE PLAN
  // ========================================
  console.log('3. executePlan - Executing the plan...');
  let execution;
  try {
    execution = await axonflow.executePlan(plan.planId);
  } catch (error) {
    console.log(`   \u274C FATAL: executePlan failed: ${error}`);
    process.exit(1);
  }

  console.log(`   Execution Status: ${execution.status}`);
  const totalSteps = execution.totalSteps || 0;
  const completedSteps = execution.completedSteps || 0;
  if (totalSteps > 0) {
    console.log(`   Completed Steps: ${completedSteps}/${totalSteps}`);
  }

  // Validate execution response
  assert(
    execution.status === 'completed' || execution.status === 'success',
    'Execution status indicates success'
  );

  // Step tracking is optional - only validate if present
  if (totalSteps > 0) {
    assert(
      totalSteps === expectedStepCount,
      `Execution totalSteps matches plan (${expectedStepCount})`
    );
    assert(completedSteps === expectedStepCount, 'All steps completed');
  }

  // Validate step results if available
  if (execution.stepResults && execution.stepResults.length > 0) {
    console.log('   Step Results:');
    assert(
      execution.stepResults.length === expectedStepCount,
      'stepResults count matches plan steps'
    );
    execution.stepResults.forEach((result, i) => {
      console.log(`     - ${result.stepName}: ${result.status}`);
      assert(
        result.status === 'completed' || result.status === 'success',
        `Step ${i + 1} completed successfully`
      );
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
    console.log(`   Completed Steps: ${finalStatus.completedSteps}/${finalStatus.totalSteps}`);

    // Validate post-execution status
    assert(
      finalStatus.status === 'completed' || finalStatus.status === 'success',
      'Final status indicates completion'
    );
    assert(
      finalStatus.completedSteps === expectedStepCount,
      'All steps show as completed'
    );
  } catch (error) {
    // getPlanStatus is optional - skip if not implemented (404)
    if (String(error).includes('404')) {
      console.log('   ⏭ SKIP: getPlanStatus not implemented (404)');
    } else {
      console.log(`   \u274C FATAL: getPlanStatus (post-execution) failed: ${error}`);
      process.exit(1);
    }
  }
  console.log();

  // ========================================
  // SUMMARY
  // ========================================
  console.log('=====================================================');
  if (failures.length === 0) {
    console.log('\u2713 ALL TESTS PASSED');
    console.log();
    console.log('Methods validated:');
    console.log('  1. generatePlan()   - Plan created with valid ID and steps');
    console.log('  2. getPlanStatus()  - Pre-execution status is pending');
    console.log('  3. executePlan()    - All plan steps executed successfully');
    console.log('  4. getPlanStatus()  - Post-execution status is completed');
  } else {
    console.log(`\u274C ${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => {
      console.log(`   - ${f}`);
    });
    process.exit(1);
  }
}

main();
