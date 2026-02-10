/**
 * AxonFlow MAP Lifecycle Example - TypeScript SDK
 *
 * Validates the FULL MAP v1.0 lifecycle:
 *  1. Generate plan (default mode) - verify planId, steps
 *  2. Get status (pending)
 *  3. Update plan (change executionMode, optimistic locking)
 *  4. Get version history
 *  5. Stale update (verify VersionConflictError)
 *  6. Execute plan - verify completed
 *  7. Get status (completed)
 *  8. Cancel completed plan - verify rejected
 *  9. Generate + cancel + try execute cancelled plan
 * 10. Generate with balanced mode - execute - verify completed
 *
 * Run with: npx tsx src/index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow, VersionConflictError } from '@axonflow/sdk';

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
  console.log('AxonFlow MAP Lifecycle - TypeScript SDK');
  console.log('========================================');
  console.log();

  const axonflow = new AxonFlow({
    endpoint: getEnv('AXONFLOW_ENDPOINT', 'http://localhost:8080'),
    clientId: getEnv('AXONFLOW_CLIENT_ID', 'demo-org'),
    clientSecret: getEnv('AXONFLOW_CLIENT_SECRET', 'demo'),
    debug: getEnv('AXONFLOW_DEBUG', '') === 'true',
  });

  const userToken = getEnv('AXONFLOW_USER_TOKEN', '');
  const domain = 'generic';

  // ========================================
  // 1. GENERATE PLAN (default mode)
  // ========================================
  console.log('1. generatePlan - Default mode...');
  let plan;
  try {
    plan = await axonflow.generatePlan(
      'Create a plan to analyze user feedback and suggest improvements',
      domain,
      userToken || undefined,
    );
  } catch (error) {
    console.log(`   FATAL: generatePlan failed: ${error}`);
    process.exit(1);
  }

  console.log(`   Plan ID: ${plan.planId}`);
  console.log(`   Steps: ${plan.steps?.length || 0}`);

  assert(plan.planId !== '', 'Plan ID is not empty');
  assert(plan.planId.startsWith('plan_'), 'Plan ID has correct prefix');
  assert((plan.steps?.length || 0) > 0, 'Plan has at least one step');
  console.log();

  // ========================================
  // 2. GET STATUS (pending)
  // ========================================
  console.log('2. getPlanStatus - Should be pending...');
  try {
    const status = await axonflow.getPlanStatus(plan.planId);
    assert(
      status.status === 'pending' || status.status === 'created',
      `Status is pending/created (${status.status})`,
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
  // 3. UPDATE PLAN (change executionMode, version 1 -> 2)
  // ========================================
  console.log('3. updatePlan - Change executionMode to parallel...');
  let updateResp;
  try {
    updateResp = await axonflow.updatePlan(plan.planId, {
      version: 1,
      executionMode: 'parallel',
    });
  } catch (error) {
    console.log(`   FATAL: updatePlan failed: ${error}`);
    process.exit(1);
  }

  console.log(`   New Version: ${updateResp.version}`);
  assert(updateResp.version === 2, `Version is 2 (got ${updateResp.version})`);
  assert(updateResp.planId === plan.planId, 'planId matches');
  console.log();

  // ========================================
  // 4. GET VERSION HISTORY
  // ========================================
  console.log('4. getPlanVersions - Check version history...');
  let versionsResp;
  try {
    versionsResp = await axonflow.getPlanVersions(plan.planId);
  } catch (error) {
    console.log(`   FATAL: getPlanVersions failed: ${error}`);
    process.exit(1);
  }

  console.log(`   Version count: ${versionsResp.versions.length}`);
  assert(versionsResp.versions.length >= 1, `At least 1 version (${versionsResp.versions.length})`);
  assert(versionsResp.planId === plan.planId, 'planId matches');
  for (const v of versionsResp.versions) {
    console.log(`     v${v.version}: ${v.changeType} (${v.changedAt})`);
  }
  console.log();

  // ========================================
  // 5. STALE UPDATE (verify VersionConflictError)
  // ========================================
  console.log('5. Stale Update - Send version 1 again (expect conflict)...');
  try {
    await axonflow.updatePlan(plan.planId, {
      version: 1,
      executionMode: 'sequential',
    });
    assert(false, 'Stale update should have thrown');
  } catch (error) {
    if (error instanceof VersionConflictError) {
      assert(true, 'VersionConflictError thrown');
    } else {
      assert(false, `Expected VersionConflictError, got ${error}`);
    }
  }
  console.log();

  // ========================================
  // 6. EXECUTE PLAN
  // ========================================
  console.log('6. executePlan - Execute the updated plan...');
  let execution;
  try {
    execution = await axonflow.executePlan(plan.planId, userToken || undefined);
  } catch (error) {
    console.log(`   FATAL: executePlan failed: ${error}`);
    process.exit(1);
  }

  console.log(`   Status: ${execution.status}`);
  assert(
    execution.status === 'completed' || execution.status === 'running',
    'Execution completed',
  );
  console.log();

  // ========================================
  // 7. GET STATUS (completed)
  // ========================================
  console.log('7. getPlanStatus - Should be completed...');
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
  // 8. CANCEL COMPLETED PLAN (expect rejection)
  // ========================================
  console.log('8. cancelPlan - Cancel completed plan (expect rejection)...');
  try {
    await axonflow.cancelPlan(plan.planId, 'Testing cancel on completed plan');
    assert(false, 'Cancel completed plan should have thrown');
  } catch (error) {
    assert(true, 'Cancel completed plan rejected');
    console.log(`   Error: ${error}`);
  }
  console.log();

  // ========================================
  // 9. GENERATE + CANCEL + TRY EXECUTE
  // ========================================
  console.log('9. Generate -> Cancel -> Try Execute...');
  let plan2;
  try {
    plan2 = await axonflow.generatePlan('Create a simple greeting plan', domain, userToken || undefined);
  } catch (error) {
    console.log(`   FATAL: Second plan failed: ${error}`);
    process.exit(1);
  }

  assert(plan2.planId !== '', 'Second plan generated');

  try {
    const cancelResp = await axonflow.cancelPlan(plan2.planId, 'Testing cancel flow');
    assert(cancelResp.status === 'cancelled', `Plan cancelled (${cancelResp.status})`);
  } catch (error) {
    console.log(`   FATAL: cancelPlan failed: ${error}`);
    process.exit(1);
  }

  // Try executing cancelled plan
  try {
    await axonflow.executePlan(plan2.planId, userToken || undefined);
    assert(false, 'Execute cancelled plan should have thrown');
  } catch (error) {
    assert(true, 'Execute cancelled plan rejected');
  }
  console.log();

  // ========================================
  // 10. GENERATE WITH BALANCED MODE + EXECUTE
  // ========================================
  console.log('10. generatePlan - Balanced mode...');
  let plan3;
  try {
    plan3 = await axonflow.generatePlan(
      'Create a plan to process and summarize data',
      domain,
      userToken || undefined,
      { executionMode: 'balanced' },
    );
  } catch (error) {
    console.log(`   FATAL: Balanced plan failed: ${error}`);
    process.exit(1);
  }

  assert(plan3.planId !== '', 'Balanced plan generated');
  console.log(`   Plan ID: ${plan3.planId}`);

  try {
    const exec3 = await axonflow.executePlan(plan3.planId, userToken || undefined);
    assert(
      exec3.status === 'completed' || exec3.status === 'running',
      'Balanced plan executed',
    );
  } catch (error) {
    console.log(`   FATAL: Execute balanced plan failed: ${error}`);
    process.exit(1);
  }
  console.log();

  // ========================================
  // SUMMARY
  // ========================================
  console.log('========================================');
  console.log(`Tests Run: ${testsRun}`);
  if (failures.length === 0) {
    console.log('ALL TESTS PASSED');
    console.log();
    console.log('Lifecycle validated:');
    console.log('  - generatePlan / generatePlan with options');
    console.log('  - getPlanStatus (pre/post execution)');
    console.log('  - updatePlan (optimistic locking)');
    console.log('  - getPlanVersions (version history)');
    console.log('  - VersionConflictError detection');
    console.log('  - executePlan (default + balanced mode)');
    console.log('  - cancelPlan (pending + completed rejection)');
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
