/**
 * AxonFlow Execution Replay - TypeScript SDK
 *
 * This example demonstrates and VALIDATES all Execution Replay SDK methods:
 * 1. listExecutions()         - List all workflow executions
 * 2. getExecution()           - Get detailed execution information
 * 3. getExecutionTimeline()   - View execution timeline
 * 4. exportExecution()        - Export execution for compliance
 *
 * VALIDATION: This example exits with code 1 if any API call fails.
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
  console.log('AxonFlow Execution Replay - TypeScript SDK');
  console.log('='.repeat(44));
  console.log();

  const client = new AxonFlow({
    endpoint: getEnv('AXONFLOW_ENDPOINT', 'http://localhost:8080'),
    clientId: getEnv('AXONFLOW_CLIENT_ID', 'demo'),
  clientSecret: getEnv('AXONFLOW_CLIENT_SECRET', 'demo'),
    debug: getEnv('AXONFLOW_DEBUG', '') === 'true',
  });

  // ========================================
  // 1. LIST EXECUTIONS
  // ========================================
  console.log('1. listExecutions - Listing workflow executions...');
  let listResult;
  try {
    listResult = await client.listExecutions({ limit: 10 });
  } catch (error) {
    console.log(`   \u274C FATAL: listExecutions failed: ${error}`);
    process.exit(1);
  }

  assert(listResult.total >= 0, 'total is a valid count');
  console.log(`   Total executions: ${listResult.total}`);

  if (listResult.executions.length > 0) {
    console.log('   Recent executions:');
    for (const exec of listResult.executions.slice(0, 3)) {
      console.log(
        `     - ${exec.requestId}: ${exec.workflowName || 'N/A'} ` +
          `(${exec.completedSteps}/${exec.totalSteps} steps, status=${exec.status})`
      );
      assert(exec.requestId !== '', 'Execution has valid requestId');
    }
  } else {
    console.log('   No executions found (run a workflow first)');
  }
  console.log();

  // Continue with detailed validation if executions exist
  if (listResult.executions.length > 0) {
    const executionId = listResult.executions[0].requestId;

    // ========================================
    // 2. GET EXECUTION DETAILS
    // ========================================
    console.log('2. getExecution - Getting execution details...');
    let execDetail;
    try {
      execDetail = await client.getExecution(executionId);
    } catch (error) {
      console.log(`   \u274C FATAL: getExecution failed: ${error}`);
      process.exit(1);
    }

    assert(execDetail.summary.requestId === executionId, 'Summary requestId matches');
    assert(execDetail.summary.status !== '', 'Summary has valid status');
    assert(execDetail.summary.totalSteps >= 0, 'Summary has valid totalSteps');

    console.log(`   Execution: ${execDetail.summary.requestId}`);
    console.log(`   Status: ${execDetail.summary.status}`);
    console.log(
      `   Steps: ${execDetail.summary.completedSteps}/${execDetail.summary.totalSteps} completed`
    );
    console.log(`   Total Tokens: ${execDetail.summary.totalTokens}`);
    console.log(`   Total Cost: $${execDetail.summary.totalCostUsd.toFixed(6)}`);
    console.log();

    // ========================================
    // 3. GET EXECUTION TIMELINE
    // ========================================
    console.log('3. getExecutionTimeline - Getting timeline view...');
    let timeline;
    try {
      timeline = await client.getExecutionTimeline(executionId);
    } catch (error) {
      console.log(`   \u274C FATAL: getExecutionTimeline failed: ${error}`);
      process.exit(1);
    }

    assert(Array.isArray(timeline), 'Timeline returns valid array');
    console.log(`   Timeline entries: ${timeline.length}`);
    for (const entry of timeline.slice(0, 3)) {
      const errorFlag = entry.hasError ? ' [ERROR]' : '';
      console.log(`     [${entry.stepIndex}] ${entry.stepName}: ${entry.status}${errorFlag}`);
    }
    console.log();

    // ========================================
    // 4. EXPORT EXECUTION
    // ========================================
    console.log('4. exportExecution - Exporting for compliance...');
    let exportData;
    try {
      exportData = await client.exportExecution(executionId, {
        includeInput: true,
        includeOutput: true,
      });
    } catch (error) {
      console.log(`   \u274C FATAL: exportExecution failed: ${error}`);
      process.exit(1);
    }

    assert(exportData !== null && exportData !== undefined, 'Export returns valid data');
    let prettyExport = JSON.stringify(exportData, null, 2);
    if (prettyExport.length > 300) {
      prettyExport = prettyExport.substring(0, 300) + '\n     ... (truncated)';
    }
    console.log(`   Export preview:\n${prettyExport}`);
    console.log();
  }

  // ========================================
  // SUMMARY
  // ========================================
  console.log('='.repeat(44));
  if (failures.length === 0) {
    console.log('\u2713 ALL TESTS PASSED');
    console.log();
    console.log('Methods validated:');
    console.log('  1. listExecutions()         - List with pagination');
    console.log('  2. getExecution()           - Get full details');
    console.log('  3. getExecutionTimeline()   - Get timeline view');
    console.log('  4. exportExecution()        - Export for compliance');
  } else {
    console.log(`\u274C ${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => {
      console.log(`   - ${f}`);
    });
    process.exit(1);
  }
}

main();
