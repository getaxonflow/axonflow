/**
 * AxonFlow Unified Execution Tracking Example - TypeScript
 *
 * This example demonstrates unified execution tracking for both MAP plans
 * and WCP workflows using the AxonFlow TypeScript SDK.
 *
 * Issue #1075 - EPIC #1074: Unified Workflow Infrastructure
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import {
  AxonFlow,
  ExecutionHelpers,
  WorkflowHelpers,
} from '@axonflow/sdk';
import type {
  ExecutionStatus,
  ExecutionType,
  ExecutionStatusValue,
  StepStatusValue,
  UnifiedListExecutionsRequest,
  CreateWorkflowRequest,
  StepGateRequest,
} from '@axonflow/sdk';

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
  }
}

async function main(): Promise<void> {
  console.log('AxonFlow Unified Execution Tracking Example - TypeScript');
  console.log('='.repeat(55));
  console.log();

  // Initialize client
  // WCP endpoints go through the agent (port 8080)
  const endpoint = process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080';
  const clientId = process.env.AXONFLOW_CLIENT_ID || 'demo';
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET || 'demo';

  const client = new AxonFlow({
    endpoint,
    clientId,
    clientSecret,
  });

  // Step 1: Create a WCP workflow to demonstrate unified tracking
  console.log('Creating WCP workflow...');
  let workflow;
  try {
    const request: CreateWorkflowRequest = {
      workflow_name: 'unified-tracking-demo',
      source: 'external',
    };
    workflow = await client.createWorkflow(request);
    console.log(`Workflow ID: ${workflow.workflow_id}`);
    assertCheck(workflow.workflow_id !== undefined && workflow.workflow_id !== '', 'Workflow ID is returned');
    assertCheck(workflow.workflow_name === 'unified-tracking-demo', `Workflow name matches (got: ${workflow.workflow_name})`);
    console.log();
  } catch (err) {
    console.log(`Error creating workflow: ${err}`);
    console.log('Note: WCP endpoints go through the agent (port 8080)');
    failures.push('createWorkflow failed');
    printSummaryAndExit();
    return;
  }

  // Step 2: Complete some steps
  console.log('Completing workflow steps...');

  let completedSteps = 0;
  for (let i = 1; i <= 3; i++) {
    const stepId = `step-${i}`;

    // Check gate
    try {
      const request: StepGateRequest = {
        step_name: `Step ${i}`,
        step_type: 'llm_call',
      };
      const gate = await client.stepGate(workflow.workflow_id, stepId, request);
      console.log(`  Step ${i}: ${gate.decision}`);
      assertCheck(gate.decision !== undefined, `Step ${i} gate returned a decision`);

      // Mark completed if allowed
      if (WorkflowHelpers.gateIsAllowed(gate)) {
        await client.markStepCompleted(workflow.workflow_id, stepId, {
          output: { result: `completed step ${i}` },
        });
        completedSteps++;
      }
    } catch (err) {
      console.log(`  Step ${i} error: ${err}`);
    }
  }
  assertCheck(completedSteps >= 1, `At least 1 step was completed (got ${completedSteps})`);

  // Complete workflow
  try {
    await client.completeWorkflow(workflow.workflow_id);
  } catch (err) {
    console.log(`Error completing workflow: ${err}`);
  }

  console.log();

  // Step 3: Get workflow status using existing API
  console.log('Getting workflow status...');
  try {
    const status = await client.getWorkflow(workflow.workflow_id);
    console.log(`  Workflow: ${status.workflow_name}`);
    console.log(`  Status: ${status.status}`);
    console.log(`  Steps: ${status.steps?.length || 0}`);
    assertCheck(status.workflow_name === 'unified-tracking-demo', `Workflow name matches (got: ${status.workflow_name})`);
    assertCheck(status.status !== undefined, `Workflow status is defined (got: ${status.status})`);
  } catch (err) {
    console.log(`Error getting status: ${err}`);
    failures.push('getWorkflow failed');
  }
  console.log();

  // Step 4: Demonstrate unified execution status types
  console.log('Unified Execution Status Types (SDK v2.7.0):');
  console.log('  ExecutionType constants:');
  console.log(`    - MAP: map_plan`);
  console.log(`    - WCP: wcp_workflow`);
  console.log();
  console.log('  ExecutionStatusValue constants:');
  console.log(`    - Pending: pending`);
  console.log(`    - Running: running`);
  console.log(`    - Completed: completed`);
  console.log(`    - Failed: failed`);
  // v4.3.0: "expired" is now a valid execution status
  console.log(`    - Expired: expired`);
  console.log();
  console.log('  ExecutionHelpers methods:');
  const isTerminalCompleted = ExecutionHelpers.isTerminal('completed');
  const isTerminalRunning = ExecutionHelpers.isTerminal('running');
  const isStepBlockingBlocked = ExecutionHelpers.isStepBlocking('blocked');
  console.log(`    - isTerminal('completed'): ${isTerminalCompleted}`);
  console.log(`    - isTerminal('running'): ${isTerminalRunning}`);
  console.log(`    - isStepBlocking('blocked'): ${isStepBlockingBlocked}`);
  assertCheck(isTerminalCompleted === true, "isTerminal('completed') returns true");
  assertCheck(isTerminalRunning === false, "isTerminal('running') returns false");
  assertCheck(isStepBlockingBlocked === true, "isStepBlocking('blocked') returns true");
  console.log();

  // Step 5: Try unified execution API (may fail if backend not wired)
  console.log('Testing unified execution API...');
  try {
    const execStatus = await client.getExecutionStatus(workflow.workflow_id);
    console.log(`  Execution ID: ${execStatus.execution_id}`);
    console.log(`  Execution Type: ${execStatus.execution_type}`);
    console.log(`  Status: ${execStatus.status}`);
    console.log(`  Progress: ${execStatus.progress_percent.toFixed(1)}%`);
  } catch (err) {
    console.log(`  Note: Unified API returned error: ${err}`);
    console.log('  (This is expected if backend unified handler not yet wired)');
  }
  console.log();

  // Step 6: List executions
  console.log('Listing unified executions...');
  try {
    const listOptions: UnifiedListExecutionsRequest = {
      execution_type: 'wcp_workflow',
      limit: 5,
    };
    const listResult = await client.listUnifiedExecutions(listOptions);
    console.log(`  Found ${listResult.total} WCP executions`);
    for (const exec of listResult.executions || []) {
      console.log(`    - ${exec.execution_id}: ${exec.name} (${exec.status})`);
    }
  } catch (err) {
    console.log(`  Note: List API returned error: ${err}`);
    console.log('  (This is expected if backend unified handler not yet wired)');
  }
  console.log();

  // Step 7: List WCP workflows (native API)
  console.log('Listing WCP workflows...');
  try {
    const workflowsResp = await client.listWorkflows({ limit: 10 });
    console.log(`  Found ${workflowsResp.total} workflows`);
    for (const wf of workflowsResp.workflows || []) {
      console.log(`    - ${wf.workflow_id}: ${wf.workflow_name} (${wf.status})`);
    }
    assertCheck(typeof workflowsResp.total === 'number', 'listWorkflows returns total count');
    assertCheck(Array.isArray(workflowsResp.workflows), 'listWorkflows returns workflows array');
    assertCheck(workflowsResp.total >= 1, `At least 1 workflow exists (got ${workflowsResp.total})`);
  } catch (err) {
    console.log(`  Note: ListWorkflows API returned error: ${err}`);
    failures.push('listWorkflows failed');
  }
  console.log();

  // Step 8: Live SSE Streaming
  console.log('Testing streamExecutionStatus (Live SSE)...');
  try {
    const sseWf = await client.createWorkflow({
      workflow_name: 'sse-streaming-demo',
      source: 'external',
    });
    console.log(`  Created workflow: ${sseWf.workflow_id}`);

    const controller = new AbortController();
    setTimeout(() => controller.abort(), 10000);

    // Execute steps after a short delay to generate SSE events
    const stepPromise = (async () => {
      await new Promise((resolve) => setTimeout(resolve, 500));
      for (let i = 1; i <= 2; i++) {
        const stepId = `step-${i}`;
        await client.stepGate(sseWf.workflow_id, stepId, {
          step_name: `SSE Step ${i}`,
          step_type: 'llm_call',
        });
        await client.markStepCompleted(sseWf.workflow_id, stepId, {
          output: { result: `sse-step-${i}-done` },
        });
      }
      await client.completeWorkflow(sseWf.workflow_id);
    })();

    let eventCount = 0;
    try {
      await client.streamExecutionStatus(sseWf.workflow_id, (status) => {
        eventCount++;
        console.log(`  SSE event ${eventCount}: status=${status.status}, progress=${status.progress_percent?.toFixed(0)}%`);
      }, { signal: controller.signal });
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        // Expected when stream ends
      } else {
        throw err;
      }
    }
    await stepPromise;
    assertCheck(eventCount > 0, `Received ${eventCount} SSE events`);
  } catch (err) {
    console.log(`  Note: SSE streaming returned error: ${err}`);
    console.log('  (SSE streaming may not be supported in this mode)');
  }
  console.log();

  // Step 9: Test cancelExecution (create workflow, then cancel)
  console.log('Testing cancelExecution...');
  try {
    const cancelTest = await client.createWorkflow({
      workflow_name: 'cancel-test-demo',
      source: 'external',
    });
    console.log(`  Created workflow: ${cancelTest.workflow_id}`);
    try {
      await client.cancelExecution(cancelTest.workflow_id, 'testing unified cancel');
      console.log(`  Cancelled workflow: ${cancelTest.workflow_id}`);
      // Verify status
      const cancelStatus = await client.getWorkflow(cancelTest.workflow_id);
      assertCheck(
        cancelStatus.status === 'aborted',
        `Workflow is aborted after cancelExecution (got: ${cancelStatus.status})`,
      );
    } catch (err) {
      console.log(`  Note: cancelExecution returned error: ${err}`);
      console.log('  (Cancel propagation requires unified handler wiring)');
    }
  } catch (err) {
    console.log(`  Error creating cancel test workflow: ${err}`);
  }
  console.log();

  // Step 10: Demonstrate resumeWorkflow (by aborting then resuming)
  console.log('Testing resumeWorkflow...');
  try {
    const resumeTest = await client.createWorkflow({
      workflow_name: 'resume-test-demo',
      source: 'external',
    });
    // Abort the workflow first
    await client.abortWorkflow(resumeTest.workflow_id, 'Testing abort for resume');
    console.log(`  Aborted workflow: ${resumeTest.workflow_id}`);
    // Try to resume it
    try {
      await client.resumeWorkflow(resumeTest.workflow_id);
      console.log(`  Resumed workflow: ${resumeTest.workflow_id}`);
    } catch (err) {
      console.log(`  Note: resumeWorkflow returned error: ${err}`);
      console.log('  (Resume may not be supported for all abort reasons)');
    }
  } catch (err) {
    console.log(`  Error creating resume test workflow: ${err}`);
  }
  console.log();

  console.log('='.repeat(55));
  console.log('Unified Execution Tracking Example Complete!');
  console.log();
  console.log('SDK methods demonstrated:');
  console.log('  WCP Workflow:');
  console.log('    - createWorkflow()');
  console.log('    - stepGate()');
  console.log('    - markStepCompleted()');
  console.log('    - completeWorkflow()');
  console.log('    - getWorkflow()');
  console.log('    - listWorkflows()');
  console.log('    - abortWorkflow()');
  console.log('    - resumeWorkflow()');
  console.log('  Unified Execution:');
  console.log('    - getExecutionStatus()');
  console.log('    - listUnifiedExecutions()');
  console.log('    - cancelExecution()');
  console.log('  SSE Streaming:');
  console.log('    - streamExecutionStatus()');
  console.log('  Helper Types:');
  console.log('    - ExecutionType (map_plan, wcp_workflow)');
  console.log('    - ExecutionStatusValue with isTerminal()');
  console.log('    - StepStatusValue with isTerminal(), isBlocking()');

  printSummaryAndExit();
}

function printSummaryAndExit(): void {
  console.log();
  if (failures.length > 0) {
    console.log(`FAILED: ${failures.length} assertion(s) failed:`);
    failures.forEach((f) => console.log(`  - ${f}`));
  } else {
    console.log('All assertions passed!');
  }
  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
