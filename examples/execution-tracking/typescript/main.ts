/**
 * AxonFlow Unified Execution Tracking Example - TypeScript
 *
 * This example demonstrates unified execution tracking for both MAP plans
 * and WCP workflows using the AxonFlow TypeScript SDK.
 *
 * Issue #1075 - EPIC #1074: Unified Workflow Infrastructure
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

async function main(): Promise<void> {
  console.log('AxonFlow Unified Execution Tracking Example - TypeScript');
  console.log('='.repeat(55));
  console.log();

  // Initialize client
  // WCP endpoints are on the orchestrator (port 8081)
  const endpoint = process.env.AXONFLOW_ENDPOINT || 'http://localhost:8081';
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
      total_steps: 3,
    };
    workflow = await client.createWorkflow(request);
    console.log(`Workflow ID: ${workflow.workflow_id}`);
    console.log();
  } catch (err) {
    console.log(`Error creating workflow: ${err}`);
    console.log('Note: WCP endpoints are on the orchestrator (port 8081)');
    return;
  }

  // Step 2: Complete some steps
  console.log('Completing workflow steps...');

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

      // Mark completed if allowed
      if (WorkflowHelpers.gateIsAllowed(gate)) {
        await client.markStepCompleted(workflow.workflow_id, stepId, {
          output: { result: `completed step ${i}` },
        });
      }
    } catch (err) {
      console.log(`  Step ${i} error: ${err}`);
    }
  }

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
  } catch (err) {
    console.log(`Error getting status: ${err}`);
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
  console.log();
  console.log('  ExecutionHelpers methods:');
  console.log(`    - isTerminal('completed'): ${ExecutionHelpers.isTerminal('completed')}`);
  console.log(`    - isTerminal('running'): ${ExecutionHelpers.isTerminal('running')}`);
  console.log(`    - isStepBlocking('blocked'): ${ExecutionHelpers.isStepBlocking('blocked')}`);
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
  } catch (err) {
    console.log(`  Note: ListWorkflows API returned error: ${err}`);
  }
  console.log();

  // Step 8: Demonstrate resumeWorkflow (by aborting then resuming)
  console.log('Testing resumeWorkflow...');
  try {
    const resumeTest = await client.createWorkflow({
      workflow_name: 'resume-test-demo',
      source: 'external',
      total_steps: 2,
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
  console.log('  Helper Types:');
  console.log('    - ExecutionType (map_plan, wcp_workflow)');
  console.log('    - ExecutionStatusValue with isTerminal()');
  console.log('    - StepStatusValue with isTerminal(), isBlocking()');
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
