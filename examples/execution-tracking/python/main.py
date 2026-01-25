#!/usr/bin/env python3
"""
AxonFlow Unified Execution Tracking Example - Python

This example demonstrates unified execution tracking for both MAP plans
and WCP workflows using the AxonFlow Python SDK.

Issue #1075 - EPIC #1074: Unified Workflow Infrastructure
"""

import os
from axonflow import (
    AxonFlow,
    ExecutionStatus,
    ExecutionStatusValue,
    ExecutionType,
    StepStatusValue,
    UnifiedListExecutionsRequest,
    CreateWorkflowRequest,
    WorkflowSource,
    StepGateRequest,
    StepType,
    MarkStepCompletedRequest,
    ListWorkflowsOptions,
)


def main():
    print("AxonFlow Unified Execution Tracking Example - Python")
    print("=" * 55)
    print()

    # Initialize client
    # WCP endpoints are on the orchestrator (port 8081)
    endpoint = os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8081")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "demo")

    client = AxonFlow.sync(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
    )

    # Step 1: Create a WCP workflow to demonstrate unified tracking
    print("Creating WCP workflow...")
    try:
        workflow = client.create_workflow(CreateWorkflowRequest(
            workflow_name="unified-tracking-demo",
            source=WorkflowSource.EXTERNAL,
            total_steps=3,
        ))
        print(f"Workflow ID: {workflow.workflow_id}")
        print()
    except Exception as e:
        print(f"Error creating workflow: {e}")
        print("Note: WCP endpoints are on the orchestrator (port 8081)")
        return

    # Step 2: Complete some steps
    print("Completing workflow steps...")

    for i in range(1, 4):
        step_id = f"step-{i}"

        # Check gate
        try:
            gate = client.step_gate(
                workflow.workflow_id,
                step_id,
                StepGateRequest(
                    step_name=f"Step {i}",
                    step_type=StepType.LLM_CALL,
                ),
            )
            print(f"  Step {i}: {gate.decision.value}")
        except Exception as e:
            print(f"  Step {i} gate error: {e}")
            continue

        # Mark completed
        try:
            client.mark_step_completed(
                workflow.workflow_id,
                step_id,
                MarkStepCompletedRequest(
                    output={"result": f"completed step {i}"},
                ),
            )
        except Exception as e:
            print(f"  Step {i} complete error: {e}")

    # Complete workflow
    try:
        client.complete_workflow(workflow.workflow_id)
    except Exception as e:
        print(f"Error completing workflow: {e}")

    print()

    # Step 3: Get workflow status using existing API
    print("Getting workflow status...")
    try:
        status = client.get_workflow(workflow.workflow_id)
        print(f"  Workflow: {status.workflow_name}")
        print(f"  Status: {status.status.value}")
        print(f"  Steps: {len(status.steps)}")
    except Exception as e:
        print(f"Error getting status: {e}")
    print()

    # Step 4: Demonstrate unified execution status types
    print("Unified Execution Status Types (SDK v1.5.0):")
    print("  ExecutionType constants:")
    print(f"    - MAP: {ExecutionType.MAP_PLAN.value}")
    print(f"    - WCP: {ExecutionType.WCP_WORKFLOW.value}")
    print()
    print("  ExecutionStatusValue constants:")
    print(f"    - Pending: {ExecutionStatusValue.PENDING.value}")
    print(f"    - Running: {ExecutionStatusValue.RUNNING.value}")
    print(f"    - Completed: {ExecutionStatusValue.COMPLETED.value}")
    print(f"    - Failed: {ExecutionStatusValue.FAILED.value}")
    print()
    print("  StepStatusValue helpers:")
    print(f"    - IsTerminal(completed): {StepStatusValue.COMPLETED.is_terminal()}")
    print(f"    - IsTerminal(running): {StepStatusValue.RUNNING.is_terminal()}")
    print(f"    - IsBlocking(blocked): {StepStatusValue.BLOCKED.is_blocking()}")
    print()

    # Step 5: Try unified execution API (may fail if backend not wired)
    print("Testing unified execution API...")
    try:
        exec_status = client.get_execution_status(workflow.workflow_id)
        print(f"  Execution ID: {exec_status.execution_id}")
        print(f"  Execution Type: {exec_status.execution_type.value}")
        print(f"  Status: {exec_status.status.value}")
        print(f"  Progress: {exec_status.progress_percent:.1f}%")
    except Exception as e:
        print(f"  Note: Unified API returned error: {e}")
        print("  (This is expected if backend unified handler not yet wired)")
    print()

    # Step 6: List executions
    print("Listing unified executions...")
    try:
        list_resp = client.list_unified_executions(UnifiedListExecutionsRequest(
            execution_type=ExecutionType.WCP_WORKFLOW,
            limit=5,
        ))
        print(f"  Found {list_resp.total} WCP executions")
        for exec in list_resp.executions:
            print(f"    - {exec.execution_id}: {exec.name} ({exec.status.value})")
    except Exception as e:
        print(f"  Note: List API returned error: {e}")
        print("  (This is expected if backend unified handler not yet wired)")
    print()

    # Step 7: List WCP workflows (native API)
    print("Listing WCP workflows...")
    try:
        workflows_resp = client.list_workflows(ListWorkflowsOptions(limit=10))
        print(f"  Found {workflows_resp.total} workflows")
        for wf in workflows_resp.workflows:
            print(f"    - {wf.workflow_id}: {wf.workflow_name} ({wf.status.value})")
    except Exception as e:
        print(f"  Note: ListWorkflows API returned error: {e}")
    print()

    # Step 8: Demonstrate ResumeWorkflow (by aborting then resuming)
    print("Testing resume_workflow...")
    try:
        resume_test = client.create_workflow(CreateWorkflowRequest(
            workflow_name="resume-test-demo",
            source=WorkflowSource.EXTERNAL,
            total_steps=2,
        ))
        # Abort the workflow first
        client.abort_workflow(resume_test.workflow_id, "Testing abort for resume")
        print(f"  Aborted workflow: {resume_test.workflow_id}")
        # Try to resume it
        try:
            client.resume_workflow(resume_test.workflow_id)
            print(f"  Resumed workflow: {resume_test.workflow_id}")
        except Exception as e:
            print(f"  Note: resume_workflow returned error: {e}")
            print("  (Resume may not be supported for all abort reasons)")
    except Exception as e:
        print(f"  Error creating resume test workflow: {e}")
    print()

    print("=" * 55)
    print("Unified Execution Tracking Example Complete!")
    print()
    print("SDK methods demonstrated:")
    print("  WCP Workflow:")
    print("    - create_workflow()")
    print("    - step_gate()")
    print("    - mark_step_completed()")
    print("    - complete_workflow()")
    print("    - get_workflow()")
    print("    - list_workflows()")
    print("    - abort_workflow()")
    print("    - resume_workflow()")
    print("  Unified Execution:")
    print("    - get_execution_status()")
    print("    - list_unified_executions()")
    print("  Helper Types:")
    print("    - ExecutionType (map_plan, wcp_workflow)")
    print("    - ExecutionStatusValue with is_terminal()")
    print("    - StepStatusValue with is_terminal(), is_blocking()")


if __name__ == "__main__":
    main()
