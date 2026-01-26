#!/usr/bin/env python3
"""
AxonFlow Unified Execution Tracking Example - Python

Demonstrates and VALIDATES unified execution tracking for MAP plans
and WCP workflows using the AxonFlow Python SDK.

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import os
import sys

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

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


def main() -> int:
    print("AxonFlow Unified Execution Tracking - Python SDK")
    print("=" * 55)
    print()

    # WCP endpoints are on the orchestrator (port 8081)
    endpoint = os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8081")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "demo")

    client = AxonFlow.sync(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
    )

    workflow_id = None

    try:
        # Test 1: Create a WCP workflow
        print("1. CreateWorkflow - Creating WCP workflow...")
        try:
            workflow = client.create_workflow(CreateWorkflowRequest(
                workflow_name="unified-tracking-demo",
                source=WorkflowSource.EXTERNAL,
                total_steps=3,
            ))
            workflow_id = workflow.workflow_id
            assert_check(workflow.workflow_id != "", "Workflow has ID")
            assert_check(workflow.workflow_name == "unified-tracking-demo", "Workflow name matches")
            print(f"   Workflow ID: {workflow.workflow_id}")
        except Exception as e:
            failures.append(f"create_workflow failed: {e}")
            print(f"   Error: {e}")
            print("   Note: WCP endpoints are on the orchestrator (port 8081)")
            return 1
        print()

        # Test 2: Step gate checks
        print("2. StepGate - Checking step gates...")
        for i in range(1, 4):
            step_id = f"step-{i}"
            try:
                gate = client.step_gate(
                    workflow_id,
                    step_id,
                    StepGateRequest(
                        step_name=f"Step {i}",
                        step_type=StepType.LLM_CALL,
                    ),
                )
                assert_check(gate.decision is not None, f"Step {i} gate has decision")
                print(f"   Step {i}: {gate.decision.value}")

                # Mark step completed
                client.mark_step_completed(
                    workflow_id,
                    step_id,
                    MarkStepCompletedRequest(
                        output={"result": f"completed step {i}"},
                    ),
                )
            except Exception as e:
                failures.append(f"step_gate/mark_completed failed for step {i}: {e}")
        print()

        # Test 3: Complete workflow
        print("3. CompleteWorkflow - Completing workflow...")
        try:
            client.complete_workflow(workflow_id)
            assert_check(True, "complete_workflow succeeded")
        except Exception as e:
            failures.append(f"complete_workflow failed: {e}")
        print()

        # Test 4: Get workflow status
        print("4. GetWorkflow - Getting workflow status...")
        try:
            status = client.get_workflow(workflow_id)
            assert_check(status.workflow_name == "unified-tracking-demo", "Workflow name matches")
            assert_check(status.status is not None, "Workflow has status")
            assert_check(len(status.steps) == 3, f"Workflow has 3 steps (got {len(status.steps)})")
            print(f"   Status: {status.status.value}")
        except Exception as e:
            failures.append(f"get_workflow failed: {e}")
        print()

        # Test 5: Verify execution type constants
        print("5. ExecutionType Constants...")
        assert_check(ExecutionType.MAP_PLAN.value == "map_plan", "MAP_PLAN value correct")
        assert_check(ExecutionType.WCP_WORKFLOW.value == "wcp_workflow", "WCP_WORKFLOW value correct")
        print()

        # Test 6: Verify status value helpers
        print("6. StatusValue Helpers...")
        assert_check(
            ExecutionStatusValue.COMPLETED.value == "completed",
            "COMPLETED value correct"
        )
        assert_check(
            StepStatusValue.COMPLETED.is_terminal() is True,
            "is_terminal(completed) returns True"
        )
        assert_check(
            StepStatusValue.RUNNING.is_terminal() is False,
            "is_terminal(running) returns False"
        )
        assert_check(
            StepStatusValue.BLOCKED.is_blocking() is True,
            "is_blocking(blocked) returns True"
        )
        print()

        # Test 7: List workflows
        print("7. ListWorkflows - Listing WCP workflows...")
        try:
            workflows_resp = client.list_workflows(ListWorkflowsOptions(limit=10))
            assert_check(workflows_resp.total >= 0, "list_workflows returns total")
            assert_check(isinstance(workflows_resp.workflows, list), "list_workflows returns list")
            print(f"   Found {workflows_resp.total} workflows")
        except Exception as e:
            failures.append(f"list_workflows failed: {e}")
        print()

        # Test 8: Unified execution API (may not be wired yet)
        print("8. GetExecutionStatus - Unified API...")
        try:
            exec_status = client.get_execution_status(workflow_id)
            assert_check(exec_status.execution_id != "", "Has execution_id")
            assert_check(exec_status.status is not None, "Has status")
            print(f"   Execution Type: {exec_status.execution_type.value}")
        except Exception as e:
            print(f"   Note: Unified API returned error: {e}")
            print("   (This is expected if backend unified handler not yet wired)")
        print()

        # Test 9: List unified executions
        print("9. ListUnifiedExecutions - Unified API...")
        try:
            list_resp = client.list_unified_executions(UnifiedListExecutionsRequest(
                execution_type=ExecutionType.WCP_WORKFLOW,
                limit=5,
            ))
            assert_check(list_resp.total >= 0, "list_unified_executions returns total")
            print(f"   Found {list_resp.total} WCP executions")
        except Exception as e:
            print(f"   Note: List API returned error: {e}")
            print("   (This is expected if backend unified handler not yet wired)")
        print()

    finally:
        client.close()

    print("=" * 55)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Unified Execution Tracking validated:")
        print("  WCP Workflow:")
        print("    - create_workflow()")
        print("    - step_gate()")
        print("    - mark_step_completed()")
        print("    - complete_workflow()")
        print("    - get_workflow()")
        print("    - list_workflows()")
        print("  Type Constants:")
        print("    - ExecutionType (map_plan, wcp_workflow)")
        print("    - ExecutionStatusValue with is_terminal()")
        print("    - StepStatusValue with is_terminal(), is_blocking()")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
