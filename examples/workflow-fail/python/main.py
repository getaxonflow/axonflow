#!/usr/bin/env python3
"""
Workflow Fail Example - Python

Demonstrates and VALIDATES the FailWorkflow SDK method:
1. Create a workflow and complete one step
2. Call fail_workflow() with a reason
3. Verify workflow status is "failed"
4. Call fail_workflow() without a reason (optional)
5. Verify a failed workflow cannot be resumed
6. Verify GetWorkflow reflects failure correctly

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from dotenv import load_dotenv
from axonflow import AxonFlow
from axonflow.workflow import (
    CreateWorkflowRequest,
    StepGateRequest,
    MarkStepCompletedRequest,
    WorkflowSource,
    StepType,
)

load_dotenv()

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   PASS: {message}")
    else:
        print(f"   FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("Workflow Fail - Python SDK (FailWorkflow Validation)")
    print("=" * 55)
    print()

    endpoint = os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
    workflow_id = None
    no_reason_wf_id = None

    async with AxonFlow(
        endpoint=endpoint,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "workflow-fail-python"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as client:

        try:
            # ========================================
            # Test 1: Create a workflow
            # ========================================
            print("1. Create Workflow")
            try:
                workflow = await client.create_workflow(
                    CreateWorkflowRequest(
                        workflow_name="fail-workflow-test",
                        source=WorkflowSource.EXTERNAL,
                        total_steps=3,
                        metadata={"test": "workflow-fail-python"},
                    )
                )
                workflow_id = workflow.workflow_id
                assert_check(workflow.workflow_id != "", "Workflow has ID")
                assert_check(workflow.workflow_id.startswith("wf_"), "Workflow ID has 'wf_' prefix")
                print(f"   Workflow ID: {workflow.workflow_id}")
            except Exception as e:
                failures.append(f"create_workflow failed: {e}")
                return 1
            print()

            # ========================================
            # Test 2: Step Gate + Complete Step
            # ========================================
            print("2. Step Gate + Complete Step")
            try:
                gate = await client.step_gate(
                    workflow_id=workflow.workflow_id,
                    step_id="step-1",
                    request=StepGateRequest(
                        step_name="Data Processing",
                        step_type=StepType.LLM_CALL,
                        model="llama3.2",
                        provider="ollama",
                        step_input={"prompt": "Process incoming data batch"},
                    ),
                )
                assert_check(gate.decision is not None, "Gate has decision")
                print(f"   Decision: {gate.decision.value}")

                if gate.is_allowed():
                    await client.mark_step_completed(
                        workflow_id=workflow.workflow_id,
                        step_id="step-1",
                        request=MarkStepCompletedRequest(
                            output={"records_processed": 150}
                        ),
                    )
                    assert_check(True, "Step 1 marked completed")
            except Exception as e:
                failures.append(f"step_gate/complete failed: {e}")
            print()

            # ========================================
            # Test 3: FailWorkflow with Reason
            # ========================================
            print("3. FailWorkflow with Reason")
            try:
                await client.fail_workflow(
                    workflow_id=workflow.workflow_id,
                    reason="LLM provider timeout after 30s",
                )
                assert_check(True, "fail_workflow() with reason succeeded")
                print("   Reason: LLM provider timeout after 30s")
            except Exception as e:
                failures.append(f"fail_workflow with reason failed: {e}")
            print()

            # ========================================
            # Test 4: Verify Workflow Status is Failed
            # ========================================
            print("4. Verify Workflow Status is Failed")
            try:
                status = await client.get_workflow(workflow.workflow_id)
                assert_check(
                    status.workflow_name == "fail-workflow-test",
                    "Workflow name matches",
                )
                status_value = status.status.value if status.status else "None"
                assert_check(
                    status_value == "failed",
                    f"Workflow status is 'failed' (got: {status_value})",
                )
                print(f"   Status: {status_value}")
                print(f"   Workflow: {status.workflow_name}")
            except Exception as e:
                failures.append(f"get_workflow verification failed: {e}")
            print()

            # ========================================
            # Test 5: FailWorkflow without Reason
            # ========================================
            print("5. FailWorkflow without Reason")
            try:
                no_reason_wf = await client.create_workflow(
                    CreateWorkflowRequest(
                        workflow_name="fail-no-reason-test",
                        source=WorkflowSource.EXTERNAL,
                        total_steps=2,
                        metadata={"test": "fail-no-reason"},
                    )
                )
                no_reason_wf_id = no_reason_wf.workflow_id
                print(f"   Workflow ID: {no_reason_wf.workflow_id}")

                await client.fail_workflow(workflow_id=no_reason_wf.workflow_id)
                assert_check(True, "fail_workflow() without reason succeeded")

                no_reason_status = await client.get_workflow(no_reason_wf.workflow_id)
                nr_status_value = no_reason_status.status.value if no_reason_status.status else "None"
                assert_check(
                    nr_status_value == "failed",
                    f"Workflow status is 'failed' (got: {nr_status_value})",
                )
                print(f"   Status: {nr_status_value}")
            except Exception as e:
                failures.append(f"fail_workflow without reason failed: {e}")
            print()

            # ========================================
            # Test 6: Verify Failed Workflow Cannot Be Resumed
            # ========================================
            print("6. Verify Failed Workflow Cannot Be Resumed")
            try:
                # Try step gate on failed workflow - should raise
                try:
                    await client.step_gate(
                        workflow_id=workflow.workflow_id,
                        step_id="step-2",
                        request=StepGateRequest(
                            step_name="Should Not Execute",
                            step_type=StepType.TOOL_CALL,
                            step_input={"tool": "noop"},
                        ),
                    )
                    assert_check(False, "StepGate on failed workflow should have raised")
                except Exception as resume_err:
                    assert_check(True, "StepGate on failed workflow raises error")
                    print(f"   Expected error: {resume_err}")

                # Try to complete the failed workflow - should raise
                try:
                    await client.complete_workflow(workflow.workflow_id)
                    assert_check(False, "CompleteWorkflow on failed workflow should have raised")
                except Exception as complete_err:
                    assert_check(True, "CompleteWorkflow on failed workflow raises error")
                    print(f"   Expected error: {complete_err}")
            except Exception as e:
                failures.append(f"resume verification failed: {e}")
            print()

        except Exception as e:
            failures.append(f"Unexpected error: {e}")
        finally:
            # Cleanup
            print("Cleanup")
            print("-------")
            for wf_id in [workflow_id, no_reason_wf_id]:
                if wf_id:
                    try:
                        await client.abort_workflow(wf_id, "test cleanup")
                        print(f"   Cleaned up workflow: {wf_id}")
                    except Exception:
                        print(f"   Warning: Could not abort {wf_id} (may already be terminal)")
            print()

    # ========================================
    # Summary
    # ========================================
    print("=" * 55)
    if not failures:
        print("ALL TESTS PASSED")
        print()
        print("FailWorkflow operations validated:")
        print("  - create_workflow()")
        print("  - step_gate() + mark_step_completed()")
        print("  - fail_workflow() with reason")
        print("  - fail_workflow() without reason")
        print("  - get_workflow() verifies 'failed' status")
        print("  - Failed workflow cannot be resumed")
        return 0
    else:
        print(f"{len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
