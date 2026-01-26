#!/usr/bin/env python3
"""
Workflow Control Plane Example - Python

Demonstrates and VALIDATES the WCP (Workflow Control Plane) SDK:
1. Create a workflow
2. Check step gates before each step
3. Mark steps as completed
4. Complete the workflow

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
    GateDecision,
)

load_dotenv()

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("Workflow Control Plane - Python SDK")
    print("=" * 50)
    print()

    workflow_id = None

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "workflow-control-python"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as client:

        try:
            # Test 1: Create a workflow
            print("1. CreateWorkflow - Creating code-review-pipeline...")
            try:
                workflow = await client.create_workflow(
                    CreateWorkflowRequest(
                        workflow_name="code-review-pipeline",
                        source=WorkflowSource.EXTERNAL,
                        total_steps=3,
                        metadata={"example": "workflow-control-python"},
                    )
                )
                workflow_id = workflow.workflow_id
                assert_check(workflow.workflow_id != "", "Workflow has ID")
                assert_check(workflow.workflow_name == "code-review-pipeline", "Workflow name matches")
                print(f"   Workflow ID: {workflow.workflow_id}")
            except Exception as e:
                failures.append(f"create_workflow failed: {e}")
                return 1
            print()

            # Test 2: Step gate - Generate Code (LLM call)
            print("2. StepGate - Generate Code (LLM_CALL)")
            try:
                gate1 = await client.step_gate(
                    workflow_id=workflow.workflow_id,
                    step_id="step-1",
                    request=StepGateRequest(
                        step_name="Generate Code",
                        step_type=StepType.LLM_CALL,
                        model="gpt-4",
                        provider="openai",
                        step_input={"prompt": "Write a Python function to sort a list"},
                    ),
                )
                assert_check(gate1.decision is not None, "Gate has decision")
                assert_check(
                    gate1.decision in [GateDecision.ALLOW, GateDecision.BLOCK, GateDecision.REQUIRE_APPROVAL],
                    f"Gate decision is valid enum (got: {gate1.decision})"
                )
                print(f"   Decision: {gate1.decision.value}")

                # Handle gate decision
                if gate1.is_blocked():
                    assert_check(gate1.reason is not None, "Blocked gate has reason")
                    print(f"   Blocked: {gate1.reason}")
                    await client.abort_workflow(workflow.workflow_id, gate1.reason)
                    return 1

                if gate1.requires_approval():
                    assert_check(True, "Approval required (Enterprise feature)")
                    print(f"   Approval URL: {gate1.approval_url}")

                # Mark step completed
                if gate1.is_allowed():
                    await client.mark_step_completed(
                        workflow_id=workflow.workflow_id,
                        step_id="step-1",
                        request=MarkStepCompletedRequest(
                            output={"code": "def sort_list(items): return sorted(items)"}
                        ),
                    )
                    assert_check(True, "Step 1 marked completed")
            except Exception as e:
                failures.append(f"step_gate step-1 failed: {e}")
            print()

            # Test 3: Step gate - Review Code (Tool call)
            print("3. StepGate - Review Code (TOOL_CALL)")
            try:
                gate2 = await client.step_gate(
                    workflow_id=workflow.workflow_id,
                    step_id="step-2",
                    request=StepGateRequest(
                        step_name="Review Code",
                        step_type=StepType.TOOL_CALL,
                        step_input={
                            "tool": "code_reviewer",
                            "code": "def sort_list(items): return sorted(items)",
                        },
                    ),
                )
                assert_check(gate2.decision is not None, "Gate has decision")
                print(f"   Decision: {gate2.decision.value}")

                if gate2.is_allowed():
                    await client.mark_step_completed(
                        workflow_id=workflow.workflow_id,
                        step_id="step-2",
                        request=MarkStepCompletedRequest(output={"review": "LGTM"}),
                    )
                    assert_check(True, "Step 2 marked completed")
            except Exception as e:
                failures.append(f"step_gate step-2 failed: {e}")
            print()

            # Test 4: Step gate - Deploy (Connector call)
            print("4. StepGate - Deploy (CONNECTOR_CALL)")
            try:
                gate3 = await client.step_gate(
                    workflow_id=workflow.workflow_id,
                    step_id="step-3",
                    request=StepGateRequest(
                        step_name="Deploy to Production",
                        step_type=StepType.CONNECTOR_CALL,
                        step_input={"connector": "github", "action": "create_pr"},
                    ),
                )
                assert_check(gate3.decision is not None, "Gate has decision")
                print(f"   Decision: {gate3.decision.value}")

                if gate3.is_allowed():
                    await client.mark_step_completed(
                        workflow_id=workflow.workflow_id,
                        step_id="step-3",
                        request=MarkStepCompletedRequest(
                            output={"pr_url": "https://github.com/example/pr/123"}
                        ),
                    )
                    assert_check(True, "Step 3 marked completed")
            except Exception as e:
                failures.append(f"step_gate step-3 failed: {e}")
            print()

            # Test 5: Complete the workflow
            print("5. CompleteWorkflow")
            try:
                await client.complete_workflow(workflow.workflow_id)
                assert_check(True, "complete_workflow succeeded")
            except Exception as e:
                failures.append(f"complete_workflow failed: {e}")
            print()

            # Test 6: Get final workflow status
            print("6. GetWorkflow - Final Status")
            try:
                status = await client.get_workflow(workflow.workflow_id)
                assert_check(status.workflow_name == "code-review-pipeline", "Workflow name matches")
                assert_check(status.status is not None, "Workflow has status")
                assert_check(len(status.steps) == 3, f"Workflow has 3 steps (got {len(status.steps)})")
                print(f"   Status: {status.status.value}")
                print(f"   Steps: {len(status.steps)}")
            except Exception as e:
                failures.append(f"get_workflow failed: {e}")
            print()

        except Exception as e:
            failures.append(f"Unexpected error: {e}")

    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("WCP operations validated:")
        print("  - create_workflow()")
        print("  - step_gate() with LLM_CALL, TOOL_CALL, CONNECTOR_CALL")
        print("  - mark_step_completed()")
        print("  - complete_workflow()")
        print("  - get_workflow()")
        print("  - GateDecision enum values and helpers")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
