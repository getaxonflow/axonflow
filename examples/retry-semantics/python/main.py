#!/usr/bin/env python3
"""
Execution Boundary Semantics Example - Python (#1414)

Demonstrates and VALIDATES idempotent retry behavior for WCP step gates:
1. Default retry behavior is idempotent (same step returns cached decision)
2. Explicit retry_policy="reevaluate" forces fresh policy evaluation
3. Response includes cached (bool) and decision_source ("fresh"/"cached")
4. Different steps are evaluated independently

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
    WorkflowSource,
    StepType,
    GateDecision,
    RetryPolicy,
)

load_dotenv()

pass_count = 0
fail_count = 0


def assert_check(condition: bool, message: str) -> None:
    global pass_count, fail_count
    if condition:
        print(f"   PASS: {message}")
        pass_count += 1
    else:
        print(f"   FAIL: {message}")
        fail_count += 1


async def main() -> int:
    print("Execution Boundary Semantics - Python (#1414)")
    print("=" * 50)
    print()
    print("This test verifies idempotent retry behavior for WCP step gates.")
    print()

    client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-org"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    )

    # Test 1: Create workflow
    print("Test 1: Create Workflow")
    print("-" * 30)

    wf = await client.create_workflow(
        CreateWorkflowRequest(
            workflow_name="retry-semantics-test",
            source=WorkflowSource.EXTERNAL,
        )
    )
    assert_check(wf.workflow_id != "", f"Workflow created: {wf.workflow_id}")
    print()

    # Test 2: First step gate (fresh evaluation)
    print("Test 2: First Step Gate (fresh evaluation)")
    print("-" * 30)

    resp1 = await client.step_gate(
        wf.workflow_id,
        "step-analyze",
        StepGateRequest(
            step_name="Analyze Data",
            step_type=StepType.TOOL_CALL,
            step_input={"tool": "data_analyzer"},
        ),
    )
    assert_check(resp1.decision == GateDecision.ALLOW, f"Decision is allow (got {resp1.decision})")
    assert_check(not resp1.cached, f"First call is NOT cached (cached={resp1.cached})")
    assert_check(
        resp1.decision_source == "fresh",
        f"Decision source is fresh (got {resp1.decision_source})",
    )
    print()

    # Test 3: Same step gate (default idempotent - cached)
    print("Test 3: Same Step Gate Again (default idempotent)")
    print("-" * 30)

    resp2 = await client.step_gate(
        wf.workflow_id,
        "step-analyze",
        StepGateRequest(
            step_name="Analyze Data",
            step_type=StepType.TOOL_CALL,
        ),
    )
    assert_check(resp2.decision == GateDecision.ALLOW, f"Same decision allow (got {resp2.decision})")
    assert_check(resp2.cached, f"Second call IS cached (cached={resp2.cached})")
    assert_check(
        resp2.decision_source == "cached",
        f"Decision source is cached (got {resp2.decision_source})",
    )
    print()

    # Test 4: Same step with retry_policy=reevaluate (fresh)
    print("Test 4: Same Step with retry_policy=reevaluate")
    print("-" * 30)

    resp3 = await client.step_gate(
        wf.workflow_id,
        "step-analyze",
        StepGateRequest(
            step_name="Analyze Data",
            step_type=StepType.TOOL_CALL,
            retry_policy=RetryPolicy.REEVALUATE,
        ),
    )
    assert_check(
        resp3.decision == GateDecision.ALLOW, f"Decision is allow (got {resp3.decision})"
    )
    assert_check(not resp3.cached, f"Reevaluate is NOT cached (cached={resp3.cached})")
    assert_check(
        resp3.decision_source == "fresh",
        f"Decision source is fresh (got {resp3.decision_source})",
    )
    print()

    # Test 5: Different step (independent evaluation)
    print("Test 5: Different Step (independent evaluation)")
    print("-" * 30)

    resp4 = await client.step_gate(
        wf.workflow_id,
        "step-summarize",
        StepGateRequest(
            step_name="Summarize Results",
            step_type=StepType.LLM_CALL,
            model="gpt-4",
            provider="openai",
        ),
    )
    assert_check(not resp4.cached, f"New step is NOT cached (cached={resp4.cached})")
    assert_check(
        resp4.decision_source == "fresh",
        f"Decision source is fresh (got {resp4.decision_source})",
    )
    print()

    # Test 6: Complete workflow
    print("Test 6: Complete Workflow")
    print("-" * 30)

    await client.complete_workflow(wf.workflow_id)
    assert_check(True, "Workflow completed")
    print()

    # Summary
    print("=" * 50)
    print(f"Results: {pass_count} passed, {fail_count} failed")
    if fail_count > 0:
        print("FAILED")
        return 1
    print("ALL PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
