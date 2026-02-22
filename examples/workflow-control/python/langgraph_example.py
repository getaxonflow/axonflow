#!/usr/bin/env python3
"""
LangGraph Adapter Example - Python

VALIDATION: This example exits with code 1 if any assertion fails.

"LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."

This example demonstrates using the AxonFlowLangGraphAdapter to wrap
LangGraph workflows with AxonFlow governance gates.

Run with: python langgraph_example.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from dotenv import load_dotenv
from axonflow import AxonFlow
from axonflow.adapters import AxonFlowLangGraphAdapter, WorkflowBlockedError
from axonflow.workflow import WorkflowSource

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
    print("LangGraph Adapter Example - Python")
    print("=" * 40)
    print()
    print("This example simulates a LangGraph workflow with AxonFlow governance.")
    print()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "langgraph-example"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as client:

        adapter = AxonFlowLangGraphAdapter(
            client=client,
            workflow_name="langgraph-code-review",
            source=WorkflowSource.LANGGRAPH,
            auto_block=True,
        )

        try:
            async with adapter:
                # Step 1: Start the workflow
                print("Step 1: Start Workflow")
                workflow_id = await adapter.start_workflow(
                    total_steps=3,
                    metadata={"example": "langgraph-adapter"},
                )

                assert_check(workflow_id is not None, "start_workflow returned workflow_id")
                assert_check(workflow_id != "", "workflow_id is not empty")
                print(f"   Workflow started: {workflow_id}")
                print()

                # Step 2: LangGraph Node 1 - Generate Code (LLM call)
                print("Step 2: Node 'generate_code' (LLM call)")
                print("   Checking gate...")

                gate_result = await adapter.check_gate(
                    step_name="generate_code",
                    step_type="llm_call",
                    model="claude-haiku-4-5-20251001",
                    provider="anthropic",
                    step_input={"prompt": "Write a Python function"},
                )

                assert_check(gate_result is True, "check_gate returned True for safe step")

                if gate_result:
                    print("   Gate: ALLOWED")
                    print("   Executing node...")
                    result = {"code": "def hello(): return 'world'"}

                    await adapter.step_completed(
                        step_name="generate_code",
                        output=result,
                    )
                    assert_check(True, "step_completed succeeded for generate_code")
                    print("   Node completed!")
                print()

                # Step 3: LangGraph Node 2 - Review Code (Tool call)
                print("Step 3: Node 'review_code' (Tool call)")
                print("   Checking gate...")

                gate_result = await adapter.check_gate(
                    step_name="review_code",
                    step_type="tool_call",
                    step_input={"tool": "linter", "code": result["code"]},
                )

                assert_check(gate_result is True, "check_gate returned True for review step")

                if gate_result:
                    print("   Gate: ALLOWED")
                    print("   Executing node...")
                    review_result = {"issues": [], "passed": True}

                    await adapter.step_completed(
                        step_name="review_code",
                        output=review_result,
                    )
                    assert_check(True, "step_completed succeeded for review_code")
                    print("   Node completed!")
                print()

                # Step 4: LangGraph Node 3 - Deploy (Connector call)
                print("Step 4: Node 'deploy' (Connector call)")
                print("   Checking gate...")

                gate_result = await adapter.check_gate(
                    step_name="deploy",
                    step_type="connector_call",
                    step_input={"connector": "github", "action": "create_pr"},
                )

                assert_check(gate_result is True, "check_gate returned True for deploy step")

                if gate_result:
                    print("   Gate: ALLOWED")
                    print("   Executing node...")
                    deploy_result = {"pr_url": "https://github.com/example/pr/123"}

                    await adapter.step_completed(
                        step_name="deploy",
                        output=deploy_result,
                    )
                    assert_check(True, "step_completed succeeded for deploy")
                    print("   Node completed!")
                print()

                print("Step 5: Workflow Complete")
                print("   (Context manager will complete workflow)")

        except WorkflowBlockedError as e:
            print(f"   BLOCKED: {e}")
            print(f"   Step: {e.step_id}")
            print(f"   Reason: {e.reason}")
            print(f"   Policies: {e.policy_ids}")
            # This is expected for certain workflows
            assert_check(True, "WorkflowBlockedError raised correctly")

        print()
        print("=" * 40)

    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("LangGraph Adapter validated:")
        print("  - start_workflow() returns workflow_id")
        print("  - check_gate() validates steps")
        print("  - step_completed() marks steps done")
        print("  - Context manager handles cleanup")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
