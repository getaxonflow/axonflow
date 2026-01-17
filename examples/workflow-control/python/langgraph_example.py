"""
LangGraph Adapter Example - Python

"LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."

This example demonstrates using the AxonFlowLangGraphAdapter to wrap
LangGraph workflows with AxonFlow governance gates.

The adapter provides a simplified interface for:
1. Starting workflows
2. Checking step gates
3. Marking steps completed
4. Handling blocked/approval-required steps
"""

import asyncio
import os

from dotenv import load_dotenv
from axonflow import AxonFlow
from axonflow.adapters import AxonFlowLangGraphAdapter, WorkflowBlockedError
from axonflow.workflow import WorkflowSource

load_dotenv()


async def main():
    print("LangGraph Adapter Example - Python")
    print("=" * 40)
    print()
    print("This example simulates a LangGraph workflow with AxonFlow governance.")
    print()

    # Connect to AxonFlow
    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "langgraph-example"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as client:

        # Create adapter with auto_block=True (raises exception on block)
        adapter = AxonFlowLangGraphAdapter(
            client=client,
            workflow_name="langgraph-code-review",
            source=WorkflowSource.LANGGRAPH,
            auto_block=True,  # Raises WorkflowBlockedError on block
        )

        try:
            # Use context manager for automatic cleanup
            async with adapter:
                # Step 1: Start the workflow
                print("Step 1: Start Workflow")
                workflow_id = await adapter.start_workflow(
                    total_steps=3,
                    metadata={"example": "langgraph-adapter"},
                )
                print(f"   Workflow started: {workflow_id}")
                print()

                # Step 2: LangGraph Node 1 - Generate Code (LLM call)
                print("Step 2: Node 'generate_code' (LLM call)")
                print("   Checking gate...")

                # check_gate returns True if allowed, raises WorkflowBlockedError if blocked
                if await adapter.check_gate(
                    step_name="generate_code",
                    step_type="llm_call",
                    model="gpt-4",
                    provider="openai",
                    step_input={"prompt": "Write a Python function"},
                ):
                    # Simulate LangGraph node execution
                    print("   Gate: ALLOWED")
                    print("   Executing node...")
                    result = {"code": "def hello(): return 'world'"}

                    # Mark step completed
                    await adapter.step_completed(
                        step_name="generate_code",
                        output=result,
                    )
                    print("   Node completed!")
                print()

                # Step 3: LangGraph Node 2 - Review Code (Tool call)
                print("Step 3: Node 'review_code' (Tool call)")
                print("   Checking gate...")

                if await adapter.check_gate(
                    step_name="review_code",
                    step_type="tool_call",
                    step_input={"tool": "linter", "code": result["code"]},
                ):
                    print("   Gate: ALLOWED")
                    print("   Executing node...")
                    review_result = {"issues": [], "passed": True}

                    await adapter.step_completed(
                        step_name="review_code",
                        output=review_result,
                    )
                    print("   Node completed!")
                print()

                # Step 4: LangGraph Node 3 - Deploy (Connector call)
                print("Step 4: Node 'deploy' (Connector call)")
                print("   Checking gate...")

                if await adapter.check_gate(
                    step_name="deploy",
                    step_type="connector_call",
                    step_input={"connector": "github", "action": "create_pr"},
                ):
                    print("   Gate: ALLOWED")
                    print("   Executing node...")
                    deploy_result = {"pr_url": "https://github.com/example/pr/123"}

                    await adapter.step_completed(
                        step_name="deploy",
                        output=deploy_result,
                    )
                    print("   Node completed!")
                print()

                # Workflow completes automatically when context manager exits
                print("Step 5: Workflow Complete")
                print("   (Context manager will complete workflow)")

        except WorkflowBlockedError as e:
            print(f"   BLOCKED: {e}")
            print(f"   Step: {e.step_id}")
            print(f"   Reason: {e.reason}")
            print(f"   Policies: {e.policy_ids}")
            # Workflow is automatically aborted by context manager on exception

        print()
        print("=" * 40)
        print("LangGraph Adapter Example Complete!")
        print()
        print("Key features demonstrated:")
        print("  1. Simplified adapter interface")
        print("  2. Automatic step ID generation")
        print("  3. Context manager for cleanup")
        print("  4. Exception-based blocking (auto_block=True)")
        print()
        print("Adapter methods:")
        print("  - start_workflow() - Register workflow")
        print("  - check_gate() - Check step permission")
        print("  - step_completed() - Mark step done")
        print("  - complete_workflow() - Finish workflow")
        print("  - abort_workflow() - Abort on error")
        print("  - wait_for_approval() - Poll for approval (Enterprise)")


if __name__ == "__main__":
    asyncio.run(main())
