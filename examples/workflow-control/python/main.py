"""
Workflow Control Plane - Python Example

"LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."

This example demonstrates how to:
1. Create a workflow
2. Check step gates before each step
3. Mark steps as completed
4. Complete the workflow
"""

import asyncio
import os

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


async def main():
    print("Workflow Control Plane - Python")
    print("=" * 40)
    print()

    # Connect to AxonFlow
    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "workflow-control-python"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as client:

        # Step 1: Create a workflow
        print("Step 1: Create Workflow")
        print("   Creating 'code-review-pipeline' workflow...")

        workflow = await client.create_workflow(
            CreateWorkflowRequest(
                workflow_name="code-review-pipeline",
                source=WorkflowSource.EXTERNAL,
                total_steps=3,
                metadata={"example": "workflow-control-python"},
            )
        )

        print("   Workflow created!")
        print(f"   Workflow ID: {workflow.workflow_id}")
        print()

        # Step 2: Check gate for first step (Generate Code - LLM call)
        print("Step 2: Check Gate - Generate Code")
        print("   Checking if 'generate_code' step is allowed...")

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

        print(f"   Decision: {gate1.decision.value}")
        if gate1.reason:
            print(f"   Reason: {gate1.reason}")

        if gate1.is_blocked():
            print("   Workflow blocked by policy. Aborting...")
            await client.abort_workflow(workflow.workflow_id, gate1.reason)
            return

        if gate1.requires_approval():
            print(f"   Approval URL: {gate1.approval_url}")
            print("   (Enterprise feature - approval workflow would be triggered)")
            # In production, you would wait for approval here

        # Mark step 1 completed
        if gate1.is_allowed():
            await client.mark_step_completed(
                workflow_id=workflow.workflow_id,
                step_id="step-1",
                request=MarkStepCompletedRequest(
                    output={"code": "def sort_list(items): return sorted(items)"}
                ),
            )
            print("   Step completed!")
        print()

        # Step 3: Check gate for second step (Review Code - Tool call)
        print("Step 3: Check Gate - Review Code")
        print("   Checking if 'review_code' step is allowed...")

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

        print(f"   Decision: {gate2.decision.value}")
        if gate2.is_allowed():
            await client.mark_step_completed(
                workflow_id=workflow.workflow_id,
                step_id="step-2",
                request=MarkStepCompletedRequest(output={"review": "LGTM"}),
            )
            print("   Step completed!")
        print()

        # Step 4: Check gate for third step (Deploy - Connector call)
        print("Step 4: Check Gate - Deploy")
        print("   Checking if 'deploy' step is allowed...")

        gate3 = await client.step_gate(
            workflow_id=workflow.workflow_id,
            step_id="step-3",
            request=StepGateRequest(
                step_name="Deploy to Production",
                step_type=StepType.CONNECTOR_CALL,
                step_input={"connector": "github", "action": "create_pr"},
            ),
        )

        print(f"   Decision: {gate3.decision.value}")
        if gate3.is_allowed():
            await client.mark_step_completed(
                workflow_id=workflow.workflow_id,
                step_id="step-3",
                request=MarkStepCompletedRequest(
                    output={"pr_url": "https://github.com/example/pr/123"}
                ),
            )
            print("   Step completed!")
        print()

        # Step 5: Complete the workflow
        print("Step 5: Complete Workflow")
        await client.complete_workflow(workflow.workflow_id)
        print("   Workflow completed!")
        print()

        # Step 6: Get final workflow status
        print("Step 6: Workflow Status")
        status = await client.get_workflow(workflow.workflow_id)
        print(f"   Workflow: {status.workflow_name}")
        print(f"   Status: {status.status.value}")
        print(f"   Steps: {len(status.steps)}")
        print()

    print("=" * 40)
    print("Workflow Control Plane Example Complete!")
    print()
    print("Key concepts demonstrated:")
    print("  1. Create workflow (register with AxonFlow)")
    print("  2. Check step gates (policy evaluation)")
    print("  3. Mark steps completed (progress tracking)")
    print("  4. Complete workflow (lifecycle management)")
    print()
    print("Next steps:")
    print("  - LangGraph adapter: python/langgraph_example.py")


if __name__ == "__main__":
    asyncio.run(main())
