"""
Multi-Agent Planning (MAP) Demo

A single natural-language request becomes an executable workflow
with governance applied at every step.

Note: This example uses 'generic' domain which works with LLM-only steps.
For travel/healthcare domains with external connectors, see Enterprise edition.
"""

import asyncio
import os

from axonflow import AxonFlow

async def main():
    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as ax:
        # Generate a plan from natural language
        # Using 'generic' domain - works without external connectors
        print("Plan Generation")
        print("=" * 40)
        plan = await ax.generate_plan(
            query="Research the benefits of renewable energy and create a summary report with recommendations",
            domain="generic",
        )

        print(f"Plan ID: {plan.plan_id}")
        print(f"Steps: {len(plan.steps)}")
        for step in plan.steps:
            print(f"  - {step.name}: {step.type}")

        # Execute the plan
        print("\nPlan Execution")
        print("=" * 40)
        result = await ax.execute_plan(plan.plan_id)
        print(f"Status: {result.status}")

        # Display audit trail
        print("\nAudit Trail")
        print("-" * 40)
        print(f"Workflow Execution ID: {result.workflow_execution_id}")
        if result.metadata:
            print(f"Execution Time: {result.metadata.execution_time_ms}ms")
            print(f"Tasks Executed: {result.metadata.tasks_executed}")
            print(f"Execution Mode: {result.metadata.execution_mode}")

        # Show per-step audit if available
        if result.metadata and result.metadata.tasks:
            print("\nPer-Step Audit:")
            for task in result.metadata.tasks:
                print(f"  - {task.name}: {task.status} ({task.duration_ms}ms)")

        print(f"\nResult Preview: {str(result.result)[:200]}...")

if __name__ == "__main__":
    asyncio.run(main())
