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
        print(f"Domain: {plan.domain}")
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
        print(f"Plan ID: {result.plan_id}")
        if result.duration:
            print(f"Duration: {result.duration}")

        # Show per-step results if available
        if result.step_results:
            print("\nStep Results:")
            for step_id, step_result in result.step_results.items():
                print(f"  - {step_id}: {step_result}")

        if result.result:
            print(f"\nResult Preview: {str(result.result)[:200]}...")

if __name__ == "__main__":
    asyncio.run(main())
