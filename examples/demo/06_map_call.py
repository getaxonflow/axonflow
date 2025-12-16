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
        plan = await ax.generate_plan(
            query="Research the benefits of renewable energy and create a summary report with recommendations",
            domain="generic",
        )

        print(f"Plan ID: {plan.plan_id}")
        print(f"Steps: {len(plan.steps)}")
        for step in plan.steps:
            print(f"  - {step.name}: {step.type}")

        # Execute the plan
        result = await ax.execute_plan(plan.plan_id)
        print(f"\nStatus: {result.status}")
        print(f"Result: {result.result}")

if __name__ == "__main__":
    asyncio.run(main())
