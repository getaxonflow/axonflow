#!/usr/bin/env python3
"""AxonFlow MAP (Multi-Agent Planning) Example - Python SDK."""

import asyncio
import os

from axonflow import AxonFlow


async def main():
    print("AxonFlow MAP Example - Python")
    print("=" * 50)
    print()

    # Initialize client - uses environment variables or defaults for self-hosted
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "demo")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=client_id,
        client_secret=client_secret,
        debug=True,
    ) as client:
        # Simple query for testing
        query = "Create a brief plan to greet a new user and ask how to help them"
        domain = "generic"

        print(f"Query: {query}")
        print(f"Domain: {domain}")
        print("-" * 50)
        print()

        try:
            # Generate a plan
            plan = await client.generate_plan(query=query, domain=domain)

            print("✅ Plan Generated Successfully")
            print(f"Plan ID: {plan.plan_id}")
            print(f"Domain: {plan.domain}")
            print(f"Steps: {len(plan.steps)}")

            for i, step in enumerate(plan.steps, 1):
                print(f"  {i}. {step.name} ({step.type})")

            print()
            print("=" * 50)
            print("✅ Python MAP Test: PASS")

        except Exception as e:
            print(f"❌ Error: {e}")
            print()
            print("=" * 50)
            print("❌ Python MAP Test: FAIL")
            raise


if __name__ == "__main__":
    asyncio.run(main())
