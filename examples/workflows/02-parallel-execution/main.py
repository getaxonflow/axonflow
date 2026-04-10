#!/usr/bin/env python3
"""
Example 2: Parallel Execution Workflow - Python

Demonstrates how AxonFlow MAP (Multi-Agent Plan) automatically parallelizes independent tasks.
"""

import asyncio
import os
import sys
import time

from axonflow import AxonFlow


async def main():
    agent_url = os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "workflow-example")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "")

    client = AxonFlow(
        endpoint=agent_url,
        client_id=client_id,
        client_secret=client_secret if client_secret else None,
    )

    print("✅ Connected to AxonFlow")

    # Complex query that benefits from parallelization
    query = (
        "Plan a 3-day trip to Paris including: (1) round-trip flights from New York, "
        "(2) hotel recommendations in the city center, and (3) top 5 tourist attractions to visit"
    )

    print("📤 Planning trip to Paris...")
    print("🔄 MAP will detect independent tasks and execute them in parallel")

    start_time = time.time()

    try:
        # Send query to AxonFlow (uses MAP for parallelization)
        response = await client.proxy_llm_call(
            user_token=os.getenv("AXONFLOW_USER_TOKEN", "user-123"),
            query=query,
            request_type="multi-agent-plan",  # Use MAP for parallel execution
            context={"provider": "openai"},
        )

        duration = time.time() - start_time

        print(f"⏱️  Parallel execution completed in {duration:.1f}s")
        print("📥 Trip Plan:")
        if hasattr(response, 'result'):
            print(response.result)
        elif hasattr(response, 'data'):
            print(response.data)
        else:
            print(response)
        print()
        print("✅ Workflow completed successfully")
        print("💡 Tip: MAP automatically parallelized the flight, hotel, and attractions search")
    except Exception as e:
        print(f"❌ Query failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
