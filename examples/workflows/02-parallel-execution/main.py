#!/usr/bin/env python3
"""
Example 2: Parallel Execution Workflow - Python

Demonstrates how AxonFlow MAP (Multi-Agent Plan) automatically parallelizes independent tasks.
"""

import os
import sys
import time

from axonflow import AxonFlow


def main():
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    license_key = os.getenv("AXONFLOW_LICENSE_KEY")

    if not license_key:
        print("❌ AXONFLOW_LICENSE_KEY must be set")
        sys.exit(1)

    client = AxonFlow(
        agent_url=agent_url,
        license_key=license_key,
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
        response = client.execute_query(
            user_token="user-123",
            query=query,
            request_type="multi-agent-plan",  # Use MAP for parallel execution
            context={"model": "gpt-4"},
        )

        duration = time.time() - start_time

        print(f"⏱️  Parallel execution completed in {duration:.1f}s")
        print("📥 Trip Plan:")
        print(response.result)
        print()
        print("✅ Workflow completed successfully")
        print("💡 Tip: MAP automatically parallelized the flight, hotel, and attractions search")
    except Exception as e:
        print(f"❌ Query failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
