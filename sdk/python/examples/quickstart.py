"""AxonFlow Python SDK Quickstart.

This example shows the simplest way to get started with AxonFlow.
Run with: python quickstart.py
"""

import asyncio
import os

from axonflow import AxonFlow


async def main() -> None:
    """Run quickstart example."""
    # Initialize client from environment variables
    async with AxonFlow(
        agent_url=os.environ.get("AXONFLOW_AGENT_URL", "https://staging-eu.getaxonflow.com"),
        client_id=os.environ.get("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.environ.get("AXONFLOW_CLIENT_SECRET", "demo-secret"),
        debug=True,
    ) as client:
        # Check agent health
        healthy = await client.health_check()
        print(f"Agent healthy: {healthy}")

        if not healthy:
            print("Agent not available, exiting")
            return

        # Execute a simple query with governance
        print("\n--- Executing governed query ---")
        response = await client.execute_query(
            user_token="demo-user",
            query="What is the capital of France?",
            request_type="chat",
        )

        print(f"Success: {response.success}")
        print(f"Blocked: {response.blocked}")
        if response.data:
            print(f"Result: {response.data}")

        # Policy info shows what was evaluated
        if response.policy_info:
            print(f"Policies evaluated: {response.policy_info.policies_evaluated}")
            print(f"Processing time: {response.policy_info.processing_time}")


def sync_example() -> None:
    """Synchronous usage example."""
    # Create sync client
    with AxonFlow.sync(
        agent_url=os.environ.get("AXONFLOW_AGENT_URL", "https://staging-eu.getaxonflow.com"),
        client_id=os.environ.get("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.environ.get("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:
        result = client.execute_query(
            user_token="demo-user",
            query="Hello, world!",
            request_type="chat",
        )
        print(f"Sync result: {result.success}")


if __name__ == "__main__":
    print("=== Async Example ===")
    asyncio.run(main())

    print("\n=== Sync Example ===")
    sync_example()
