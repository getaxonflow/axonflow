"""
LLM Provider Routing Example

This example demonstrates how AxonFlow routes requests to LLM providers.
Provider selection is controlled SERVER-SIDE via environment variables,
not per-request. This ensures consistent routing policies across your org.

Server-side configuration (environment variables):
  LLM_ROUTING_STRATEGY=weighted|round_robin|failover|cost_optimized*
  PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20
  DEFAULT_LLM_PROVIDER=openai

* cost_optimized is Enterprise only
"""

import asyncio
import os

from axonflow import AxonFlow


async def main():
    # Initialize client
    client = AxonFlow(
        agent_url=os.environ.get("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id="demo-client",
        client_secret="demo-secret",
        license_key=os.environ.get("AXONFLOW_LICENSE_KEY"),
    )

    print("=== LLM Provider Routing Examples ===\n")
    print("Provider selection is server-side. Configure via environment variables:")
    print("  LLM_ROUTING_STRATEGY=weighted")
    print("  PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20\n")

    # Example 1: Send a request (server decides which provider to use)
    print("1. Send request (server routes based on configured strategy):")
    try:
        response = await client.execute_query(
            user_token="demo-user",
            query="What is 2 + 2?",
            request_type="chat",
        )
        data = str(response.data)[:100] if response.data else "N/A"
        print(f"   Response: {data}...")
        print(f"   Success: {response.success}\n")
    except Exception as e:
        print(f"   Error: {e}\n")

    # Example 2: Multiple requests show distribution based on weights
    print("2. Multiple requests (observe provider distribution):")
    for i in range(1, 4):
        try:
            response = await client.execute_query(
                user_token="demo-user",
                query=f"Question {i}: What is the capital of France?",
                request_type="chat",
            )
            print(f"   Request {i}: Success (provider selected by server)")
        except Exception as e:
            print(f"   Request {i} Error: {e}")
    print()

    # Example 3: Health check
    print("3. Check agent health:")
    try:
        is_healthy = await client.health_check()
        print(f"   Healthy: {is_healthy}")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n=== Examples Complete ===")
    print("\nTo change provider routing, update server environment variables:")
    print("  - LLM_ROUTING_STRATEGY: weighted, round_robin, failover")
    print("  - PROVIDER_WEIGHTS: distribution percentages")
    print("  - DEFAULT_LLM_PROVIDER: fallback for failover strategy")


if __name__ == "__main__":
    asyncio.run(main())
