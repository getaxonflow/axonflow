"""
LLM Provider Routing Example

This example demonstrates how to:
1. Use default routing (server-side configuration)
2. Specify a preferred provider in requests
3. Query provider status

Server-side configuration (environment variables):
  LLM_ROUTING_STRATEGY=weighted|round_robin|failover
  PROVIDER_WEIGHTS=openai:50,anthropic:30,bedrock:20
  DEFAULT_LLM_PROVIDER=bedrock
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

    # Example 1: Default routing (uses server-side strategy)
    print("1. Default routing (server decides provider):")
    try:
        default_response = await client.execute_query(
            user_token="demo-user",
            query="What is 2 + 2?",
            request_type="chat",
        )
        data = str(default_response.data)[:100] if default_response.data else "N/A"
        print(f"   Response: {data}...")
        print(f"   Success: {default_response.success}\n")
    except Exception as e:
        print(f"   Error: {e}\n")

    # Example 2: Request specific provider (Ollama - local)
    print("2. Request specific provider (Ollama):")
    try:
        ollama_response = await client.execute_query(
            user_token="demo-user",
            query="What is the capital of France?",
            request_type="chat",
            context={"provider": "ollama"},  # Request specific provider
        )
        data = str(ollama_response.data)[:100] if ollama_response.data else "N/A"
        print(f"   Response: {data}...")
        print(f"   Success: {ollama_response.success}\n")
    except Exception as e:
        print(f"   Error: {e}\n")

    # Example 3: Request with model override
    print("3. Request with specific model:")
    try:
        model_response = await client.execute_query(
            user_token="demo-user",
            query="What is machine learning in one sentence?",
            request_type="chat",
            context={
                "provider": "ollama",
                "model": "tinyllama",  # Specify exact model
            },
        )
        data = str(model_response.data)[:100] if model_response.data else "N/A"
        print(f"   Response: {data}...")
        print(f"   Success: {model_response.success}\n")
    except Exception as e:
        print(f"   Error: {e}\n")

    # Example 4: Health check
    print("4. Check agent health:")
    try:
        is_healthy = await client.health_check()
        print(f"   Healthy: {is_healthy}")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n=== Examples Complete ===")


if __name__ == "__main__":
    asyncio.run(main())
