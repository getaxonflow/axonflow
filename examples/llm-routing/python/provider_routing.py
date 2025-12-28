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

from axonflow import AxonFlowClient


async def main():
    # Initialize client
    client = AxonFlowClient(
        endpoint=os.environ.get("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        license_key=os.environ.get("AXONFLOW_LICENSE_KEY"),
        tenant=os.environ.get("AXONFLOW_TENANT", "demo"),
    )

    print("=== LLM Provider Routing Examples ===\n")

    # Example 1: Default routing (uses server-side strategy)
    print("1. Default routing (server decides provider):")
    default_response = await client.proxy(
        query="What is 2 + 2?",
        request_type="chat",
    )
    print(f"   Response: {default_response.response[:50] if default_response.response else 'N/A'}...")
    print(f"   Provider used: {default_response.metadata.get('provider', 'unknown') if default_response.metadata else 'unknown'}\n")

    # Example 2: Request a specific provider
    print("2. Request specific provider (OpenAI):")
    openai_response = await client.proxy(
        query="What is the capital of France?",
        request_type="chat",
        context={"provider": "openai"},  # Request specific provider
    )
    print(f"   Response: {openai_response.response[:50] if openai_response.response else 'N/A'}...")
    print(f"   Provider used: {openai_response.metadata.get('provider', 'unknown') if openai_response.metadata else 'unknown'}\n")

    # Example 3: Request Anthropic
    print("3. Request specific provider (Anthropic):")
    anthropic_response = await client.proxy(
        query="Explain quantum computing in one sentence.",
        request_type="chat",
        context={"provider": "anthropic"},
    )
    print(f"   Response: {anthropic_response.response[:50] if anthropic_response.response else 'N/A'}...")
    print(f"   Provider used: {anthropic_response.metadata.get('provider', 'unknown') if anthropic_response.metadata else 'unknown'}\n")

    # Example 4: Request with model override
    print("4. Request with specific model:")
    model_response = await client.proxy(
        query="What is machine learning?",
        request_type="chat",
        context={
            "provider": "openai",
            "model": "gpt-4o-mini",  # Specify exact model
        },
    )
    print(f"   Response: {model_response.response[:50] if model_response.response else 'N/A'}...")
    print(f"   Model used: {model_response.metadata.get('model', 'unknown') if model_response.metadata else 'unknown'}\n")

    # Example 5: Health check to see available providers
    print("5. Check provider health status:")
    health = await client.health()
    print(f"   Status: {health.status}")
    if health.providers:
        for name, status in health.providers.items():
            healthy = status.get("healthy", False) if isinstance(status, dict) else False
            print(f"   - {name}: {'✓ healthy' if healthy else '✗ unhealthy'}")

    print("\n=== Examples Complete ===")


if __name__ == "__main__":
    asyncio.run(main())
