# Community LLM Provider E2E Tests using Python SDK
import asyncio
import os
from axonflow import AxonFlowClient


async def main():
    # Create client
    endpoint = os.environ.get("ORCHESTRATOR_URL", "http://localhost:8081")
    client = AxonFlowClient(endpoint=endpoint)

    print("=== Community LLM Provider Tests (Python SDK) ===")
    print(f"Target: {endpoint}\n")

    # Test 1: List providers
    print("Test 1: List providers")
    try:
        providers = await client.list_providers()
        for p in providers:
            print(f"  - {p.name} ({p.type}): {p.health.status}")
    except Exception as e:
        print(f"  Failed: {e}")
    print()

    # Test 2: Per-request OpenAI
    print("Test 2: Per-request selection - OpenAI")
    try:
        resp = await client.process(
            query="Say hello in 3 words",
            request_type="chat",
            context={"provider": "openai"},
            user={"email": "test@example.com", "role": "user"},
        )
        print(f"  Provider: {resp.provider_info.provider}")
        print(f"  Response: {resp.data.data[:50]}..." if len(resp.data.data) > 50 else f"  Response: {resp.data.data}")
    except Exception as e:
        print(f"  Failed: {e}")
    print()

    # Test 3: Per-request Anthropic
    print("Test 3: Per-request selection - Anthropic")
    try:
        resp = await client.process(
            query="Say hello in 3 words",
            request_type="chat",
            context={"provider": "anthropic"},
            user={"email": "test@example.com", "role": "user"},
        )
        print(f"  Provider: {resp.provider_info.provider}")
        print(f"  Response: {resp.data.data[:50]}..." if len(resp.data.data) > 50 else f"  Response: {resp.data.data}")
    except Exception as e:
        print(f"  Failed: {e}")
    print()

    # Test 4: Per-request Gemini
    print("Test 4: Per-request selection - Gemini")
    try:
        resp = await client.process(
            query="Say hello in 3 words",
            request_type="chat",
            context={"provider": "gemini"},
            user={"email": "test@example.com", "role": "user"},
        )
        print(f"  Provider: {resp.provider_info.provider}")
        print(f"  Response: {resp.data.data[:50]}..." if len(resp.data.data) > 50 else f"  Response: {resp.data.data}")
    except Exception as e:
        print(f"  Failed: {e}")
    print()

    # Test 5: Weighted routing distribution
    print("Test 5: Weighted routing distribution (5 requests)")
    providers_used = {}
    for i in range(5):
        try:
            resp = await client.process(
                query="Hello",
                request_type="chat",
                user={"email": "test@example.com", "role": "user"},
            )
            provider = resp.provider_info.provider
            providers_used[provider] = providers_used.get(provider, 0) + 1
            print(f"  Request {i+1}: {provider}")
        except Exception as e:
            print(f"  Request {i+1}: failed ({e})")
    print()

    print("=== Tests Complete ===")


if __name__ == "__main__":
    asyncio.run(main())
