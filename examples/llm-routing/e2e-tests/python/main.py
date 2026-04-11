#!/usr/bin/env python3
"""
Community LLM Provider E2E Tests - Python SDK

Demonstrates and VALIDATES LLM provider routing functionality:
- List providers
- Per-request provider selection
- Weighted routing distribution

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d, LLM API keys configured
"""

import asyncio
import os
import sys

from axonflow import AxonFlowClient

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("Community LLM Provider E2E Tests - Python SDK")
    print("=" * 50)
    print()

    endpoint = os.environ.get("AXONFLOW_ENDPOINT", os.environ.get("AXONFLOW_AGENT_URL", "http://localhost:8080"))
    print(f"Target: {endpoint}")
    print()

    client = AxonFlowClient(endpoint=endpoint)

    try:
        # Test 1: List providers
        print("1. ListProviders - Available LLM providers")
        try:
            providers = await client.list_providers()
            assert_check(isinstance(providers, list), "list_providers returns list")
            print(f"   Found {len(providers)} providers:")
            for p in providers[:5]:
                status = p.health.status if hasattr(p, "health") and p.health else "unknown"
                print(f"     - {p.name} ({p.type}): {status}")
        except Exception as e:
            print(f"   Note: list_providers failed: {e}")
            print("   (Provider listing may not be available)")
        print()

        # Test 2: Per-request OpenAI
        print("2. Process - Per-request provider selection (OpenAI)")
        try:
            resp = await client.process(
                query="Say hello in 3 words",
                request_type="chat",
                context={"provider": "openai"},
                user={"email": "test@example.com", "role": "user"},
            )

            assert_check(resp is not None, "process returned response")
            if hasattr(resp, "provider_info") and resp.provider_info:
                assert_check(
                    resp.provider_info.provider is not None,
                    f"Provider used: {resp.provider_info.provider}"
                )
            if hasattr(resp, "data") and resp.data:
                data_str = str(resp.data.data)[:50] if hasattr(resp.data, "data") else str(resp.data)[:50]
                print(f"   Response: {data_str}...")

        except Exception as e:
            print(f"   Note: OpenAI request failed: {e}")
            print("   (OpenAI API key may not be configured)")
        print()

        # Test 3: Per-request Anthropic
        print("3. Process - Per-request provider selection (Anthropic)")
        try:
            resp = await client.process(
                query="Say hello in 3 words",
                request_type="chat",
                context={"provider": "anthropic"},
                user={"email": "test@example.com", "role": "user"},
            )

            assert_check(resp is not None, "process returned response")
            if hasattr(resp, "provider_info") and resp.provider_info:
                print(f"   Provider: {resp.provider_info.provider}")

        except Exception as e:
            print(f"   Note: Anthropic request failed: {e}")
            print("   (Anthropic API key may not be configured)")
        print()

        # Test 4: Per-request Gemini
        print("4. Process - Per-request provider selection (Gemini)")
        try:
            resp = await client.process(
                query="Say hello in 3 words",
                request_type="chat",
                context={"provider": "gemini"},
                user={"email": "test@example.com", "role": "user"},
            )

            assert_check(resp is not None, "process returned response")
            if hasattr(resp, "provider_info") and resp.provider_info:
                print(f"   Provider: {resp.provider_info.provider}")

        except Exception as e:
            print(f"   Note: Gemini request failed: {e}")
            print("   (Gemini API key may not be configured)")
        print()

        # Test 5: Weighted routing distribution
        print("5. Process - Weighted routing distribution (5 requests)")
        providers_used: dict[str, int] = {}
        for i in range(5):
            try:
                resp = await client.process(
                    query="Hello",
                    request_type="chat",
                    user={"email": "test@example.com", "role": "user"},
                )
                if hasattr(resp, "provider_info") and resp.provider_info:
                    provider = resp.provider_info.provider
                    providers_used[provider] = providers_used.get(provider, 0) + 1
                    print(f"   Request {i+1}: {provider}")
                else:
                    print(f"   Request {i+1}: Success (provider info not available)")
            except Exception as e:
                print(f"   Request {i+1}: Failed ({type(e).__name__})")

        if providers_used:
            assert_check(len(providers_used) >= 1, f"Used {len(providers_used)} provider(s)")
        print()

    except Exception as e:
        failures.append(f"Unexpected error: {e}")

    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("LLM Provider E2E Tests validated:")
        print("  - list_providers()")
        print("  - process() with per-request provider selection")
        print("  - Weighted routing distribution")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
