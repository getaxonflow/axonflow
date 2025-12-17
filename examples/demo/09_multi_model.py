"""
Part 7: Multi-Model Routing

AxonFlow is vendor-neutral - use any LLM provider:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude 3)
- Local models (Ollama)
- Any OpenAI-compatible API

Same governance policies, any provider.
Switch providers without changing application code.
"""

import asyncio
import os

from axonflow import AxonFlow
from axonflow.exceptions import PolicyViolationError


# Providers to demonstrate (if configured)
PROVIDERS = [
    {
        "name": "OpenAI",
        "provider": "openai",
        "model": "gpt-3.5-turbo",
        "env_key": "OPENAI_API_KEY",
    },
    {
        "name": "Anthropic",
        "provider": "anthropic",
        "model": "claude-3-haiku-20240307",
        "env_key": "ANTHROPIC_API_KEY",
    },
]


async def test_provider(client: AxonFlow, provider_config: dict, query: str):
    """Test a specific provider."""
    name = provider_config["name"]
    provider = provider_config["provider"]
    model = provider_config["model"]
    env_key = provider_config["env_key"]

    print(f"Provider: {name}")
    print(f"  Model: {model}")

    # Check if provider is configured
    if not os.getenv(env_key):
        print(f"  Status: SKIPPED (no {env_key})")
        print()
        return False

    try:
        response = await client.execute_query(
            user_token="demo-user",
            query=query,
            request_type="chat",
            context={
                "provider": provider,
                "model": model,
            },
        )

        if response.blocked:
            print(f"  Status: BLOCKED")
            print(f"  Reason: {response.block_reason}")
        else:
            print(f"  Status: SUCCESS")

            if response.policy_info:
                print(f"  Processing: {response.policy_info.processing_time}")

            # Show response preview
            result = str(response.result or response.data)
            print(f"  Response: {result[:100]}...")

        return True

    except Exception as e:
        print(f"  Status: ERROR - {e}")
        return False

    finally:
        print()


async def multi_model_demo():
    print("Multi-Model Routing Demo")
    print("=" * 60)
    print()
    print("Same query, same governance, different providers.")
    print()

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:

        query = "What makes a great customer support experience? Answer in one sentence."
        print(f"Query: \"{query}\"")
        print()
        print("-" * 60)

        tested = 0
        for provider_config in PROVIDERS:
            if await test_provider(client, provider_config, query):
                tested += 1

        if tested == 0:
            print("No LLM providers configured.")
            print()
            print("To enable multi-model routing, set:")
            print("  export OPENAI_API_KEY=your-key")
            print("  export ANTHROPIC_API_KEY=your-key")
            print()

        # Show policy consistency
        print("-" * 60)
        print("Policy Consistency Test")
        print("-" * 60)
        print()

        # Test that policies work the same across providers
        malicious = "Get users; DROP TABLE customers; --"
        print(f"Testing SQL injection across providers:")
        print(f"Query: \"{malicious}\"")
        print()

        for provider_config in PROVIDERS[:1]:  # Test with first available
            if os.getenv(provider_config["env_key"]):
                try:
                    response = await client.execute_query(
                        user_token="demo-user",
                        query=malicious,
                        request_type="chat",
                        context={
                            "provider": provider_config["provider"],
                            "model": provider_config["model"],
                        },
                    )

                    if response.blocked:
                        print(f"Result: BLOCKED (expected)")
                        print(f"Policy: {response.block_reason}")
                        print()
                        print("Same policies apply regardless of provider.")
                    else:
                        print(f"Result: ALLOWED (check policy config)")

                except PolicyViolationError as e:
                    print(f"Result: BLOCKED (expected)")
                    print(f"Reason: {e}")
                    print()
                    print("Same policies apply regardless of provider.")
                except Exception as e:
                    print(f"Result: ERROR - {e}")

                break
        else:
            print("[Skipped - no providers configured]")

        print()


async def show_supported_providers():
    """List all supported providers."""
    print("-" * 60)
    print("Supported Providers")
    print("-" * 60)
    print()
    print("AxonFlow supports any LLM provider:")
    print()
    print("  Cloud Providers:")
    print("    - OpenAI (GPT-4, GPT-4 Turbo, GPT-3.5)")
    print("    - Anthropic (Claude 3 Opus, Sonnet, Haiku)")
    print("    - Google (Gemini Pro, Gemini Ultra)")
    print("    - Cohere (Command, Command Light)")
    print()
    print("  Self-Hosted:")
    print("    - Ollama (Llama 2, Mistral, etc.)")
    print("    - vLLM")
    print("    - Any OpenAI-compatible API")
    print()
    print("  Configuration:")
    print("    - Set provider API keys in environment")
    print("    - Or configure in AxonFlow orchestrator")
    print("    - Switch providers via context parameter")
    print()


async def main():
    await multi_model_demo()
    await show_supported_providers()

    print("=" * 60)
    print("Multi-Model Summary")
    print("=" * 60)
    print()
    print("Benefits of vendor-neutral routing:")
    print("  - No vendor lock-in")
    print("  - Consistent governance across providers")
    print("  - Easy provider switching")
    print("  - Cost optimization (route to cheaper models)")
    print("  - Resilience (failover between providers)")
    print()


if __name__ == "__main__":
    asyncio.run(main())
