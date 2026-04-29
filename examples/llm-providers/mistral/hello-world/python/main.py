"""
Mistral LLM Provider - Hello World (Python SDK)

Demonstrates Gateway Mode and Proxy Mode with Mistral through AxonFlow.

Prerequisites:
    docker compose up -d
    pip install axonflow>=7.0.0
    export AXONFLOW_CLIENT_SECRET=your-secret

Usage:
    python main.py
"""

import asyncio
import os
import sys

from axonflow import AxonFlow


async def main():
    endpoint = os.environ.get("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = os.environ.get("AXONFLOW_CLIENT_ID", "community")
    client_secret = os.environ.get("AXONFLOW_CLIENT_SECRET", "")

    async with AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
    ) as client:
        print("Mistral LLM Provider - Hello World (Python SDK)")
        print("=" * 50)

        # Gateway Mode: Pre-check + Audit
        print("\n--- Gateway Mode ---")
        precheck = await client.pre_check(
            query="Explain Mistral AI in one sentence.",
            context={"provider": "mistral", "model": "mistral-small-latest"},
        )

        if precheck.approved:
            print(f"Pre-check approved (context: {precheck.context_id})")

            await client.audit_llm_call(
                context_id=precheck.context_id,
                response_summary="Mistral Python SDK gateway test",
                provider="mistral",
                model="mistral-small-latest",
                latency_ms=400,
                token_usage={
                    "prompt_tokens": 15,
                    "completion_tokens": 40,
                    "total_tokens": 55,
                },
            )
            print("Audit logged successfully")
        else:
            print("Pre-check blocked")

        # Proxy Mode
        print("\n--- Proxy Mode ---")
        resp = await client.proxy_llm_call(
            query="What is 2 + 2? Answer with just the number.",
            context={"provider": "mistral"},
        )

        if resp.blocked:
            print("Request blocked by policy")
        else:
            print(f"Response: {resp.data}")
            if resp.provider_info:
                print(
                    f"Provider: {resp.provider_info.get('provider', 'unknown')}, "
                    f"Tokens: {resp.provider_info.get('token_usage', {}).get('total_tokens', 0)}"
                )

        # Policy enforcement
        print("\n--- Policy Enforcement ---")
        sqli_resp = await client.proxy_llm_call(
            query="SELECT * FROM users; DROP TABLE users;",
            context={"provider": "mistral"},
        )
        if sqli_resp.blocked:
            print("SQLi correctly blocked by policy")
        else:
            print("WARNING: SQLi was not blocked")

    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
