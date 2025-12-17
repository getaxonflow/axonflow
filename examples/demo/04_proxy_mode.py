"""
Part 3.1: Proxy Mode Integration

Proxy Mode is the simplest integration pattern:
  App → AxonFlow → LLM → Response

AxonFlow handles:
- Policy enforcement
- LLM routing
- Response auditing
- Cost tracking

You get governance with a single API call.
"""

import asyncio
import os
import time

from axonflow import AxonFlow


async def main():
    print("Proxy Mode Demo")
    print("=" * 60)
    print()
    print("Flow: App → AxonFlow → LLM → Response")
    print("      (Single API call, full governance)")
    print()

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:

        # Query 1: Safe query
        print("-" * 60)
        print("Query 1: Safe customer support query")
        print("-" * 60)

        query = "What are the top 3 reasons customers contact support?"

        print(f"Query: \"{query}\"")
        print()

        start = time.time()
        response = await client.execute_query(
            user_token="support-agent-demo",
            query=query,
            request_type="chat",
            context={"department": "support", "role": "agent"},
        )
        latency = int((time.time() - start) * 1000)

        if response.blocked:
            print(f"Status: BLOCKED")
            print(f"Reason: {response.block_reason}")
        else:
            print(f"Status: SUCCESS")
            print(f"Total Latency: {latency}ms")
            print()

            if response.policy_info:
                print("Policy Info:")
                print(f"  Processing Time: {response.policy_info.processing_time}")
                if response.policy_info.policies_evaluated:
                    print(f"  Policies Evaluated: {response.policy_info.policies_evaluated}")

            print()
            print("Response Preview:")
            result = str(response.result or response.data)
            print(f"  {result[:200]}..." if len(result) > 200 else f"  {result}")

        print()

        # Query 2: Query with injection attempt (should be blocked)
        print("-" * 60)
        print("Query 2: Query with SQL injection (should be blocked)")
        print("-" * 60)

        malicious_query = "List users; DROP TABLE customers; --"

        print(f"Query: \"{malicious_query}\"")
        print()

        response = await client.execute_query(
            user_token="support-agent-demo",
            query=malicious_query,
            request_type="chat",
        )

        if response.blocked:
            print(f"Status: BLOCKED (expected)")
            print(f"Reason: {response.block_reason}")
            if response.policy_info and response.policy_info.policies_evaluated:
                print(f"Policy: {response.policy_info.policies_evaluated}")
        else:
            print(f"Status: ALLOWED (unexpected - check policy config)")

        print()

        # Summary
        print("=" * 60)
        print("Proxy Mode Summary")
        print("=" * 60)
        print()
        print("With one API call, you get:")
        print("  - Policy enforcement (PII, injection blocking)")
        print("  - LLM routing (OpenAI, Anthropic, etc.)")
        print("  - Complete audit trail")
        print("  - Token usage and cost tracking")
        print()


if __name__ == "__main__":
    asyncio.run(main())
