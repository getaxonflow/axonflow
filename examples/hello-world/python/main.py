"""
AxonFlow Hello World - Python

The simplest possible AxonFlow integration:
1. Connect to AxonFlow
2. Check if a query passes policy evaluation
3. Print the result

This example demonstrates the core AxonFlow workflow without any LLM calls.
"""

import asyncio
import os

from dotenv import load_dotenv
from axonflow import AxonFlow

load_dotenv()


async def main():
    print("AxonFlow Hello World - Python")
    print("=" * 40)
    print()

    # Connect to AxonFlow
    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        # Test queries
        test_cases = [
            {
                "name": "Safe Query",
                "query": "What is the weather today?",
                "expected": "approved",
            },
            {
                "name": "SQL Injection",
                "query": "SELECT * FROM users; DROP TABLE users;",
                "expected": "blocked",
            },
            {
                "name": "PII (SSN)",
                "query": "Process payment for SSN 123-45-6789",
                "expected": "blocked",
            },
        ]

        for test in test_cases:
            print(f"Test: {test['name']}")
            print(f"  Query: {test['query'][:50]}...")
            print()

            try:
                # Check policy approval
                result = await axonflow.get_policy_approved_context(
                    user_token="hello-world-user",
                    query=test["query"],
                )

                if result.approved:
                    print(f"  Result: APPROVED")
                    print(f"  Context ID: {result.context_id}")
                else:
                    print(f"  Result: BLOCKED")
                    print(f"  Reason: {result.block_reason}")

                if result.policies:
                    print(f"  Policies: {', '.join(result.policies)}")

                # Check if result matches expectation
                actual = "approved" if result.approved else "blocked"
                status = "PASS" if actual == test["expected"] else "FAIL"
                print(f"  Test: {status} (expected {test['expected']})")

            except Exception as e:
                print(f"  Result: ERROR")
                print(f"  Error: {e}")

            print()

    print("=" * 40)
    print("Hello World Complete!")
    print()
    print("Next steps:")
    print("  - Gateway Mode: examples/integrations/gateway-mode/")
    print("  - Proxy Mode: examples/integrations/proxy-mode/")
    print("  - LangChain: examples/integrations/langchain/")


if __name__ == "__main__":
    asyncio.run(main())
