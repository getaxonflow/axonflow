"""
AxonFlow Proxy Mode - Python Example

Proxy Mode is the simplest integration pattern:
- Send your query to AxonFlow
- AxonFlow handles policy enforcement AND LLM routing
- Get the response back

No need to manage LLM API keys or audit calls - AxonFlow handles everything.
"""

import asyncio
import os
import time

from dotenv import load_dotenv
from axonflow import AxonFlow

load_dotenv()


async def main():
    print("AxonFlow Proxy Mode - Python Example")
    print("=" * 60)
    print()

    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:

        # Example queries
        queries = [
            {
                "query": "What are the key benefits of AI governance?",
                "user_token": "user-proxy-python",
                "request_type": "chat",
                "context": {"department": "engineering"},
            },
            {
                "query": "List 3 principles of responsible AI development.",
                "user_token": "user-proxy-python",
                "request_type": "chat",
                "context": {"format": "list"},
            },
        ]

        for i, q in enumerate(queries, 1):
            print()
            print("-" * 60)
            print(f"Query {i}: \"{q['query'][:50]}...\"")
            print("-" * 60)

            start_time = time.time()

            try:
                # Single call to AxonFlow - it handles policy check AND LLM call
                response = await client.execute_query(
                    user_token=q["user_token"],
                    query=q["query"],
                    request_type=q["request_type"],
                    context=q["context"],
                )

                latency_ms = int((time.time() - start_time) * 1000)

                if response.blocked:
                    print(f"\n  Status: BLOCKED")
                    print(f"  Reason: {response.block_reason}")
                    if response.policy_info:
                        print(f"  Policies: {response.policy_info.policies_evaluated}")
                else:
                    print(f"\n  Status: SUCCESS")
                    print(f"  Latency: {latency_ms}ms")

                    if response.policy_info:
                        print(f"\n  Policy Info:")
                        print(f"    Policies: {response.policy_info.policies_evaluated}")
                        print(f"    Processing: {response.policy_info.processing_time}")

                    print(f"\n  Response:")
                    result_str = str(response.result or response.data)
                    print(f"    {result_str[:300]}{'...' if len(result_str) > 300 else ''}")

            except Exception as e:
                print(f"\n  Status: ERROR")
                print(f"  Error: {e}")

        # Demonstrate blocked query (SQL injection)
        print()
        print("-" * 60)
        print("Query 3 (SQL Injection - should be blocked):")
        print("-" * 60)

        try:
            sql_response = await client.execute_query(
                user_token="user-proxy-python",
                query="SELECT * FROM users; DROP TABLE secrets;",
                request_type="chat",
                context={},
            )

            if sql_response.blocked:
                print(f"\n  Status: BLOCKED (expected)")
                print(f"  Reason: {sql_response.block_reason}")
            else:
                print(f"\n  Status: ALLOWED (unexpected)")

        except Exception as e:
            print(f"\n  Status: ERROR")
            print(f"  Error: {e}")

        print()
        print("=" * 60)
        print("Proxy Mode Demo Complete")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
