"""
Part 4: MCP Connectors - AI Meets Your Data

MCP (Model Context Protocol) connectors let AI safely access your data:
- PostgreSQL: Query databases with natural language
- HTTP: Call external APIs
- More connectors available in Enterprise

All queries go through policy enforcement - SQL injection blocked,
PII redacted, and everything audited.
"""

import asyncio
import os

from axonflow import AxonFlow
from axonflow.exceptions import PolicyViolationError


# Sample queries for the support ticket database
CONNECTOR_QUERIES = [
    {
        "name": "Open Tickets Summary",
        "query": "How many support tickets are currently open?",
        "expected": "count query",
    },
    {
        "name": "Priority Breakdown",
        "query": "Show me a breakdown of tickets by priority level",
        "expected": "group by query",
    },
    {
        "name": "Agent Workload",
        "query": "Which support agent has the most tickets assigned?",
        "expected": "aggregation query",
    },
    {
        "name": "Recent Critical Issues",
        "query": "List critical priority tickets from the last 24 hours",
        "expected": "filtered query",
    },
]


async def demo_postgres_connector():
    print("PostgreSQL Connector Demo")
    print("=" * 60)
    print()
    print("Natural language queries against the support_tickets table.")
    print("AxonFlow converts to SQL and enforces governance.")
    print()

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:

        for q in CONNECTOR_QUERIES:
            print("-" * 60)
            print(f"Query: {q['name']}")
            print("-" * 60)
            print(f"Natural language: \"{q['query']}\"")
            print()

            try:
                # Use execute_query with connector context
                response = await client.execute_query(
                    user_token="support-agent-demo",
                    query=q["query"],
                    request_type="connector",
                    context={
                        "connector": "postgres",
                        "database": "support_tickets",
                    },
                )

                if response.blocked:
                    print(f"Status: BLOCKED")
                    print(f"Reason: {response.block_reason}")
                else:
                    print(f"Status: SUCCESS")

                    # Show response preview
                    if response.result:
                        result_str = str(response.result)
                        print(f"Result: {result_str[:200]}{'...' if len(result_str) > 200 else ''}")
                    elif response.data:
                        data_str = str(response.data)
                        print(f"Data: {data_str[:200]}{'...' if len(data_str) > 200 else ''}")

                    if response.policy_info:
                        print(f"Processing: {response.policy_info.processing_time}")

            except Exception as e:
                # Connector might not be configured
                print(f"Status: ERROR")
                print(f"Message: {e}")
                print()
                print("Note: Ensure PostgreSQL connector is configured and")
                print("      demo data is seeded: ./config/seed-data/seed.sh")

            print()


async def demo_injection_blocking():
    """Show that SQL injection is blocked even through connectors."""
    print("-" * 60)
    print("Security Test: SQL Injection via Connector")
    print("-" * 60)

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:

        malicious_query = "Show tickets; DROP TABLE support_tickets; --"
        print(f"Query: \"{malicious_query}\"")
        print()

        try:
            response = await client.execute_query(
                user_token="support-agent-demo",
                query=malicious_query,
                request_type="connector",
                context={"connector": "postgres"},
            )

            if response.blocked:
                print(f"Status: BLOCKED (expected)")
                print(f"Reason: {response.block_reason}")
                print()
                print("Even through connectors, SQL injection is blocked!")
            else:
                print(f"Status: ALLOWED (check policy configuration)")

        except PolicyViolationError as e:
            print(f"Status: BLOCKED (expected)")
            print(f"Reason: {e}")
            print()
            print("SQL injection blocked - even through connectors!")
        except Exception as e:
            print(f"Status: ERROR - {e}")

    print()


async def main():
    await demo_postgres_connector()
    await demo_injection_blocking()

    print("=" * 60)
    print("MCP Connector Summary")
    print("=" * 60)
    print()
    print("Connectors let AI access your data safely:")
    print("  - Natural language → SQL conversion")
    print("  - All queries through policy enforcement")
    print("  - SQL injection blocked automatically")
    print("  - Response scanning for data leaks")
    print("  - Complete audit trail")
    print()


if __name__ == "__main__":
    asyncio.run(main())
