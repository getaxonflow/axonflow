"""
Part 2.2: SQL Injection Blocking

AxonFlow blocks SQL injection attacks at multiple levels:
- Input scanning: Detects SQLi patterns in user queries
- Response scanning: Detects SQLi payloads in connector responses

37+ regex patterns across 8 attack categories ensure comprehensive protection.
"""

import asyncio
import os

from axonflow import AxonFlow


# SQL injection test cases
SQLI_TESTS = [
    {
        "name": "UNION-based injection",
        "query": "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
        "category": "UNION attack",
    },
    {
        "name": "DROP TABLE attack",
        "query": "Get user info; DROP TABLE users; --",
        "category": "Data destruction",
    },
    {
        "name": "TRUNCATE attack",
        "query": "List all orders; TRUNCATE audit_logs;",
        "category": "Data destruction",
    },
    {
        "name": "Comment injection",
        "query": "Show tickets WHERE status='open' --admin bypass",
        "category": "Comment-based bypass",
    },
    {
        "name": "Boolean-based blind",
        "query": "Find user WHERE 1=1 OR username='admin'",
        "category": "Boolean blind",
    },
    {
        "name": "Time-based blind",
        "query": "Get data; WAITFOR DELAY '00:00:10'",
        "category": "Time-based",
    },
]


async def test_sql_injection(client: AxonFlow) -> None:
    """Test SQL injection blocking."""
    print("SQL Injection Blocking Tests")
    print("=" * 60)
    print()

    blocked = 0
    total = len(SQLI_TESTS)

    for test in SQLI_TESTS:
        print(f"Test: {test['name']} ({test['category']})")
        print(f"  Query: \"{test['query'][:50]}...\"")

        try:
            ctx = await client.get_policy_approved_context(
                user_token="demo-user",
                query=test["query"],
            )

            if not ctx.approved:
                print(f"  Result: BLOCKED")
                if ctx.policies:
                    print(f"  Policy: {ctx.policies[0]}")
                blocked += 1
            else:
                print(f"  Result: ALLOWED (check policy configuration)")

        except Exception as e:
            # Some severe attacks may cause the request to be rejected entirely
            print(f"  Result: REJECTED - {e}")
            blocked += 1

        print()

    print("-" * 60)
    print(f"Results: {blocked}/{total} injection attempts blocked")
    print()


async def test_safe_sql_like_query(client: AxonFlow) -> None:
    """Test that legitimate SQL-related queries pass."""
    print("Legitimate Query Test")
    print("=" * 60)
    print()

    # A query that mentions SQL but isn't an injection attempt
    query = "How do I write a SQL query to join two tables?"

    print(f"Query: \"{query}\"")

    ctx = await client.get_policy_approved_context(
        user_token="demo-user",
        query=query,
    )

    if ctx.approved:
        print(f"Result: ALLOWED (expected)")
        print(f"  This is a legitimate educational question about SQL.")
    else:
        print(f"Result: BLOCKED")
        print(f"  Reason: {ctx.block_reason}")

    print()


async def main():
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:
        await test_sql_injection(client)
        await test_safe_sql_like_query(client)


if __name__ == "__main__":
    asyncio.run(main())
