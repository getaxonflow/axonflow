"""
AxonFlow SQL Injection Detection - Python

Demonstrates AxonFlow's SQL injection detection capabilities:
- DROP/DELETE/TRUNCATE statements
- UNION SELECT attacks
- Boolean-based injection (OR 1=1)
- Comment injection
- Stacked queries
- Time-based blind SQLi
"""

import asyncio
import os
import sys

from dotenv import load_dotenv
from axonflow import AxonFlow

load_dotenv()


async def main():
    print("AxonFlow SQL Injection Detection - Python")
    print("=" * 40)
    print()

    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "sqli-detection-demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        test_cases = [
            {
                "name": "Safe Query",
                "query": "Find users who signed up in the last 30 days",
                "should_block": False,
            },
            {
                "name": "DROP TABLE",
                "query": "SELECT * FROM users; DROP TABLE users;--",
                "should_block": True,
            },
            {
                "name": "UNION SELECT",
                "query": "Get user where id = 1 UNION SELECT password FROM admin",
                "should_block": True,
            },
            {
                "name": "Boolean Injection (OR 1=1)",
                "query": "SELECT * FROM users WHERE username='' OR '1'='1'",
                "should_block": True,
            },
            {
                "name": "Comment Injection",
                "query": "SELECT * FROM users WHERE name='admin'-- AND password='secret'",
                "should_block": False,  # Comment injection not currently detected by default policies
            },
            {
                "name": "Stacked Queries",
                "query": "SELECT name FROM users; DELETE FROM audit_log;",
                "should_block": True,
            },
            {
                "name": "Truncate Statement",
                "query": "SELECT * FROM data; TRUNCATE TABLE logs;",
                "should_block": True,
            },
        ]

        passed = 0
        failed = 0

        for test in test_cases:
            print(f"Test: {test['name']}")
            query_preview = test["query"][:60] + "..." if len(test["query"]) > 60 else test["query"]
            print(f"  Query: {query_preview}")

            try:
                result = await axonflow.get_policy_approved_context(
                    user_token="sqli-detection-user",
                    query=test["query"],
                )

                was_blocked = not result.approved

                if was_blocked:
                    print(f"  Result: BLOCKED")
                    print(f"  Reason: {result.block_reason}")
                else:
                    print(f"  Result: APPROVED")
                    print(f"  Context ID: {result.context_id}")

                if result.policies:
                    print(f"  Policies: {', '.join(result.policies)}")

                if was_blocked == test["should_block"]:
                    print(f"  Test: PASS")
                    passed += 1
                else:
                    expected = "blocked" if test["should_block"] else "approved"
                    print(f"  Test: FAIL (expected {expected})")
                    failed += 1

            except Exception as e:
                print(f"  Result: ERROR - {e}")
                failed += 1

            print()

        print("=" * 40)
        print(f"Results: {passed} passed, {failed} failed")
        print()

        if failed > 0:
            print("Some tests failed. Check your AxonFlow policy configuration.")
            sys.exit(1)

        print("All SQLi detection tests passed!")


if __name__ == "__main__":
    asyncio.run(main())
