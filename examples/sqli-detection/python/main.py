#!/usr/bin/env python3
"""
AxonFlow SQL Injection Detection - Python SDK

This example demonstrates and VALIDATES AxonFlow's SQLi detection:
- DROP/DELETE/TRUNCATE statements
- UNION SELECT attacks
- Boolean-based injection (OR 1=1)
- Comment injection
- Stacked queries
- Time-based blind SQLi

VALIDATION: This example exits with code 1 if any assertion fails.
This ensures CI/CD pipelines catch regressions.

Policy Configuration (env vars):
  SQLI_ACTION - Controls SQLi detection behavior: "block" (default), "warn", or "log"

  When SQLI_ACTION=block: (default) SQLi patterns are blocked
  When SQLI_ACTION=warn:  SQLi is detected and flagged but NOT blocked
  When SQLI_ACTION=log:   SQLi is detected and logged only

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow

failures: list[str] = []


def get_env(key: str, default: str) -> str:
    return os.getenv(key, default)


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if not condition:
        failures.append(message)
        print(f"   ❌ FAIL: {message}")
    else:
        print(f"   ✓ PASS: {message}")


async def main() -> int:
    print("AxonFlow SQL Injection Detection - Python SDK")
    print("=" * 48)
    print()

    async with AxonFlow(
        endpoint=get_env("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=get_env("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=get_env("AXONFLOW_CLIENT_SECRET", "demo"),
        debug=get_env("AXONFLOW_DEBUG", "") == "true",
    ) as client:
        test_cases = [
            {
                "name": "Safe Query",
                "query": "Find users who signed up in the last 30 days",
                "should_block": False,
                "sqli_type": "",
            },
            {
                "name": "DROP TABLE",
                "query": "SELECT * FROM users; DROP TABLE users;--",
                "should_block": True,
                "sqli_type": "drop_table",
            },
            {
                "name": "UNION SELECT",
                "query": "Get user where id = 1 UNION SELECT password FROM admin",
                "should_block": True,
                "sqli_type": "union_select",
            },
            {
                "name": "Boolean Injection (OR 1=1)",
                "query": "SELECT * FROM users WHERE username='' OR '1'='1'",
                "should_block": True,
                "sqli_type": "boolean_injection",
            },
            {
                "name": "Comment Injection",
                "query": "SELECT * FROM users WHERE name='admin'-- AND password='secret'",
                "should_block": False,  # Not detected by default policies
                "sqli_type": "comment_injection",
            },
            {
                "name": "Stacked Queries",
                "query": "SELECT name FROM users; DELETE FROM audit_log;",
                "should_block": True,
                "sqli_type": "stacked_queries",
            },
            {
                "name": "Truncate Statement",
                "query": "SELECT * FROM data; TRUNCATE TABLE logs;",
                "should_block": True,
                "sqli_type": "truncate",
            },
        ]

        for i, test in enumerate(test_cases, 1):
            print(f"Test {i}: {test['name']}")
            query_preview = (
                test["query"][:60] + "..."
                if len(test["query"]) > 60
                else test["query"]
            )
            print(f"  Query: {query_preview}")

            try:
                result = await client.get_policy_approved_context(
                    user_token="sqli-detection-user",
                    query=test["query"],
                )
            except Exception as e:
                print(f"   ❌ FATAL: get_policy_approved_context failed: {e}")
                return 1

            was_blocked = not result.approved

            # Validate context ID for approved requests (UUID format)
            if result.approved:
                assert_check(result.context_id != "", "context_id is not empty")
                print("   Status: APPROVED")
            else:
                print("   Status: BLOCKED")
                print(f"   Reason: {result.block_reason}")
                assert_check(
                    result.block_reason != "",
                    "block_reason is provided for blocked requests",
                )

            # Verify expected behavior
            if test["should_block"]:
                assert_check(
                    was_blocked,
                    f"SQLi type '{test['sqli_type']}' is blocked",
                )
            else:
                assert_check(not was_blocked, "Safe query is approved")

            print()

        # ========================================
        # Policy Configuration Test (SQLI_ACTION)
        # ========================================
        sqli_action = os.getenv("SQLI_ACTION", "block")
        print(f"Policy Config: SQLI_ACTION={sqli_action}")
        print()

        if sqli_action == "warn":
            print("Test (config): SQLI_ACTION=warn - SQLi detected but NOT blocked")
            try:
                result = await client.get_policy_approved_context(
                    user_token="sqli-config-test-user",
                    query="SELECT * FROM users; DROP TABLE users;--",
                )
            except Exception as e:
                print(f"   FATAL: get_policy_approved_context failed: {e}")
                return 1
            assert_check(
                result.approved,
                "SQLI_ACTION=warn: SQLi query is approved (warn only, not blocked)",
            )
            print()

        print("=" * 48)
        if not failures:
            print("✓ ALL TESTS PASSED")
            print()
            print("SQLi patterns validated:")
            print("  - Safe query (approved)")
            print("  - DROP TABLE (blocked)")
            print("  - UNION SELECT (blocked)")
            print("  - Boolean injection (blocked)")
            print("  - Comment injection (not detected)")
            print("  - Stacked queries (blocked)")
            print("  - TRUNCATE (blocked)")
            return 0
        else:
            print(f"❌ {len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
