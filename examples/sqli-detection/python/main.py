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

Expected outcome (v11): the stored policy action decides. Every shipped
sys_sqli_* policy stores action "warn", so a detected SQLi pattern is APPROVED
and the matched sys_sqli_* policy id is returned in `policies` - the detection
signal. It is not blocked. To block SQL injection, record an organization
override of category "sqli" with action "block"
(PUT /api/v1/detection-posture/sqli on the customer portal API, Enterprise) or
change the policy's action. This example validates the shipped actions with no
override recorded; against an org with sqli=block it fails loudly.
The SQLI_ACTION environment variable no longer sets an action.

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


def sqli_policies(policies: list[str] | None) -> list[str]:
    """Return the sys_sqli_* ids among the matched policies."""
    return [p for p in (policies or []) if p.startswith("sys_sqli_")]


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
                "expect_detected": False,
                "sqli_type": "",
            },
            {
                "name": "DROP TABLE",
                "query": "SELECT * FROM users; DROP TABLE users;--",
                "expect_detected": True,
                "sqli_type": "drop_table",
            },
            {
                "name": "UNION SELECT",
                "query": "Get user where id = 1 UNION SELECT password FROM admin",
                "expect_detected": True,
                "sqli_type": "union_select",
            },
            {
                "name": "Boolean Injection (OR 1=1)",
                "query": "SELECT * FROM users WHERE username='' OR '1'='1'",
                "expect_detected": True,
                "sqli_type": "boolean_injection",
            },
            {
                "name": "Comment Injection",
                "query": "SELECT * FROM users WHERE name='admin'-- AND password='secret'",
                "expect_detected": False,  # Not detected by default policies
                "sqli_type": "comment_injection",
            },
            {
                "name": "Stacked Queries",
                "query": "SELECT name FROM users; DELETE FROM audit_log;",
                "expect_detected": True,
                "sqli_type": "stacked_queries",
            },
            {
                "name": "Truncate Statement",
                "query": "SELECT * FROM data; TRUNCATE TABLE logs;",
                "expect_detected": True,
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
                    user_token=get_env("AXONFLOW_USER_TOKEN", "sqli-detection-user"),
                    query=test["query"],
                )
            except Exception as e:
                print(f"   ❌ FATAL: get_policy_approved_context failed: {e}")
                return 1

            detected = sqli_policies(result.policies)

            # Validate context ID for approved requests (UUID format)
            if result.approved:
                assert_check(result.context_id != "", "context_id is not empty")
                if detected:
                    print(f"   Status: APPROVED - SQLi WARNED ({', '.join(detected)})")
                else:
                    print("   Status: APPROVED")
            else:
                print("   Status: BLOCKED")
                print(f"   Reason: {result.block_reason}")
                print(
                    "   (the shipped sys_sqli_* action is warn; a block means an org "
                    "sqli=block override or an edited policy action)"
                )

            # Verify expected behavior: the stored "warn" action approves the request
            if test["expect_detected"]:
                assert_check(
                    result.approved,
                    f"SQLi type '{test['sqli_type']}' is approved with a warning (stored action: warn)",
                )
                assert_check(
                    len(detected) > 0,
                    f"SQLi type '{test['sqli_type']}' is detected (sys_sqli_* policy matched)",
                )
            elif test["sqli_type"] == "":
                assert_check(result.approved, "Safe query is approved")
                assert_check(not detected, "Safe query matches no sys_sqli_* policy")
            else:
                assert_check(result.approved, f"SQLi type '{test['sqli_type']}' is approved")

            print()

        print("=" * 48)
        if not failures:
            print("✓ ALL TESTS PASSED")
            print()
            print("SQLi patterns validated:")
            print("  - Safe query (approved)")
            print("  - DROP TABLE (detected, warned)")
            print("  - UNION SELECT (detected, warned)")
            print("  - Boolean injection (detected, warned)")
            print("  - Comment injection (not detected)")
            print("  - Stacked queries (detected, warned)")
            print("  - TRUNCATE (detected, warned)")
            print()
            print("SQL injection warns by default. To block it, record an org override")
            print("sqli=block or change the policy action.")
            return 0
        else:
            print(f"❌ {len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
