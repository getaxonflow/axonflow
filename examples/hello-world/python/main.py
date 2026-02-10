#!/usr/bin/env python3
"""
AxonFlow Hello World - Python

The simplest possible AxonFlow integration:
1. Connect to AxonFlow
2. Check if a query passes policy evaluation
3. Print the result

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("AxonFlow Hello World - Python")
    print("=" * 40)
    print()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as axonflow:

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
                "expected": "approved",  # v3.0.0: PII defaults to redact mode
            },
        ]

        for test in test_cases:
            print(f"Test: {test['name']}")
            print(f"  Query: {test['query'][:50]}...")

            try:
                result = await axonflow.get_policy_approved_context(
                    user_token=os.getenv("AXONFLOW_USER_TOKEN", "hello-world-user"),
                    query=test["query"],
                )

                actual = "approved" if result.approved else "blocked"
                if result.approved:
                    print(f"  Result: APPROVED (context_id: {result.context_id[:8]}...)")
                else:
                    print(f"  Result: BLOCKED ({result.block_reason})")

                assert_check(
                    actual == test["expected"],
                    f"{test['name']}: expected {test['expected']}, got {actual}",
                )

            except Exception as e:
                print(f"  Result: ERROR - {e}")
                failures.append(f"{test['name']}: exception - {e}")

            print()

    print("=" * 40)
    if not failures:
        print("✓ ALL TESTS PASSED")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
