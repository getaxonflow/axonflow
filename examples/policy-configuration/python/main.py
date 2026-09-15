#!/usr/bin/env python3
"""
AxonFlow Policy Configuration - Python SDK

This example demonstrates and VALIDATES policy configuration using the pre-check API.
This example sends test queries through the pre-check API
(get_policy_approved_context) and checks that the Agent responds according to the
shipped policy actions.

v11: the stored policy action decides. Environment variables no longer set
detection actions (PII_ACTION, SQLI_ACTION and their GATEWAY_/MCP_ variants are
ignored, with a boot WARN). The shipped request-phase actions exercised here:
  sys_pii_ssn, sys_pii_credit_card = warn (approved, policy id in policies)
  sys_sqli_*                       = warn (approved, policy id in policies)

To change an outcome, record an organization override (customer portal API,
Enterprise: PUT /api/v1/detection-posture/{pii|sqli} with {"action":"block"})
or change the policy's action. This example validates the shipped actions with
no override recorded.

Still read from the environment (a non-action knob, must match Agent config):
  GATEWAY_STATIC_POLICIES_ENABLED = true | false (default: true)

VALIDATION: This example exits with code 1 if any assertion fails.
This ensures CI/CD pipelines catch regressions.

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


def has_policy_prefix(policies: list[str] | None, prefix: str) -> bool:
    """Return True if any matched policy id starts with prefix."""
    return any(p.startswith(prefix) for p in (policies or []))


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if not condition:
        failures.append(message)
        print(f"   FAIL: {message}")
    else:
        print(f"   PASS: {message}")


async def main() -> int:
    print("AxonFlow Per-Mode Policy Configuration - Python SDK")
    print("=" * 52)
    print()

    # The pre-check API uses the Gateway engine. Detection actions come from the
    # stored policy rows (no org override recorded), not from the environment.
    policies_enabled = get_env("GATEWAY_STATIC_POLICIES_ENABLED", "true").lower()

    print("Expected actions: shipped stored actions (PII warn at request phase, SQLi warn)")
    print(f"Static policies enabled: {policies_enabled}")
    print()

    async with AxonFlow(
        endpoint=get_env("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=get_env("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=get_env("AXONFLOW_CLIENT_SECRET", ""),
        debug=get_env("AXONFLOW_DEBUG", "") == "true",
    ) as client:

        # -----------------------------------------------------------
        # Test 1: Safe query -- should always be approved
        # -----------------------------------------------------------
        print("Test 1: Safe Query (No PII, No SQLi)")
        print("-" * 37)
        try:
            result = await client.get_policy_approved_context(
                user_token=get_env("AXONFLOW_USER_TOKEN", "policy-config-user"),
                query="What is the current date?",
            )
        except Exception as e:
            print(f"   FATAL: Policy check failed: {e}")
            return 1

        assert_check(result.approved, "Safe query is approved")
        assert_check(result.context_id != "", "Context ID is returned")
        print()

        # -----------------------------------------------------------
        # Test 2: PII query (SSN) -- sys_pii_ssn stores warn for the request phase
        # -----------------------------------------------------------
        print("Test 2: PII Query (SSN '123-45-6789')")
        print("-" * 38)
        print("  Expected action: warn (stored)")

        try:
            result = await client.get_policy_approved_context(
                user_token=get_env("AXONFLOW_USER_TOKEN", "policy-config-user"),
                query="Process refund for SSN 123-45-6789",
            )
        except Exception as e:
            print(f"   FATAL: Policy check failed: {e}")
            return 1

        if policies_enabled == "false":
            # When static policies are disabled, everything passes through
            assert_check(result.approved, "PII query approved (static policies disabled)")
            assert_check(len(result.policies) == 0, "No policies matched (static policies disabled)")
        else:
            # warn approves the request and reports the matched policy
            assert_check(result.approved, "PII query approved with a warning (stored action: warn)")
            assert_check(has_policy_prefix(result.policies, "sys_pii_"), "PII policy detected (sys_pii_* in policies)")
            print(f"   Policies: {result.policies}")
            if not result.approved:
                print(
                    f"   Block reason: {result.block_reason} "
                    "(an org pii=block override or an edited policy action is in force)"
                )
        print()

        # -----------------------------------------------------------
        # Test 3: SQLi query -- every sys_sqli_* policy stores warn
        # -----------------------------------------------------------
        print("Test 3: SQL Injection (UNION SELECT)")
        print("-" * 37)
        print("  Expected action: warn (stored)")

        try:
            result = await client.get_policy_approved_context(
                user_token=get_env("AXONFLOW_USER_TOKEN", "policy-config-user"),
                query="SELECT name FROM employees UNION SELECT password FROM admin",
            )
        except Exception as e:
            print(f"   FATAL: Policy check failed: {e}")
            return 1

        if policies_enabled == "false":
            assert_check(result.approved, "SQLi query approved (static policies disabled)")
        else:
            # SQL injection warns by default; it is not blocked
            assert_check(result.approved, "SQLi query approved with a warning (stored action: warn)")
            assert_check(has_policy_prefix(result.policies, "sys_sqli_"), "SQLi policy detected (sys_sqli_* in policies)")
            print(f"   Policies: {result.policies}")
            if not result.approved:
                print(
                    f"   Block reason: {result.block_reason} "
                    "(an org sqli=block override or an edited policy action is in force)"
                )
        print()

        # -----------------------------------------------------------
        # Test 4: Credit card PII -- validates PII detection breadth
        # -----------------------------------------------------------
        print("Test 4: Credit Card PII")
        print("-" * 23)

        try:
            result = await client.get_policy_approved_context(
                user_token=get_env("AXONFLOW_USER_TOKEN", "policy-config-user"),
                query="Charge card 4111-1111-1111-1111 for $50",
            )
        except Exception as e:
            print(f"   FATAL: Policy check failed: {e}")
            return 1

        if policies_enabled == "false":
            assert_check(result.approved, "Credit card query approved (static policies disabled)")
        else:
            # sys_pii_credit_card stores warn for the request phase
            assert_check(result.approved, "Credit card approved with a warning (stored action: warn)")
            assert_check(has_policy_prefix(result.policies, "sys_pii_"), "Credit card PII detected (sys_pii_* in policies)")
        print()

    # -----------------------------------------------------------
    # Summary
    # -----------------------------------------------------------
    print("=" * 52)
    if not failures:
        print("ALL TESTS PASSED")
        print()
        print("Policy configuration validated:")
        print(f"  shipped stored actions (PII warn, SQLi warn), enabled={policies_enabled}")
        return 0
    else:
        print(f"{len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
