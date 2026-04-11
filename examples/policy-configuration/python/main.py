#!/usr/bin/env python3
"""
AxonFlow Policy Configuration - Python SDK

This example demonstrates and VALIDATES policy configuration using the pre-check API.
AxonFlow's static policies can be configured using environment variables.
This example validates the CURRENT configuration by sending test queries through
the pre-check API (get_policy_approved_context) and checking that the Agent responds
according to the configured policy actions.

Environment variables (must match Agent-side config):
  PII_ACTION   = block | redact | warn | log  (default: redact)
  SQLI_ACTION  = block | warn | log           (default: block)
  GATEWAY_STATIC_POLICIES_ENABLED = true | false (default: true)

Mode-specific overrides (higher precedence):
  GATEWAY_PII_ACTION, GATEWAY_SQLI_ACTION

IMPORTANT: Changing policy behavior requires restarting the AxonFlow Agent with
different env vars. This example validates behavior for the CURRENT configuration.

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

    # Read expected policy actions (must match Agent-side config)
    # Pre-check API uses the Gateway engine, so read Gateway-specific overrides first
    pii_action = get_env("GATEWAY_PII_ACTION", get_env("PII_ACTION", "redact")).lower()
    sqli_action = get_env("GATEWAY_SQLI_ACTION", get_env("SQLI_ACTION", "block")).lower()
    policies_enabled = get_env("GATEWAY_STATIC_POLICIES_ENABLED", "true").lower()

    print(f"Expected PII_ACTION:  {pii_action}")
    print(f"Expected SQLI_ACTION: {sqli_action}")
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
        # Test 2: PII query (SSN) -- behavior depends on PII_ACTION
        # -----------------------------------------------------------
        print("Test 2: PII Query (SSN '123-45-6789')")
        print("-" * 38)
        print(f"  Expected action: {pii_action}")

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
        elif pii_action == "block":
            assert_check(not result.approved, "PII query blocked (PII_ACTION=block)")
            assert_check(result.block_reason is not None and result.block_reason != "", "Block reason provided")
            if result.block_reason:
                print(f"   Block reason: {result.block_reason}")
        elif pii_action == "redact":
            # In redact mode, request phase approves but flags PII
            assert_check(result.approved, "PII query approved in request phase (PII_ACTION=redact)")
            assert_check(len(result.policies) > 0, "PII policies detected")
            print(f"   Policies: {result.policies}")
        elif pii_action == "warn":
            assert_check(result.approved, "PII query approved (PII_ACTION=warn)")
            assert_check(len(result.policies) > 0, "PII policies detected for warning")
        elif pii_action == "log":
            assert_check(result.approved, "PII query approved (PII_ACTION=log)")
        else:
            print(f"   Unknown PII_ACTION: {pii_action}")
            failures.append(f"Unknown PII_ACTION: {pii_action}")
        print()

        # -----------------------------------------------------------
        # Test 3: SQLi query -- behavior depends on SQLI_ACTION
        # -----------------------------------------------------------
        print("Test 3: SQL Injection (UNION SELECT)")
        print("-" * 37)
        print(f"  Expected action: {sqli_action}")

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
        elif sqli_action == "block":
            assert_check(not result.approved, "SQLi query blocked (SQLI_ACTION=block)")
            assert_check(result.block_reason is not None and result.block_reason != "", "Block reason provided")
            if result.block_reason:
                print(f"   Block reason: {result.block_reason}")
        elif sqli_action == "warn":
            assert_check(result.approved, "SQLi query approved with warning (SQLI_ACTION=warn)")
        elif sqli_action == "log":
            assert_check(result.approved, "SQLi query approved (SQLI_ACTION=log)")
        else:
            print(f"   Unknown SQLI_ACTION: {sqli_action}")
            failures.append(f"Unknown SQLI_ACTION: {sqli_action}")
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
        elif pii_action == "block":
            assert_check(not result.approved, "Credit card blocked (PII_ACTION=block)")
        elif pii_action == "redact":
            assert_check(result.approved, "Credit card approved for redaction (PII_ACTION=redact)")
            assert_check(len(result.policies) > 0, "Credit card PII detected")
        elif pii_action in ("warn", "log"):
            assert_check(result.approved, f"Credit card approved (PII_ACTION={pii_action})")
        print()

    # -----------------------------------------------------------
    # Summary
    # -----------------------------------------------------------
    print("=" * 52)
    if not failures:
        print("ALL TESTS PASSED")
        print()
        print("Policy configuration validated:")
        print(f"  PII_ACTION={pii_action}, SQLI_ACTION={sqli_action}, enabled={policies_enabled}")
        return 0
    else:
        print(f"{len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
