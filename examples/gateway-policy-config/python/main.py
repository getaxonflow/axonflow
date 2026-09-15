#!/usr/bin/env python3
"""
AxonFlow Gateway Policy Configuration - Python SDK

This example demonstrates and VALIDATES per-mode Gateway policy configuration.
This example sends test queries through the Gateway mode API
(get_policy_approved_context + proxy_llm_call) and checks that the Agent responds
according to the shipped policy actions.

v11: the stored policy action decides. GATEWAY_PII_ACTION, GATEWAY_SQLI_ACTION,
PII_ACTION and SQLI_ACTION no longer set an action (ignored, with a boot WARN).
The shipped request-phase actions exercised here:

  sys_pii_ssn = warn (approved, policy id in policies)
  sys_sqli_*  = warn (approved, policy id in policies)

To change an outcome, record an organization override (customer portal API,
Enterprise: PUT /api/v1/detection-posture/{pii|sqli} with {"action":"block"})
or change the policy's action. This example validates the shipped actions with
no override recorded.

Still read from the environment (a non-action knob, must match Agent config):

  GATEWAY_STATIC_POLICIES_ENABLED = true | false (default: true)

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow

failures: list[str] = []


def has_policy_prefix(policies: list[str] | None, prefix: str) -> bool:
    """Return True if any matched policy id starts with prefix."""
    return any(p.startswith(prefix) for p in (policies or []))


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if not condition:
        failures.append(message)
        print(f"   \u274c FAIL: {message}")
    else:
        print(f"   \u2713 PASS: {message}")


async def main() -> int:
    print("AxonFlow Gateway Policy Configuration - Python SDK")
    print("=" * 51)
    print()

    # Detection actions come from the stored policy rows (no org override
    # recorded), not from the environment.
    policies_enabled = os.getenv("GATEWAY_STATIC_POLICIES_ENABLED", "true").lower()

    print("Expected actions: shipped stored actions (PII warn at request phase, SQLi warn)")
    print(f"Static policies enabled: {policies_enabled}")
    print()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
        debug=os.getenv("AXONFLOW_DEBUG", "") == "true",
    ) as client:

        # -----------------------------------------------------------
        # Test 1: Safe query -- always approved
        # -----------------------------------------------------------
        print("Test 1: Safe Query Pre-Check")
        print("-" * 28)
        try:
            result = await client.get_policy_approved_context(
                user_token=os.environ.get("AXONFLOW_USER_TOKEN", ""),
                query="What are the best practices for deploying AI models?",
            )
        except Exception as e:
            print(f"   \u274c FATAL: get_policy_approved_context failed: {e}")
            return 1

        assert_check(result.approved, "Safe query is approved")
        assert_check(result.context_id != "", "Context ID returned")
        print()

        # -----------------------------------------------------------
        # Test 2: PII query (SSN) -- sys_pii_ssn stores warn for the request phase
        # -----------------------------------------------------------
        print("Test 2: PII Query (SSN '123-45-6789')")
        print("-" * 38)
        print("  Expected action: warn (stored)")

        try:
            result = await client.get_policy_approved_context(
                user_token=os.environ.get("AXONFLOW_USER_TOKEN", ""),
                query="Look up the customer with SSN 123-45-6789 and return their balance",
            )
        except Exception as e:
            print(f"   \u274c FATAL: Pre-check failed: {e}")
            return 1

        if policies_enabled == "false":
            assert_check(result.approved, "PII approved (static policies disabled)")
            assert_check(
                result.policies is None or len(result.policies) == 0,
                "No policies matched (disabled)",
            )
        else:
            # warn approves the request and reports the matched policy
            assert_check(result.approved, "PII approved with a warning (stored action: warn)")
            assert_check(
                has_policy_prefix(result.policies, "sys_pii_"),
                "PII policy detected (sys_pii_* in policies)",
            )
            if result.policies:
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
        print("Test 3: SQLi Query (UNION SELECT)")
        print("-" * 34)
        print("  Expected action: warn (stored)")

        try:
            result = await client.get_policy_approved_context(
                user_token=os.environ.get("AXONFLOW_USER_TOKEN", ""),
                query="Run this: SELECT name FROM users UNION SELECT password FROM admin_users",
            )
        except Exception as e:
            print(f"   \u274c FATAL: Pre-check failed: {e}")
            return 1

        if policies_enabled == "false":
            assert_check(result.approved, "SQLi approved (static policies disabled)")
        else:
            # SQL injection warns by default; it is not blocked
            assert_check(result.approved, "SQLi approved with a warning (stored action: warn)")
            assert_check(
                has_policy_prefix(result.policies, "sys_sqli_"),
                "SQLi policy detected (sys_sqli_* in policies)",
            )
            if result.policies:
                print(f"   Policies: {result.policies}")
            if not result.approved:
                print(
                    f"   Block reason: {result.block_reason} "
                    "(an org sqli=block override or an edited policy action is in force)"
                )
        print()

        # -----------------------------------------------------------
        # Test 4: ProxyLLMCall -- end-to-end governed LLM call
        # -----------------------------------------------------------
        print("Test 4: ProxyLLMCall (End-to-End)")
        print("-" * 33)
        try:
            llm_resp = await client.proxy_llm_call(
                user_token=os.environ.get("AXONFLOW_USER_TOKEN", ""),
                query="Explain cloud computing in one sentence.",
                request_type="chat",
            )
        except Exception as e:
            print(f"   \u274c FATAL: proxy_llm_call failed: {e}")
            return 1

        assert_check(llm_resp.success, "ProxyLLMCall succeeded")
        assert_check(not llm_resp.blocked, "Safe LLM call was not blocked")
        # LLM response text is in data.data (nested) or result field
        response_text = llm_resp.result or ""
        if not response_text and isinstance(llm_resp.data, dict):
            response_text = llm_resp.data.get("data", "")
        assert_check(len(response_text) > 0, "LLM response is not empty")
        if response_text:
            print(f"   Response: {response_text[:80]}...")
        print()

    # -----------------------------------------------------------
    # Summary
    # -----------------------------------------------------------
    print("=" * 51)
    if not failures:
        print("\u2713 ALL TESTS PASSED")
        print()
        print("Gateway policy config validated:")
        print(f"  shipped stored actions (PII warn, SQLi warn), enabled={policies_enabled}")
        return 0
    else:
        print(f"\u274c {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
