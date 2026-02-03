#!/usr/bin/env python3
"""
AxonFlow Gateway Policy Configuration - Python SDK

This example demonstrates and VALIDATES per-mode Gateway policy configuration.
AxonFlow's static policies can be configured per-mode using environment variables.
This example validates the CURRENT configuration by sending test queries through
the Gateway mode API (get_policy_approved_context + proxy_llm_call) and checking
that the Agent responds according to the configured policy actions.

Environment variables (must match Agent-side config):

  GATEWAY_PII_ACTION   = block | redact | log  (default: redact)
  GATEWAY_SQLI_ACTION  = block | warn | log    (default: block)

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow

failures: list[str] = []


def get_env(key: str, fallback_key: str, default: str) -> str:
    """Get env var with fallback key support."""
    value = os.getenv(key)
    if value:
        return value
    value = os.getenv(fallback_key)
    if value:
        return value
    return default


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

    # Read expected policy actions (with fallback keys, matching Go version)
    pii_action = get_env("GATEWAY_PII_ACTION", "PII_ACTION", "redact").lower()
    sqli_action = get_env("GATEWAY_SQLI_ACTION", "SQLI_ACTION", "block").lower()
    policies_enabled = os.getenv("GATEWAY_STATIC_POLICIES_ENABLED", "true").lower()

    print(f"Expected PII_ACTION:  {pii_action}")
    print(f"Expected SQLI_ACTION: {sqli_action}")
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
                user_token="",
                query="What are the best practices for deploying AI models?",
            )
        except Exception as e:
            print(f"   \u274c FATAL: get_policy_approved_context failed: {e}")
            return 1

        assert_check(result.approved, "Safe query is approved")
        assert_check(result.context_id != "", "Context ID returned")
        print()

        # -----------------------------------------------------------
        # Test 2: PII query (SSN) -- depends on GATEWAY_PII_ACTION
        # -----------------------------------------------------------
        print("Test 2: PII Query (SSN '123-45-6789')")
        print("-" * 38)
        print(f"  Expected action: {pii_action}")

        try:
            result = await client.get_policy_approved_context(
                user_token="",
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
            if pii_action == "block":
                assert_check(not result.approved, "PII blocked (GATEWAY_PII_ACTION=block)")
                assert_check(
                    result.block_reason is not None and result.block_reason != "",
                    "Block reason provided",
                )
                if result.block_reason:
                    print(f"   Block reason: {result.block_reason}")
            elif pii_action == "redact":
                assert_check(result.approved, "PII approved for redaction (GATEWAY_PII_ACTION=redact)")
                assert_check(
                    result.policies is not None and len(result.policies) > 0,
                    "PII policies detected",
                )
                if result.policies:
                    print(f"   Policies: {result.policies}")
            elif pii_action == "warn":
                assert_check(result.approved, "PII approved with warning (GATEWAY_PII_ACTION=warn)")
                assert_check(
                    result.policies is not None and len(result.policies) > 0,
                    "PII policies detected",
                )
            elif pii_action == "log":
                assert_check(result.approved, "PII approved (GATEWAY_PII_ACTION=log)")
        print()

        # -----------------------------------------------------------
        # Test 3: SQLi query -- depends on GATEWAY_SQLI_ACTION
        # -----------------------------------------------------------
        print("Test 3: SQLi Query (UNION SELECT)")
        print("-" * 34)
        print(f"  Expected action: {sqli_action}")

        try:
            result = await client.get_policy_approved_context(
                user_token="",
                query="Run this: SELECT name FROM users UNION SELECT password FROM admin_users",
            )
        except Exception as e:
            print(f"   \u274c FATAL: Pre-check failed: {e}")
            return 1

        if policies_enabled == "false":
            assert_check(result.approved, "SQLi approved (static policies disabled)")
        else:
            if sqli_action == "block":
                assert_check(not result.approved, "SQLi blocked (GATEWAY_SQLI_ACTION=block)")
                assert_check(
                    result.block_reason is not None and result.block_reason != "",
                    "Block reason provided",
                )
                if result.block_reason:
                    print(f"   Block reason: {result.block_reason}")
            elif sqli_action == "warn":
                assert_check(result.approved, "SQLi approved with warning (GATEWAY_SQLI_ACTION=warn)")
            elif sqli_action == "log":
                assert_check(result.approved, "SQLi approved (GATEWAY_SQLI_ACTION=log)")
        print()

        # -----------------------------------------------------------
        # Test 4: ProxyLLMCall -- end-to-end governed LLM call
        # -----------------------------------------------------------
        print("Test 4: ProxyLLMCall (End-to-End)")
        print("-" * 33)
        try:
            llm_resp = await client.proxy_llm_call(
                user_token="",
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
        print(f"  PII_ACTION={pii_action}, SQLI_ACTION={sqli_action}, enabled={policies_enabled}")
        return 0
    else:
        print(f"\u274c {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
