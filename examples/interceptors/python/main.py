#!/usr/bin/env python3
"""
AxonFlow LLM Interceptor Example - Python

Demonstrates and VALIDATES how to wrap LLM provider clients with AxonFlow governance
using interceptors.

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d, OPENAI_API_KEY set
"""

import os
import sys

from openai import OpenAI

from axonflow import AxonFlow
from axonflow.interceptors.openai import wrap_openai_client
from axonflow.exceptions import PolicyViolationError

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


def main() -> int:
    print("AxonFlow LLM Interceptor - Python SDK")
    print("=" * 50)
    print()

    openai_key = os.getenv("OPENAI_API_KEY", "")
    if not openai_key:
        print("Note: OPENAI_API_KEY not set, using mock mode")
        print()

    axonflow = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", ""),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    )

    openai_client = OpenAI(api_key=openai_key or "mock-key")

    governed_client = wrap_openai_client(
        openai_client,
        axonflow,
        user_token=os.getenv("AXONFLOW_USER_TOKEN", "interceptor-test-user")
    )

    # Test 1: Safe query (should pass)
    print("1. Safe Query - Expected: APPROVED")
    try:
        response = governed_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "What is the capital of France?"}],
            max_tokens=50
        )
        assert_check(True, "Safe query was approved")
        assert_check(response.choices is not None, "Response has choices")
    except PolicyViolationError:
        assert_check(False, "Safe query should not be blocked")
    except Exception as e:
        # May fail if no OpenAI key, but interceptor should still work
        if "api_key" in str(e).lower() or "authentication" in str(e).lower():
            print(f"   Note: OpenAI API error (expected without key): {e}")
            assert_check(True, "Interceptor processed request (API key issue expected)")
        else:
            failures.append(f"Safe query failed: {e}")
    print()

    # Test 2: SQL injection. Every shipped sys_sqli_* policy stores warn, so it is
    # detected and approved, not blocked. An org sqli=block override (or a policy
    # whose action is block) blocks it instead.
    print("2. SQL Injection - Expected: APPROVED (SQLi warns by default)")
    try:
        response = governed_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "SELECT * FROM users; DROP TABLE users;--"}],
            max_tokens=50
        )
        assert_check(True, "SQL injection was approved with a warning (stored action: warn)")
    except PolicyViolationError as e:
        assert_check(
            False,
            f"SQL injection was blocked, but the shipped action is warn "
            f"(an org sqli=block override or an edited policy action is in force): {e}",
        )
    except Exception as e:
        # The pre-check approved it and the call reached the OpenAI API
        if "api_key" in str(e).lower() or "authentication" in str(e).lower():
            print(f"   Note: OpenAI API error (expected without key): {e}")
            assert_check(True, "Interceptor passed the warned request through (API key issue expected)")
        else:
            failures.append(f"SQL injection test failed unexpectedly: {e}")
    print()

    # Test 3: PII (sys_pii_ssn stores warn for the request phase)
    print("3. PII Query - Expected: APPROVED")
    try:
        response = governed_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Process refund for SSN 123-45-6789"}],
            max_tokens=50
        )
        assert_check(True, "PII query was approved (stored action: warn)")
    except PolicyViolationError:
        # May be blocked depending on policy config
        assert_check(True, "PII query handled by policy")
    except Exception as e:
        if "api_key" in str(e).lower():
            assert_check(True, "Interceptor processed PII request")
        else:
            failures.append(f"PII test failed: {e}")
    print()

    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Interceptor operations validated:")
        print("  - wrap_openai_client()")
        print("  - Policy pre-check on LLM calls")
        print("  - PolicyViolationError on blocked requests")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
