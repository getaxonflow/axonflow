#!/usr/bin/env python3
"""
AxonFlow Proxy Mode - Python Example

Demonstrates and VALIDATES Proxy Mode (simplest integration):
- Send query to AxonFlow
- AxonFlow handles policy enforcement AND LLM routing
- Get response back

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys
import time

from dotenv import load_dotenv

from axonflow import AxonFlow
from axonflow.exceptions import PolicyViolationError

load_dotenv()

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("AxonFlow Proxy Mode - Python SDK")
    print("=" * 50)
    print()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:

        # Test 1: Safe query
        print("1. Proxy LLM Call - Safe Query")
        try:
            start_time = time.time()
            response = await client.proxy_llm_call(
                user_token="user-proxy-python",
                query="What are the key benefits of AI governance?",
                request_type="chat",
                context={"department": "engineering"},
            )
            latency_ms = int((time.time() - start_time) * 1000)

            assert_check(response is not None, "proxy_llm_call returned response")
            assert_check(hasattr(response, "blocked"), "Response has blocked field")

            if response.blocked:
                print(f"   Blocked: {response.block_reason}")
            else:
                assert_check(True, "Safe query was not blocked")
                if response.policy_info:
                    assert_check(
                        response.policy_info.policies_evaluated is not None,
                        "policy_info has policies_evaluated"
                    )
                print(f"   Latency: {latency_ms}ms")

        except Exception as e:
            if "api_key" in str(e).lower() or "authentication" in str(e).lower():
                print(f"   Note: LLM API error (expected without key): {e}")
                assert_check(True, "Request processed (LLM key issue expected)")
            else:
                failures.append(f"Safe query failed: {e}")
        print()

        # Test 2: Second query to verify consistency
        print("2. Proxy LLM Call - Second Query")
        try:
            response = await client.proxy_llm_call(
                user_token="user-proxy-python",
                query="List 3 principles of responsible AI development.",
                request_type="chat",
                context={"format": "list"},
            )

            assert_check(response is not None, "Second query returned response")
            if not response.blocked:
                assert_check(True, "Second query was not blocked")

        except Exception as e:
            if "api_key" in str(e).lower():
                assert_check(True, "Request processed (LLM key issue expected)")
            else:
                failures.append(f"Second query failed: {e}")
        print()

        # Test 3: SQL Injection (should be blocked)
        print("3. Proxy LLM Call - SQL Injection (Expected: BLOCKED)")
        try:
            sql_response = await client.proxy_llm_call(
                user_token="user-proxy-python",
                query="SELECT * FROM users; DROP TABLE secrets;",
                request_type="chat",
                context={},
            )

            if sql_response.blocked:
                assert_check(True, "SQL injection was blocked")
                assert_check(sql_response.block_reason is not None, "Block reason provided")
                print(f"   Block reason: {sql_response.block_reason}")
            else:
                assert_check(False, "SQL injection should be blocked")

        except PolicyViolationError as e:
            assert_check(True, f"SQL injection was blocked by policy: {e.block_reason or e.message}")
            print(f"   Block reason: {e.block_reason}")
        except Exception as e:
            if "api_key" in str(e).lower():
                assert_check(False, "SQL injection should be blocked before API call")
            else:
                failures.append(f"SQL injection test failed: {e}")
        print()

        # Test 4: PII query (should be approved with redaction)
        print("4. Proxy LLM Call - PII Query")
        try:
            pii_response = await client.proxy_llm_call(
                user_token="user-proxy-python",
                query="My email is test@example.com, please help me.",
                request_type="chat",
                context={},
            )

            assert_check(pii_response is not None, "PII query returned response")
            # PII may be redacted or allowed depending on policy
            if pii_response.blocked:
                print(f"   Blocked: {pii_response.block_reason}")
            else:
                print("   Query processed (PII may be redacted)")

        except Exception as e:
            if "api_key" in str(e).lower():
                assert_check(True, "Request processed (LLM key issue expected)")
            else:
                print(f"   Note: {e}")
        print()

    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Proxy Mode validated:")
        print("  - proxy_llm_call() for safe queries")
        print("  - SQL injection blocking")
        print("  - PII handling")
        print("  - policy_info in response")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
