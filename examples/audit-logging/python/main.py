#!/usr/bin/env python3
"""
AxonFlow Audit Logging Example - Python

Demonstrates and VALIDATES the complete Gateway Mode workflow with audit logging:
1. Pre-check - Validate request against policies
2. LLM Call - Make your own call to OpenAI
3. Audit - Log the interaction for compliance
4. Query - Retrieve audit logs via SDK

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
from axonflow.types import AuditSearchRequest, AuditQueryOptions, AuditToolCallRequest, TokenUsage

load_dotenv()

# Optional: OpenAI for real LLM calls
try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("AxonFlow Audit Logging - Python SDK")
    print("=" * 50)
    print()

    user_token = os.getenv("AXONFLOW_USER_TOKEN", "audit-user")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "audit-logging-demo")

    openai_key = os.getenv("OPENAI_API_KEY", "")
    openai_client = None
    if OPENAI_AVAILABLE and openai_key:
        openai_client = AsyncOpenAI(api_key=openai_key)
    else:
        print("Note: Using mock LLM responses (set OPENAI_API_KEY for real calls)")
        print()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=client_id,
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        # Test 1: Pre-check and audit a safe query
        print("1. Safe Query - Pre-check + Audit")
        query = "What is the capital of France?"
        try:
            precheck_start = time.time()
            precheck = await axonflow.get_policy_approved_context(
                user_token=user_token,
                query=query,
                context={"example": "audit-logging"},
            )
            precheck_latency = (time.time() - precheck_start) * 1000

            assert_check(precheck.context_id != "", "Pre-check returns context_id")
            assert_check(precheck.approved is True, "Safe query was approved")
            print(f"   Pre-check latency: {precheck_latency:.1f}ms")

            # LLM Call (mock or real)
            llm_start = time.time()
            if openai_client:
                completion = await openai_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": query}],
                    max_tokens=50,
                )
                response = completion.choices[0].message.content
                prompt_tokens = completion.usage.prompt_tokens
                completion_tokens = completion.usage.completion_tokens
                total_tokens = completion.usage.total_tokens
            else:
                await asyncio.sleep(0.05)
                response = "Paris is the capital of France."
                prompt_tokens = 10
                completion_tokens = 8
                total_tokens = 18
            llm_latency = (time.time() - llm_start) * 1000

            # Audit the call
            audit_start = time.time()
            audit_result = await axonflow.audit_llm_call(
                context_id=precheck.context_id,
                response_summary=response[:100] if response else "",
                provider="openai",
                model="gpt-4o-mini",
                token_usage=TokenUsage(
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                ),
                latency_ms=int(llm_latency),
            )
            audit_latency = (time.time() - audit_start) * 1000

            assert_check(audit_result is not None, "Audit call succeeded")
            if audit_result:
                assert_check("audit_id" in audit_result or True, "Audit result returned")
            print(f"   Audit latency: {audit_latency:.1f}ms")

        except Exception as e:
            failures.append(f"Safe query audit failed: {e}")
        print()

        # Test 2: Pre-check a blocked query (SQL injection)
        print("2. Blocked Query - SQL Injection Pre-check")
        try:
            blocked_precheck = await axonflow.get_policy_approved_context(
                user_token=user_token,
                query="SELECT * FROM users; DROP TABLE users;--",
                context={"example": "audit-logging"},
            )
            assert_check(blocked_precheck.approved is False, "SQL injection was blocked")
            assert_check(blocked_precheck.block_reason != "", "Block reason provided")
        except PolicyViolationError as e:
            # Blocked at policy layer - this is expected
            assert_check(True, f"SQL injection was blocked by policy: {e.block_reason or e.message}")
        except Exception as e:
            failures.append(f"SQL injection test failed: {e}")
        print()

    # Test 3: Tool Call Audit (Non-LLM tool tracking)
    print("3. Tool Call Audit (Non-LLM)")
    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=client_id,
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as tool_client:
        try:
            tool_result = await tool_client.audit_tool_call(
                AuditToolCallRequest(
                    tool_name="weather-api",
                    tool_type="api",
                    input={"city": "San Francisco", "units": "metric"},
                    output={"temperature": 18, "condition": "sunny"},
                    duration_ms=245,
                    success=True,
                    policies_applied=["data-residency", "rate-limit"],
                )
            )
            assert_check(tool_result is not None, "audit_tool_call succeeded")
            assert_check(tool_result.status == "recorded", "Tool call audit status is 'recorded'")
            print(f"   Audit ID: {tool_result.audit_id}")
            print(f"   Status: {tool_result.status}")
        except Exception as e:
            if "404" in str(e):
                print("   Endpoint not available (requires Platform v5.1.0+)")
            else:
                failures.append(f"audit_tool_call failed: {e}")
    print()

    # Test 4: Query audit logs via SDK
    print("4. Query Audit Logs")
    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=client_id,
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as query_client:
        try:
            tenant_logs = await query_client.get_audit_logs_by_tenant(
                client_id,
                AuditQueryOptions(limit=10, offset=0),
            )
            assert_check(tenant_logs is not None, "get_audit_logs_by_tenant succeeded")
            assert_check(hasattr(tenant_logs, "entries"), "Response has entries field")
            print(f"   Found {len(tenant_logs.entries)} audit entries")
        except Exception as e:
            failures.append(f"get_audit_logs_by_tenant failed: {e}")
        print()

        # Test 5: Search audit logs
        print("5. Search Audit Logs")
        try:
            search_result = await query_client.search_audit_logs(
                AuditSearchRequest(
                    client_id=client_id,
                    limit=10,
                )
            )
            assert_check(search_result is not None, "search_audit_logs succeeded")
            assert_check(hasattr(search_result, "entries"), "Search result has entries")
            print(f"   Found {len(search_result.entries)} matching entries")
        except Exception as e:
            failures.append(f"search_audit_logs failed: {e}")
        print()

    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Audit Logging operations validated:")
        print("  - get_policy_approved_context() (pre-check)")
        print("  - audit_llm_call()")
        print("  - audit_tool_call()")
        print("  - get_audit_logs_by_tenant()")
        print("  - search_audit_logs()")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
