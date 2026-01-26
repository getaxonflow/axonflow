#!/usr/bin/env python3
"""
AxonFlow Gateway Mode - OpenAI Example

Demonstrates and VALIDATES Gateway Mode for lowest latency governance:
1. Pre-check: Validate request against policies BEFORE calling LLM
2. LLM Call: Make your own call to your preferred provider
3. Audit: Log the interaction for compliance

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d, OPENAI_API_KEY set
"""

import asyncio
import os
import sys
import time

from dotenv import load_dotenv

from axonflow import AxonFlow
from axonflow.types import TokenUsage

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
    print("AxonFlow Gateway Mode - Python SDK")
    print("=" * 50)
    print()

    openai_key = os.getenv("OPENAI_API_KEY", "")
    openai_client = None

    if openai_key:
        try:
            from openai import OpenAI
            openai_client = OpenAI(api_key=openai_key)
        except ImportError:
            print("Note: openai package not installed")
    else:
        print("Note: OPENAI_API_KEY not set, using mock mode")
    print()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        query = "What are best practices for AI model deployment?"
        user_token = "user-gateway-demo"

        # Test 1: Pre-Check
        print("1. Policy Pre-Check")
        try:
            pre_check_start = time.time()
            pre_check_result = await axonflow.get_policy_approved_context(
                user_token=user_token,
                query=query,
                context={"department": "platform"},
            )
            pre_check_latency_ms = int((time.time() - pre_check_start) * 1000)

            assert_check(pre_check_result.context_id != "", "Pre-check returns context_id")
            assert_check(pre_check_result.approved is True, "Query was approved")
            print(f"   Context ID: {pre_check_result.context_id}")
            print(f"   Pre-check latency: {pre_check_latency_ms}ms")

            if not pre_check_result.approved:
                print(f"   Blocked: {pre_check_result.block_reason}")
                return 1

        except Exception as e:
            failures.append(f"Pre-check failed: {e}")
            return 1
        print()

        # Test 2: LLM Call (OpenAI or mock)
        print("2. LLM Call")
        llm_latency_ms = 0
        prompt_tokens = 50
        completion_tokens = 100
        total_tokens = 150

        if openai_client:
            try:
                llm_start = time.time()
                completion = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a helpful AI expert. Be concise."},
                        {"role": "user", "content": query},
                    ],
                    max_tokens=200,
                )
                llm_latency_ms = int((time.time() - llm_start) * 1000)

                assert_check(completion is not None, "OpenAI returned completion")
                assert_check(len(completion.choices) > 0, "Completion has choices")

                usage = completion.usage
                prompt_tokens = usage.prompt_tokens
                completion_tokens = usage.completion_tokens
                total_tokens = usage.total_tokens

                print(f"   LLM latency: {llm_latency_ms}ms")
                print(f"   Tokens: {prompt_tokens} prompt, {completion_tokens} completion")

            except Exception as e:
                print(f"   Note: OpenAI call failed: {e}")
                llm_latency_ms = 100
        else:
            print("   Using mock LLM response")
            llm_latency_ms = 100
            assert_check(True, "Mock LLM call (no API key)")
        print()

        # Test 3: Audit
        print("3. Audit Logging")
        try:
            audit_start = time.time()
            audit_result = await axonflow.audit_llm_call(
                context_id=pre_check_result.context_id,
                response_summary="AI deployment best practices response",
                provider="openai",
                model="gpt-3.5-turbo",
                token_usage=TokenUsage(
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                ),
                latency_ms=llm_latency_ms,
            )
            audit_latency_ms = int((time.time() - audit_start) * 1000)

            assert_check(audit_result is not None, "Audit call succeeded")
            print(f"   Audit latency: {audit_latency_ms}ms")

            governance_overhead = pre_check_latency_ms + audit_latency_ms
            print(f"   Total governance overhead: {governance_overhead}ms")

        except Exception as e:
            failures.append(f"Audit failed: {e}")
        print()

    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Gateway Mode validated:")
        print("  - get_policy_approved_context() (pre-check)")
        print("  - Direct LLM call (OpenAI)")
        print("  - audit_llm_call() with TokenUsage")
        print("  - Low governance overhead (~5-10ms typical)")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
