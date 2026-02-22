#!/usr/bin/env python3
"""
AxonFlow Gateway Mode - Anthropic Claude Example

VALIDATION: This example exits with code 1 if any assertion fails.

Demonstrates Gateway Mode with Anthropic's Claude models.
Same pattern as OpenAI: Pre-check -> LLM Call -> Audit

Run with: python anthropic_example.py
Prerequisites: docker compose up -d, ANTHROPIC_API_KEY set
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
    print("AxonFlow Gateway Mode - Anthropic Claude Example")
    print("=" * 60)
    print()

    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if not anthropic_key:
        print("Note: ANTHROPIC_API_KEY not set, running pre-check validation only")
        return await run_precheck_only()

    try:
        from anthropic import Anthropic
    except ImportError:
        print("Note: anthropic package not installed, running pre-check validation only")
        return await run_precheck_only()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:
        anthropic = Anthropic(api_key=anthropic_key)

        user_token = "user-456"
        query = "Explain the importance of audit trails in AI systems."
        context = {
            "user_role": "compliance_officer",
            "department": "legal",
        }

        print(f'Query: "{query}"')
        print(f"User: {user_token}")
        print()

        # Step 1: Pre-Check
        print("Step 1: Policy Pre-Check...")
        pre_check_start = time.time()

        pre_check_result = await axonflow.get_policy_approved_context(
            user_token=user_token,
            query=query,
            context=context,
        )

        pre_check_latency_ms = int((time.time() - pre_check_start) * 1000)

        assert_check(pre_check_result is not None, "Pre-check returned result")
        assert_check(pre_check_result.context_id != "", "Pre-check returned context_id")
        assert_check(pre_check_result.approved is True, "Query was approved")

        print(f"   Completed in {pre_check_latency_ms}ms")
        print(f"   Context ID: {pre_check_result.context_id}")

        if not pre_check_result.approved:
            print(f"   Blocked: {pre_check_result.block_reason}")
            failures.append("Query was unexpectedly blocked")
            return 1

        print()

        # Step 2: Claude LLM Call
        print("Step 2: LLM Call (Claude)...")
        llm_start = time.time()

        message = anthropic.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=200,
            messages=[
                {
                    "role": "user",
                    "content": query,
                },
            ],
        )

        llm_latency_ms = int((time.time() - llm_start) * 1000)
        response = message.content[0].text if message.content else ""

        assert_check(message is not None, "Anthropic returned message")
        assert_check(len(message.content) > 0, "Message has content")
        assert_check(response != "", "Response text is not empty")

        print(f"   Response received in {llm_latency_ms}ms")
        print(f"   Tokens: {message.usage.input_tokens} in, {message.usage.output_tokens} out")
        print()

        # Step 3: Audit
        print("Step 3: Audit Logging...")
        audit_start = time.time()

        await axonflow.audit_llm_call(
            context_id=pre_check_result.context_id,
            response_summary=response[:100] if len(response) > 100 else response,
            provider="anthropic",
            model="claude-haiku-4-5-20251001",
            token_usage=TokenUsage(
                prompt_tokens=message.usage.input_tokens,
                completion_tokens=message.usage.output_tokens,
                total_tokens=message.usage.input_tokens + message.usage.output_tokens,
            ),
            latency_ms=llm_latency_ms,
        )

        audit_latency_ms = int((time.time() - audit_start) * 1000)
        assert_check(True, "Audit call succeeded")
        print(f"   Audit logged in {audit_latency_ms}ms")
        print()

        # Results
        governance_overhead_ms = pre_check_latency_ms + audit_latency_ms
        print("=" * 60)
        print(f"Response:\n{response[:200]}...\n")
        print(f"Governance overhead: {governance_overhead_ms}ms")
        print(f"   (Pre-check: {pre_check_latency_ms}ms + Audit: {audit_latency_ms}ms)")

    print()
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Anthropic Gateway Mode validated:")
        print("  - get_policy_approved_context() pre-check")
        print("  - Anthropic Claude API call")
        print("  - audit_llm_call() with token usage")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


async def run_precheck_only() -> int:
    """Run pre-check validation when Anthropic key not available."""
    print()
    print("--- Running Pre-Check Validation Only ---")

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        pre_check_result = await axonflow.get_policy_approved_context(
            user_token="test-user",
            query="Explain the importance of audit trails in AI systems.",
            context={"provider": "anthropic"},
        )

        assert_check(pre_check_result is not None, "Pre-check returned result")
        assert_check(pre_check_result.context_id != "", "Pre-check returned context_id")
        assert_check(pre_check_result.approved is True, "Safe query was approved")

    print()
    if not failures:
        print("✓ ALL TESTS PASSED (Pre-check only)")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
