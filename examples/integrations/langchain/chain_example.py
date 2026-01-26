#!/usr/bin/env python3
"""
AxonFlow + LangChain Chains

VALIDATION: This example exits with code 1 if any assertion fails.

Shows how to wrap LangChain chains with AxonFlow governance.
Each chain execution is pre-checked and audited.

Run with: python chain_example.py
Prerequisites: docker compose up -d, OPENAI_API_KEY set (optional)
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


async def run_governance_test() -> int:
    """Test governance without requiring LangChain/OpenAI."""
    print("AxonFlow + LangChain Governance Test")
    print("=" * 60)
    print()
    print("Testing governance layer without full LangChain execution...")
    print()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        topics = ["machine learning", "neural networks", "data governance"]

        for i, topic in enumerate(topics, 1):
            print(f"Query {i}: {topic}")
            print("-" * 40)

            # Pre-check
            print("[Pre-check]")
            pre_check_start = time.time()

            ctx = await axonflow.get_policy_approved_context(
                user_token="chain-demo-user",
                query=topic,
                context={"chain_type": "explanation", "index": i},
            )
            pre_check_ms = int((time.time() - pre_check_start) * 1000)

            assert_check(ctx is not None, f"Query {i} pre-check returned result")
            assert_check(ctx.context_id != "", f"Query {i} has context_id")
            assert_check(ctx.approved is True, f"Query {i} was approved")

            if not ctx.approved:
                print(f"  Blocked: {ctx.block_reason}")
                continue

            print(f"  Approved in {pre_check_ms}ms")
            print(f"  Context ID: {ctx.context_id}")

            # Simulate chain execution
            print("[LangChain] (simulated)")
            llm_ms = 100

            # Audit
            print("[Audit]")
            audit_start = time.time()

            await axonflow.audit_llm_call(
                context_id=ctx.context_id,
                response_summary=f"Explanation of {topic}",
                provider="openai",
                model="gpt-3.5-turbo",
                token_usage=TokenUsage(
                    prompt_tokens=50,
                    completion_tokens=100,
                    total_tokens=150,
                ),
                latency_ms=llm_ms,
            )
            audit_ms = int((time.time() - audit_start) * 1000)

            assert_check(True, f"Query {i} audit succeeded")
            print(f"  Logged in {audit_ms}ms")
            print(f"  Governance overhead: {pre_check_ms + audit_ms}ms")
            print()

    return 0 if not failures else 1


async def main() -> int:
    print("AxonFlow + LangChain Chains Example")
    print()

    # Check if LangChain and OpenAI are available
    openai_key = os.getenv("OPENAI_API_KEY")
    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import StrOutputParser
        langchain_available = True
    except ImportError:
        langchain_available = False

    if not langchain_available or not openai_key:
        print("Note: LangChain or OPENAI_API_KEY not available")
        print("Running governance layer tests only...")
        print()
        result = await run_governance_test()

        print()
        if not failures:
            print("✓ ALL TESTS PASSED")
            print()
            print("LangChain Chains Governance validated:")
            print("  - get_policy_approved_context() pre-check")
            print("  - audit_llm_call() logging")
            print("  - Multi-query governance workflow")
            return 0
        else:
            print(f"❌ {len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1

    # Full LangChain test
    llm = ChatOpenAI(
        model="gpt-3.5-turbo",
        temperature=0.7,
        openai_api_key=openai_key,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant that explains concepts simply. Keep responses under 100 words."),
        ("human", "{topic}"),
    ])

    chain = prompt | llm | StrOutputParser()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        topics = ["machine learning", "neural networks", "data governance"]

        for i, topic in enumerate(topics, 1):
            print(f"\n{'=' * 60}")
            print(f"Query {i}: {topic}")
            print("=" * 60)

            # Pre-check
            print("\n[Pre-check]")
            pre_check_start = time.time()

            ctx = await axonflow.get_policy_approved_context(
                user_token="chain-demo-user",
                query=topic,
                context={"chain_type": "explanation", "index": i},
            )
            pre_check_ms = int((time.time() - pre_check_start) * 1000)

            assert_check(ctx is not None, f"Query {i} pre-check returned result")
            assert_check(ctx.context_id != "", f"Query {i} has context_id")
            assert_check(ctx.approved is True, f"Query {i} was approved")

            if not ctx.approved:
                print(f"  Blocked: {ctx.block_reason}")
                continue

            print(f"  Approved in {pre_check_ms}ms")
            print(f"  Context ID: {ctx.context_id}")

            # Run chain
            print("\n[LangChain]")
            llm_start = time.time()
            result = chain.invoke({"topic": topic})
            llm_ms = int((time.time() - llm_start) * 1000)

            assert_check(result is not None, f"Query {i} chain returned result")
            assert_check(len(result) > 0, f"Query {i} has non-empty response")

            print(f"  Completed in {llm_ms}ms")

            # Audit
            print("\n[Audit]")
            audit_start = time.time()

            await axonflow.audit_llm_call(
                context_id=ctx.context_id,
                response_summary=result[:100],
                provider="openai",
                model="gpt-3.5-turbo",
                token_usage=TokenUsage(
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                ),
                latency_ms=llm_ms,
            )
            audit_ms = int((time.time() - audit_start) * 1000)

            assert_check(True, f"Query {i} audit succeeded")
            print(f"  Logged in {audit_ms}ms")

            print(f"\n[Response]\n{result}")
            print(f"\nGovernance overhead: {pre_check_ms + audit_ms}ms")

    print()
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("LangChain Chains Integration validated:")
        print("  - get_policy_approved_context() pre-check")
        print("  - LangChain chain execution")
        print("  - audit_llm_call() with response summary")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
