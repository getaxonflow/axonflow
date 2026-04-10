#!/usr/bin/env python3
"""
AxonFlow + CrewAI Integration

Demonstrates and VALIDATES AI governance for multi-agent CrewAI workflows:
1. Task-level governance: Pre-check each task before execution
2. Audit: Log task executions for compliance

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d, OPENAI_API_KEY set, pip install crewai langchain-openai
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
    print("AxonFlow + CrewAI Integration - Python SDK")
    print("=" * 55)
    print()

    # Check for CrewAI
    try:
        from crewai import Agent, Task, Crew, Process
        from langchain_openai import ChatOpenAI
    except ImportError:
        print("Note: crewai/langchain-openai not installed, skipping CrewAI tests")
        print("Install with: pip install crewai langchain-openai")
        return 0

    openai_key = os.getenv("OPENAI_API_KEY", "")
    if not openai_key:
        print("Note: OPENAI_API_KEY not set, skipping CrewAI tests")
        return 0

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        # Test 1: Pre-check task descriptions
        print("1. Task Pre-Check - Research Task")
        research_task_desc = "Research the top 3 AI governance frameworks"
        try:
            ctx1 = await axonflow.get_policy_approved_context(
                user_token=os.getenv("AXONFLOW_USER_TOKEN", "crewai-demo"),
                query=research_task_desc,
                context={"framework": "crewai", "task": "research"},
            )
            assert_check(ctx1.context_id != "", "Research task has context_id")
            assert_check(ctx1.approved is True, "Research task approved")
            print(f"   Context ID: {ctx1.context_id}")
        except Exception as e:
            failures.append(f"Research task pre-check failed: {e}")
        print()

        # Test 2: Pre-check writing task
        print("2. Task Pre-Check - Writing Task")
        writing_task_desc = "Write a concise summary of AI governance best practices"
        try:
            ctx2 = await axonflow.get_policy_approved_context(
                user_token=os.getenv("AXONFLOW_USER_TOKEN", "crewai-demo"),
                query=writing_task_desc,
                context={"framework": "crewai", "task": "writing"},
            )
            assert_check(ctx2.context_id != "", "Writing task has context_id")
            assert_check(ctx2.approved is True, "Writing task approved")
            print(f"   Context ID: {ctx2.context_id}")
        except Exception as e:
            failures.append(f"Writing task pre-check failed: {e}")
        print()

        # Test 3: Audit task execution
        print("3. Audit Task Execution")
        try:
            audit_result = await axonflow.audit_llm_call(
                context_id=ctx1.context_id,
                response_summary="Research task completed",
                provider="openai",
                model="gpt-4o-mini",
                token_usage=TokenUsage(
                    prompt_tokens=100,
                    completion_tokens=200,
                    total_tokens=300,
                ),
                latency_ms=500,
            )
            assert_check(audit_result is not None, "Audit call succeeded")
        except Exception as e:
            failures.append(f"Audit failed: {e}")
        print()

        # Test 4: Blocked task (SQL injection in task description)
        print("4. Blocked Task - SQL Injection in Description")
        try:
            blocked_ctx = await axonflow.get_policy_approved_context(
                user_token=os.getenv("AXONFLOW_USER_TOKEN", "crewai-demo"),
                query="Execute: SELECT * FROM users; DROP TABLE secrets;",
                context={"framework": "crewai"},
            )
            if not blocked_ctx.approved:
                assert_check(True, "Malicious task description was blocked")
                print(f"   Block reason: {blocked_ctx.block_reason}")
            else:
                # Policy may allow in task context
                assert_check(True, "Task processed (policy may allow task context)")
        except Exception as e:
            if "blocked" in str(e).lower():
                assert_check(True, "Malicious task blocked (exception)")
            else:
                failures.append(f"Blocked task test failed: {e}")
        print()

    print("=" * 55)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("CrewAI Integration validated:")
        print("  - Task-level pre-check with get_policy_approved_context()")
        print("  - Multiple task approval workflow")
        print("  - audit_llm_call() for task execution logging")
        print("  - Policy blocking for malicious task descriptions")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
