#!/usr/bin/env python3
"""
AxonFlow Health Check Example - Python

Demonstrates and VALIDATES health check of AxonFlow services.

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("AxonFlow Health Check - Python SDK")
    print("=" * 40)
    print()

    client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", ""),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    )

    # 1. Check Agent health
    print("1. Agent Health Check...")
    try:
        agent_healthy = await client.health_check()
        assert_check(agent_healthy is True, "Agent is healthy")
    except Exception as e:
        failures.append(f"Agent health check failed: {e}")
    print()

    # 2. Check Orchestrator health
    print("2. Orchestrator Health Check...")
    try:
        orch_healthy = await client.orchestrator_health_check()
        assert_check(orch_healthy is True, "Orchestrator is healthy")
    except Exception as e:
        failures.append(f"Orchestrator health check failed: {e}")
    print()

    print("=" * 40)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Health checks validated:")
        print("  - Agent health_check()")
        print("  - Orchestrator orchestrator_health_check()")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
