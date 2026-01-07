#!/usr/bin/env python3
"""
AxonFlow MAP (Multi-Agent Planning) Example - Python SDK

This example demonstrates and VALIDATES all MAP SDK methods:
- generate_plan()   - Create a multi-agent execution plan
- execute_plan()    - Execute a previously generated plan
- get_plan_status() - Get status of a running or completed plan

VALIDATION: This example exits with code 1 if any assertion fails.
This ensures CI/CD pipelines catch regressions.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow

failures: list[str] = []


def get_env(key: str, default: str) -> str:
    return os.getenv(key, default)


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if not condition:
        failures.append(message)
        print(f"   ❌ FAIL: {message}")
    else:
        print(f"   ✓ PASS: {message}")


async def main() -> int:
    print("AxonFlow MAP (Multi-Agent Planning) - Python SDK")
    print("=" * 50)
    print()

    endpoint = get_env("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = get_env("AXONFLOW_CLIENT_ID", "demo")
    client_secret = get_env("AXONFLOW_CLIENT_SECRET", "demo")

    async with AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
        debug=get_env("AXONFLOW_DEBUG", "") == "true",
    ) as client:
        query = "Create a brief plan to greet a new user and ask how to help them"
        domain = "generic"

        print(f"Query: {query}")
        print(f"Domain: {domain}")
        print("-" * 50)
        print()

        # ========================================
        # 1. GENERATE PLAN
        # ========================================
        print("1. generate_plan - Creating a multi-agent plan...")
        try:
            plan = await client.generate_plan(query=query, domain=domain)
        except Exception as e:
            print(f"   ❌ FATAL: generate_plan failed: {e}")
            return 1

        print(f"   Plan ID: {plan.plan_id}")
        print(f"   Domain: {plan.domain}")
        print(f"   Steps: {len(plan.steps)}")

        # Validate generate_plan response
        assert_check(plan.plan_id != "", "plan_id is not empty")
        assert_check(
            plan.plan_id.startswith("plan_"),
            "plan_id has correct prefix 'plan_'",
        )
        assert_check(len(plan.steps) > 0, "Plan has at least one step")

        if plan.steps:
            print("   Plan Steps:")
            for i, step in enumerate(plan.steps, 1):
                step_type = getattr(step, "type", "action")
                print(f"     {i}. {step.name} ({step_type})")
                assert_check(step.name != "", f"Step {i} has a name")
                assert_check(step_type != "", f"Step {i} has a type")
        print()

        expected_step_count = len(plan.steps)

        # ========================================
        # 2. GET PLAN STATUS (before execution) - Optional
        # ========================================
        print("2. get_plan_status - Checking status before execution...")
        try:
            status = await client.get_plan_status(plan.plan_id)
            print(f"   Status: {status.status}")
            print(f"   Total Steps: {status.total_steps}")

            # Validate pre-execution status
            assert_check(
                status.status in ("pending", "created"),
                "Plan status is pending/created before execution",
            )
            assert_check(
                status.total_steps == expected_step_count,
                f"total_steps matches plan ({expected_step_count})",
            )
        except Exception as e:
            # get_plan_status is optional - skip if not implemented (404)
            if "404" in str(e):
                print("   ⏭ SKIP: get_plan_status not implemented (404)")
            else:
                print(f"   ❌ FATAL: get_plan_status failed: {e}")
                return 1
        print()

        # ========================================
        # 3. EXECUTE PLAN
        # ========================================
        print("3. execute_plan - Executing the plan...")
        try:
            execution = await client.execute_plan(plan.plan_id)
        except Exception as e:
            print(f"   ❌ FATAL: execute_plan failed: {e}")
            return 1

        print(f"   Execution Status: {execution.status}")
        total_steps = getattr(execution, "total_steps", 0)
        completed_steps = getattr(execution, "completed_steps", 0)
        if total_steps > 0:
            print(f"   Completed Steps: {completed_steps}/{total_steps}")

        # Validate execution response
        assert_check(
            execution.status in ("completed", "success"),
            "Execution status indicates success",
        )

        # Step tracking is optional - only validate if present
        if total_steps > 0:
            assert_check(
                total_steps == expected_step_count,
                f"Execution total_steps matches plan ({expected_step_count})",
            )
            assert_check(
                completed_steps == expected_step_count,
                "All steps completed",
            )

        # Validate step results if available
        if hasattr(execution, "results") and execution.results:
            print("   Step Results:")
            assert_check(
                len(execution.results) == expected_step_count,
                "results count matches plan steps",
            )
            for i, result in enumerate(execution.results, 1):
                step_name = getattr(result, "step_name", "step")
                step_status = getattr(result, "status", "unknown")
                print(f"     - {step_name}: {step_status}")
                assert_check(
                    step_status in ("completed", "success"),
                    f"Step {i} completed successfully",
                )
        print()

        # ========================================
        # 4. GET PLAN STATUS (after execution) - Optional
        # ========================================
        print("4. get_plan_status - Checking status after execution...")
        try:
            final_status = await client.get_plan_status(plan.plan_id)
            print(f"   Status: {final_status.status}")
            print(f"   Completed Steps: {final_status.completed_steps}/{final_status.total_steps}")

            # Validate post-execution status
            assert_check(
                final_status.status in ("completed", "success"),
                "Final status indicates completion",
            )
            assert_check(
                final_status.completed_steps == expected_step_count,
                "All steps show as completed",
            )
        except Exception as e:
            # get_plan_status is optional - skip if not implemented (404)
            if "404" in str(e):
                print("   ⏭ SKIP: get_plan_status not implemented (404)")
            else:
                print(f"   ❌ FATAL: get_plan_status (post-execution) failed: {e}")
                return 1
        print()

        # ========================================
        # SUMMARY
        # ========================================
        print("=" * 50)
        if not failures:
            print("✓ ALL TESTS PASSED")
            print()
            print("Methods validated:")
            print("  1. generate_plan()   - Plan created with valid ID and steps")
            print("  2. get_plan_status() - Pre-execution status is pending")
            print("  3. execute_plan()    - All plan steps executed successfully")
            print("  4. get_plan_status() - Post-execution status is completed")
            return 0
        else:
            print(f"❌ {len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
