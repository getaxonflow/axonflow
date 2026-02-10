#!/usr/bin/env python3
"""
AxonFlow MAP Confirm Mode Example - Python SDK (Enterprise Only)

Demonstrates the confirm execution mode where every step
requires explicit approval before execution.

REQUIRES: Enterprise license

Flow:
 1. Generate plan with execution_mode="confirm"
 2. Execute plan -> returns "awaiting_approval"
 3. Resume plan (approve step) -> executes step, pauses at next
 4. Repeat until all steps complete

Run with: python main.py
Prerequisites: docker compose up -d (enterprise mode)
"""

import asyncio
import os
import sys

from axonflow import AxonFlow, ExecutionMode

failures: list[str] = []
tests_run = 0


def get_env(key: str, default: str) -> str:
    return os.getenv(key, default)


def assert_check(condition: bool, message: str) -> None:
    global tests_run
    tests_run += 1
    if not condition:
        failures.append(message)
        print(f"   FAIL: {message}")
    else:
        print(f"   PASS: {message}")


async def main() -> int:
    print("AxonFlow MAP Confirm Mode - Python SDK (Enterprise)")
    print("=" * 55)
    print()

    endpoint = get_env("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = get_env("AXONFLOW_CLIENT_ID", "demo-org")
    client_secret = get_env("AXONFLOW_CLIENT_SECRET", "demo")
    user_token = get_env("AXONFLOW_USER_TOKEN", "")
    domain = "travel"

    async with AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
        debug=get_env("AXONFLOW_DEBUG", "") == "true",
    ) as client:
        # ========================================
        # 1. GENERATE PLAN WITH CONFIRM MODE
        # ========================================
        print("1. generate_plan - Confirm mode...")
        try:
            plan = await client.generate_plan(
                query="Search flights, analyze options, and book the best one",
                domain=domain,
                user_token=user_token if user_token else None,
                execution_mode=ExecutionMode.CONFIRM,
            )
        except Exception as e:
            err_msg = str(e).lower()
            if "enterprise" in err_msg or "403" in str(e) or "license" in err_msg:
                print(f"   SKIP: Confirm mode requires enterprise license: {e}")
                print()
                print("=" * 55)
                print("Skipped - enterprise license required")
                return 0
            print(f"   FATAL: generate_plan failed: {e}")
            return 1

        print(f"   Plan ID: {plan.plan_id}")
        print(f"   Steps: {len(plan.steps)}")

        assert_check(plan.plan_id != "", "Confirm mode plan generated")
        assert_check(len(plan.steps) > 0, "Plan has steps")
        print()

        # ========================================
        # 2. EXECUTE PLAN (should return awaiting_approval)
        # ========================================
        print("2. execute_plan - Should return awaiting_approval...")
        try:
            execution = await client.execute_plan(
                plan.plan_id,
                user_token=user_token if user_token else None,
            )
        except Exception as e:
            print(f"   FATAL: execute_plan failed: {e}")
            return 1

        assert_check(
            execution.status == "awaiting_approval",
            f"Status is awaiting_approval ({execution.status})",
        )
        print()

        # ========================================
        # 3-N. RESUME LOOP (approve each step)
        # ========================================
        total_steps = len(plan.steps)
        for step in range(1, total_steps + 1):
            print(f"{step + 2}. resume_plan - Approve step {step}...")

            try:
                resume_resp = await client.resume_plan(plan.plan_id, approved=True)
            except Exception as e:
                print(f"   FATAL: resume_plan failed: {e}")
                return 1

            print(f"   Status: {resume_resp.status}")

            if resume_resp.status == "completed":
                assert_check(True, f"Plan completed after step {step}")
                print()
                break
            elif resume_resp.status == "awaiting_approval":
                assert_check(True, f"Step {step} approved, paused at next step")
            else:
                assert_check(False, f"Unexpected status after resume: {resume_resp.status}")
            print()

        # ========================================
        # FINAL STATUS CHECK
        # ========================================
        print("Final Status Check...")
        try:
            final_status = await client.get_plan_status(plan.plan_id)
            assert_check(
                final_status.status in ("completed", "success"),
                f"Final status is completed ({final_status.status})",
            )
        except Exception as e:
            if "404" in str(e):
                print("   SKIP: get_plan_status not implemented (404)")
            else:
                print(f"   FATAL: get_plan_status failed: {e}")
                return 1
        print()

        # ========================================
        # SUMMARY
        # ========================================
        print("=" * 55)
        print(f"Tests Run: {tests_run}")
        if not failures:
            print("ALL TESTS PASSED")
            print()
            print("Confirm mode flow:")
            print("  1. generate_plan (confirm)")
            print("  2. execute_plan -> awaiting_approval")
            print("  3. resume_plan (approve) x N steps")
            print("  4. get_plan_status -> completed")
            return 0
        else:
            print(f"{len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
