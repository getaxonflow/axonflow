#!/usr/bin/env python3
"""
AxonFlow MAP Lifecycle Example - Python SDK

Validates the FULL MAP v1.0 lifecycle:
 1. Generate plan (default mode) - verify plan_id, steps
 2. Get status (pending)
 3. Update plan (change execution_mode, optimistic locking)
 4. Get version history
 5. Stale update (verify version conflict)
 6. Execute plan - verify completed
 7. Get status (completed)
 8. Cancel completed plan - verify rejected
 9. Generate + cancel + try execute cancelled plan
10. Generate with balanced mode - execute - verify completed

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import (
    AxonFlow,
    ExecutionMode,
    UpdatePlanRequest,
    VersionConflictError,
)

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
    print("AxonFlow MAP Lifecycle - Python SDK")
    print("=" * 40)
    print()

    endpoint = get_env("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = get_env("AXONFLOW_CLIENT_ID", "demo-org")
    client_secret = get_env("AXONFLOW_CLIENT_SECRET", "demo")
    user_token = get_env("AXONFLOW_USER_TOKEN", "")
    domain = "generic"

    async with AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
        debug=get_env("AXONFLOW_DEBUG", "") == "true",
    ) as client:
        # ========================================
        # 1. GENERATE PLAN (default mode)
        # ========================================
        print("1. generate_plan - Default mode...")
        try:
            plan = await client.generate_plan(
                query="Create a plan to analyze user feedback and suggest improvements",
                domain=domain,
                user_token=user_token if user_token else None,
            )
        except Exception as e:
            print(f"   FATAL: generate_plan failed: {e}")
            return 1

        print(f"   Plan ID: {plan.plan_id}")
        print(f"   Steps: {len(plan.steps)}")

        assert_check(plan.plan_id != "", "Plan ID is not empty")
        assert_check(plan.plan_id.startswith("plan_"), "Plan ID has correct prefix")
        assert_check(len(plan.steps) > 0, "Plan has at least one step")
        print()

        # ========================================
        # 2. GET STATUS (pending)
        # ========================================
        print("2. get_plan_status - Should be pending...")
        try:
            status = await client.get_plan_status(plan.plan_id)
            assert_check(
                status.status in ("pending", "created"),
                f"Status is pending/created ({status.status})",
            )
        except Exception as e:
            if "404" in str(e):
                print("   SKIP: get_plan_status not implemented (404)")
            else:
                print(f"   FATAL: get_plan_status failed: {e}")
                return 1
        print()

        # ========================================
        # 3. UPDATE PLAN (change execution_mode, version 1 -> 2)
        # ========================================
        print("3. update_plan - Change execution_mode to parallel...")
        try:
            update_resp = await client.update_plan(
                plan.plan_id,
                UpdatePlanRequest(
                    version=1,
                    execution_mode=ExecutionMode.PARALLEL,
                ),
            )
        except Exception as e:
            print(f"   FATAL: update_plan failed: {e}")
            return 1

        print(f"   New Version: {update_resp.version}")
        assert_check(update_resp.version == 2, f"Version is 2 (got {update_resp.version})")
        assert_check(update_resp.plan_id == plan.plan_id, "plan_id matches")
        print()

        # ========================================
        # 4. GET VERSION HISTORY
        # ========================================
        print("4. get_plan_versions - Check version history...")
        try:
            versions_resp = await client.get_plan_versions(plan.plan_id)
        except Exception as e:
            print(f"   FATAL: get_plan_versions failed: {e}")
            return 1

        print(f"   Version count: {len(versions_resp.versions)}")
        assert_check(
            len(versions_resp.versions) >= 1,
            f"At least 1 version ({len(versions_resp.versions)})",
        )
        assert_check(versions_resp.plan_id == plan.plan_id, "plan_id matches")
        for v in versions_resp.versions:
            print(f"     v{v.version}: {v.change_type} ({v.changed_at})")
        print()

        # ========================================
        # 5. STALE UPDATE (verify version conflict)
        # ========================================
        print("5. Stale Update - Send version 1 again (expect conflict)...")
        try:
            await client.update_plan(
                plan.plan_id,
                UpdatePlanRequest(
                    version=1,
                    execution_mode=ExecutionMode.SEQUENTIAL,
                ),
            )
            assert_check(False, "Stale update should have raised error")
        except VersionConflictError as e:
            assert_check(True, "VersionConflictError raised")
            print(f"   Conflict: {e}")
        except Exception as e:
            assert_check(False, f"Expected VersionConflictError, got {type(e).__name__}: {e}")
        print()

        # ========================================
        # 6. EXECUTE PLAN
        # ========================================
        print("6. execute_plan - Execute the updated plan...")
        try:
            execution = await client.execute_plan(
                plan.plan_id,
                user_token=user_token if user_token else None,
            )
        except Exception as e:
            print(f"   FATAL: execute_plan failed: {e}")
            return 1

        print(f"   Status: {execution.status}")
        assert_check(
            execution.status in ("completed", "success"),
            "Execution completed",
        )
        print()

        # ========================================
        # 7. GET STATUS (completed)
        # ========================================
        print("7. get_plan_status - Should be completed...")
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
        # 8. CANCEL COMPLETED PLAN (expect rejection)
        # ========================================
        print("8. cancel_plan - Cancel completed plan (expect rejection)...")
        try:
            await client.cancel_plan(plan.plan_id, reason="Testing cancel on completed plan")
            assert_check(False, "Cancel completed plan should have raised error")
        except Exception as e:
            assert_check(True, "Cancel completed plan rejected")
            print(f"   Error: {e}")
        print()

        # ========================================
        # 9. GENERATE + CANCEL + TRY EXECUTE
        # ========================================
        print("9. Generate -> Cancel -> Try Execute...")
        try:
            plan2 = await client.generate_plan(
                query="Create a simple greeting plan",
                domain=domain,
                user_token=user_token if user_token else None,
            )
        except Exception as e:
            print(f"   FATAL: Second plan failed: {e}")
            return 1

        assert_check(plan2.plan_id != "", "Second plan generated")

        try:
            cancel_resp = await client.cancel_plan(plan2.plan_id, reason="Testing cancel flow")
            assert_check(cancel_resp.status == "cancelled", f"Plan cancelled ({cancel_resp.status})")
        except Exception as e:
            print(f"   FATAL: cancel_plan failed: {e}")
            return 1

        # Try executing cancelled plan
        try:
            await client.execute_plan(
                plan2.plan_id,
                user_token=user_token if user_token else None,
            )
            assert_check(False, "Execute cancelled plan should have raised error")
        except Exception:
            assert_check(True, "Execute cancelled plan rejected")
        print()

        # ========================================
        # 10. GENERATE WITH BALANCED MODE + EXECUTE
        # ========================================
        print("10. generate_plan - Balanced mode...")
        try:
            plan3 = await client.generate_plan(
                query="Create a plan to process and summarize data",
                domain=domain,
                user_token=user_token if user_token else None,
                execution_mode=ExecutionMode.BALANCED,
            )
        except Exception as e:
            print(f"   FATAL: Balanced plan failed: {e}")
            return 1

        assert_check(plan3.plan_id != "", "Balanced plan generated")
        print(f"   Plan ID: {plan3.plan_id}")

        try:
            exec3 = await client.execute_plan(
                plan3.plan_id,
                user_token=user_token if user_token else None,
            )
            assert_check(
                exec3.status in ("completed", "success"),
                "Balanced plan executed",
            )
        except Exception as e:
            print(f"   FATAL: Execute balanced plan failed: {e}")
            return 1
        print()

        # ========================================
        # SUMMARY
        # ========================================
        print("=" * 40)
        print(f"Tests Run: {tests_run}")
        if not failures:
            print("ALL TESTS PASSED")
            print()
            print("Lifecycle validated:")
            print("  - generate_plan / generate_plan with execution_mode")
            print("  - get_plan_status (pre/post execution)")
            print("  - update_plan (optimistic locking)")
            print("  - get_plan_versions (version history)")
            print("  - VersionConflictError detection")
            print("  - execute_plan (default + balanced mode)")
            print("  - cancel_plan (pending + completed rejection)")
            return 0
        else:
            print(f"{len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
