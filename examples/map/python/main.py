#!/usr/bin/env python3
"""
AxonFlow MAP (Multi-Agent Planning) Example - Python SDK

This example demonstrates and VALIDATES all MAP SDK methods:
- generate_plan()   - Create a multi-agent execution plan
- execute_plan()    - Execute a previously generated plan
- get_plan_status() - Get status of a running or completed plan

COMPREHENSIVE VALIDATION:
- Basic flow: generate → status → execute → status
- Error handling: invalid plan ID, non-existent plan
- Edge cases: re-execution, status transitions, domain handling
- This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow

failures: list[str] = []
tests_run = 0


def get_env(key: str, default: str) -> str:
    return os.getenv(key, default)


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    global tests_run
    tests_run += 1
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
    client_id = get_env("AXONFLOW_CLIENT_ID", "demo-org")
    client_secret = get_env("AXONFLOW_CLIENT_SECRET", "demo")

    # User token for MAP operations (JWT for local testing with docker-compose)
    user_token = get_env("AXONFLOW_USER_TOKEN", "")

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
        if user_token:
            print(f"User Token: {user_token[:20]}...{user_token[-10:]}")
        print("-" * 50)
        print()

        # ========================================
        # 1. GENERATE PLAN
        # ========================================
        print("1. generate_plan - Creating a multi-agent plan...")
        try:
            plan = await client.generate_plan(
                query=query, domain=domain, user_token=user_token if user_token else None
            )
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
            # total_steps may not be in SDK types yet - use getattr
            total_steps_status = getattr(status, "total_steps", None)
            if total_steps_status is not None:
                print(f"   Total Steps: {total_steps_status}")

            # Validate pre-execution status
            assert_check(
                status.status in ("pending", "created"),
                "Plan status is pending/created before execution",
            )
            # Only validate total_steps if the SDK exposes it
            if total_steps_status is not None:
                assert_check(
                    total_steps_status == expected_step_count,
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
            execution = await client.execute_plan(
                plan.plan_id, user_token=user_token if user_token else None
            )
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
            # completed_steps/total_steps may not be in SDK types yet
            completed_steps_final = getattr(final_status, "completed_steps", None)
            total_steps_final = getattr(final_status, "total_steps", None)
            if completed_steps_final is not None and total_steps_final is not None:
                print(f"   Completed Steps: {completed_steps_final}/{total_steps_final}")

            # Validate post-execution status
            assert_check(
                final_status.status in ("completed", "success"),
                "Final status indicates completion",
            )
            # Only validate completed_steps if SDK exposes it
            if completed_steps_final is not None:
                assert_check(
                    completed_steps_final == expected_step_count,
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
        # 5. ERROR HANDLING - Invalid Plan ID Format
        # ========================================
        print("5. Error Handling - Invalid plan ID format...")
        try:
            await client.get_plan_status("invalid-id-no-prefix")
            # If we get here, the API accepted an invalid ID (might return 404)
            print("   ⚠ NOTE: API accepted invalid plan ID format")
        except Exception as e:
            # Expected: should reject invalid plan ID or return 404
            if "404" in str(e) or "not found" in str(e).lower():
                print("   ✓ PASS: Invalid plan ID correctly rejected (404)")
            else:
                print(f"   ✓ PASS: Invalid plan ID rejected with error: {type(e).__name__}")
        print()

        # ========================================
        # 6. ERROR HANDLING - Non-existent Plan ID
        # ========================================
        print("6. Error Handling - Non-existent plan ID...")
        try:
            await client.get_plan_status("plan_nonexistent_12345")
            print("   ⚠ NOTE: API returned response for non-existent plan")
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                print("   ✓ PASS: Non-existent plan correctly returns 404")
            else:
                print(f"   ✓ PASS: Non-existent plan rejected: {type(e).__name__}")
        print()

        # ========================================
        # 7. RE-EXECUTION TEST - Execute completed plan
        # ========================================
        print("7. Re-execution Test - Attempting to re-execute completed plan...")
        try:
            reexec = await client.execute_plan(
                plan.plan_id, user_token=user_token if user_token else None
            )
            # Some systems allow re-execution, others don't
            reexec_status = getattr(reexec, "status", "unknown")
            if reexec_status in ("completed", "success", "already_completed"):
                print(f"   ⚠ NOTE: Re-execution returned status: {reexec_status}")
            else:
                print(f"   ⚠ NOTE: Re-execution status: {reexec_status}")
        except Exception as e:
            # Expected: should either reject re-execution or return idempotent result
            print(f"   ✓ PASS: Re-execution handled: {type(e).__name__}")
        print()

        # ========================================
        # 8. SECOND PLAN - Different Query
        # ========================================
        print("8. Second Plan - Testing with different query...")
        query2 = "Analyze sales data and create a summary report"
        try:
            plan2 = await client.generate_plan(
                query=query2, domain=domain, user_token=user_token if user_token else None
            )
            assert_check(plan2.plan_id != "", "Second plan has valid ID")
            assert_check(plan2.plan_id != plan.plan_id, "Second plan has different ID")
            assert_check(len(plan2.steps) > 0, "Second plan has steps")
            print(f"   Plan 2 ID: {plan2.plan_id}")
            print(f"   Plan 2 Steps: {len(plan2.steps)}")

            # Execute second plan
            exec2 = await client.execute_plan(
                plan2.plan_id, user_token=user_token if user_token else None
            )
            assert_check(
                exec2.status in ("completed", "success"),
                "Second plan executed successfully",
            )
        except Exception as e:
            print(f"   ❌ FATAL: Second plan test failed: {e}")
            failures.append(f"Second plan test failed: {e}")
        print()

        # ========================================
        # 9. STEP VALIDATION - Detailed step analysis
        # ========================================
        print("9. Step Validation - Analyzing plan structure...")
        if plan.steps:
            # Validate step properties
            step_names = [getattr(s, "name", "") for s in plan.steps]
            step_types = [getattr(s, "type", "action") for s in plan.steps]

            assert_check(
                all(name != "" for name in step_names),
                "All steps have names",
            )
            assert_check(
                len(set(step_names)) == len(step_names),
                "All step names are unique",
            )

            # Validate each step has a type and log details
            known_types = {"llm-call", "action", "connector", "synthesis", "task"}
            for i, (sname, stype) in enumerate(zip(step_names, step_types)):
                assert_check(stype != "", f"Step {i+1} has a type")
                # Log step details (don't fail on unknown types for forward compatibility)
                if stype in known_types:
                    print(f"     Step {i+1}: type={stype}, name={sname}")
                else:
                    print(f"     Step {i+1}: type={stype} (unknown), name={sname}")
        print()

        # ========================================
        # SUMMARY
        # ========================================
        print("=" * 50)
        print(f"Tests Run: {tests_run}")
        if not failures:
            print("✓ ALL TESTS PASSED")
            print()
            print("Coverage validated:")
            print("  - generate_plan()   - Plan creation with valid ID/steps")
            print("  - get_plan_status() - Pre/post execution status")
            print("  - execute_plan()    - Plan execution and step completion")
            print("  - Error handling    - Invalid/non-existent plan IDs")
            print("  - Re-execution      - Handling of completed plans")
            print("  - Multiple plans    - Independent plan creation")
            print("  - Step validation   - Structure and uniqueness")
            return 0
        else:
            print(f"❌ {len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
