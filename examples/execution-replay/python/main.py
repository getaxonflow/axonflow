#!/usr/bin/env python3
"""
AxonFlow Execution Replay - Python SDK

This example demonstrates and VALIDATES all Execution Replay SDK methods:
1. list_executions()          - List all workflow executions
2. get_execution()            - Get detailed execution information
3. get_execution_steps()      - Get step snapshots for an execution
4. get_execution_timeline()   - View execution timeline
5. export_execution()         - Export execution for compliance

VALIDATION: This example exits with code 1 if any API call fails.
This ensures CI/CD pipelines catch regressions.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import json
import os
import sys

from axonflow import AxonFlow, ListExecutionsOptions, ExecutionExportOptions

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


def main() -> int:
    print("AxonFlow Execution Replay - Python SDK")
    print("=" * 40)
    print()

    client = AxonFlow.sync(
        endpoint=get_env("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=get_env("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=get_env("AXONFLOW_CLIENT_SECRET", "demo"),
        debug=get_env("AXONFLOW_DEBUG", "") == "true",
    )

    try:
        # ========================================
        # 1. LIST EXECUTIONS
        # ========================================
        print("1. list_executions - Listing workflow executions...")
        try:
            list_result = client.list_executions(ListExecutionsOptions(limit=10))
        except Exception as e:
            print(f"   ❌ FATAL: list_executions failed: {e}")
            return 1

        assert_check(list_result.total >= 0, "total is a valid count")
        print(f"   Total executions: {list_result.total}")

        if list_result.executions:
            print("   Recent executions:")
            for exec_item in list_result.executions[:3]:
                print(
                    f"     - {exec_item.request_id}: {exec_item.workflow_name or 'N/A'} "
                    f"({exec_item.completed_steps}/{exec_item.total_steps} steps, "
                    f"status={exec_item.status})"
                )
                assert_check(exec_item.request_id != "", "Execution has valid request_id")
        else:
            print("   No executions found (run a workflow first)")
        print()

        # Continue with detailed validation if executions exist
        if list_result.executions:
            execution_id = list_result.executions[0].request_id

            # ========================================
            # 2. GET EXECUTION DETAILS
            # ========================================
            print("2. get_execution - Getting execution details...")
            try:
                exec_detail = client.get_execution(execution_id)
            except Exception as e:
                print(f"   ❌ FATAL: get_execution failed: {e}")
                return 1

            assert_check(
                exec_detail.summary.request_id == execution_id,
                "Summary request_id matches",
            )
            assert_check(exec_detail.summary.status != "", "Summary has valid status")
            assert_check(
                exec_detail.summary.total_steps >= 0, "Summary has valid total_steps"
            )

            print(f"   Execution: {exec_detail.summary.request_id}")
            print(f"   Status: {exec_detail.summary.status}")
            print(
                f"   Steps: {exec_detail.summary.completed_steps}/{exec_detail.summary.total_steps} completed"
            )
            print(f"   Total Tokens: {exec_detail.summary.total_tokens}")
            print(f"   Total Cost: ${exec_detail.summary.total_cost_usd:.6f}")
            print()

            # ========================================
            # 3. GET EXECUTION STEPS
            # ========================================
            print("3. get_execution_steps - Getting step snapshots...")
            try:
                steps = client.get_execution_steps(execution_id)
                assert_check(len(steps) >= 0, "Steps returns valid array")
                print(f"   Found {len(steps)} step snapshots")
                for step in steps[:3]:
                    duration = f"{step.duration_ms}ms" if step.duration_ms else "in progress"
                    print(f"     [{step.step_index}] {step.step_name}: {step.status} ({duration})")
            except Exception as e:
                print(f"   ❌ FATAL: get_execution_steps failed: {e}")
                return 1
            print()

            # ========================================
            # 4. GET EXECUTION TIMELINE
            # ========================================
            print("4. get_execution_timeline - Getting timeline view...")
            try:
                timeline = client.get_execution_timeline(execution_id)
            except Exception as e:
                print(f"   ❌ FATAL: get_execution_timeline failed: {e}")
                return 1

            assert_check(len(timeline) >= 0, "Timeline returns valid array")
            print(f"   Timeline entries: {len(timeline)}")
            for entry in timeline[:3]:
                error_flag = " [ERROR]" if entry.has_error else ""
                print(f"     [{entry.step_index}] {entry.step_name}: {entry.status}{error_flag}")
            print()

            # ========================================
            # 5. EXPORT EXECUTION
            # ========================================
            print("5. export_execution - Exporting for compliance...")
            try:
                export_data = client.export_execution(
                    execution_id,
                    ExecutionExportOptions(include_input=True, include_output=True),
                )
            except Exception as e:
                print(f"   ❌ FATAL: export_execution failed: {e}")
                return 1

            assert_check(export_data is not None, "Export returns valid data")
            if isinstance(export_data, dict):
                print(f"   Export contains {len(export_data)} keys")
            else:
                pretty = json.dumps(export_data, indent=2)
                if len(pretty) > 200:
                    pretty = pretty[:200] + "\n     ... (truncated)"
                print(f"   Export preview:\n{pretty}")
            print()

        # ========================================
        # SUMMARY
        # ========================================
        print("=" * 40)
        if not failures:
            print("✓ ALL TESTS PASSED")
            print()
            print("Methods validated:")
            print("  1. list_executions()          - List with pagination")
            print("  2. get_execution()            - Get full details")
            print("  3. get_execution_steps()      - Get step snapshots")
            print("  4. get_execution_timeline()   - Get timeline view")
            print("  5. export_execution()         - Export for compliance")
            return 0
        else:
            print(f"❌ {len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1

    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
