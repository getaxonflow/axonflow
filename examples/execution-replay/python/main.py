#!/usr/bin/env python3
"""
AxonFlow Execution Replay API - Python SDK Example (Comprehensive)

This example demonstrates ALL Execution Replay SDK methods:
1. list_executions()          - List all workflow executions
2. get_execution()            - Get detailed execution information
3. get_execution_steps()      - Get step snapshots for an execution
4. get_execution_timeline()   - View execution timeline
5. export_execution()         - Export execution for compliance
6. delete_execution()         - Delete an execution

The Execution Replay feature captures every step of workflow execution
for debugging, auditing, and compliance purposes (EU AI Act Article 12).

Run with: python main.py
Prerequisites: docker compose up -d
"""

import json
import os
from axonflow import AxonFlow, ListExecutionsOptions, ExecutionExportOptions


def main():
    print("AxonFlow Execution Replay - Python SDK (Comprehensive)")
    print("=" * 55)
    print()

    # Initialize the AxonFlow client
    agent_url = os.environ.get("AXONFLOW_AGENT_URL", "http://localhost:8080")
    orchestrator_url = os.environ.get("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081")

    # Use sync client for this example
    client = AxonFlow.sync(
        agent_url=agent_url,
        orchestrator_url=orchestrator_url,
        debug=True,
    )

    execution_to_delete = None

    try:
        # ========================================
        # 1. LIST EXECUTIONS
        # ========================================
        print("1. list_executions - Listing workflow executions...")
        list_result = client.list_executions(ListExecutionsOptions(limit=10))

        print(f"   Total executions: {list_result.total}")
        if list_result.executions:
            print("   Recent executions:")
            for exec_item in list_result.executions[:3]:
                print(f"     - {exec_item.request_id}: {exec_item.workflow_name or 'N/A'} "
                      f"({exec_item.completed_steps}/{exec_item.total_steps} steps, "
                      f"status={exec_item.status})")
            if len(list_result.executions) > 3:
                print(f"     ... and {len(list_result.executions) - 3} more")
        else:
            print("   No executions found. Run a workflow to generate execution data.")
        print()

        # Continue with specific execution if available
        if list_result.executions:
            execution_id = list_result.executions[0].request_id

            # ========================================
            # 2. GET EXECUTION DETAILS
            # ========================================
            print("2. get_execution - Getting execution details...")
            exec_detail = client.get_execution(execution_id)

            print(f"   Execution: {exec_detail.summary.request_id}")
            print(f"   Workflow: {exec_detail.summary.workflow_name or 'N/A'}")
            print(f"   Status: {exec_detail.summary.status}")
            print(f"   Steps: {exec_detail.summary.completed_steps}/{exec_detail.summary.total_steps} completed")
            print(f"   Total Tokens: {exec_detail.summary.total_tokens}")
            print(f"   Total Cost: ${exec_detail.summary.total_cost_usd:.6f}")
            print()

            # ========================================
            # 3. GET EXECUTION STEPS
            # ========================================
            print("3. get_execution_steps - Getting step snapshots...")
            try:
                steps = client.get_execution_steps(execution_id)
                print(f"   Found {len(steps)} step snapshots:")
                for step in steps[:5]:
                    duration = f"{step.duration_ms}ms" if step.duration_ms else "in progress"
                    print(f"     [{step.step_index}] {step.step_name}: {step.status} ({duration})")
                    if hasattr(step, 'tokens_used') and step.tokens_used:
                        print(f"         Tokens: {step.tokens_used}")
                if len(steps) > 5:
                    print(f"     ... and {len(steps) - 5} more steps")
            except Exception as e:
                print(f"   Note: get_execution_steps error: {e}")
            print()

            # ========================================
            # 4. GET EXECUTION TIMELINE
            # ========================================
            print("4. get_execution_timeline - Getting timeline view...")
            timeline = client.get_execution_timeline(execution_id)

            print(f"   Timeline ({len(timeline)} entries):")
            for entry in timeline[:5]:
                error_flag = " [ERROR]" if entry.has_error else ""
                approval_flag = " [APPROVAL]" if entry.has_approval else ""
                print(f"     [{entry.step_index}] {entry.step_name}: {entry.status}{error_flag}{approval_flag}")
            if len(timeline) > 5:
                print(f"     ... and {len(timeline) - 5} more entries")
            print()

            # ========================================
            # 5. EXPORT EXECUTION
            # ========================================
            print("5. export_execution - Exporting for compliance...")
            export_data = client.export_execution(
                execution_id,
                ExecutionExportOptions(include_input=True, include_output=True)
            )

            # Show export summary
            if isinstance(export_data, dict):
                print(f"   Export contains:")
                for key in list(export_data.keys())[:5]:
                    value = export_data[key]
                    if isinstance(value, (list, dict)):
                        print(f"     - {key}: {type(value).__name__} ({len(value)} items)")
                    else:
                        print(f"     - {key}: {value}")
            else:
                pretty_export = json.dumps(export_data, indent=2)
                if len(pretty_export) > 300:
                    pretty_export = pretty_export[:300] + "\n     ... (truncated)"
                print(f"   Export (truncated):\n{pretty_export}")
            print()

            # ========================================
            # 6. DELETE EXECUTION (demonstration)
            # ========================================
            print("6. delete_execution - Deleting execution...")

            # If there are multiple executions, delete the oldest one for demo
            if len(list_result.executions) > 1:
                execution_to_delete = list_result.executions[-1].request_id
                try:
                    client.delete_execution(execution_to_delete)
                    print(f"   Deleted execution: {execution_to_delete}")
                    execution_to_delete = None  # Mark as deleted
                except Exception as e:
                    print(f"   Note: delete_execution error: {e}")
            else:
                print("   Skipping delete (only one execution available)")
                print("   In production, use: client.delete_execution(execution_id)")
            print()

        print("=" * 55)
        print("All 6 Execution Replay SDK methods demonstrated!")
        print()
        print("Methods tested:")
        print("  1. list_executions()          - List executions with filtering")
        print("  2. get_execution()            - Get full execution details")
        print("  3. get_execution_steps()      - Get individual step snapshots")
        print("  4. get_execution_timeline()   - Get timeline for visualization")
        print("  5. export_execution()         - Export for compliance/archival")
        print("  6. delete_execution()         - Delete execution and snapshots")
        print()
        print("EU AI Act Article 12 Compliance:")
        print("  - Decision chain tracking")
        print("  - Full audit trail")
        print("  - Export for regulatory review")

    finally:
        client.close()


if __name__ == "__main__":
    main()
