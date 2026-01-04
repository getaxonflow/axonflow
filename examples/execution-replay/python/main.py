#!/usr/bin/env python3
"""
AxonFlow Execution Replay API - Python SDK Example

This example demonstrates how to use the AxonFlow Python SDK to:
1. List all workflow executions
2. Get detailed execution information
3. View execution timeline
4. Export execution for compliance

The Execution Replay feature captures every step of workflow execution
for debugging, auditing, and compliance purposes.
"""

import json
import os
from axonflow import AxonFlow, ListExecutionsOptions, ExecutionExportOptions


def main():
    print("AxonFlow Execution Replay API - Python SDK")
    print("========================================")
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

    try:
        # 1. List all executions
        print("Step 1: List Executions")
        print("------------------------")

        list_result = client.list_executions(ListExecutionsOptions(limit=10))

        print(f"Total executions: {list_result.total}")
        if list_result.executions:
            print("Recent executions:")
            for exec_item in list_result.executions:
                print(f"  - {exec_item.request_id}: {exec_item.workflow_name or 'N/A'} "
                      f"({exec_item.completed_steps}/{exec_item.total_steps} steps, "
                      f"status={exec_item.status})")
        else:
            print("No executions found. Run a workflow to generate execution data.")
        print()

        # 2. Get specific execution (if available)
        if list_result.executions:
            execution_id = list_result.executions[0].request_id

            print("Step 2: Get Execution Details")
            print("------------------------------")

            exec_detail = client.get_execution(execution_id)

            print(f"Execution: {exec_detail.summary.request_id}")
            print(f"  Workflow: {exec_detail.summary.workflow_name or 'N/A'}")
            print(f"  Status: {exec_detail.summary.status}")
            print(f"  Steps: {exec_detail.summary.completed_steps}/{exec_detail.summary.total_steps} completed")
            print(f"  Total Tokens: {exec_detail.summary.total_tokens}")
            print(f"  Total Cost: ${exec_detail.summary.total_cost_usd:.6f}")
            print("  Steps:")
            for step in exec_detail.steps:
                duration = f"{step.duration_ms}ms" if step.duration_ms else "in progress"
                print(f"    [{step.step_index}] {step.step_name}: {step.status} ({duration})")
            print()

            # 3. Get execution timeline
            print("Step 3: Get Execution Timeline")
            print("-------------------------------")

            timeline = client.get_execution_timeline(execution_id)

            print("Timeline:")
            for entry in timeline:
                error_flag = " [ERROR]" if entry.has_error else ""
                approval_flag = " [APPROVAL]" if entry.has_approval else ""
                print(f"  [{entry.step_index}] {entry.step_name}: {entry.status}{error_flag}{approval_flag}")
            print()

            # 4. Export execution
            print("Step 4: Export Execution")
            print("-------------------------")

            export_data = client.export_execution(
                execution_id,
                ExecutionExportOptions(include_input=True, include_output=True)
            )

            # Pretty print the export (truncated)
            pretty_export = json.dumps(export_data, indent=2)
            if len(pretty_export) > 500:
                pretty_export = pretty_export[:500] + "\n  ... (truncated)"
            print(f"Export (truncated):\n{pretty_export}")
            print()

    finally:
        client.close()

    print("========================================")
    print("Execution Replay Demo Complete!")
    print()
    print("SDK Methods Used:")
    print("  client.list_executions()          - List executions")
    print("  client.get_execution(id)          - Get execution details")
    print("  client.get_execution_steps(id)    - Get execution steps")
    print("  client.get_execution_timeline(id) - Get execution timeline")
    print("  client.export_execution(id)       - Export execution")
    print("  client.delete_execution(id)       - Delete execution")


if __name__ == "__main__":
    main()
