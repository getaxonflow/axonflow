#!/usr/bin/env python3
"""
Workflow Policy Enforcement - Python Example

Demonstrates:
1. MAP policy enforcement with policy_info in execution response
2. WCP policy enforcement with policies_evaluated/matched in step gate response
3. Audit log verification to confirm operations are logged
"""

import asyncio
import os
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from axonflow import AxonFlow
from axonflow.types import AuditSearchRequest
from axonflow.workflow import (
    CreateWorkflowRequest,
    StepGateRequest,
    StepType,
    WorkflowSource,
)


async def main():
    print("==========================================")
    print("Workflow Policy Enforcement - Python Example")
    print("==========================================")
    print()

    # Initialize client - use orchestrator endpoint for workflow APIs
    client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8081"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "secret"),
    )

    # Record start time for audit log query (use UTC for RFC3339 compatibility)
    start_time = datetime.now(timezone.utc) - timedelta(seconds=1)

    # ==========================================
    # Part 1: WCP Policy Enforcement
    # ==========================================

    print("Part 1: WCP (Workflow Control Plane) Policy Enforcement")
    print("--------------------------------------------------------")
    print()

    # Create workflow
    print("1.1 Creating workflow...")
    workflow = await client.create_workflow(
        CreateWorkflowRequest(
            workflow_name="policy-demo-python",
            source=WorkflowSource.EXTERNAL,
            total_steps=3,
            metadata={"example": "workflow-policy-python"},
        )
    )
    print(f"    Workflow ID: {workflow.workflow_id}")
    print()

    # Check step gate - demonstrates policies_evaluated and policies_matched
    print("1.2 Checking step gate (demonstrates policy info in response)...")
    gate = await client.step_gate(
        workflow_id=workflow.workflow_id,
        step_id="step-1",
        request=StepGateRequest(
            step_name="Analyze Data",
            step_type=StepType.LLM_CALL,
            model="gpt-4",
            provider="openai",
            step_input={"prompt": "Analyze customer sentiment"},
        ),
    )

    print(f"    Decision: {gate.decision}")
    if gate.reason:
        print(f"    Reason: {gate.reason}")

    # Display policy evaluation details (Issue #1021)
    if gate.policies_evaluated:
        print("    Policies Evaluated:")
        for p in gate.policies_evaluated:
            print(f"      - {p.policy_name} ({p.policy_id}): action={p.action}")

    if gate.policies_matched:
        print("    Policies Matched:")
        for p in gate.policies_matched:
            print(f"      - {p.policy_name}: {p.action} (reason: {p.reason})")
    print()

    # Handle decision
    if gate.decision == "block":
        print("    Step BLOCKED by policy!")
        print("    Aborting workflow...")
        await client.abort_workflow(workflow.workflow_id, gate.reason)
        return

    if gate.decision == "require_approval":
        print(f"    Step requires approval: {gate.approval_url}")
        # In production, wait for approval

    # Mark step completed
    if gate.decision == "allow":
        await client.mark_step_completed(workflow.workflow_id, "step-1")
        print("    Step completed!")
    print()

    # Test with potentially sensitive content
    print("1.3 Testing with database query (potential SQLi check)...")
    gate2 = await client.step_gate(
        workflow_id=workflow.workflow_id,
        step_id="step-2",
        request=StepGateRequest(
            step_name="Execute Query",
            step_type=StepType.TOOL_CALL,
            step_input={"query": "SELECT name, email FROM customers LIMIT 10"},
        ),
    )

    print(f"    Decision: {gate2.decision}")
    if gate2.policies_evaluated:
        print(f"    Policies checked: {len(gate2.policies_evaluated)}")
    if gate2.policies_matched:
        print(f"    Policies matched: {len(gate2.policies_matched)}")
        for p in gate2.policies_matched:
            print(f"      - {p.policy_name}: {p.reason}")
    print()

    # Complete workflow
    print("1.4 Completing workflow...")
    await client.complete_workflow(workflow.workflow_id)
    print("    Workflow completed!")
    print()

    # ==========================================
    # Part 2: Audit Log Verification
    # ==========================================

    print("Part 2: Audit Log Verification")
    print("------------------------------")
    print()

    # Delay to ensure audit logs are flushed (batch writer flushes every 5-10 seconds)
    print("    Waiting for audit log batch flush...")
    time.sleep(6)

    # Search for workflow audit logs
    print("2.1 Searching for workflow audit logs...")
    try:
        audit_response = await client.search_audit_logs(
            AuditSearchRequest(
                start_time=start_time,
                limit=50,
            )
        )

        # Count workflow-related entries
        workflow_logs: Counter[str] = Counter()
        for entry in audit_response.entries:
            if entry.request_id == workflow.workflow_id:
                workflow_logs[entry.request_type] += 1

        if workflow_logs:
            total_count = sum(workflow_logs.values())
            print(f"    ✅ Found {total_count} audit log entries for workflow {workflow.workflow_id}:")
            for req_type, count in workflow_logs.items():
                print(f"       - {req_type}: {count}")
        else:
            print("    ⚠️  No audit logs found for this workflow")
            print("       (Audit logs may take a moment to flush)")
        print()

        # Verify expected audit entries
        print("2.2 Verifying expected audit entries...")
        expected_types = ["workflow_created", "workflow_step_gate", "workflow_completed"]
        all_found = True
        for expected in expected_types:
            found = any(
                entry.request_id == workflow.workflow_id and entry.request_type == expected
                for entry in audit_response.entries
            )
            if found:
                print(f"    ✅ {expected}: FOUND")
            else:
                print(f"    ❌ {expected}: NOT FOUND")
                all_found = False
        print()

        if all_found:
            print("    ✅ All expected audit log entries verified!")
        else:
            print("    ⚠️  Some audit log entries were not found")
        print()

    except Exception as e:
        print(f"    ERROR searching audit logs: {e}")
        print()

    # ==========================================
    # Summary
    # ==========================================

    print("==========================================")
    print("Summary")
    print("==========================================")
    print()
    print("WCP Policy Enforcement (Issue #1021):")
    print("  - StepGateResponse.policies_evaluated: all checked policies")
    print("  - StepGateResponse.policies_matched: policies that triggered decision")
    print("  - PolicyMatch includes: policy_id, policy_name, action, reason")
    print()
    print("Audit Logging (Issue #1019):")
    print("  - workflow_created: logged when workflow is registered")
    print("  - workflow_step_gate: logged for each step gate check")
    print("  - workflow_completed: logged when workflow completes")
    print("  - workflow_aborted: logged when workflow is aborted")
    print()
    print("MAP Policy Enforcement (Issue #1020):")
    print("  - PlanExecutionResponse.policy_info: policy evaluation result")
    print("  - Includes: allowed, applied_policies, risk_score")
    print("  - Returns 403 Forbidden if policies block execution")
    print()


if __name__ == "__main__":
    asyncio.run(main())
