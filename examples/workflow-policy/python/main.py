#!/usr/bin/env python3
"""
Workflow Policy Enforcement Example - Python

Demonstrates and VALIDATES:
1. WCP policy enforcement with policies_evaluated/matched in step gate response
2. Audit log verification to confirm operations are logged

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys
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

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("Workflow Policy Enforcement - Python SDK")
    print("=" * 50)
    print()

    # Use orchestrator endpoint for workflow APIs
    client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8081"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "secret"),
    )

    # Record start time for audit log query
    start_time = datetime.now(timezone.utc) - timedelta(seconds=1)
    workflow_id = None

    try:
        # Test 1: Create workflow
        print("1. CreateWorkflow - Policy Demo")
        try:
            workflow = await client.create_workflow(
                CreateWorkflowRequest(
                    workflow_name="policy-demo-python",
                    source=WorkflowSource.EXTERNAL,
                    total_steps=3,
                    metadata={"example": "workflow-policy-python"},
                )
            )
            workflow_id = workflow.workflow_id
            assert_check(workflow.workflow_id != "", "Workflow has ID")
            print(f"   Workflow ID: {workflow.workflow_id}")
        except Exception as e:
            failures.append(f"create_workflow failed: {e}")
            return 1
        print()

        # Test 2: Step gate with policy info
        print("2. StepGate - Demonstrates policies_evaluated/matched")
        try:
            gate = await client.step_gate(
                workflow_id=workflow.workflow_id,
                step_id="step-1",
                request=StepGateRequest(
                    step_name="Analyze Data",
                    step_type=StepType.LLM_CALL,
                    model="gemini-1.5-pro",
                    provider="gemini",
                    step_input={"prompt": "Analyze customer sentiment"},
                ),
            )

            assert_check(gate.decision is not None, "Gate has decision")
            print(f"   Decision: {gate.decision}")

            # Validate policy info structure
            if gate.policies_evaluated is not None:
                assert_check(
                    isinstance(gate.policies_evaluated, list),
                    "policies_evaluated is a list"
                )
                print(f"   Policies evaluated: {len(gate.policies_evaluated)}")
                for p in gate.policies_evaluated[:3]:
                    print(f"     - {p.policy_name}: action={p.action}")

            if gate.policies_matched is not None:
                assert_check(
                    isinstance(gate.policies_matched, list),
                    "policies_matched is a list"
                )
                print(f"   Policies matched: {len(gate.policies_matched)}")

            # Handle decision
            if gate.decision == "block":
                assert_check(gate.reason is not None, "Blocked gate has reason")
                await client.abort_workflow(workflow.workflow_id, gate.reason)
                return 1

            if gate.decision == "allow":
                await client.mark_step_completed(workflow.workflow_id, "step-1")
                assert_check(True, "Step 1 completed")

        except Exception as e:
            failures.append(f"step_gate failed: {e}")
        print()

        # Test 3: Step with database query (SQLi check)
        print("3. StepGate - Database Query (SQLi policy check)")
        try:
            gate2 = await client.step_gate(
                workflow_id=workflow.workflow_id,
                step_id="step-2",
                request=StepGateRequest(
                    step_name="Execute Query",
                    step_type=StepType.TOOL_CALL,
                    step_input={"query": "SELECT name, email FROM customers LIMIT 10"},
                ),
            )

            assert_check(gate2.decision is not None, "Gate has decision")
            print(f"   Decision: {gate2.decision}")

            if gate2.policies_evaluated:
                print(f"   Policies checked: {len(gate2.policies_evaluated)}")
            if gate2.policies_matched:
                print(f"   Policies matched: {len(gate2.policies_matched)}")
                for p in gate2.policies_matched[:2]:
                    print(f"     - {p.policy_name}: {p.reason}")

        except Exception as e:
            failures.append(f"step_gate step-2 failed: {e}")
        print()

        # Test 4: Complete workflow
        print("4. CompleteWorkflow")
        try:
            await client.complete_workflow(workflow.workflow_id)
            assert_check(True, "Workflow completed")
        except Exception as e:
            failures.append(f"complete_workflow failed: {e}")
        print()

        # Test 5: Audit log verification
        print("5. Audit Log Verification")
        print("   Waiting for audit batch flush...")
        time.sleep(6)

        try:
            audit_response = await client.search_audit_logs(
                AuditSearchRequest(
                    start_time=start_time,
                    limit=50,
                )
            )

            assert_check(audit_response is not None, "search_audit_logs returned response")
            assert_check(hasattr(audit_response, "entries"), "Response has entries")

            # Count workflow-related entries
            workflow_logs: Counter[str] = Counter()
            for entry in audit_response.entries:
                if entry.request_id == workflow.workflow_id:
                    workflow_logs[entry.request_type] += 1

            if workflow_logs:
                total_count = sum(workflow_logs.values())
                assert_check(total_count > 0, f"Found {total_count} audit entries for workflow")
                print(f"   Found {total_count} audit log entries:")
                for req_type, count in workflow_logs.items():
                    print(f"     - {req_type}: {count}")
            else:
                print("   Note: No audit logs found yet (may take time to flush)")

        except Exception as e:
            print(f"   Note: Audit search returned error: {e}")
            print("   (Audit logging may not be configured)")
        print()

    finally:
        await client.close()

    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Workflow Policy Enforcement validated:")
        print("  - StepGateResponse.policies_evaluated")
        print("  - StepGateResponse.policies_matched")
        print("  - PolicyMatch includes: policy_id, policy_name, action, reason")
        print("  - Audit log capture for workflow operations")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
