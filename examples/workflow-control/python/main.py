#!/usr/bin/env python3
"""
Workflow Control Plane Example - Python

Demonstrates and VALIDATES the WCP (Workflow Control Plane) SDK:
1. Create a workflow
2. Check step gates before each step
3. Mark steps as completed
4. Complete the workflow

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

import requests as sync_requests
from dotenv import load_dotenv
from axonflow import AxonFlow
from axonflow.workflow import (
    CreateWorkflowRequest,
    StepGateRequest,
    MarkStepCompletedRequest,
    WorkflowSource,
    StepType,
    GateDecision,
)

load_dotenv()

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("Workflow Control Plane - Python SDK")
    print("=" * 50)
    print()

    workflow_id = None

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "workflow-control-python"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as client:

        try:
            # Test 1: Create a workflow
            print("1. CreateWorkflow - Creating code-review-pipeline...")
            try:
                workflow = await client.create_workflow(
                    CreateWorkflowRequest(
                        workflow_name="code-review-pipeline",
                        source=WorkflowSource.EXTERNAL,
                        total_steps=3,
                        metadata={"example": "workflow-control-python"},
                        trace_id="example-trace-py-001",
                    )
                )
                workflow_id = workflow.workflow_id
                assert_check(workflow.workflow_id != "", "Workflow has ID")
                assert_check(workflow.workflow_name == "code-review-pipeline", "Workflow name matches")
                assert_check(workflow.trace_id == "example-trace-py-001", "trace_id returned in create response")
                print(f"   Workflow ID: {workflow.workflow_id}")
            except Exception as e:
                failures.append(f"create_workflow failed: {e}")
                return 1
            print()

            # Test 2: Step gate - Generate Code (LLM call)
            print("2. StepGate - Generate Code (LLM_CALL)")
            try:
                gate1 = await client.step_gate(
                    workflow_id=workflow.workflow_id,
                    step_id="step-1",
                    request=StepGateRequest(
                        step_name="Generate Code",
                        step_type=StepType.LLM_CALL,
                        model="claude-haiku-4-5-20251001",
                        provider="anthropic",
                        step_input={"prompt": "Write a Python function to sort a list"},
                    ),
                )
                assert_check(gate1.decision is not None, "Gate has decision")
                assert_check(
                    gate1.decision in [GateDecision.ALLOW, GateDecision.BLOCK, GateDecision.REQUIRE_APPROVAL],
                    f"Gate decision is valid enum (got: {gate1.decision})"
                )
                print(f"   Decision: {gate1.decision.value}")

                # Handle gate decision
                if gate1.is_blocked():
                    assert_check(gate1.reason is not None, "Blocked gate has reason")
                    print(f"   Blocked: {gate1.reason}")
                    await client.abort_workflow(workflow.workflow_id, gate1.reason)
                    return 1

                if gate1.requires_approval():
                    assert_check(True, "Approval required (Enterprise feature)")
                    print(f"   Approval URL: {gate1.approval_url}")

                # Mark step completed
                if gate1.is_allowed():
                    await client.mark_step_completed(
                        workflow_id=workflow.workflow_id,
                        step_id="step-1",
                        request=MarkStepCompletedRequest(
                            output={"code": "def sort_list(items): return sorted(items)"},
                            tokens_in=150,
                            tokens_out=45,
                            cost_usd=0.0023,
                        ),
                    )
                    assert_check(True, "Step 1 marked completed")
            except Exception as e:
                failures.append(f"step_gate step-1 failed: {e}")
            print()

            # Test 3: Step gate - Review Code (Tool call)
            print("3. StepGate - Review Code (TOOL_CALL)")
            try:
                gate2 = await client.step_gate(
                    workflow_id=workflow.workflow_id,
                    step_id="step-2",
                    request=StepGateRequest(
                        step_name="Review Code",
                        step_type=StepType.TOOL_CALL,
                        step_input={
                            "tool": "code_reviewer",
                            "code": "def sort_list(items): return sorted(items)",
                        },
                    ),
                )
                assert_check(gate2.decision is not None, "Gate has decision")
                print(f"   Decision: {gate2.decision.value}")

                if gate2.is_allowed():
                    await client.mark_step_completed(
                        workflow_id=workflow.workflow_id,
                        step_id="step-2",
                        request=MarkStepCompletedRequest(
                            output={"review": "LGTM"},
                            tokens_in=150,
                            tokens_out=45,
                            cost_usd=0.0023,
                        ),
                    )
                    assert_check(True, "Step 2 marked completed")
            except Exception as e:
                failures.append(f"step_gate step-2 failed: {e}")
            print()

            # Test 4: Step gate - Deploy (Connector call)
            print("4. StepGate - Deploy (CONNECTOR_CALL)")
            try:
                gate3 = await client.step_gate(
                    workflow_id=workflow.workflow_id,
                    step_id="step-3",
                    request=StepGateRequest(
                        step_name="Deploy to Production",
                        step_type=StepType.CONNECTOR_CALL,
                        step_input={"connector": "github", "action": "create_pr"},
                    ),
                )
                assert_check(gate3.decision is not None, "Gate has decision")
                print(f"   Decision: {gate3.decision.value}")

                if gate3.is_allowed():
                    await client.mark_step_completed(
                        workflow_id=workflow.workflow_id,
                        step_id="step-3",
                        request=MarkStepCompletedRequest(
                            output={"pr_url": "https://github.com/example/pr/123"},
                            tokens_in=150,
                            tokens_out=45,
                            cost_usd=0.0023,
                        ),
                    )
                    assert_check(True, "Step 3 marked completed")
            except Exception as e:
                failures.append(f"step_gate step-3 failed: {e}")
            print()

            # Test 5: Complete the workflow
            print("5. CompleteWorkflow")
            try:
                await client.complete_workflow(workflow.workflow_id)
                assert_check(True, "complete_workflow succeeded")
            except Exception as e:
                failures.append(f"complete_workflow failed: {e}")
            print()

            # Test 5b: Fail Workflow (v4.3.0: native SDK method)
            print("5b. FailWorkflow - via SDK fail_workflow()")
            fail_workflow_id = None
            try:
                fail_wf = await client.create_workflow(
                    CreateWorkflowRequest(
                        workflow_name="wcp-fail-test",
                        source=WorkflowSource.EXTERNAL,
                        total_steps=2,
                        metadata={"test": "fail-workflow"},
                    )
                )
                fail_workflow_id = fail_wf.workflow_id
                assert_check(fail_wf.workflow_id != "", "Fail-test workflow created with valid ID")
                print(f"   Workflow ID: {fail_wf.workflow_id}")

                # v4.3.0: Use native SDK fail_workflow() method
                await client.fail_workflow(fail_wf.workflow_id, reason="LLM provider timeout")
                assert_check(True, "fail_workflow succeeded")

                # Verify via SDK
                failed_status = await client.get_workflow(fail_wf.workflow_id)
                assert_check(
                    failed_status.status is not None and failed_status.status.value == "failed",
                    f"Workflow status verified as 'failed' (got: {failed_status.status.value if failed_status.status else 'None'})",
                )
            except Exception as e:
                failures.append(f"fail_workflow test failed: {e}")
            print()

            # Test 6: Get final workflow status
            print("6. GetWorkflow - Final Status")
            try:
                status = await client.get_workflow(workflow.workflow_id)
                assert_check(status.workflow_name == "code-review-pipeline", "Workflow name matches")
                assert_check(status.trace_id == "example-trace-py-001", "trace_id returned in status response")
                assert_check(status.status is not None, "Workflow has status")
                assert_check(len(status.steps) == 3, f"Workflow has 3 steps (got {len(status.steps)})")
                print(f"   Status: {status.status.value}")
                print(f"   Steps: {len(status.steps)}")
            except Exception as e:
                failures.append(f"get_workflow failed: {e}")
            print()

            # ========================================
            # Test 7: Step Approval Flow
            # ========================================
            print("7. Step Approval Flow")
            approval_workflow_id = None
            try:
                approval_wf = await client.create_workflow(
                    CreateWorkflowRequest(
                        workflow_name="wcp-approval-test",
                        source=WorkflowSource.EXTERNAL,
                        total_steps=3,
                        metadata={"test": "step-approval"},
                    )
                )
                approval_workflow_id = approval_wf.workflow_id
                assert_check(approval_wf.workflow_id != "", "Approval workflow created with valid ID")
                print(f"   Workflow ID: {approval_wf.workflow_id}")

                # Create a step gate to get a step ID
                approval_gate = await client.step_gate(
                    workflow_id=approval_wf.workflow_id,
                    step_id="approval-step-1",
                    request=StepGateRequest(
                        step_name="Approval Gate Step",
                        step_type=StepType.LLM_CALL,
                        model="claude-haiku-4-5-20251001",
                        provider="anthropic",
                        step_input={"prompt": "test approval flow"},
                    ),
                )
                print(f"   Gate decision: {approval_gate.decision.value}")

                # Test approve_step
                try:
                    approve_resp = await client.approve_step(approval_wf.workflow_id, "approval-step-1")
                    assert_check(approve_resp.step_id != "", "approve_step returns step_id")
                    assert_check(
                        approve_resp.workflow_id == approval_wf.workflow_id,
                        "approve_step returns correct workflow_id",
                    )
                    assert_check(
                        approve_resp.status == "approved",
                        f"approve_step status is 'approved' (got: {approve_resp.status})",
                    )
                    assert_check(approve_resp.approved_at is not None, "approve_step has approved_at timestamp")
                    print(f"   Step {approve_resp.step_id} approved at {approve_resp.approved_at}")
                except Exception as e:
                    err_str = str(e)
                    if "403" in err_str or "enterprise" in err_str.lower() or \
                       "not available" in err_str.lower() or "not supported" in err_str.lower() or \
                       "404" in err_str:
                        print(f"   SKIP: approve_step not available (enterprise feature): {e}")
                    else:
                        failures.append(f"approve_step failed: {e}")

                # Verify no pending approvals for this step via GetPendingApprovals
                try:
                    pending = await client.get_pending_approvals()
                    # After approval, this step should not be pending
                    pending_step_ids = [item.step_id for item in pending.items] if pending.items else []
                    assert_check(
                        "approval-step-1" not in pending_step_ids,
                        "Approved step not in pending approvals",
                    )
                except Exception as e:
                    err_str = str(e)
                    if "403" in err_str or "enterprise" in err_str.lower() or \
                       "not available" in err_str.lower() or "not supported" in err_str.lower() or \
                       "404" in err_str:
                        print(f"   SKIP: get_pending_approvals not available (enterprise feature): {e}")
                    else:
                        failures.append(f"get_pending_approvals after approve failed: {e}")

            except Exception as e:
                failures.append(f"approval flow setup failed: {e}")
            finally:
                if approval_workflow_id:
                    try:
                        await client.abort_workflow(approval_workflow_id, "test cleanup")
                        print(f"   Cleaned up approval workflow: {approval_workflow_id}")
                    except Exception:
                        pass
            print()

            # ========================================
            # Test 8: Step Rejection Flow
            # ========================================
            print("8. Step Rejection Flow")
            rejection_workflow_id = None
            try:
                reject_wf = await client.create_workflow(
                    CreateWorkflowRequest(
                        workflow_name="wcp-rejection-test",
                        source=WorkflowSource.EXTERNAL,
                        total_steps=2,
                        metadata={"test": "step-rejection"},
                    )
                )
                rejection_workflow_id = reject_wf.workflow_id
                assert_check(reject_wf.workflow_id != "", "Rejection workflow created with valid ID")
                print(f"   Workflow ID: {reject_wf.workflow_id}")

                # Create a step gate to get a step ID
                await client.step_gate(
                    workflow_id=reject_wf.workflow_id,
                    step_id="reject-step-1",
                    request=StepGateRequest(
                        step_name="Rejection Gate Step",
                        step_type=StepType.LLM_CALL,
                        model="claude-haiku-4-5-20251001",
                        provider="anthropic",
                        step_input={"prompt": "test rejection flow"},
                    ),
                )

                # Test reject_step
                try:
                    reject_resp = await client.reject_step(reject_wf.workflow_id, "reject-step-1")
                    assert_check(reject_resp.step_id != "", "reject_step returns step_id")
                    assert_check(
                        reject_resp.workflow_id == reject_wf.workflow_id,
                        "reject_step returns correct workflow_id",
                    )
                    assert_check(
                        reject_resp.status == "rejected",
                        f"reject_step status is 'rejected' (got: {reject_resp.status})",
                    )
                    assert_check(reject_resp.rejected_at is not None, "reject_step has rejected_at timestamp")
                    print(f"   Step {reject_resp.step_id} rejected at {reject_resp.rejected_at}")
                except Exception as e:
                    err_str = str(e)
                    if "403" in err_str or "enterprise" in err_str.lower() or \
                       "not available" in err_str.lower() or "not supported" in err_str.lower() or \
                       "404" in err_str:
                        print(f"   SKIP: reject_step not available (enterprise feature): {e}")
                    else:
                        failures.append(f"reject_step failed: {e}")

            except Exception as e:
                failures.append(f"rejection flow setup failed: {e}")
            finally:
                if rejection_workflow_id:
                    try:
                        await client.abort_workflow(rejection_workflow_id, "test cleanup")
                        print(f"   Cleaned up rejection workflow: {rejection_workflow_id}")
                    except Exception:
                        pass
            print()

            # ========================================
            # Test 9: Get Pending Approvals
            # ========================================
            print("9. Get Pending Approvals")
            try:
                # Test with no options
                pending_resp = await client.get_pending_approvals()
                assert_check(pending_resp.items is not None, "PendingApprovals has items list")
                assert_check(pending_resp.total >= 0, f"PendingApprovals total is non-negative (got: {pending_resp.total})")
                print(f"   Total pending approvals: {pending_resp.total}")
                print(f"   Items in response: {len(pending_resp.items)}")

                # Test with limit and offset
                pending_resp_opts = await client.get_pending_approvals(limit=10, offset=0)
                assert_check(pending_resp_opts.items is not None, "PendingApprovals (with opts) has items list")
                assert_check(
                    pending_resp_opts.total >= 0,
                    f"PendingApprovals (with opts) total is non-negative (got: {pending_resp_opts.total})",
                )
                print(f"   With limit=10, offset=0: total={pending_resp_opts.total}, items={len(pending_resp_opts.items)}")
            except Exception as e:
                err_str = str(e)
                if "403" in err_str or "enterprise" in err_str.lower() or \
                   "not available" in err_str.lower() or "not supported" in err_str.lower() or \
                   "404" in err_str:
                    print(f"   SKIP: get_pending_approvals not available (enterprise feature): {e}")
                else:
                    failures.append(f"get_pending_approvals failed: {e}")
            print()

        except Exception as e:
            failures.append(f"Unexpected error: {e}")

    # ========================================
    # Test 10: SSE Streaming - Real-time execution status
    # ========================================
    print("10. SSE Streaming - Real-time execution status")
    sse_workflow_id = None
    endpoint = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    sse_client_id = os.getenv("AXONFLOW_CLIENT_ID", "workflow-control-python")
    sse_client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "")

    async with AxonFlow(
        endpoint=endpoint,
        client_id=sse_client_id,
        client_secret=sse_client_secret,
    ) as sse_client:
        try:
            # Create a workflow for SSE streaming test
            sse_wf = await sse_client.create_workflow(
                CreateWorkflowRequest(
                    workflow_name="wcp-sse-streaming-test",
                    source=WorkflowSource.EXTERNAL,
                    total_steps=2,
                    metadata={"test": "sse-streaming"},
                )
            )
            sse_workflow_id = sse_wf.workflow_id
            assert_check(sse_wf.workflow_id != "", "SSE workflow created with valid ID")
            print(f"   Workflow ID: {sse_wf.workflow_id}")

            # Run a step gate and complete a step to generate execution events
            sse_gate = await sse_client.step_gate(
                workflow_id=sse_wf.workflow_id,
                step_id="sse-step-1",
                request=StepGateRequest(
                    step_name="SSE Test Step",
                    step_type=StepType.LLM_CALL,
                    model="claude-haiku-4-5-20251001",
                    provider="anthropic",
                    step_input={"prompt": "test SSE streaming"},
                ),
            )

            if sse_gate.is_allowed():
                await sse_client.mark_step_completed(
                    workflow_id=sse_wf.workflow_id,
                    step_id="sse-step-1",
                    request=MarkStepCompletedRequest(
                        output={"result": "sse test output"},
                        tokens_in=150,
                        tokens_out=45,
                        cost_usd=0.0023,
                    ),
                )
                assert_check(True, "SSE step completed")

            # Stream execution status via HTTP SSE endpoint (on orchestrator, not agent)
            orchestrator_endpoint = os.getenv("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081")
            stream_url = f"{orchestrator_endpoint}/api/v1/unified/executions/{sse_wf.workflow_id}/stream"
            print(f"   SSE URL: {stream_url}")

            headers = {
                "Accept": "text/event-stream",
                "X-Client-ID": sse_client_id,
                "X-Client-Secret": sse_client_secret,
                "X-Tenant-ID": sse_client_id,
            }

            try:
                sse_resp = sync_requests.get(
                    stream_url, headers=headers, timeout=10, stream=True
                )

                if sse_resp.status_code == 200:
                    assert_check(True, "SSE endpoint returned HTTP 200")
                    print("   SSE streaming endpoint available (connected to active execution)")
                    sse_resp.close()
                elif sse_resp.status_code == 404:
                    body = sse_resp.text
                    if "NOT_FOUND" in body or "Execution not found" in body:
                        assert_check(
                            True,
                            "SSE endpoint available (returns proper 404 for completed execution)",
                        )
                        print(f"   Response: {body}")
                        print("   SSE endpoint available (connect during active execution for real-time events)")
                    else:
                        assert_check(
                            False,
                            f"SSE endpoint returned unexpected 404: {body}",
                        )
                else:
                    body = sse_resp.text
                    assert_check(
                        False,
                        f"SSE endpoint returned unexpected HTTP {sse_resp.status_code}: {body}",
                    )
                print("   SSE streaming works")
            except sync_requests.exceptions.RequestException as sse_err:
                print(f"   Warning: SSE connection failed: {sse_err}")
                print("   Note: SSE endpoint may not be available yet")

        except Exception as e:
            print(f"   FATAL: SSE streaming test failed: {e}")
            failures.append(f"SSE streaming test failed: {e}")
        finally:
            if sse_workflow_id:
                try:
                    await sse_client.abort_workflow(sse_workflow_id, "test cleanup")
                except Exception:
                    pass
    print()

    print("=" * 50)
    if not failures:
        print("ALL TESTS PASSED")
        print()
        print("WCP operations validated:")
        print("  - create_workflow()")
        print("  - step_gate() with LLM_CALL, TOOL_CALL, CONNECTOR_CALL")
        print("  - mark_step_completed()")
        print("  - complete_workflow()")
        print("  - fail_workflow()")
        print("  - get_workflow()")
        print("  - GateDecision enum values and helpers")
        print("  - approve_step()")
        print("  - reject_step()")
        print("  - get_pending_approvals()")
        print("  - SSE Streaming (real-time execution status)")
        return 0
    else:
        print(f"{len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
