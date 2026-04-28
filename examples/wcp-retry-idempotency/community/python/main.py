"""WCP retry_context + idempotency_key E2E example (Issue #1673 Phase 1 + 2).

Exercises the new SDK surface end-to-end against a running v7.3.0 enterprise
stack. Every assertion fails the process on mismatch.

Run:
    source /tmp/axonflow-e2e-env.sh
    export AXONFLOW_BASE_URL=http://localhost:8080
    python examples/wcp_retry_idempotency.py
"""

from __future__ import annotations

import asyncio
import os
import sys

from axonflow import AxonFlow
from axonflow.exceptions import IdempotencyKeyMismatchError
from axonflow.workflow import (
    CreateWorkflowRequest,
    MarkStepCompletedRequest,
    StepGateRequest,
    StepType,
)


def must_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        print(f"missing env: {name}", file=sys.stderr)
        sys.exit(1)
    return v


def banner(msg: str) -> None:
    print()
    print("━━━", msg, "━━━")


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def assert_eq(label: str, want: object, got: object) -> None:
    if want != got:
        fail(f"{label}: want {want!r}, got {got!r}")


def assert_true(label: str, cond: bool) -> None:
    if not cond:
        fail(f"assertion failed: {label}")


async def act1(client: AxonFlow) -> None:
    wf = await client.create_workflow(CreateWorkflowRequest(workflow_name="py-sdk-retry-context"))
    print(f"workflow: {wf.workflow_id}")

    # 1) First gate — first-call invariants
    first = await client.step_gate(
        wf.workflow_id,
        "step-1",
        StepGateRequest(step_name="first-step", step_type=StepType.TOOL_CALL),
    )
    rc = first.retry_context
    assert rc is not None, "retry_context missing on first gate"
    assert_eq("first gate_count", 1, rc.gate_count)
    assert_eq("first completion_count", 0, rc.completion_count)
    assert_eq("first prior_completion_status", "none", rc.prior_completion_status)
    assert_true("first !prior_output_available", not rc.prior_output_available)
    assert_eq(
        "first last_decision (first-call invariant)",
        first.decision.value,
        rc.last_decision.value if hasattr(rc.last_decision, "value") else rc.last_decision,
    )
    assert_eq("first FirstAttemptAt == LastAttemptAt", rc.first_attempt_at, rc.last_attempt_at)
    print("  first gate invariants ✔")

    # 2) Complete, then re-gate
    await client.mark_step_completed(
        wf.workflow_id,
        "step-1",
        MarkStepCompletedRequest(output={"transfer_id": "TXN-py-1", "amount": 500}),
    )
    re_gate = await client.step_gate(
        wf.workflow_id,
        "step-1",
        StepGateRequest(step_type=StepType.TOOL_CALL),
    )
    rc = re_gate.retry_context
    assert rc is not None
    assert_eq("re-gate post-complete gate_count", 2, rc.gate_count)
    assert_eq("re-gate post-complete completion_count", 1, rc.completion_count)
    assert_eq(
        "re-gate post-complete prior_completion_status", "completed", rc.prior_completion_status
    )
    assert_true("re-gate post-complete prior_output_available", rc.prior_output_available)
    assert_true("re-gate post-complete prior_output omitted by default", rc.prior_output is None)
    assert_true("re-gate post-complete cached==True", re_gate.cached is True)
    print("  re-gate post-complete ✔")

    # 3) Gate on step-2 without completion (agent-crash simulation)
    await client.step_gate(
        wf.workflow_id,
        "step-2",
        StepGateRequest(step_name="second-step", step_type=StepType.TOOL_CALL),
    )
    re_gate2 = await client.step_gate(
        wf.workflow_id,
        "step-2",
        StepGateRequest(step_type=StepType.TOOL_CALL),
    )
    assert re_gate2.retry_context is not None
    assert_eq(
        "gated_not_completed status",
        "gated_not_completed",
        re_gate2.retry_context.prior_completion_status,
    )
    assert_eq("gated_not_completed completion_count", 0, re_gate2.retry_context.completion_count)
    print("  gated_not_completed ✔")

    # 4) include_prior_output=True recovers the payload
    with_prior = await client.step_gate(
        wf.workflow_id,
        "step-1",
        StepGateRequest(step_type=StepType.TOOL_CALL),
        include_prior_output=True,
    )
    assert with_prior.retry_context is not None
    assert_true("prior_output populated", with_prior.retry_context.prior_output is not None)
    assert_eq(
        "prior_output[transfer_id]",
        "TXN-py-1",
        with_prior.retry_context.prior_output["transfer_id"],
    )
    print("  prior_output recovery ✔")


async def act2(client: AxonFlow) -> None:
    wf = await client.create_workflow(CreateWorkflowRequest(workflow_name="py-sdk-idempotency-key"))
    print(f"workflow: {wf.workflow_id}")

    original_key = "payment:wire:py-sdk-invoice-1"

    # 5) Gate with key — retry_context.idempotency_key echoes
    first = await client.step_gate(
        wf.workflow_id,
        "step-1",
        StepGateRequest(
            step_name="wire", step_type=StepType.TOOL_CALL, idempotency_key=original_key
        ),
    )
    assert first.retry_context is not None
    assert_eq(
        "retry_context.idempotency_key echo", original_key, first.retry_context.idempotency_key
    )
    print("  key round-trip ✔")

    # 6) Re-gate with different key → IdempotencyKeyMismatchError
    try:
        await client.step_gate(
            wf.workflow_id,
            "step-1",
            StepGateRequest(
                step_type=StepType.TOOL_CALL, idempotency_key="payment:wire:different-2"
            ),
        )
        fail("expected IdempotencyKeyMismatchError on gate with different key")
    except IdempotencyKeyMismatchError as err:
        assert_eq("mismatch expected_key", original_key, err.expected_idempotency_key)
        assert_eq("mismatch received_key", "payment:wire:different-2", err.received_idempotency_key)
        assert_true("mismatch workflow_id populated", err.workflow_id.startswith("wf_"))
        assert_eq("mismatch step_id", "step-1", err.step_id)
    print("  typed 409 error ✔")

    # 7) Complete with matching key
    await client.mark_step_completed(
        wf.workflow_id,
        "step-1",
        MarkStepCompletedRequest(output={"transfer_id": "TXN-K1"}, idempotency_key=original_key),
    )
    print("  complete with matching key ✔")


async def main() -> None:
    endpoint = os.environ.get("AXONFLOW_BASE_URL", "http://localhost:8080")
    client_id = os.environ.get("AXONFLOW_CLIENT_ID", "demo")
    client_secret = os.environ.get("AXONFLOW_CLIENT_SECRET", "demo-secret")

    client = AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
    )

    try:
        banner("Act 1 — retry_context (Python SDK)")
        await act1(client)

        banner("Act 2 — idempotency_key (Python SDK)")
        await act2(client)

        banner("All assertions passed ✔")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
