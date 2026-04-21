"""Evaluation-tier retry-aware policy demo (Python SDK).

Creates a dynamic policy via the policy REST API (the Python SDK doesn't
expose a policy-create helper), then uses the SDK's step_gate to prove
the retry-aware condition fires on retry_policy="reevaluate".

⚠️ Evaluation or Enterprise license required.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import urllib.request

from axonflow import AxonFlow
from axonflow.workflow import (
    CreateWorkflowRequest,
    StepGateRequest,
    StepType,
    ToolContext,
    RetryPolicy,
)


def must_env(k: str) -> str:
    v = os.environ.get(k)
    if not v:
        print(f"missing env: {k}", file=sys.stderr)
        sys.exit(1)
    return v


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def banner(s: str) -> None:
    print()
    print("━━━", s, "━━━")


def _auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def create_retry_aware_policy(base_url: str, client_id: str, client_secret: str) -> str:
    body = json.dumps({
        "name": "Retry on gated-not-completed wire requires approval (Python)",
        "description": "Human verification required before re-executing a wire when the prior attempt never completed.",
        "type": "context_aware",
        "priority": 100,
        "enabled": True,
        "conditions": [
            {"field": "step.gate_count", "operator": "greater_than", "value": 1},
            {"field": "step.prior_completion_status", "operator": "equals", "value": "gated_not_completed"},
            {"field": "context.tool_name", "operator": "equals", "value": "core_banking_transfer"},
        ],
        "actions": [{
            "type": "require_approval",
            "config": {
                "reason": "Retry on un-completed wire — verify with bank before re-execution",
                "severity": "high",
            },
        }],
    }).encode()

    req = urllib.request.Request(
        f"{base_url}/api/v1/policies",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": _auth_header(client_id, client_secret),
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        fail(f"create policy: HTTP {e.code} body={e.read().decode()}")

    pid = payload.get("policy", {}).get("id", "")
    if not pid:
        fail(f"create policy: missing policy.id in response, body={payload}")
    return pid


def delete_policy(base_url: str, client_id: str, client_secret: str, policy_id: str) -> None:
    req = urllib.request.Request(
        f"{base_url}/api/v1/policies/{policy_id}",
        method="DELETE",
        headers={"Authorization": _auth_header(client_id, client_secret)},
    )
    try:
        urllib.request.urlopen(req).close()
    except urllib.error.URLError:
        pass  # best-effort teardown


async def main() -> None:
    endpoint = os.environ.get("AXONFLOW_BASE_URL", "http://localhost:8080")
    client_id = must_env("AXONFLOW_CLIENT_ID")
    client_secret = must_env("AXONFLOW_CLIENT_SECRET")

    banner("Retry-aware policy (Python SDK, Evaluation tier)")

    policy_id = create_retry_aware_policy(endpoint, client_id, client_secret)
    print(f"  policy created: {policy_id}")

    client = AxonFlow(endpoint=endpoint, client_id=client_id, client_secret=client_secret)
    try:
        wf = await client.create_workflow(CreateWorkflowRequest(workflow_name="eval-retry-aware-py"))
        print(f"  workflow: {wf.workflow_id}")

        base_req = StepGateRequest(
            step_name="Initiate Wire",
            step_type=StepType.TOOL_CALL,
            step_input={"amount_eur": 750, "to_account": "1234"},
            tool_context=ToolContext(tool_name="core_banking_transfer", tool_type="api"),
        )

        # 1) First gate — allow
        first = await client.step_gate(wf.workflow_id, "step-1", base_req)
        if first.decision.value != "allow":
            fail(f"first gate: want allow, got {first.decision}")
        print("  first gate: allow (gate_count=1, policy doesn't fire) ✔")

        # 2) Cached retry — allow, policy bypassed
        cached = await client.step_gate(wf.workflow_id, "step-1", base_req)
        if not cached.cached:
            fail("second gate should be cached")
        if cached.decision.value != "allow":
            fail(f"cached gate: want allow, got {cached.decision}")
        print("  second gate cached: still allow (cache bypasses policy) ✔")

        # 3) Reevaluate — retry-aware policy fires
        reeval_req = StepGateRequest(
            step_name="Initiate Wire",
            step_type=StepType.TOOL_CALL,
            step_input={"amount_eur": 750, "to_account": "1234"},
            tool_context=ToolContext(tool_name="core_banking_transfer", tool_type="api"),
            retry_policy=RetryPolicy.REEVALUATE,
        )
        third = await client.step_gate(wf.workflow_id, "step-1", reeval_req)
        if third.cached:
            fail("reevaluate gate should not be cached")
        if third.decision.value != "require_approval":
            fail(f"reevaluate gate: want require_approval, got {third.decision} ({third.reason})")
        print("  third gate (reevaluate): require_approval (policy FIRED) ✔")

        banner("Evaluation-tier Python SDK demo passed ✔")
    finally:
        delete_policy(endpoint, client_id, client_secret, policy_id)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
