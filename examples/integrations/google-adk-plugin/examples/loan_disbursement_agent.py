# Copyright 2026 AxonFlow
# SPDX-License-Identifier: Apache-2.0

"""End-to-end loan-desk demo: ADK agent + AxonFlowPlugin + 4-step HITL flow.

Scenario
--------
A "loan desk" agent has one tool: `disburse_payment(amount_cents, customer_id)`.
AxonFlow policy: any disbursement above $10,000 requires human approval.

The plugin's `before_tool_callback` calls `check_tool_input`. For the
high-value attempt the platform returns `require_approval` with an
empty queue. The plugin then runs the 4-step HITL flow against AxonFlow:

  1. Gate (`check_tool_input`) returns `block_reason="require_approval"`
  2. Plugin POSTs to `/api/v1/hitl/queue` to enqueue the row
  3. Plugin polls `GET /api/v1/hitl/queue/{approval_id}` every 2s
  4. On `approved` → tool runs. On `rejected` / `expired` / timeout → deny.

The example prints the `approval_id` from step 2 so the reviewer can
post the approval out-of-band:

    curl -X POST $AXONFLOW_ENDPOINT/api/v1/hitl/queue/<approval_id>/approve \\
         -H 'Content-Type: application/json' \\
         -d '{"reviewer_id":"compliance","reviewer_email":"compliance@bank.example"}'

Run
---
    # 1. Bring up an AxonFlow agent on :8080
    cd /path/to/axonflow-enterprise && docker compose up -d

    # 2. Create the policy in AxonFlow (manual or via SDK).
    #    Configure a static policy that returns `require_approval` on
    #    tool calls where parameters.amount_cents > 1000000.

    # 3. Set up Google ADK auth (Gemini API key).
    export GOOGLE_API_KEY=...
    export AXONFLOW_ENDPOINT=http://localhost:8080
    export AXONFLOW_CLIENT_ID=loan-desk
    export AXONFLOW_CLIENT_SECRET=...

    # 4. (Enterprise mode only) Set AXONFLOW_USER_JWT to a JWT signed
    #    with the tenant key. In community mode leave it unset.
    export AXONFLOW_USER_JWT=eyJhbGciOi...   # only needed in enterprise

    # 5. Run.
    python loan_disbursement_agent.py

    # 6. The plugin emits an INFO log on entry to step 3:
    #
    #    axonflow hitl AWAITING APPROVAL: request_id=<approval_id>; approve via
    #    POST /api/v1/hitl/queue/<approval_id>/{approve|reject} ...
    #
    #    Scenario B expects APPROVE; scenario C expects REJECT. From a
    #    second terminal (substitute the actual approval_id printed by
    #    the script):
    #
    #    # Scenario B — approve:
    curl -X POST $AXONFLOW_ENDPOINT/api/v1/hitl/queue/<approval_id_B>/approve \\
         -H 'Content-Type: application/json' \\
         -d '{"reviewer_id":"compliance","reviewer_email":"compliance@bank.example"}'

    #    # Scenario C — reject (same body shape, different verb):
    curl -X POST $AXONFLOW_ENDPOINT/api/v1/hitl/queue/<approval_id_C>/reject \\
         -H 'Content-Type: application/json' \\
         -d '{"reviewer_id":"compliance","reviewer_email":"compliance@bank.example","comment":"Disbursement above $50k requires VP approval"}'

Output shape
------------
The script prints three scenarios end-to-end:

    Scenario A — small disbursement ($500): tool runs without approval gate.
    Scenario B — large disbursement ($50,000): require_approval → row created
                 → polling → reviewer approves → tool runs.
    Scenario C — large disbursement ($75,000) where the reviewer rejects:
                 require_approval → row created → polling → reviewer rejects
                 → tool is denied + agent sees the deny short-circuit.

The plugin's defensive timeouts + circuit breaker mean an AxonFlow outage
during a non-approval call causes the agent to fail open (continue without
governance), with a warning logged. Approval-gated calls always fail
closed (deny) on outage — they are safety-critical.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("loan_disbursement_agent")


def disburse_payment(amount_cents: int, customer_id: str) -> dict[str, str | int]:
    """Move money to a customer's account.

    This is a fake tool — it just returns a confirmation dict. In a real
    deployment this would call an internal payment-rail service.
    """
    return {
        "status": "ok",
        "customer_id": customer_id,
        "amount_cents": amount_cents,
        "transaction_id": f"tx-{customer_id}-{amount_cents}",
    }


async def main() -> int:
    try:
        from google.adk.agents import LlmAgent
        from google.adk.runners import InMemoryRunner
    except ImportError:
        logger.error(
            "google-adk is not installed. Run `pip install google-adk>=2.0` to use this example."
        )
        return 1

    from axonflow_adk import AxonFlowPlugin, AxonFlowPluginConfig

    endpoint = os.environ.get("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = os.environ.get("AXONFLOW_CLIENT_ID", "loan-desk")
    client_secret = os.environ.get("AXONFLOW_CLIENT_SECRET", "")

    plugin = AxonFlowPlugin(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
        config=AxonFlowPluginConfig(
            request_type="loan-desk-chat",
            tool_connector_type="loan-desk-tool",
            # Default is True (4-step HITL flow with reviewer polling).
            # Set False to deny `require_approval` immediately without
            # creating a queue row.
            enable_hitl_polling=True,
            # Reviewer has up to 10 minutes to approve.
            approval_max_wait_seconds=600.0,
            approval_poll_interval_seconds=3.0,
            extra_context={"product": "loan_desk_demo"},
        ),
    )

    agent = LlmAgent(
        model=os.environ.get("ADK_MODEL", "gemini-2.0-flash"),
        name="loan_desk",
        instruction=(
            "You are a loan-desk agent. When asked to disburse a payment, "
            "call `disburse_payment(amount_cents, customer_id)`. NEVER skip "
            "the tool. Report the transaction id back to the user."
        ),
        tools=[disburse_payment],
    )

    runner = InMemoryRunner(
        agent=agent,
        app_name="loan_desk_demo",
        plugins=[plugin],
    )

    user_jwt = os.environ.get("AXONFLOW_USER_JWT", "")

    async def _seed_session_token(session_id: str) -> None:
        """Write the AxonFlow JWT into the ADK session state.

        Enterprise-mode policy enforcement requires `user_token` to be a
        JWT signed with the tenant key. The plugin reads it from
        `state["axonflow_user_token"]`. If `AXONFLOW_USER_JWT` is unset
        the plugin falls back to `default_user_token="anonymous"` (the
        community-mode shape).
        """
        if not user_jwt:
            return
        session_service = runner.session_service
        sess = await session_service.create_session(
            app_name="loan_desk_demo",
            user_id="cust-001",
            session_id=session_id,
        )
        sess.state["axonflow_user_token"] = user_jwt

    logger.info("=" * 80)
    logger.info("Scenario A — small disbursement ($500): tool runs without approval gate.")
    await _seed_session_token("sess-A")
    async for event in runner.run_async(
        user_id="cust-001",
        session_id="sess-A",
        new_message="Please disburse $500 to customer cust-001.",
    ):
        logger.info("event: %s", _summarize_event(event))

    logger.info("=" * 80)
    logger.info(
        "Scenario B — large disbursement ($50,000): plugin will enqueue a "
        "HITL row and POLL. Watch for the 'axonflow hitl AWAITING APPROVAL: "
        "request_id=...' log, then APPROVE that approval_id from a second "
        "terminal using the curl in the module docstring."
    )
    await _seed_session_token("sess-B")
    async for event in runner.run_async(
        user_id="cust-001",
        session_id="sess-B",
        new_message="Please disburse $50,000 to customer cust-001.",
    ):
        logger.info("event: %s", _summarize_event(event))

    logger.info("=" * 80)
    logger.info(
        "Scenario C — large disbursement ($75,000) with reviewer REJECT: "
        "plugin enqueues row, polls, reviewer rejects, agent sees deny. "
        "REJECT scenario C's approval_id from a second terminal."
    )
    await _seed_session_token("sess-C")
    async for event in runner.run_async(
        user_id="cust-001",
        session_id="sess-C",
        new_message="Please disburse $75,000 to customer cust-001.",
    ):
        logger.info("event: %s", _summarize_event(event))

    # Clean up the owned AxonFlow client — important for long-running
    # services so the underlying httpx connection pool does not leak.
    await plugin.aclose()
    return 0


def _summarize_event(event: object) -> str:
    """Best-effort one-line summary for log readability."""
    parts: list[str] = []
    for attr in ("author", "tool_call", "tool_response", "content"):
        value = getattr(event, attr, None)
        if value is None:
            continue
        if attr == "content":
            inner = getattr(value, "parts", None) or []
            text = " ".join(getattr(p, "text", "") or "" for p in inner).strip()
            if text:
                parts.append(f"text={text[:200]!r}")
        else:
            parts.append(f"{attr}={value!r}"[:200])
    return " ".join(parts) or repr(event)[:200]


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
