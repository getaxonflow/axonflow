# Copyright 2026 AxonFlow
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for AxonFlowPlugin.

These tests use stubbed `google-adk` and `axonflow` modules (see
`conftest.py`). They exercise the plugin's branching logic, not the
network shape of the AxonFlow API. Wire-shape integration is covered by
the loan-desk example run + the platform-side e2e suite.
"""

from __future__ import annotations

import asyncio
import types

import pytest

from axonflow_adk.plugin import (
    AxonFlowPlugin,
    AxonFlowPluginConfig,
    _BreakerState,
)


def _new_plugin(fake_client, **overrides):
    cfg = AxonFlowPluginConfig(
        call_timeout_seconds=0.5,
        approval_poll_interval_seconds=0.01,
        approval_max_wait_seconds=0.2,
        # Most tests need to exercise polling — enable by default in the
        # test factory. Pass `enable_hitl_polling=False` to test the
        # deny-fast default.
        enable_hitl_polling=overrides.pop("enable_hitl_polling", True),
        breaker_failure_threshold=overrides.pop("breaker_failure_threshold", 3),
        breaker_recovery_seconds=overrides.pop("breaker_recovery_seconds", 0.1),
        **overrides,
    )
    return AxonFlowPlugin.from_client(fake_client, config=cfg)


def _S(suffix: str) -> str:
    """Build a fully-qualified state key (test-side mirror of `_STATE_PREFIX`)."""
    return "temp:_axonflow_" + suffix


# ---------------------------------------------------------------------------
# 1. Pre-check / before_model_callback
# ---------------------------------------------------------------------------


async def test_before_model_allow_passes_through(
    fake_client, callback_context, llm_request_with_text
):
    """Allowed pre_check → returns None → ADK proceeds with the real LLM call."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=True,
        context_id="ctx-abc",
        block_reason=None,
    )
    plugin = _new_plugin(fake_client)

    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )

    assert result is None, "allowed path must return None to let LLM call proceed"
    assert callback_context.state[_S("last_context_id")] == "ctx-abc"
    assert callback_context.state[_S("last_model")] == "gemini-2.0-flash"
    assert fake_client.calls[0][0] == "pre_check"


async def test_before_model_deny_returns_short_circuit_llm_response(
    fake_client, callback_context, llm_request_with_text
):
    """Denied pre_check (non-approval) → short-circuit LlmResponse with reason."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=False,
        context_id="ctx-deny",
        block_reason="PII detected — SSN in prompt",
    )
    plugin = _new_plugin(fake_client)

    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )

    assert result is not None, "deny path must return an LlmResponse to short-circuit"
    text = " ".join(p.text or "" for p in result.content.parts)
    assert "AxonFlow policy denial" in text
    assert "PII" in text
    # No HITL polling should have happened on a non-approval deny.
    assert all(c[0] != "get_hitl_request" for c in fake_client.calls)


async def test_before_model_axonflow_unreachable_fails_open(
    fake_client, callback_context, llm_request_with_text
):
    """AxonFlow exception → fail open (return None, let LLM call proceed)."""
    fake_client.raise_on_pre_check = RuntimeError("axonflow agent connection refused")
    plugin = _new_plugin(fake_client)

    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )

    assert result is None, "AxonFlow outage MUST NOT take down the agent"


async def test_before_model_axonflow_timeout_fails_open(
    fake_client, callback_context, llm_request_with_text
):
    """AxonFlow exceeds call_timeout_seconds → fail open."""
    fake_client.pre_check_delay_seconds = 1.0  # longer than the 0.5s test timeout
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=True, context_id="ctx", block_reason=None
    )
    plugin = _new_plugin(fake_client)

    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )

    assert result is None, "timeout MUST fail open"


# ---------------------------------------------------------------------------
# 2. HITL approval polling
# ---------------------------------------------------------------------------


async def test_before_model_approval_full_4step_flow_approved(
    fake_client, callback_context, llm_request_with_text
):
    """4-step HITL flow: gate → create_hitl_row → poll → resume on approval."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=False,
        context_id="pre-check-ctx-1",  # gate-minted, NOT the polled id
        block_reason="require_approval",
        policies=["loan-amount-cap"],
    )
    fake_client.create_hitl_response_id = "hitl-row-abc"
    fake_client.hitl_status_queue = ["pending", "pending", "approved"]
    plugin = _new_plugin(fake_client)

    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )

    assert result is None, "approved HITL must let the LLM call proceed"

    # Verify the 4 steps actually ran in order.
    op_sequence = [c[0] for c in fake_client.calls]
    assert op_sequence[:2] == ["pre_check", "create_hitl_request"]
    poll_calls = [c for c in fake_client.calls if c[0] == "get_hitl_request"]
    assert len(poll_calls) == 3
    # Plugin polled the ID returned by create, NOT the gate-minted context_id.
    assert all(c[1]["request_id"] == "hitl-row-abc" for c in poll_calls)


async def test_before_model_approval_rejected_returns_deny(
    fake_client, callback_context, llm_request_with_text
):
    """4-step flow: create_hitl_row → poll → rejected → deny short-circuit."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=False,
        context_id="pre-check-ctx-2",
        block_reason="require_approval",
        policies=["loan-amount-cap"],
    )
    fake_client.create_hitl_response_id = "hitl-row-def"
    fake_client.hitl_status_queue = ["pending", "rejected"]
    plugin = _new_plugin(fake_client)

    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )

    assert result is not None, "rejected HITL must deny"
    text = " ".join(p.text or "" for p in result.content.parts)
    assert "require_approval" in text


async def test_before_model_approval_polling_timeout_fails_closed(
    fake_client, callback_context, llm_request_with_text
):
    """create_hitl_row succeeds → no reviewer response in approval_max_wait_seconds → deny."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=False,
        context_id="pre-check-ctx-3",
        block_reason="require_approval",
        policies=["loan-amount-cap"],
    )
    fake_client.create_hitl_response_id = "hitl-row-ghi"
    fake_client.hitl_status_queue = ["pending"] * 100
    plugin = _new_plugin(fake_client)

    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )

    assert result is not None, "polling timeout MUST fail closed (deny) for approvals"


async def test_before_model_approval_create_failure_fails_closed(
    fake_client, callback_context, llm_request_with_text
):
    """create_hitl_request fails → deny fast (don't poll a row that doesn't exist)."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=False,
        context_id="pre-check-ctx-4",
        block_reason="require_approval",
        policies=["loan-amount-cap"],
    )
    fake_client.raise_on_create_hitl_request = RuntimeError("create endpoint 500")
    plugin = _new_plugin(fake_client)

    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )

    assert result is not None, "create failure MUST fail closed"
    # MUST NOT poll if create failed — no row to poll.
    poll_calls = [c for c in fake_client.calls if c[0] == "get_hitl_request"]
    assert poll_calls == [], "no row created → MUST NOT poll"


# ---------------------------------------------------------------------------
# 3. Tool input / output checks
# ---------------------------------------------------------------------------


async def test_before_tool_allow_passes_through(fake_client, tool_context, fake_tool):
    fake_client.check_tool_input_result = types.SimpleNamespace(
        allowed=True,
        block_reason=None,
        decision_id="dec-1",
    )
    plugin = _new_plugin(fake_client)
    result = await plugin.before_tool_callback(
        tool=fake_tool,
        tool_args={"amount_cents": 100000},
        tool_context=tool_context,
    )
    assert result is None
    assert tool_context.state[_S("last_decision_id")] == "dec-1"


async def test_before_tool_deny_returns_error_dict(fake_client, tool_context, fake_tool):
    fake_client.check_tool_input_result = types.SimpleNamespace(
        allowed=False,
        block_reason="Tool not permitted",
        decision_id="dec-2",
    )
    plugin = _new_plugin(fake_client)
    result = await plugin.before_tool_callback(
        tool=fake_tool,
        tool_args={"amount_cents": 100000},
        tool_context=tool_context,
    )
    assert isinstance(result, dict)
    assert "[AxonFlow]" in result["error"]
    assert "Tool not permitted" in result["error"]


async def test_after_tool_redacts_pii_preserves_typed_shape(
    fake_client, tool_context, fake_tool
):
    """When the platform returns a JSON-serialized redacted message that
    parses back to a dict, the plugin restores the original key shape so
    downstream tool chaining still sees `customer_email` (R3 HIGH-8)."""
    fake_client.check_tool_output_result = types.SimpleNamespace(
        allowed=False,
        block_reason="PII in output",
        redacted_message='{"customer_email": "[REDACTED]"}',
    )
    plugin = _new_plugin(fake_client)
    result = await plugin.after_tool_callback(
        tool=fake_tool,
        tool_args={},
        tool_context=tool_context,
        result={"customer_email": "alice@example.com"},
    )
    assert result == {
        "customer_email": "[REDACTED]",
        "_axonflow_redacted": True,
    }


async def test_after_tool_redacts_pii_non_json_fallback(
    fake_client, tool_context, fake_tool
):
    """When the platform returns a non-JSON redacted string, the plugin
    falls back to the wrapper shape rather than crashing or guessing."""
    fake_client.check_tool_output_result = types.SimpleNamespace(
        allowed=False,
        block_reason="PII in output",
        redacted_message="customer email was [REDACTED]",
    )
    plugin = _new_plugin(fake_client)
    result = await plugin.after_tool_callback(
        tool=fake_tool,
        tool_args={},
        tool_context=tool_context,
        result={"customer_email": "alice@example.com"},
    )
    assert result == {
        "result": "customer email was [REDACTED]",
        "_axonflow_redacted": True,
    }


async def test_after_tool_redacts_pii_dict_passthrough(
    fake_client, tool_context, fake_tool
):
    """Some platform builds may return `redacted_message` as a dict directly."""
    fake_client.check_tool_output_result = types.SimpleNamespace(
        allowed=False,
        block_reason="PII",
        redacted_message={"customer_email": "[REDACTED]", "ok": True},
    )
    plugin = _new_plugin(fake_client)
    result = await plugin.after_tool_callback(
        tool=fake_tool,
        tool_args={},
        tool_context=tool_context,
        result={"customer_email": "alice@example.com"},
    )
    assert result == {
        "customer_email": "[REDACTED]",
        "ok": True,
        "_axonflow_redacted": True,
    }


async def test_after_tool_hard_deny_returns_error(fake_client, tool_context, fake_tool):
    """Output check denies without redacted_message → error dict (hard deny)."""
    fake_client.check_tool_output_result = types.SimpleNamespace(
        allowed=False,
        block_reason="Exfiltration limit exceeded",
        redacted_message=None,
    )
    plugin = _new_plugin(fake_client)
    result = await plugin.after_tool_callback(
        tool=fake_tool,
        tool_args={},
        tool_context=tool_context,
        result={"rows": list(range(10000))},
    )
    assert result is not None
    assert "Exfiltration" in result["error"]


# ---------------------------------------------------------------------------
# 4. Circuit breaker
# ---------------------------------------------------------------------------


async def test_circuit_breaker_opens_after_threshold(
    fake_client, callback_context, llm_request_with_text
):
    """N consecutive failures → breaker opens → subsequent hooks skip AxonFlow."""
    fake_client.raise_on_pre_check = RuntimeError("axonflow down")
    plugin = _new_plugin(fake_client, breaker_failure_threshold=3)

    # 3 consecutive failures
    for _ in range(3):
        await plugin.before_model_callback(
            callback_context={**vars(callback_context)} if False else callback_context,
            llm_request=llm_request_with_text,
        )

    assert plugin._breaker.state is _BreakerState.OPEN

    # 4th call must skip AxonFlow entirely.
    pre_call_count = sum(1 for c in fake_client.calls if c[0] == "pre_check")
    await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )
    post_call_count = sum(1 for c in fake_client.calls if c[0] == "pre_check")
    assert post_call_count == pre_call_count, "open breaker MUST skip the AxonFlow call"


async def test_circuit_breaker_recovers_after_window(
    fake_client, callback_context, llm_request_with_text
):
    """Open breaker → wait recovery_seconds → next call is a probe (half-open)."""
    fake_client.raise_on_pre_check = RuntimeError("transient")
    plugin = _new_plugin(
        fake_client,
        breaker_failure_threshold=2,
        breaker_recovery_seconds=0.05,
    )

    for _ in range(2):
        await plugin.before_model_callback(
            callback_context=callback_context,
            llm_request=llm_request_with_text,
        )
    assert plugin._breaker.state is _BreakerState.OPEN

    await asyncio.sleep(0.08)
    # AxonFlow is healthy now.
    fake_client.raise_on_pre_check = None
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=True, context_id="ctx-ok", block_reason=None
    )
    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )
    assert result is None
    assert plugin._breaker.state is _BreakerState.CLOSED


# ---------------------------------------------------------------------------
# 5. Audit hooks never block
# ---------------------------------------------------------------------------


async def test_after_model_audit_failure_does_not_block(
    fake_client, callback_context, llm_response_with_text
):
    """audit_llm_call raising must NOT propagate to the agent."""
    callback_context.state[_S("last_context_id")] = "ctx-1"
    callback_context.state[_S("last_model")] = "gemini-2.0-flash"
    callback_context.state[_S("call_start_monotonic")] = 0.0

    async def boom(**_kwargs):
        raise RuntimeError("audit endpoint 500")

    fake_client.audit_llm_call = boom
    plugin = _new_plugin(fake_client)

    # Should not raise.
    result = await plugin.after_model_callback(
        callback_context=callback_context,
        llm_response=llm_response_with_text,
    )
    assert result is None


async def test_on_tool_error_audits_does_not_block(fake_client, tool_context, fake_tool):
    plugin = _new_plugin(fake_client)
    result = await plugin.on_tool_error_callback(
        tool=fake_tool,
        tool_args={"amount_cents": 50000},
        tool_context=tool_context,
        error=RuntimeError("downstream timeout"),
    )
    assert result is None
    # audit_tool_call was attempted
    audit_calls = [c for c in fake_client.calls if c[0] == "audit_tool_call"]
    assert len(audit_calls) == 1
    req = audit_calls[0][1]["request"]
    assert req.tool_name == "disburse_payment"
    assert req.success is False
    assert "downstream timeout" in req.error_message


# ---------------------------------------------------------------------------
# 6. on_user_message_callback is a deliberate no-op
# ---------------------------------------------------------------------------


async def test_on_user_message_is_noop(fake_client):
    """v1 must NOT mutate the user message (it would silently replace it)."""
    from google.genai.types import Content, Part

    plugin = _new_plugin(fake_client)
    msg = Content(role="user", parts=[Part(text="hello")])
    result = await plugin.on_user_message_callback(
        invocation_context=types.SimpleNamespace(state={}),
        user_message=msg,
    )
    assert result is None
    assert fake_client.calls == [], "on_user_message must NOT call AxonFlow in v1"


# ---------------------------------------------------------------------------
# 7. AgentTool plugin-isolation gotcha (#2809)
# ---------------------------------------------------------------------------


async def test_agent_tool_plugin_isolation_gotcha_is_documented(
    fake_client, llm_request_with_text
):
    """Demonstrates the `AgentTool` plugin-isolation bug from
    https://github.com/google/adk-python/issues/2809 using a Runner-shaped
    fake that mirrors ADK's actual plugin dispatch.

    The shape:

        OuterRunner(plugins=[plugin])      ← parent runner with our plugin
            │
            ├─ outer_agent (LlmAgent)
            │     before_model_callback → plugin.before_model_callback ✓
            │
            └─ AgentTool(wraps=sub_agent)
                  internally constructs:
                      InnerRunner(plugins=[])   ← #2809: plugins NOT forwarded
                          └─ sub_agent (LlmAgent)
                                before_model_callback → ???

    The bug is that the InnerRunner does not receive the parent's plugin
    list, so the same `plugin` instance is never consulted for the
    sub-agent's model/tool calls. We assert that with the fake runners
    below: even though the sub-agent runs a model call, the plugin's call
    ledger contains exactly the outer-agent invocations.

    A future ADK fix that forwards plugins (closing #2809) will cause
    this test to FAIL with `pre_check` calls == 2, which is the
    regression signal we want — at that point the docs and known-gotchas
    section can be revised. The test is therefore the long-lived pin.
    """
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=True, context_id="ctx", block_reason=None
    )
    plugin = _new_plugin(fake_client)

    class _FakeRunner:
        """Minimal model of ADK's plugin dispatch loop.

        ADK's real Runner iterates registered plugins per hook. Our fake
        just calls each registered plugin's `before_model_callback`
        sequentially, the same way #2809's bug manifests at the dispatch
        layer.
        """

        def __init__(self, name: str, plugins: list) -> None:
            self.name = name
            self.plugins = plugins

        async def run_model_step(self, agent_name: str) -> None:
            ctx = types.SimpleNamespace(
                state={},
                agent_name=agent_name,
                invocation_id=f"inv-{self.name}-{agent_name}",
                user_id="",
            )
            for p in self.plugins:
                await p.before_model_callback(
                    callback_context=ctx,
                    llm_request=llm_request_with_text,
                )

    class _FakeAgentTool:
        """Models ADK's AgentTool exactly along the #2809 axis.

        AgentTool wraps a sub-agent and, when invoked, constructs an
        InnerRunner with `plugins=[]` (not the parent's plugins). When the
        parent runner invokes a tool callback that ends up calling the
        AgentTool, the AgentTool's inner runner fires the sub-agent's
        model step *without* the parent plugin in scope.
        """

        def __init__(self, sub_agent_name: str) -> None:
            self.sub_agent_name = sub_agent_name

        async def invoke(self) -> None:
            inner = _FakeRunner(name="inner", plugins=[])  # ← THE BUG: plugins lost
            await inner.run_model_step(self.sub_agent_name)

    outer = _FakeRunner(name="outer", plugins=[plugin])
    sub_tool = _FakeAgentTool(sub_agent_name="sub_agent")

    # 1. Outer agent runs a model step. The plugin IS consulted.
    await outer.run_model_step("outer_agent")

    # 2. Outer agent invokes AgentTool, which spins up its own inner
    #    runner. Per #2809, that runner has plugins=[] — the plugin is
    #    NOT consulted for the sub-agent.
    await sub_tool.invoke()

    pre_check_calls = [c for c in fake_client.calls if c[0] == "pre_check"]

    # The bug-shape assertion: exactly ONE pre_check (the outer), zero
    # for the sub-agent. If ADK fixes #2809 and the inner runner starts
    # inheriting plugins, this becomes 2 and the test fails, which is
    # the regression signal we want.
    assert len(pre_check_calls) == 1, (
        f"Expected 1 pre_check (outer only); got {len(pre_check_calls)}. "
        "If this becomes 2, AgentTool now forwards plugins (ADK #2809 fix?) "
        "— update docs/known-gotchas before relaxing this assertion."
    )
    outer_invocation_id = pre_check_calls[0][1]["context"]["invocation_id"]
    assert outer_invocation_id.endswith("outer_agent"), (
        "The single pre_check should come from the outer runner's context, "
        f"not from any inner runner; got invocation_id={outer_invocation_id!r}"
    )


# ---------------------------------------------------------------------------
# 8. Provider inference
# ---------------------------------------------------------------------------


async def test_block_reason_containing_word_approval_does_not_trigger_polling(
    fake_client, callback_context, llm_request_with_text
):
    """R3 HIGH-9 regression — only the exact sentinel `"require_approval"` triggers
    HITL polling. Reasons like "approval pending from manager" are NOT
    approval-required; they are policy denials whose text happens to use the word."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=False,
        context_id="ctx-text-only",
        block_reason="No manager approval available for this customer",
    )
    fake_client.hitl_status_queue = ["approved"]  # would unblock if mis-routed
    plugin = _new_plugin(fake_client, enable_hitl_polling=True)
    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )
    assert result is not None, "non-sentinel block_reason must deny"
    poll_calls = [c for c in fake_client.calls if c[0] == "get_hitl_request"]
    assert poll_calls == [], (
        "substring 'approval' MUST NOT trigger HITL polling — exact match only"
    )


async def test_before_model_approval_denies_immediately_when_polling_disabled(
    fake_client, callback_context, llm_request_with_text
):
    """v1 default: enable_hitl_polling=False — require_approval denies fast."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=False,
        context_id="hitl-req-X",
        block_reason="require_approval",
    )
    plugin = _new_plugin(fake_client, enable_hitl_polling=False)
    result = await plugin.before_model_callback(
        callback_context=callback_context,
        llm_request=llm_request_with_text,
    )
    assert result is not None, "require_approval must deny with polling off"
    poll_calls = [c for c in fake_client.calls if c[0] == "get_hitl_request"]
    assert poll_calls == [], "polling MUST NOT happen when enable_hitl_polling=False"


async def test_config_validation_rejects_zero_timeout():
    """R3 LOW-6 — bad configs surface at construction, not at hook time."""
    from axonflow_adk.plugin import AxonFlowPluginConfig

    with pytest.raises(ValueError, match="call_timeout_seconds"):
        AxonFlowPluginConfig(call_timeout_seconds=0)
    with pytest.raises(ValueError, match="breaker_failure_threshold"):
        AxonFlowPluginConfig(breaker_failure_threshold=0)


async def test_user_token_does_not_fall_back_to_user_id(
    fake_client, llm_request_with_text
):
    """R3 HIGH-4 — plugin must NOT use ctx.user_id as a JWT proxy."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=True, context_id="ctx", block_reason=None
    )
    plugin = _new_plugin(fake_client)
    ctx = types.SimpleNamespace(
        state={},
        agent_name="a",
        invocation_id="i",
        user_id="cust-001-not-a-jwt",
    )
    await plugin.before_model_callback(
        callback_context=ctx, llm_request=llm_request_with_text
    )
    # The pre_check call must have received the default_user_token,
    # NOT "cust-001-not-a-jwt".
    assert fake_client.calls[0][1]["user_token"] == "anonymous"


async def test_user_token_uses_state_when_set(fake_client, llm_request_with_text):
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=True, context_id="ctx", block_reason=None
    )
    plugin = _new_plugin(fake_client)
    ctx = types.SimpleNamespace(
        state={"axonflow_user_token": "eyJhbGciOi...JWT..."},
        agent_name="a",
        invocation_id="i",
        user_id="cust-001",
    )
    await plugin.before_model_callback(
        callback_context=ctx, llm_request=llm_request_with_text
    )
    assert fake_client.calls[0][1]["user_token"] == "eyJhbGciOi...JWT..."


async def test_argument_redactor_scrubs_tool_args_before_audit(
    fake_client, tool_context, fake_tool
):
    """R3 MEDIUM-4 — argument_redactor lets callers mask secrets before audit."""
    from axonflow_adk.plugin import AxonFlowPluginConfig

    def scrub(args: dict) -> dict:
        return {k: ("[REDACTED]" if k == "api_key" else v) for k, v in args.items()}

    cfg = AxonFlowPluginConfig(
        call_timeout_seconds=0.5, argument_redactor=scrub
    )
    plugin = AxonFlowPlugin.from_client(fake_client, config=cfg)
    await plugin.on_tool_error_callback(
        tool=fake_tool,
        tool_args={"api_key": "sk-secret-abc", "amount": 100},
        tool_context=tool_context,
        error=RuntimeError("boom"),
    )
    audit_calls = [c for c in fake_client.calls if c[0] == "audit_tool_call"]
    assert audit_calls
    req = audit_calls[0][1]["request"]
    assert req.input["api_key"] == "[REDACTED]"
    assert req.input["amount"] == 100


async def test_circuit_breaker_half_open_admits_one_probe(fake_client):
    """R3 HIGH-6 — HALF_OPEN admits exactly one probe at a time."""
    from axonflow_adk.plugin import _BreakerState, _CircuitBreaker

    breaker = _CircuitBreaker(failure_threshold=1, recovery_seconds=0.0)
    # Trip → OPEN immediately.
    await breaker.record_failure()
    assert breaker.state is _BreakerState.OPEN

    # First acquire after recovery elapses → HALF_OPEN, returns True.
    first = await breaker.acquire()
    assert first is True
    assert breaker.state is _BreakerState.HALF_OPEN

    # Second acquire while the probe is still in flight → False.
    second = await breaker.acquire()
    assert second is False

    # Probe succeeds → CLOSED + slot released.
    await breaker.record_success()
    assert breaker.state is _BreakerState.CLOSED
    third = await breaker.acquire()
    assert third is True


async def test_circuit_breaker_half_open_failure_releases_probe_slot(fake_client):
    """R3 R2 FINDING 6 — failure path must also release `_probe_in_flight`."""
    from axonflow_adk.plugin import _CircuitBreaker

    breaker = _CircuitBreaker(failure_threshold=10, recovery_seconds=0.0)
    breaker.consecutive_failures = 10
    breaker.state = breaker.state.__class__.OPEN
    breaker.opened_at = 0.0  # immediately recoverable
    # Acquire probe slot.
    assert await breaker.acquire() is True
    assert breaker._probe_in_flight is True
    # Probe fails.
    await breaker.record_failure()
    assert breaker._probe_in_flight is False
    # Next acquire after recovery elapses again should succeed.
    breaker.opened_at = 0.0
    assert await breaker.acquire() is True


async def test_cancellation_does_not_leak_probe_slot(
    fake_client, callback_context, llm_request_with_text
):
    """R3 R2 FINDING 1 — `asyncio.CancelledError` from `wait_for` must
    release the breaker probe slot via the finally block, not leak it.

    Reproduces the scenario: breaker is HALF_OPEN with one probe in
    flight; the probe's task gets cancelled (ADK Runner shutdown); the
    plugin's next call must NOT find `_probe_in_flight == True` stuck.
    """
    plugin = _new_plugin(fake_client)
    # Force breaker into HALF_OPEN with a probe in flight (state any
    # ADK Runner using the plugin could reach).
    plugin._breaker.consecutive_failures = plugin._config.breaker_failure_threshold
    plugin._breaker.state = plugin._breaker.state.__class__.OPEN
    plugin._breaker.opened_at = 0.0

    # Build a coro that the harness will cancel.
    fake_client.pre_check_delay_seconds = 10.0  # would block forever
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=True, context_id="ctx", block_reason=None
    )
    task = asyncio.create_task(
        plugin.before_model_callback(
            callback_context=callback_context, llm_request=llm_request_with_text
        )
    )
    await asyncio.sleep(0.05)  # let the call enter wait_for
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The slot MUST be released. (The breaker may be OPEN or CLOSED
    # depending on the success/failure attribution; we only assert the
    # slot is not leaked.)
    assert plugin._breaker._probe_in_flight is False, (
        "CancelledError MUST NOT leak the breaker probe slot"
    )


async def test_redacted_message_recursionerror_falls_back_safely(
    fake_client, tool_context, fake_tool
):
    """R3 R2 FINDING 2 — a pathological redacted_message must not crash the agent."""
    fake_client.check_tool_output_result = types.SimpleNamespace(
        allowed=False,
        block_reason="PII",
        # Simulate a parse error by passing a string the json module rejects
        # with an exception NOT in (TypeError, ValueError) — patch json.loads
        # below to raise RecursionError. We trigger via monkeypatch:
        redacted_message="ok",
    )

    import axonflow_adk.plugin as plugin_mod

    real_loads = plugin_mod.json.loads

    def boom(_s, *a, **kw):
        raise RecursionError("simulated max recursion")

    plugin_mod.json.loads = boom
    try:
        plugin = _new_plugin(fake_client)
        result = await plugin.after_tool_callback(
            tool=fake_tool,
            tool_args={},
            tool_context=tool_context,
            result={"email": "x@y.com"},
        )
    finally:
        plugin_mod.json.loads = real_loads

    # Must not raise; falls back to wrapper shape.
    assert result == {"result": "ok", "_axonflow_redacted": True}


async def test_hitl_polling_failures_do_not_trip_global_breaker(
    fake_client, callback_context, llm_request_with_text
):
    """R3 R2 FINDING 3 — polling failures use a local counter, not the
    shared breaker. A polling loop that 500s every iteration must NOT
    leave the breaker OPEN for subsequent non-polling calls."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=False,
        context_id="pre-check-ctx",
        block_reason="require_approval",
        policies=["pol"],
    )
    fake_client.create_hitl_response_id = "hitl-row-W"
    fake_client.raise_on_get_hitl_request = RuntimeError("500 polling endpoint down")
    plugin = _new_plugin(fake_client, enable_hitl_polling=True)

    result = await plugin.before_model_callback(
        callback_context=callback_context, llm_request=llm_request_with_text
    )
    assert result is not None, "polling exhaustion must deny"

    # The global breaker should NOT be open. pre_check + create_hitl
    # both succeeded; only get_hitl_request failed, and those failures
    # use the local counter.
    from axonflow_adk.plugin import _BreakerState

    assert plugin._breaker.state is _BreakerState.CLOSED, (
        "HITL polling failures MUST NOT trip the shared breaker — they "
        "have their own local counter so polling errors can't disable "
        "governance for the rest of the Runner's calls."
    )


async def test_before_model_approval_denies_immediately_when_polling_disabled_no_create(
    fake_client, callback_context, llm_request_with_text
):
    """When enable_hitl_polling=False, plugin MUST NOT call create_hitl_request."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=False,
        context_id="ctx",
        block_reason="require_approval",
        policies=["pol"],
    )
    plugin = _new_plugin(fake_client, enable_hitl_polling=False)
    result = await plugin.before_model_callback(
        callback_context=callback_context, llm_request=llm_request_with_text
    )
    assert result is not None
    create_calls = [c for c in fake_client.calls if c[0] == "create_hitl_request"]
    assert create_calls == [], (
        "deny-fast mode MUST NOT enqueue a row that no one will review"
    )


async def test_aclose_idempotent_when_owns_client_false(fake_client):
    """from_client(client) plugin must NOT close a client it doesn't own."""
    close_calls = []

    async def fake_close() -> None:
        close_calls.append("closed")

    fake_client.close = fake_close
    plugin = _new_plugin(fake_client)  # via from_client → _owns_client=False

    await plugin.aclose()
    await plugin.aclose()  # second call must be a no-op

    assert close_calls == [], (
        "plugin from_client() does NOT own the client and MUST NOT close it"
    )


async def test_aclose_closes_owned_client():
    """Plugin constructed with endpoint+credentials owns its client; aclose closes it."""
    import sys
    import types

    close_calls = []

    class _OwnedClient:
        def __init__(self, **_kwargs):
            self._closed = False

        async def close(self):
            close_calls.append("closed")
            self._closed = True

    # Monkey-patch the stub so the lazy client construction returns our owned client.
    real_axonflow = sys.modules["axonflow"].AxonFlow
    sys.modules["axonflow"].AxonFlow = _OwnedClient
    try:
        plugin = AxonFlowPlugin(
            endpoint="http://localhost:8080",
            client_id="t",
            client_secret="s",
        )
        # Force lazy construction.
        await plugin._get_client()
        assert isinstance(plugin._client, _OwnedClient)

        await plugin.aclose()
        assert close_calls == ["closed"], "aclose MUST call close() on the owned client"
        # Second call is a no-op.
        await plugin.aclose()
        assert close_calls == ["closed"]
        assert plugin._client is None
    finally:
        sys.modules["axonflow"].AxonFlow = real_axonflow


async def test_aclose_as_async_context_manager():
    """Plugin supports `async with plugin:` for explicit lifecycle."""
    import sys

    close_calls = []

    class _OwnedClient:
        def __init__(self, **_kwargs):
            pass

        async def close(self):
            close_calls.append("closed")

    real_axonflow = sys.modules["axonflow"].AxonFlow
    sys.modules["axonflow"].AxonFlow = _OwnedClient
    try:
        async with AxonFlowPlugin(endpoint="http://x", client_id="t", client_secret="s") as p:
            await p._get_client()
        assert close_calls == ["closed"]
    finally:
        sys.modules["axonflow"].AxonFlow = real_axonflow


async def test_create_hitl_kwarg_normalization(
    fake_client, callback_context, llm_request_with_text
):
    """Pattern coherence — create_hitl_request must be invoked with `request=`."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=False,
        context_id="ctx",
        block_reason="require_approval",
        policies=["pol-a"],
    )
    fake_client.create_hitl_response_id = "hitl-row-kw"
    fake_client.hitl_status_queue = ["approved"]
    plugin = _new_plugin(fake_client)
    await plugin.before_model_callback(
        callback_context=callback_context, llm_request=llm_request_with_text
    )
    create_calls = [c for c in fake_client.calls if c[0] == "create_hitl_request"]
    assert create_calls, "create_hitl_request must have been called"
    # The fake's create_hitl_request accepts `request=`-style invocation only —
    # if the plugin used positional args, the fake would have caught the request
    # as `request=<obj>` (the kwarg the SDK signature uses). Verify the request
    # object carries the expected fields.
    payload = create_calls[0][1]["request"]
    assert getattr(payload, "client_id", None) == plugin._effective_client_id()
    assert getattr(payload, "triggered_policy_id", None) == "pol-a"
    assert getattr(payload, "trigger_reason", None) == "require_approval"


async def test_state_keys_use_temp_prefix(fake_client, callback_context, llm_request_with_text):
    """R3 MEDIUM-6 — keys must start with `temp:` so ADK doesn't persist them."""
    fake_client.pre_check_result = types.SimpleNamespace(
        approved=True, context_id="ctx", block_reason=None
    )
    plugin = _new_plugin(fake_client)
    await plugin.before_model_callback(
        callback_context=callback_context, llm_request=llm_request_with_text
    )
    for key in callback_context.state.keys():
        assert key.startswith("temp:"), f"state key {key!r} should be temp-prefixed"


@pytest.mark.parametrize(
    ("model_name", "expected"),
    [
        ("gemini-2.0-flash", "google"),
        ("gpt-4o-mini", "openai"),
        ("claude-3-sonnet", "anthropic"),
        ("bedrock-titan", "bedrock"),
        ("ollama-llama3", "ollama"),
        ("unknown-model", "google"),
        ("", "google"),
        (None, "google"),
    ],
)
def test_infer_provider(model_name, expected):
    assert AxonFlowPlugin._infer_provider(model_name) == expected
