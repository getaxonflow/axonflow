# Copyright 2026 AxonFlow
# SPDX-License-Identifier: Apache-2.0

"""AxonFlow governance plugin for Google ADK.

`AxonFlowPlugin` extends `google.adk.plugins.BasePlugin` and routes the six
governance-relevant hooks through the existing `axonflow` Python SDK
(`pre_check`, `audit_llm_call`, `check_tool_input`, `check_tool_output`,
`audit_tool_call`) so every model + tool call across every agent on the
Runner is governed.

Three hard design constraints:

1. **Reuse the `axonflow` Python SDK.** The plugin does not speak raw HTTP.
   Auth, retry, observability, and version pinning are inherited from the
   SDK that already ships to PyPI as `axonflow>=8.0`.

2. **A buggy plugin must not break the agent.** Every hook is wrapped by a
   per-call timeout (default 5s) and a half-open circuit breaker (default
   open after 5 consecutive failures, recover after 30s). When the circuit
   is open or a hook errors, the plugin **fails open** (returns None and
   lets the model/tool call proceed) so an AxonFlow outage cannot take
   down every ADK agent registered on the Runner.

3. **`require_approval` fails closed.** Unlike the generic failure path,
   when policy explicitly requires human approval, the plugin polls the
   HITL queue and short-circuits the call with a deny on rejection,
   expiry, or polling timeout. Approvals are safety-critical; defaulting
   to "allow" here would silently bypass governance.

The plugin signatures match `BasePlugin` exactly (keyword-only args, async
def, optional return). See
https://github.com/google/adk-python/blob/main/src/google/adk/plugins/base_plugin.py
for the canonical hook surface.

Cross-language clone discipline (Java / Go / TypeScript / Kotlin /
OpenAI Agents SDK):

  • All SDK invocations use keyword arguments. Positional args are an
    anti-pattern here because the SDK reorders + renames params across
    minor releases, and the cross-language clones cannot mirror Python
    positional binding rules.
  • The 4-step HITL flow is canonical: gate → create_hitl_row → poll →
    resume/deny. Same shape in every language.
  • Defensive defaults (timeout, half-open breaker, fail-open per hook,
    fail-closed on approvals) are part of the contract, not the
    implementation — clone them.
  • `enable_hitl_polling` defaults to True. Operators who want
    deny-fast must set False explicitly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.agents.invocation_context import InvocationContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext
    from google.genai import types as genai_types

    from axonflow import AxonFlow

# google-adk + axonflow are hard runtime dependencies. We import at module
# scope so subclass attribution is correct under the framework's plugin
# discovery, and so import failures surface at agent boot rather than at
# the first hook call (where they could otherwise bypass `_call_with_guard`
# and break the agent — R3 HIGH-5).
from google.adk.plugins.base_plugin import BasePlugin  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.genai import types as genai_types  # noqa: E402
from axonflow.types import AuditToolCallRequest, TokenUsage  # noqa: E402

# State keys are prefixed with `temp:` (the ADK convention) so they do
# NOT persist to long-term session state across invocations
# (R3 MEDIUM-6 — `google.adk.sessions.state.TEMP_PREFIX` equivalent).
_STATE_PREFIX = "temp:_axonflow_"

logger = logging.getLogger(__name__)


class ApprovalTimeout(Exception):
    """Raised internally when HITL polling exceeds the configured ceiling."""


class ApprovalRejected(Exception):
    """Raised internally when a reviewer rejected (or the platform expired) the request."""


class _BreakerState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class _CircuitBreaker:
    """Half-open circuit breaker around the AxonFlow client.

    The breaker exists so that an AxonFlow outage cannot take down every
    ADK agent registered on the Runner. When the circuit is open the
    plugin fails open (returns None) on every hook until the recovery
    window elapses. HALF_OPEN admits exactly ONE probe at a time
    (R3 HIGH-6) — concurrent hook invocations during recovery do not
    leak a thundering herd onto a still-recovering AxonFlow.

    All state mutations are guarded by an `asyncio.Lock` (R3 MEDIUM-5)
    so concurrent hook calls cannot race the counter. The lock is async
    because all hooks are async — if you mix this plugin with threaded
    callers, wrap with `asyncio.run_coroutine_threadsafe`.
    """

    def __init__(self, failure_threshold: int, recovery_seconds: float) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self.state: _BreakerState = _BreakerState.CLOSED
        self.consecutive_failures: int = 0
        self.opened_at: float = 0.0
        self._lock = asyncio.Lock()
        self._probe_in_flight: bool = False

    async def acquire(self) -> bool:
        """Atomically check the breaker and reserve a probe slot if HALF_OPEN.

        Returns True when the caller may proceed with the underlying call,
        False when the breaker is blocking (either OPEN before recovery,
        or HALF_OPEN with a probe already in flight).
        """
        async with self._lock:
            if self.state is _BreakerState.CLOSED:
                return True
            if self.state is _BreakerState.OPEN:
                if (time.monotonic() - self.opened_at) >= self.recovery_seconds:
                    self.state = _BreakerState.HALF_OPEN
                    self._probe_in_flight = True
                    return True
                return False
            # HALF_OPEN: admit exactly one probe.
            if self._probe_in_flight:
                return False
            self._probe_in_flight = True
            return True

    async def record_success(self) -> None:
        async with self._lock:
            self.state = _BreakerState.CLOSED
            self.consecutive_failures = 0
            self.opened_at = 0.0
            self._probe_in_flight = False

    async def record_failure(self) -> None:
        async with self._lock:
            self.consecutive_failures += 1
            if self.consecutive_failures >= self.failure_threshold:
                self.state = _BreakerState.OPEN
                self.opened_at = time.monotonic()
            self._probe_in_flight = False


@dataclass
class AxonFlowPluginConfig:
    """Tunable knobs. All have safe defaults — most users do not set these."""

    # Per-hook deadline. AxonFlow REST calls that exceed this are abandoned
    # and the hook fails open (or fails closed for approvals — see below).
    call_timeout_seconds: float = 5.0
    # Default `user_token` propagated when ADK's invocation context does not
    # carry one. Override via callback_context state['axonflow_user_token'].
    # In enterprise mode this MUST be a JWT, not a free-form identifier
    # (R3 HIGH-4) — the platform's apiAuthMiddleware rejects non-JWTs.
    default_user_token: str = "anonymous"
    # HITL polling is ENABLED by default — the plugin runs the full
    # 4-step approval flow:
    #
    #   1. pre_check / check_tool_input returns require_approval
    #   2. plugin calls axonflow.create_hitl_request(...) → approval_id
    #   3. plugin polls axonflow.get_hitl_request(approval_id) until terminal
    #   4. plugin allows on "approved" / denies on rejected | expired | timeout
    #
    # Earlier v1 drafts shipped this as opt-in because the SDK had no
    # `create_hitl_request` method, so polling against the gate-minted
    # correlation IDs 404'd indefinitely (R3 R1 HIGH-1/HIGH-2). That gap
    # closed in `axonflow` v8.2.0 with the explicit row-create endpoint,
    # so the full reviewer-driven flow is now functional. Set this False
    # if you want deny-fast semantics — the plugin will short-circuit on
    # `require_approval` without enqueuing a row.
    enable_hitl_polling: bool = True
    approval_poll_interval_seconds: float = 2.0
    approval_max_wait_seconds: float = 300.0
    # Circuit breaker.
    breaker_failure_threshold: int = 5
    breaker_recovery_seconds: float = 30.0
    # Default request_type label propagated to AxonFlow's pre_check. Useful
    # for filtering decisions in the AxonFlow audit log.
    request_type: str = "adk-chat"
    # Default connector_type label for tool-call audit. ADK tools are not
    # MCP connectors, but reusing the MCP-style check-input / check-output
    # endpoints gives us PII redaction + policy enforcement on tool I/O.
    tool_connector_type: str = "adk-tool"
    # Default tenant_id / client_id (overrides what is on the SDK client).
    tenant_id: str | None = None
    # Stable identifier surfaced in audit context. Unique per Runner is OK.
    plugin_name: str = "AxonFlowPlugin"
    # Extra static fields merged into every audit context.
    extra_context: dict[str, Any] = field(default_factory=dict)
    # Optional callback that scrubs sensitive fields from tool_args BEFORE
    # they are sent to `audit_tool_call` (R3 MEDIUM-4). Default: send as-is.
    argument_redactor: Callable[[dict[str, Any]], dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        # R3 LOW-6 — surface configuration mistakes at construction time
        # rather than at first hook call (where they would just fail open).
        if self.call_timeout_seconds <= 0:
            raise ValueError("call_timeout_seconds must be > 0")
        if self.approval_poll_interval_seconds <= 0:
            raise ValueError("approval_poll_interval_seconds must be > 0")
        if self.approval_max_wait_seconds <= 0:
            raise ValueError("approval_max_wait_seconds must be > 0")
        if self.breaker_failure_threshold <= 0:
            raise ValueError("breaker_failure_threshold must be > 0")
        if self.breaker_recovery_seconds <= 0:
            raise ValueError("breaker_recovery_seconds must be > 0")


class AxonFlowPlugin(BasePlugin):
    """Registers AxonFlow governance on a Google ADK Runner.

    Usage:
        from google.adk.runners import InMemoryRunner
        from axonflow_adk import AxonFlowPlugin

        runner = InMemoryRunner(
            agent=root_agent,
            app_name="loan_desk",
            plugins=[AxonFlowPlugin(
                endpoint="http://localhost:8080",
                client_id="loan-desk",
                client_secret="...",
            )],
        )

    Or with an existing `AxonFlow` client:

        from axonflow import AxonFlow
        axon = AxonFlow(endpoint="...", client_id="...", client_secret="...")
        runner = InMemoryRunner(
            agent=root_agent,
            app_name="loan_desk",
            plugins=[AxonFlowPlugin.from_client(axon)],
        )

    Hook → endpoint mapping:

        on_user_message_callback     → no-op (reserved for ADR-pinned future use)
        before_model_callback        → axonflow.pre_check
        after_model_callback         → axonflow.audit_llm_call
        before_tool_callback         → axonflow.check_tool_input
        after_tool_callback          → axonflow.check_tool_output
        on_tool_error_callback       → axonflow.audit_tool_call

    Known ADK behaviors the plugin does NOT work around:

      • `AgentTool` does not inherit Runner plugins
        (https://github.com/google/adk-python/issues/2809). Sub-agents
        invoked via `AgentTool` are NOT governed by this plugin. Use the
        explicit `RemoteA2aAgent` pattern, or register the plugin on the
        inner Runner as well.

    Args (constructor):
        endpoint: AxonFlow agent URL (e.g. `http://localhost:8080`).
        client_id: AxonFlow client identifier.
        client_secret: AxonFlow client secret.
        config: Optional `AxonFlowPluginConfig` overriding tunables.
        axonflow_client: Optional pre-built `AxonFlow` instance — when
            provided, `endpoint`/`client_id`/`client_secret` are ignored
            and the plugin reuses the caller's client.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        *,
        config: AxonFlowPluginConfig | None = None,
        axonflow_client: AxonFlow | None = None,
    ) -> None:
        cfg = config or AxonFlowPluginConfig()
        super().__init__(name=cfg.plugin_name)
        self._config = cfg
        self._owns_client = axonflow_client is None
        self._client: AxonFlow | None = axonflow_client
        # When the caller did not pass an AxonFlow client, build one
        # lazily on first hook so that constructing the plugin in a sync
        # context (e.g. at module import) does not need an event loop.
        self._endpoint = endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._client_lock = asyncio.Lock()
        self._breaker = _CircuitBreaker(
            failure_threshold=cfg.breaker_failure_threshold,
            recovery_seconds=cfg.breaker_recovery_seconds,
        )

    @classmethod
    def from_client(
        cls,
        client: AxonFlow,
        *,
        config: AxonFlowPluginConfig | None = None,
    ) -> AxonFlowPlugin:
        return cls(config=config, axonflow_client=client)

    # ----- Lifecycle ----------------------------------------------------

    async def aclose(self) -> None:
        """Close the owned AxonFlow client (no-op if the caller passed one in).

        ADK does not call plugin lifecycle hooks on Runner shutdown, so
        the host app is responsible for invoking this when its Runner is
        being torn down (long-running services that swap Runners per
        deployment, test harnesses that build many Runners, etc).
        Without this, the underlying httpx client's connection pool
        leaks until process exit.

        Safe to call from multiple tasks concurrently. The shared client
        lock guards the read-and-clear of `self._client`, so only one
        caller actually invokes `close()` on the underlying SDK client
        (R3 R3 MEDIUM-3).
        """
        if not self._owns_client:
            return
        async with self._client_lock:
            client = self._client
            if client is None:
                return
            self._client = None  # subsequent calls (or concurrent ones
            # released from the lock below) will short-circuit on this.
        close = getattr(client, "close", None)
        if close is None:
            return
        try:
            result = close()
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:  # noqa: BLE001 - never raise out of cleanup
            logger.warning("axonflow client close failed: %s", exc)

    async def __aenter__(self) -> AxonFlowPlugin:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.aclose()

    # ----- Internal helpers ---------------------------------------------

    async def _get_client(self) -> AxonFlow:
        if self._client is not None:
            return self._client
        async with self._client_lock:
            if self._client is None:
                # Imported lazily so unit tests that stub the plugin out
                # do not need the SDK on the import path.
                from axonflow import AxonFlow as AxonFlowClient

                self._client = AxonFlowClient(
                    endpoint=self._endpoint,
                    client_id=self._client_id,
                    client_secret=self._client_secret,
                )
            return self._client

    async def _call_with_guard(
        self,
        op_name: str,
        coro_factory: Any,
        *,
        fail_open: bool = True,
    ) -> Any:
        """Run `coro_factory()` with timeout + circuit breaker.

        `coro_factory` is a 0-arg async callable so we can short-circuit
        without ever scheduling the underlying coroutine when the breaker
        is open (avoids the un-awaited-coroutine warning).

        When `fail_open` is True (the default for audit-style hooks), any
        failure or open-circuit returns None and the agent continues. When
        `fail_open` is False (the approval path), the caller is responsible
        for translating the None return into a deny short-circuit.

        R3 R2 FINDING 1 — the breaker probe slot MUST be released even
        when a caller cancels the awaiting task (`asyncio.CancelledError`
        is a `BaseException` subclass; it would otherwise leak the slot
        and permanently disable the breaker). We use try/finally with an
        explicit `released` flag so success/failure attribution is
        preserved AND the slot is freed on any exit path.
        """
        if not await self._breaker.acquire():
            logger.debug("axonflow.%s skipped: circuit open", op_name)
            return None
        outcome: str = "failure"  # default if we exit via cancel/BaseException
        try:
            try:
                result = await asyncio.wait_for(
                    coro_factory(),
                    timeout=self._config.call_timeout_seconds,
                )
                outcome = "success"
                return result
            except asyncio.TimeoutError:
                logger.warning(
                    "axonflow.%s timed out after %.1fs; %s",
                    op_name,
                    self._config.call_timeout_seconds,
                    "failing open" if fail_open else "deferring to caller",
                )
                return None
            except Exception as exc:  # noqa: BLE001 - intentional broad catch at the boundary
                logger.warning(
                    "axonflow.%s failed: %s; %s",
                    op_name,
                    exc,
                    "failing open" if fail_open else "deferring to caller",
                )
                return None
        finally:
            # Always release the breaker slot. `outcome` reflects whether
            # this counts as a success (resets counter) or a failure
            # (increments counter, may trip OPEN). On cancellation/
            # BaseException, we treat as failure — defensive, and
            # the cancel re-raises through this finally anyway.
            if outcome == "success":
                await self._breaker.record_success()
            else:
                await self._breaker.record_failure()

    def _effective_client_id(self) -> str:
        """Resolve the AxonFlow `client_id` for HITL row creation.

        The HITL `CreateRequestInput.client_id` is required (platform
        rejects empty). Prefer the explicit constructor arg, then the
        underlying SDK client's configured client_id, else fall back to
        the plugin name (visible label, never empty).
        """
        if isinstance(self._client_id, str) and self._client_id:
            return self._client_id
        client = self._client
        if client is not None:
            inner = getattr(client, "_config", None)
            cid = getattr(inner, "client_id", None)
            if isinstance(cid, str) and cid:
                return cid
        return self._config.plugin_name

    def _user_token(self, ctx: Any) -> str:
        """Resolve the AxonFlow `user_token` for the current call.

        ADK does not have a first-class `user_token` concept. We look in:
          1. callback_context.state['axonflow_user_token']
          2. config.default_user_token

        We do NOT fall back to `ctx.user_id` (R3 HIGH-4). In enterprise
        mode the platform's apiAuthMiddleware expects a JWT signed with
        the tenant key, and ADK's `user_id` is a raw identifier string
        (e.g. "cust-001"). Falling back to it would 401 every call,
        which `_call_with_guard` would silently fail-open — disabling
        governance across the entire deployment. Host apps MUST set
        `state["axonflow_user_token"] = <jwt>` for enterprise mode.
        """
        state_token: Any = None
        state = getattr(ctx, "state", None)
        if state is not None:
            try:
                state_token = state.get("axonflow_user_token")
            except Exception:  # noqa: BLE001 - state.get can be a dict-like or a model
                state_token = getattr(state, "axonflow_user_token", None)
        if isinstance(state_token, str) and state_token:
            return state_token
        return self._config.default_user_token

    @staticmethod
    def _stringify_llm_request(llm_request: LlmRequest) -> str:
        """Best-effort extraction of the user prompt for governance evaluation.

        ADK's `LlmRequest.contents` is a list of `Content` parts. We
        concatenate the text parts of the most-recent user-role content
        block. This is the same heuristic ADK's own session service uses
        when it surfaces a "user query" to plugins.
        """
        contents = getattr(llm_request, "contents", None) or []
        for item in reversed(contents):
            role = getattr(item, "role", None)
            parts = getattr(item, "parts", None) or []
            text_parts = [getattr(p, "text", None) for p in parts]
            text = " ".join(t for t in text_parts if isinstance(t, str) and t)
            if role in (None, "user") and text:
                return text
        # Fall back: stringify the whole request shape (only used for
        # audit; never for blocking).
        return str(contents)[:2000]

    @staticmethod
    def _stringify_llm_response(llm_response: LlmResponse) -> str:
        content = getattr(llm_response, "content", None)
        if content is None:
            return ""
        parts = getattr(content, "parts", None) or []
        text_parts = [getattr(p, "text", None) for p in parts]
        return " ".join(t for t in text_parts if isinstance(t, str) and t)

    @staticmethod
    def _deny_llm_response(reason: str) -> LlmResponse:
        """Build the canonical deny short-circuit for `before_model_callback`.

        Returning an `LlmResponse` from `before_model_callback` skips the
        actual LLM call. The model output the agent sees becomes the text
        we pass here. We use `genai_types.Content` directly rather than
        `LlmResponse.from_text` because the latter is not a public/stable
        constructor across ADK 2.x versions.
        """
        return LlmResponse(
            content=genai_types.Content(
                role="model",
                parts=[genai_types.Part(text=f"[AxonFlow policy denial] {reason}")],
            )
        )

    # ----- HITL approval path -------------------------------------------

    @staticmethod
    def _is_approval_required_block_reason(block_reason: str | None) -> bool:
        """Exact-match check against the platform's `require_approval` sentinel.

        R3 HIGH-9 — substring matching previously false-positived on any
        policy whose reason mentioned the word "approval". The current
        platform sets `BlockReason = "require_approval"` verbatim at
        `platform/agent/gateway_handlers.go:656` and the corresponding
        proxy-mode site at `platform/agent/run.go:1693`. Matching the
        exact sentinel is wire-stable and unambiguous.
        """
        return block_reason == "require_approval"

    async def _create_hitl_row(
        self,
        *,
        client_id: str,
        user_id: str | None,
        original_query: str,
        request_type: str,
        request_context: dict[str, Any] | None,
        block_reason: str,
        triggered_policies: list[tuple[str, str | None]] | None,
        severity: str | None = None,
    ) -> str | None:
        """Step 2 of the 4-step HITL flow — enqueue a queue row + return its id.

        The platform's `pre_check` / `check_tool_input` gate sets
        `BlockReason="require_approval"` and mints a correlation
        `context_id` / `decision_id`, but does NOT create the HITL
        queue row at those sites. The plugin owns step 2 — calling
        `client.create_hitl_request(...)` to enqueue the row so a
        reviewer can act on it. The returned `request_id` is the
        canonical handle for polling.

        `triggered_policies` is a list of (policy_id, policy_name?)
        tuples; the first entry is sent on the wire. When the policy
        name is None we mirror policy_id into the name field (the
        platform stores both, but for `pre_check` the SDK only surfaces
        IDs — `check_tool_input` surfaces both via `ExplainPolicy`).

        Returns None on transient failure (network, breaker open).
        The caller treats None as deny-fast (fail-closed for approvals).
        """
        from axonflow.hitl import HITLCreateInput

        if triggered_policies:
            first_id, first_name = triggered_policies[0]
        else:
            first_id, first_name = "", None
        create_input = HITLCreateInput(
            client_id=client_id,
            user_id=user_id or None,
            original_query=original_query,
            request_type=request_type,
            request_context=request_context,
            triggered_policy_id=first_id,
            triggered_policy_name=first_name or first_id,
            trigger_reason=block_reason,
            severity=severity,
        )

        async def _do_create() -> Any:
            client = await self._get_client()
            return await client.create_hitl_request(request=create_input)

        created = await self._call_with_guard(
            "create_hitl_request", _do_create, fail_open=False
        )
        if created is None:
            return None
        rid = getattr(created, "request_id", None)
        return rid if isinstance(rid, str) and rid else None

    async def _await_hitl_decision(self, request_id: str) -> bool:
        """Step 3 of the 4-step HITL flow — poll the queue until terminal.

        Returns:
            True  → reviewer approved
            False → reviewer rejected OR platform expired OR polling exceeded
                    `approval_max_wait_seconds`

        Fail-closed: polling errors that aren't transient deny the call.
        Approvals are safety-critical and silently allowing them on an
        AxonFlow outage would defeat the gate. Polling uses a LOCAL
        consecutive-failure counter — it does NOT share the global
        breaker counter, so a misconfigured approval gate cannot trip
        the breaker OPEN for other in-flight calls on the Runner
        (R3 R2 FINDING 3).
        """
        # Operator-visible signal of the canonical approval_id. Without
        # this the loan-desk example's "AWAITING APPROVAL: <id>" prompt
        # would never fire — the only logs in the polling loop are
        # `logger.debug` on individual poll errors. INFO so default-
        # configured loggers actually surface it (R3 R3 HIGH-3).
        logger.info(
            "axonflow hitl AWAITING APPROVAL: request_id=%s; approve via "
            "POST /api/v1/hitl/queue/%s/{approve|reject} (poll_interval=%.1fs, "
            "max_wait=%.0fs)",
            request_id,
            request_id,
            self._config.approval_poll_interval_seconds,
            self._config.approval_max_wait_seconds,
        )
        deadline = time.monotonic() + self._config.approval_max_wait_seconds
        client = await self._get_client()
        # R3 R2 FINDING 3 — HITL polling failures MUST NOT share the
        # global breaker counter. Otherwise a single misconfigured
        # approval gate (e.g. polling against a platform that doesn't
        # create the HITL row on `pre_check`) trips the breaker OPEN
        # and disables governance for every OTHER in-flight call across
        # the Runner. Use a local counter + raw call with timeout, and
        # leave the global breaker reflecting only the AxonFlow agent's
        # actual availability.
        consecutive_poll_failures = 0
        while time.monotonic() < deadline:
            try:
                req = await asyncio.wait_for(
                    client.get_hitl_request(request_id),
                    timeout=self._config.call_timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.debug("axonflow hitl poll for %s timed out", request_id)
                consecutive_poll_failures += 1
                req = None
            except Exception as exc:  # noqa: BLE001 - boundary
                logger.debug("axonflow hitl poll for %s failed: %s", request_id, exc)
                consecutive_poll_failures += 1
                req = None
            if req is None:
                # Bail early on a sustained outage so the agent doesn't
                # hang for the full approval_max_wait_seconds when the
                # platform is clearly unreachable / the HITL row never
                # gets created.
                if consecutive_poll_failures >= self._config.breaker_failure_threshold:
                    logger.warning(
                        "axonflow hitl poll for %s denied: %d consecutive failures",
                        request_id,
                        consecutive_poll_failures,
                    )
                    return False
                await asyncio.sleep(self._config.approval_poll_interval_seconds)
                continue
            consecutive_poll_failures = 0
            status = (getattr(req, "status", "") or "").lower()
            if status == "approved":
                return True
            if status in ("rejected", "expired"):
                return False
            await asyncio.sleep(self._config.approval_poll_interval_seconds)
        logger.warning(
            "axonflow hitl poll for %s exceeded %.0fs; denying",
            request_id,
            self._config.approval_max_wait_seconds,
        )
        return False

    # ----- BasePlugin hooks ---------------------------------------------

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: genai_types.Content,
    ) -> genai_types.Content | None:
        """No-op in v1.

        Returning a non-None Content here REPLACES the user message — far
        too dangerous a side effect for a governance plugin. Audit of the
        user prompt happens at `before_model_callback` time via `pre_check`.
        Reserved for a future ADR if we add user-message redaction.
        """
        return None

    async def before_model_callback(
        self,
        *,
        callback_context: CallbackContext,
        llm_request: LlmRequest,
    ) -> LlmResponse | None:
        """Pre-check + (optionally) HITL-gate the LLM call.

        Returns:
            None        → allow (the framework proceeds to the real LLM call)
            LlmResponse → short-circuit (the agent sees this as the model output)
        """
        query = self._stringify_llm_request(llm_request)
        user_token = self._user_token(callback_context)
        context = {
            "framework": "google-adk",
            "agent_name": getattr(callback_context, "agent_name", None),
            "invocation_id": getattr(callback_context, "invocation_id", None),
            **self._config.extra_context,
        }
        # Stash the model name so the after_model audit can label the
        # provider correctly without having to re-parse LlmRequest later.
        model_name = getattr(llm_request, "model", None)
        if isinstance(model_name, str):
            self._set_state(callback_context, "last_model", model_name)
        self._set_state(callback_context, "call_start_monotonic", time.monotonic())

        async def _do_pre_check() -> Any:
            client = await self._get_client()
            return await client.pre_check(
                user_token=user_token,
                query=query,
                context=context,
            )

        result = await self._call_with_guard(
            "pre_check",
            _do_pre_check,
            fail_open=True,
        )
        if result is None:
            # Fail-open: AxonFlow unreachable or timed out.
            return None
        if getattr(result, "approved", False):
            # Stash context_id so the after_model audit can link to the
            # pre-check decision in AxonFlow's audit log.
            self._set_state(
                callback_context,
                "last_context_id",
                getattr(result, "context_id", None),
            )
            return None

        block_reason = getattr(result, "block_reason", None) or "blocked by policy"
        if self._is_approval_required_block_reason(block_reason):
            if not self._config.enable_hitl_polling:
                # Deny-fast mode — caller has set the flag explicitly to
                # OFF, opting out of the reviewer-driven flow. Host app
                # is expected to surface the deny + drive its own
                # workflow.
                logger.info(
                    "axonflow pre_check require_approval: denying (HITL polling disabled)",
                )
                return self._deny_llm_response(block_reason)
            # Step 2 — enqueue the HITL row. The platform's `pre_check`
            # gate sets BlockReason="require_approval" but does not
            # create the queue row itself; we own that step. For the
            # model path the SDK only surfaces policy IDs, so the name
            # column on the HITL row mirrors the ID.
            triggered_ids = getattr(result, "policies", None) or []
            triggered_tuples: list[tuple[str, str | None]] = [
                (pid, None) for pid in triggered_ids if isinstance(pid, str) and pid
            ]
            new_request_id = await self._create_hitl_row(
                client_id=self._effective_client_id(),
                user_id=user_token if user_token != self._config.default_user_token else None,
                original_query=query,
                request_type=self._config.request_type,
                request_context=context,
                block_reason=block_reason,
                triggered_policies=triggered_tuples,
            )
            if not new_request_id:
                logger.warning(
                    "axonflow pre_check require_approval: queue row creation "
                    "failed; denying (fail-closed)",
                )
                return self._deny_llm_response(block_reason)
            # Step 3 — poll the queue.
            approved = await self._await_hitl_decision(new_request_id)
            # Step 4 — resume or deny.
            if approved:
                self._set_state(callback_context, "last_context_id", new_request_id)
                return None
            return self._deny_llm_response(block_reason)
        return self._deny_llm_response(block_reason)

    async def after_model_callback(
        self,
        *,
        callback_context: CallbackContext,
        llm_response: LlmResponse,
    ) -> LlmResponse | None:
        """Audit the LLM response. Never blocks.

        Returning None tells ADK to use the unmodified `llm_response`.
        Output policy enforcement on model output is owned by the
        platform (separate ADR roadmap). Audit only here.
        """
        context_id = self._get_state(callback_context, "last_context_id")
        if not isinstance(context_id, str) or not context_id:
            # No pre-check ran (or pre-check failed open) — without a
            # context_id the audit endpoint will 400. Skip.
            return None
        response_summary = self._stringify_llm_response(llm_response)[:2000] or "<no-content>"
        model_name = self._get_state(callback_context, "last_model") or "unknown"
        start = self._get_state(callback_context, "call_start_monotonic")
        latency_ms = int((time.monotonic() - start) * 1000) if isinstance(start, float) else 0
        try:
            token_usage = self._extract_token_usage(llm_response)
        except Exception as exc:  # noqa: BLE001 - defensive: never break the agent
            logger.warning("axonflow token-usage extraction failed: %s", exc)
            token_usage = TokenUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0)
        provider = self._infer_provider(model_name)

        async def _do_audit() -> Any:
            client = await self._get_client()
            return await client.audit_llm_call(
                context_id=context_id,
                response_summary=response_summary,
                provider=provider,
                model=str(model_name),
                token_usage=token_usage,
                latency_ms=latency_ms,
            )

        # Audit failures must never break the agent.
        await self._call_with_guard("audit_llm_call", _do_audit, fail_open=True)
        return None

    @staticmethod
    def _extract_token_usage(llm_response: LlmResponse) -> TokenUsage:
        """Pull a `TokenUsage` from an ADK `LlmResponse`.

        ADK proxies the genai `usage_metadata` shape, which exposes
        `prompt_token_count`, `candidates_token_count`,
        `total_token_count`. When the upstream LLM did not report usage,
        we return zeros — `audit_llm_call` accepts that.

        R3 HIGH-5 — `TokenUsage` is imported at module scope so a stale
        / missing SDK can't surface here as an unguarded ImportError.
        """
        usage = getattr(llm_response, "usage_metadata", None)
        if usage is None:
            return TokenUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0)
        prompt = int(getattr(usage, "prompt_token_count", 0) or 0)
        completion = int(getattr(usage, "candidates_token_count", 0) or 0)
        total = int(getattr(usage, "total_token_count", 0) or (prompt + completion))
        return TokenUsage(
            prompt_tokens=prompt,
            completion_tokens=completion,
            total_tokens=total,
        )

    @staticmethod
    def _infer_provider(model_name: Any) -> str:
        """Best-effort provider label from the model name.

        ADK does not surface a separate `provider` field at this point in
        the callback. The audit endpoint just stores the string. When the
        name is ambiguous we fall back to `"google"` (the ADK default).
        """
        if not isinstance(model_name, str) or not model_name:
            return "google"
        lowered = model_name.lower()
        if "gemini" in lowered or "palm" in lowered:
            return "google"
        if "gpt" in lowered or "openai" in lowered:
            return "openai"
        if "claude" in lowered or "anthropic" in lowered:
            return "anthropic"
        if "bedrock" in lowered:
            return "bedrock"
        if "ollama" in lowered:
            return "ollama"
        return "google"

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> dict[str, Any] | None:
        """Check tool input. Returns `{"error": reason}` on deny."""
        tool_name = getattr(tool, "name", tool.__class__.__name__)
        user_token = self._user_token(tool_context)

        async def _do_check() -> Any:
            client = await self._get_client()
            return await client.check_tool_input(
                connector_type=self._config.tool_connector_type,
                statement=tool_name,
                operation="execute",
                parameters=tool_args,
                user_token=user_token,
                tenant_id=self._config.tenant_id,
            )

        result = await self._call_with_guard(
            "check_tool_input",
            _do_check,
            fail_open=True,
        )
        if result is None:
            return None
        if getattr(result, "allowed", False):
            self._set_state(
                tool_context,
                "last_decision_id",
                getattr(result, "decision_id", None),
            )
            return None

        block_reason = getattr(result, "block_reason", None) or "tool blocked by policy"
        if self._is_approval_required_block_reason(block_reason):
            if not self._config.enable_hitl_polling:
                logger.info(
                    "axonflow check_tool_input require_approval: denying (HITL polling disabled)",
                )
                return {"error": f"[AxonFlow] {block_reason}"}
            # Step 2 — enqueue the HITL row. The platform's
            # check_tool_input gate sets BlockReason="require_approval"
            # but does not create the queue row at that site; we own it.
            # `check_tool_input` surfaces `ExplainPolicy` matches with
            # both `policy_id` AND `policy_name`, so we plumb the name
            # through to the HITL row for reviewer readability (R3 R3
            # MEDIUM-1).
            triggered_tuples: list[tuple[str, str | None]] = []
            policy_matches = getattr(result, "policy_matches", None) or []
            for match in policy_matches:
                pid = getattr(match, "policy_id", None) or getattr(match, "id", None)
                if not isinstance(pid, str) or not pid:
                    continue
                pname = getattr(match, "policy_name", None) or getattr(match, "name", None)
                triggered_tuples.append((pid, pname if isinstance(pname, str) and pname else None))
            new_request_id = await self._create_hitl_row(
                client_id=self._effective_client_id(),
                user_id=user_token if user_token != self._config.default_user_token else None,
                original_query=f"tool: {tool_name}",
                request_type=self._config.tool_connector_type,
                request_context={"tool_name": tool_name, "tool_args": self._safe_input_dict(tool_args)},
                block_reason=block_reason,
                triggered_policies=triggered_tuples,
                severity=getattr(result, "risk_level", None),
            )
            if not new_request_id:
                logger.warning(
                    "axonflow check_tool_input require_approval: queue row "
                    "creation failed; denying (fail-closed)",
                )
                return {"error": f"[AxonFlow] {block_reason}"}
            # Step 3 — poll.
            approved = await self._await_hitl_decision(new_request_id)
            # Step 4 — resume or deny.
            if approved:
                self._set_state(tool_context, "last_decision_id", new_request_id)
                return None
            return {"error": f"[AxonFlow] {block_reason}"}
        return {"error": f"[AxonFlow] {block_reason}"}

    async def after_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Check tool output. Returns redacted dict on PII; None on pass."""
        tool_name = getattr(tool, "name", tool.__class__.__name__)
        user_token = self._user_token(tool_context)
        # ADK tool results are arbitrary JSON-serializable dicts. We pass
        # the result through `message=` so the platform's content-safety
        # + PII redaction passes can scan it. Row-shaped results (e.g.
        # SQL connectors) should go through the connector-typed MCP
        # check-output path instead — that is a separate integration.
        try:
            result_text = json.dumps(result, default=str)[:8000]
        except (TypeError, ValueError):
            result_text = str(result)[:8000]

        async def _do_check() -> Any:
            client = await self._get_client()
            return await client.check_tool_output(
                connector_type=self._config.tool_connector_type,
                message=result_text,
                metadata={"tool_name": tool_name},
                user_token=user_token,
                tenant_id=self._config.tenant_id,
            )

        check = await self._call_with_guard(
            "check_tool_output",
            _do_check,
            fail_open=True,
        )
        if check is None:
            return None
        if getattr(check, "allowed", False):
            return None

        # Platform redacted the output. R3 HIGH-8: preserve the original
        # typed dict shape as much as possible. The platform's
        # `redacted_message` field is the same payload as we sent in but
        # with PII spans masked — when that is the JSON we serialized, we
        # round-trip it back to a dict so downstream tool chaining still
        # sees the same key structure (with redacted values). When it
        # isn't parseable (the platform returned a non-JSON string), we
        # fall back to the wrapper shape and tag the redaction.
        redacted_message = getattr(check, "redacted_message", None)
        block_reason = getattr(check, "block_reason", None) or "output blocked by policy"
        if redacted_message is None:
            return {"error": f"[AxonFlow] {block_reason}"}
        if isinstance(redacted_message, str):
            # R3 R2 FINDING 2 — broaden the exception scope. `TypeError`/
            # `ValueError` cover well-formed-but-not-JSON inputs, but
            # pathologically nested payloads can raise `RecursionError`
            # (a subclass of Exception, not of ValueError) and we must
            # not crash the agent on a buggy platform release.
            try:
                parsed = json.loads(redacted_message)
            except Exception as exc:  # noqa: BLE001 - boundary defense
                logger.warning(
                    "axonflow redacted_message JSON parse failed: %s; "
                    "falling back to wrapper shape",
                    exc,
                )
                parsed = None
            if isinstance(parsed, dict):
                # Preserve typed shape so the model sees the same keys.
                parsed["_axonflow_redacted"] = True
                return parsed
            return {"result": redacted_message, "_axonflow_redacted": True}
        # Some platform builds return a dict directly.
        if isinstance(redacted_message, dict):
            out: dict[str, Any] = dict(redacted_message)
            out["_axonflow_redacted"] = True
            return out
        return {"result": redacted_message, "_axonflow_redacted": True}

    async def on_tool_error_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        error: Exception,
    ) -> dict[str, Any] | None:
        """Audit tool errors. Never blocks."""
        tool_name = getattr(tool, "name", tool.__class__.__name__)
        user_token = self._user_token(tool_context)
        scrubbed = self._safe_input_dict(tool_args)
        if scrubbed and self._config.argument_redactor is not None:
            try:
                scrubbed = self._config.argument_redactor(scrubbed)
            except Exception as exc:  # noqa: BLE001 - never break audit
                logger.warning("axonflow argument_redactor failed: %s", exc)
        try:
            request = AuditToolCallRequest(
                tool_name=tool_name,
                tool_type="adk-tool",
                input=scrubbed,
                user_id=user_token,
                success=False,
                error_message=str(error)[:2000],
            )
        except Exception as exc:  # noqa: BLE001 - SDK shape drift tolerated
            logger.warning(
                "axonflow AuditToolCallRequest construction failed: %s; skipping audit", exc
            )
            return None

        async def _do_audit() -> Any:
            client = await self._get_client()
            return await client.audit_tool_call(request=request)

        await self._call_with_guard("audit_tool_call", _do_audit, fail_open=True)
        return None

    @staticmethod
    def _safe_input_dict(args: Any) -> dict[str, Any] | None:
        """Coerce tool_args into a dict for AuditToolCallRequest.input.

        ADK passes positional/keyword args through `tool_args` as a dict
        most of the time, but we accept Pydantic models and namespaces too.
        """
        if isinstance(args, dict):
            return args
        if hasattr(args, "model_dump"):
            try:
                dumped = args.model_dump()
                return dumped if isinstance(dumped, dict) else None
            except Exception:  # noqa: BLE001
                return None
        if hasattr(args, "__dict__"):
            return {k: v for k, v in vars(args).items() if not k.startswith("_")}
        return None

    # ----- State helpers ------------------------------------------------
    #
    # All plugin bookkeeping keys are prefixed with `_STATE_PREFIX`
    # (= `"temp:_axonflow_"`). The `temp:` segment is ADK's documented
    # convention for non-persistent session state (per
    # google.adk.sessions.state.TEMP_PREFIX), so these keys do NOT leak
    # across invocations or persist long-term — R3 MEDIUM-6.

    @staticmethod
    def _set_state(ctx: Any, suffix: str, value: Any) -> None:
        state = getattr(ctx, "state", None)
        if state is None:
            return
        key = _STATE_PREFIX + suffix
        try:
            state[key] = value
        except (TypeError, KeyError):
            # `state` is a model-like with attribute access, not a Mapping.
            setattr(state, key, value)

    @staticmethod
    def _get_state(ctx: Any, suffix: str) -> Any:
        state = getattr(ctx, "state", None)
        if state is None:
            return None
        key = _STATE_PREFIX + suffix
        try:
            return state.get(key)
        except AttributeError:
            return getattr(state, key, None)
