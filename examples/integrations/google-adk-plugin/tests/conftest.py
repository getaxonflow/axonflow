# Copyright 2026 AxonFlow
# SPDX-License-Identifier: Apache-2.0

"""Shared test fixtures.

The unit tests in this directory stub out both `google-adk` and `axonflow`
at the boundary, so they run without either dependency installed. This is
deliberate: the plugin module itself does have hard imports of those
libraries (per the canonical pattern), but the tests exercise the
plugin's *logic* (deny path, circuit breaker, HITL polling) by injecting
a fake `AxonFlow` client and constructing minimal stub objects for
`CallbackContext` / `ToolContext` / `LlmRequest` / `LlmResponse`.

If `google-adk` is installed, these tests still pass — they only depend
on the shape of the values the plugin extracts from those objects
(`.state`, `.contents`, `.usage_metadata`).
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest


def _install_minimal_genai_stub() -> None:
    """Provide the small subset of `google.genai.types` the plugin uses.

    If the real `google-genai` package is installed, leave it alone — the
    plugin will use the canonical types. Otherwise stub with attribute-
    holding namespaces that match the attribute shape (`role`, `parts[].text`).
    """
    if "google.genai" in sys.modules:
        return
    google = sys.modules.setdefault("google", types.ModuleType("google"))
    genai = types.ModuleType("google.genai")
    google.genai = genai
    sys.modules["google.genai"] = genai

    genai_types = types.ModuleType("google.genai.types")

    class Part:
        def __init__(self, text: str | None = None) -> None:
            self.text = text

    class Content:
        def __init__(self, role: str | None = None, parts: list[Part] | None = None) -> None:
            self.role = role
            self.parts = parts or []

    genai_types.Part = Part
    genai_types.Content = Content
    sys.modules["google.genai.types"] = genai_types
    genai.types = genai_types


def _install_minimal_adk_stub() -> None:
    """Provide stubs for `google.adk.plugins.base_plugin.BasePlugin` and
    `google.adk.models.llm_response.LlmResponse` if ADK isn't installed."""
    if "google.adk" in sys.modules:
        return
    google = sys.modules.setdefault("google", types.ModuleType("google"))
    adk = types.ModuleType("google.adk")
    google.adk = adk
    sys.modules["google.adk"] = adk

    plugins_pkg = types.ModuleType("google.adk.plugins")
    base_plugin_mod = types.ModuleType("google.adk.plugins.base_plugin")

    class BasePlugin:
        def __init__(self, name: str) -> None:
            self.name = name

    base_plugin_mod.BasePlugin = BasePlugin
    plugins_pkg.base_plugin = base_plugin_mod
    sys.modules["google.adk.plugins"] = plugins_pkg
    sys.modules["google.adk.plugins.base_plugin"] = base_plugin_mod

    models_pkg = types.ModuleType("google.adk.models")
    llm_response_mod = types.ModuleType("google.adk.models.llm_response")

    class LlmResponse:
        def __init__(self, content: Any = None, usage_metadata: Any = None) -> None:
            self.content = content
            self.usage_metadata = usage_metadata

    llm_response_mod.LlmResponse = LlmResponse
    models_pkg.llm_response = llm_response_mod
    sys.modules["google.adk.models"] = models_pkg
    sys.modules["google.adk.models.llm_response"] = llm_response_mod


def _install_minimal_axonflow_stub() -> None:
    """Stub `axonflow` + `axonflow.types` if the SDK isn't on sys.path.

    We only stub `AxonFlow` (so the constructor lazy-import works) and
    `TokenUsage` + `AuditToolCallRequest` (used inside the plugin). Tests
    that exercise hook logic always inject their own fake client via
    `from_client`, so the stub `AxonFlow` is never actually instantiated.
    """
    if "axonflow" in sys.modules:
        return
    axonflow_mod = types.ModuleType("axonflow")

    class AxonFlow:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise NotImplementedError("test stub — pass an explicit client via from_client()")

    axonflow_mod.AxonFlow = AxonFlow
    sys.modules["axonflow"] = axonflow_mod

    types_mod = types.ModuleType("axonflow.types")

    class TokenUsage:
        def __init__(
            self,
            prompt_tokens: int = 0,
            completion_tokens: int = 0,
            total_tokens: int = 0,
        ) -> None:
            self.prompt_tokens = prompt_tokens
            self.completion_tokens = completion_tokens
            self.total_tokens = total_tokens

    class AuditToolCallRequest:
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    types_mod.TokenUsage = TokenUsage
    types_mod.AuditToolCallRequest = AuditToolCallRequest
    sys.modules["axonflow.types"] = types_mod
    axonflow_mod.types = types_mod

    # axonflow.hitl stub — the plugin imports `HITLCreateInput` lazily
    # inside `_create_hitl_row` to keep the SDK import surface narrow.
    # We mirror the model attributes the plugin sets.
    hitl_mod = types.ModuleType("axonflow.hitl")

    class HITLCreateInput:
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    hitl_mod.HITLCreateInput = HITLCreateInput
    sys.modules["axonflow.hitl"] = hitl_mod
    axonflow_mod.hitl = hitl_mod


_install_minimal_genai_stub()
_install_minimal_adk_stub()
_install_minimal_axonflow_stub()


@pytest.fixture
def fake_client() -> Any:
    """A configurable fake AxonFlow SDK client.

    Tests set attributes (`pre_check_result`, `raise_on_pre_check`, etc.)
    to drive plugin behavior, then read `calls` to assert what the plugin
    did. All async methods are recorded in `calls` as
    `(method_name, kwargs)` tuples.
    """

    class _FakeClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, Any]]] = []
            self.pre_check_result: Any = None
            self.raise_on_pre_check: Exception | None = None
            self.pre_check_delay_seconds: float = 0.0
            self.check_tool_input_result: Any = None
            self.raise_on_check_tool_input: Exception | None = None
            self.check_tool_output_result: Any = None
            self.audit_llm_call_result: Any = None
            self.audit_tool_call_result: Any = None
            # HITL polling state: pop from front. Each entry is a status.
            self.hitl_status_queue: list[str] = []
            self.raise_on_get_hitl_request: Exception | None = None
            # HITL create-row state: the fake mints a new request_id on
            # each call so polling has something deterministic to track.
            # Set to None to simulate creation failure.
            self.create_hitl_response_id: str | None = "hitl-row-created-001"
            self.raise_on_create_hitl_request: Exception | None = None

        async def pre_check(self, **kwargs: Any) -> Any:
            import asyncio

            self.calls.append(("pre_check", kwargs))
            if self.pre_check_delay_seconds:
                await asyncio.sleep(self.pre_check_delay_seconds)
            if self.raise_on_pre_check:
                raise self.raise_on_pre_check
            return self.pre_check_result

        async def check_tool_input(self, **kwargs: Any) -> Any:
            self.calls.append(("check_tool_input", kwargs))
            if self.raise_on_check_tool_input:
                raise self.raise_on_check_tool_input
            return self.check_tool_input_result

        async def check_tool_output(self, **kwargs: Any) -> Any:
            self.calls.append(("check_tool_output", kwargs))
            return self.check_tool_output_result

        async def audit_llm_call(self, **kwargs: Any) -> Any:
            self.calls.append(("audit_llm_call", kwargs))
            return self.audit_llm_call_result

        async def audit_tool_call(self, request: Any) -> Any:
            self.calls.append(("audit_tool_call", {"request": request}))
            return self.audit_tool_call_result

        async def get_hitl_request(self, request_id: str) -> Any:
            self.calls.append(("get_hitl_request", {"request_id": request_id}))
            if self.raise_on_get_hitl_request:
                raise self.raise_on_get_hitl_request
            status = self.hitl_status_queue.pop(0) if self.hitl_status_queue else "pending"
            obj = types.SimpleNamespace(status=status, request_id=request_id)
            return obj

        async def create_hitl_request(self, *, request: Any = None, **kwargs: Any) -> Any:
            # Keyword-only signature (R3 R3 MEDIUM-2). Positional invocation
            # would TypeError before the plugin even gets to enqueue the
            # row — gives the test suite an enforceable cross-language
            # clone-discipline gate.
            self.calls.append(("create_hitl_request", {"request": request}))
            if self.raise_on_create_hitl_request:
                raise self.raise_on_create_hitl_request
            if self.create_hitl_response_id is None:
                raise RuntimeError("create_hitl_response_id=None (test-configured failure)")
            return types.SimpleNamespace(
                request_id=self.create_hitl_response_id,
                status="pending",
            )

    return _FakeClient()


@pytest.fixture
def callback_context() -> Any:
    """A minimal CallbackContext stand-in: just `state` (a dict) + agent_name."""
    return types.SimpleNamespace(
        state={},
        agent_name="test_agent",
        invocation_id="inv-test-1",
        user_id="",
    )


@pytest.fixture
def tool_context() -> Any:
    return types.SimpleNamespace(
        state={},
        agent_name="test_agent",
        invocation_id="inv-test-1",
        user_id="",
    )


@pytest.fixture
def llm_request_with_text() -> Any:
    """Stub `LlmRequest` exposing `.contents[].parts[].text` + `.model`."""
    from google.genai.types import Content, Part

    return types.SimpleNamespace(
        contents=[Content(role="user", parts=[Part(text="Approve $50,000 loan disbursement")])],
        model="gemini-2.0-flash",
    )


@pytest.fixture
def llm_response_with_text() -> Any:
    from google.adk.models.llm_response import LlmResponse
    from google.genai.types import Content, Part

    return LlmResponse(
        content=Content(role="model", parts=[Part(text="Disbursement initiated.")]),
        usage_metadata=types.SimpleNamespace(
            prompt_token_count=12,
            candidates_token_count=4,
            total_token_count=16,
        ),
    )


@pytest.fixture
def fake_tool() -> Any:
    return types.SimpleNamespace(name="disburse_payment")
