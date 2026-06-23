"""Unit tests for decide_client: request building, parsing, error handling."""

from __future__ import annotations

import base64
import time

import httpx
import pytest

from decide_client import (
    AxonFlowDecideClient,
    DecideResult,
    NeedsApproval,
    PolicyDenied,
    PolicyUnavailable,
    _basic_auth_header,
    build_decide_request,
    parse_decide_response,
)


def _client(**kw) -> AxonFlowDecideClient:
    defaults = dict(
        agent_url="http://localhost:8080",
        client_id="cid",
        client_secret="secret",
        tenant_id="tid",
    )
    defaults.update(kw)
    return AxonFlowDecideClient(**defaults)


def test_basic_auth_header_matches_sdk_shape():
    header = _basic_auth_header("cid", "secret")
    assert header.startswith("Basic ")
    decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
    assert decoded == "cid:secret"


def test_build_decide_request_gateway_id_is_per_tool():
    body = build_decide_request(
        stage="tool", query="q", tool="get_merchant_count_by_region", tenant_id="tid"
    )
    assert body["caller_identity"]["gateway_id"] == "mcp-decision-mode-get_merchant_count_by_region"
    assert body["caller_identity"]["tenant_id"] == "tid"
    assert body["target"] == {"type": "tool", "tool": "get_merchant_count_by_region"}
    assert body["stage"] == "tool"
    assert "context" not in body  # omitted when not supplied


def test_build_decide_request_includes_context_when_supplied():
    body = build_decide_request(
        stage="tool", query="q", tool="t", tenant_id="tid", context={"x-ai-agent": "claude-code"}
    )
    assert body["context"] == {"x-ai-agent": "claude-code"}


def test_build_decide_request_rejects_invalid_stage():
    with pytest.raises(ValueError):
        build_decide_request(stage="bogus", query="q", tool="t", tenant_id="tid")


def test_parse_decide_response_maps_fields():
    result = parse_decide_response(
        {
            "verdict": "allow",
            "decision_id": "abc",
            "trace_id": "def",
            "reasons": ["r"],
            "obligations": [{"type": "redact_pii", "detail": "d"}],
            "evaluated_policies": ["p"],
            "stage": "tool",
            "expires_at": "2026-05-29T12:00:00Z",
        },
        duration_ms=12,
    )
    assert result.verdict == "allow"
    assert result.decision_id == "abc"
    assert result.requires_redaction is True
    assert result.duration_ms == 12
    assert result.expires_at == "2026-05-29T12:00:00Z"


def test_parse_decide_response_defensive_defaults():
    # A malformed body (missing everything) must not crash; defaults to deny.
    result = parse_decide_response({})
    assert result.verdict == "deny"
    assert result.reasons == []
    assert result.obligations == []
    assert result.requires_redaction is False


def test_resolve_deny_raises_with_full_result():
    client = _client()
    result = DecideResult(verdict="deny", decision_id="d1", trace_id="t1", reasons=["nope"], evaluated_policies=["pol"])
    with pytest.raises(PolicyDenied) as exc:
        client._resolve(result)
    assert exc.value.result.decision_id == "d1"
    assert exc.value.result.evaluated_policies == ["pol"]


def test_resolve_needs_approval_carries_decision_identity():
    client = _client()
    result = DecideResult(
        verdict="needs_approval", decision_id="d", trace_id="t",
        evaluated_policies=["pol"], reasons=["awaiting approver"],
    )
    resolved = client._resolve(result)
    assert isinstance(resolved, NeedsApproval)
    # The identity must survive so the paused call stays correlatable.
    assert resolved.decision_id == "d"
    assert resolved.trace_id == "t"
    assert resolved.evaluated_policies == ["pol"]


def test_resolve_allow_returns_result():
    client = _client()
    result = DecideResult(verdict="allow", decision_id="d", trace_id="t")
    assert client._resolve(result) is result


def test_handle_http_200_allow():
    client = _client()
    resp = httpx.Response(200, json={"verdict": "allow", "decision_id": "d", "trace_id": "t"})
    out = client._handle_http(resp, time.monotonic())
    assert out.verdict == "allow"


def test_handle_http_200_deny_raises():
    client = _client()
    resp = httpx.Response(
        200,
        json={"verdict": "deny", "decision_id": "d", "trace_id": "t", "reasons": ["pii"], "evaluated_policies": ["indonesia_pii_protection"]},
    )
    with pytest.raises(PolicyDenied):
        client._handle_http(resp, time.monotonic())


def test_handle_http_503_fail_closed():
    client = _client(fail_closed=True)
    resp = httpx.Response(503, json={"verdict": "deny"})
    with pytest.raises(PolicyUnavailable):
        client._handle_http(resp, time.monotonic())


def test_handle_http_503_fail_open_returns_synthetic_allow():
    client = _client(fail_closed=False)
    resp = httpx.Response(503, json={"verdict": "deny"})
    out = client._handle_http(resp, time.monotonic())
    assert out.verdict == "allow"
    assert out.reasons and out.reasons[0].startswith("pdp_unavailable_fail_open")


def test_handle_http_4xx_is_fail_closed_not_silent_allow():
    client = _client(fail_closed=True)
    resp = httpx.Response(403, json={"error": "tenant mismatch", "verdict": "deny"})
    with pytest.raises(PolicyUnavailable):
        client._handle_http(resp, time.monotonic())


def test_handle_http_non_json_fail_closed():
    client = _client(fail_closed=True)
    resp = httpx.Response(200, text="not json")
    with pytest.raises(PolicyUnavailable):
        client._handle_http(resp, time.monotonic())


def test_decide_unreachable_pdp_fail_closed():
    # Real connect-refused against a dead port -> retries once -> fail-closed.
    client = _client(agent_url="http://127.0.0.1:9", timeout=1.0, fail_closed=True)
    with pytest.raises(PolicyUnavailable):
        client.decide(stage="tool", query="q", tool="t")


def test_decide_unreachable_pdp_fail_open():
    client = _client(agent_url="http://127.0.0.1:9", timeout=1.0, fail_closed=False)
    out = client.decide(stage="tool", query="q", tool="t")
    assert out.verdict == "allow"
    assert out.decision_id == ""


async def test_decide_async_unreachable_pdp_fail_closed():
    client = _client(agent_url="http://127.0.0.1:9", timeout=1.0, fail_closed=True)
    with pytest.raises(PolicyUnavailable):
        await client.decide_async(stage="tool", query="q", tool="t")
