"""Unit tests for mcp_server: tool registration, stubs, and the Governor paths."""

from __future__ import annotations

import json

from audit_log import AuditLog
from decide_client import NEEDS_APPROVAL, DecideResult, PolicyDenied, PolicyUnavailable
from mcp_server import (
    GOVERNED_TOOLS,
    Governor,
    LeaderSession,
    _merchant_count_by_region,
    _merchant_onboarding_velocity,
    build_from_env,
)


class _FakeClient:
    """Test double for AxonFlowDecideClient.decide_async."""

    def __init__(self, behavior):
        self._behavior = behavior
        self.last_context = None
        self.last_query = None

    async def decide_async(self, *, stage, query, tool, context=None):
        self.last_context = context
        self.last_query = query
        if isinstance(self._behavior, Exception):
            raise self._behavior
        if callable(self._behavior):
            return self._behavior()
        return self._behavior


def _governor(behavior, tmp_path) -> tuple[Governor, AuditLog, str]:
    audit_path = str(tmp_path / "audit_log.jsonl")
    audit = AuditLog(audit_path)
    session = LeaderSession(session_id="sess-1", leader_email="leader@example.com")
    gov = Governor(_FakeClient(behavior), audit, session)
    return gov, audit, audit_path


def _last_row(path: str) -> dict:
    return json.loads(open(path, encoding="utf-8").read().splitlines()[-1])


# --- tool registration coverage ---------------------------------------------
async def test_registered_tools_match_governed_set():
    server = build_from_env()
    listed = await server.list_tools()
    assert sorted(t.name for t in listed) == sorted(GOVERNED_TOOLS)


# --- data stubs (aggregated only) -------------------------------------------
def test_merchant_count_known_region_returns_one_record():
    text, count = _merchant_count_by_region("Jakarta")
    assert count == 1
    assert "active merchants" in text


def test_merchant_count_unknown_region_returns_zero_records():
    text, count = _merchant_count_by_region("Atlantis")
    assert count == 0
    assert "No aggregated data" in text


def test_onboarding_velocity_known_and_unknown():
    text, count = _merchant_onboarding_velocity("2026-05")
    assert count == 1 and "velocity" in text.lower()
    _, zero = _merchant_onboarding_velocity("1999-01")
    assert zero == 0


# --- Governor verdict paths --------------------------------------------------
async def test_governor_allow_returns_data_and_audits(tmp_path):
    result = DecideResult(verdict="allow", decision_id="dec-1", trace_id="tr-1", evaluated_policies=[])
    gov, _, path = _governor(result, tmp_path)
    reply = await gov.run_tool("get_merchant_count_by_region", {"region": "Jakarta"}, lambda: ("12 merchants", 1))
    assert "12 merchants" in reply
    row = _last_row(path)
    assert row["verdict"] == "allow"
    assert row["decision_id"] == "dec-1"
    assert row["response_record_count"] == 1


async def test_governor_allow_applies_redact_obligation(tmp_path):
    result = DecideResult(
        verdict="allow",
        decision_id="dec",
        trace_id="tr",
        obligations=[{"type": "redact_pii", "detail": "mask"}],
    )
    gov, _, _ = _governor(result, tmp_path)
    reply = await gov.run_tool("get_merchant_count_by_region", {"region": "Jakarta"}, lambda: ("data", 1))
    assert "redact_pii" in reply


async def test_governor_deny_blocks_and_audits(tmp_path):
    denied = PolicyDenied(
        DecideResult(
            verdict="deny",
            decision_id="dec-deny",
            trace_id="tr",
            reasons=["Critical Indonesia PII detected (NIK or NPWP)"],
            evaluated_policies=["indonesia_pii_protection"],
        )
    )
    produced = []
    gov, _, path = _governor(denied, tmp_path)
    reply = await gov.run_tool(
        "get_merchant_count_by_region",
        {"region": "3174042506780001"},
        lambda: (produced.append(1) or ("SHOULD NOT RUN", 1)),
    )
    assert "blocked" in reply.lower()
    assert produced == []  # data producer never invoked on deny
    row = _last_row(path)
    assert row["verdict"] == "deny"
    assert row["evaluated_policies"] == ["indonesia_pii_protection"]
    assert row["response_record_count"] == 0


async def test_governor_needs_approval(tmp_path):
    gov, _, path = _governor(NEEDS_APPROVAL, tmp_path)
    reply = await gov.run_tool("get_merchant_count_by_region", {"region": "Jakarta"}, lambda: ("d", 1))
    assert "approval" in reply.lower()
    assert _last_row(path)["verdict"] == "needs_approval"


async def test_governor_unavailable_fails_closed(tmp_path):
    gov, _, path = _governor(PolicyUnavailable("connect refused"), tmp_path)
    reply = await gov.run_tool("get_merchant_count_by_region", {"region": "Jakarta"}, lambda: ("d", 1))
    assert "blocked" in reply.lower() and "unavailable" in reply.lower()
    assert _last_row(path)["verdict"] == "unavailable"


async def test_governor_unexpected_error_fails_closed(tmp_path):
    gov, _, path = _governor(ValueError("boom"), tmp_path)
    reply = await gov.run_tool("get_merchant_count_by_region", {"region": "Jakarta"}, lambda: ("d", 1))
    assert "blocked" in reply.lower()
    assert _last_row(path)["verdict"] == "error"


async def test_governor_forwards_identity_context(tmp_path):
    result = DecideResult(verdict="allow", decision_id="d", trace_id="t")
    gov, _, _ = _governor(result, tmp_path)
    await gov.run_tool("get_merchant_count_by_region", {"region": "Jakarta"}, lambda: ("d", 1))
    ctx = gov.client.last_context
    assert ctx["x-ai-agent"] == "claude-code"
    assert ctx["x-session-id"] == "sess-1"
    assert ctx["x-leader-identity"] == "leader@example.com"


async def test_governor_query_includes_raw_args_for_pii_detection(tmp_path):
    result = DecideResult(verdict="allow", decision_id="d", trace_id="t")
    gov, _, _ = _governor(result, tmp_path)
    await gov.run_tool("get_merchant_count_by_region", {"region": "3174042506780001"}, lambda: ("d", 1))
    # The NIK must appear in the query text so the PDP can detect it.
    assert "3174042506780001" in gov.client.last_query


def test_leader_session_context_keys():
    ctx = LeaderSession(session_id="s", leader_email="e").context()
    assert set(ctx) == {"x-ai-agent", "x-session-id", "x-leader-identity"}
