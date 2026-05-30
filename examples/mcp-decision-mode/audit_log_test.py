"""Unit tests for audit_log: hashing determinism + Layer 1 schema correctness."""

from __future__ import annotations

import json
from datetime import datetime

from audit_log import (
    LAYER1_REQUIRED_FIELDS,
    AuditLog,
    build_audit_row,
    hash_parameters,
)


def test_hash_parameters_is_deterministic_and_order_independent():
    a = hash_parameters({"region": "Jakarta", "month": "2026-05"})
    b = hash_parameters({"month": "2026-05", "region": "Jakarta"})
    assert a == b
    assert len(a) == 64  # sha256 hex


def test_hash_parameters_distinguishes_different_args():
    assert hash_parameters({"region": "Jakarta"}) != hash_parameters({"region": "Surabaya"})


def test_build_audit_row_has_all_layer1_fields():
    row = build_audit_row(
        session_id="s",
        leader_email="leader@example.com",
        tool_name="get_merchant_count_by_region",
        parameters={"region": "Jakarta"},
        decision_id="dec",
        verdict="allow",
        evaluated_policies=["p"],
        response_record_count=1,
        duration_ms=7,
        ai_agent="claude-code",
        trace_id="tr",
    )
    for field in LAYER1_REQUIRED_FIELDS:
        assert field in row, f"Layer 1 field missing: {field}"
    # Correlation + Layer 2 fields the PoC scope adds.
    assert row["decision_id"] == "dec"
    assert row["verdict"] == "allow"
    assert row["evaluated_policies"] == ["p"]
    assert row["ai_agent"] == "claude-code"
    assert row["trace_id"] == "tr"


def test_build_audit_row_timestamp_is_iso8601():
    row = build_audit_row(
        session_id="s",
        leader_email="l",
        tool_name="t",
        parameters={},
        decision_id="",
        verdict="allow",
        evaluated_policies=[],
        response_record_count=0,
        duration_ms=0,
    )
    # Must parse as ISO 8601 with a timezone.
    parsed = datetime.fromisoformat(row["timestamp"])
    assert parsed.tzinfo is not None


def test_build_audit_row_parameters_hash_matches_helper():
    params = {"region": "Bandung"}
    row = build_audit_row(
        session_id="s",
        leader_email="l",
        tool_name="t",
        parameters=params,
        decision_id="",
        verdict="allow",
        evaluated_policies=[],
        response_record_count=0,
        duration_ms=0,
    )
    assert row["parameters_hash"] == hash_parameters(params)


def test_audit_log_record_appends_valid_jsonl(tmp_path):
    path = tmp_path / "audit_log.jsonl"
    log = AuditLog(str(path))
    log.record(
        session_id="s1",
        leader_email="l",
        tool_name="t",
        parameters={"region": "Medan"},
        decision_id="d1",
        verdict="allow",
        evaluated_policies=[],
        response_record_count=1,
        duration_ms=3,
    )
    log.record(
        session_id="s1",
        leader_email="l",
        tool_name="t",
        parameters={"region": "9999"},
        decision_id="d2",
        verdict="deny",
        evaluated_policies=["indonesia_pii_protection"],
        response_record_count=0,
        duration_ms=2,
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    rows = [json.loads(ln) for ln in lines]
    assert rows[0]["verdict"] == "allow"
    assert rows[1]["verdict"] == "deny"
    assert rows[1]["evaluated_policies"] == ["indonesia_pii_protection"]


def test_audit_log_record_returns_row(tmp_path):
    path = tmp_path / "sub" / "audit_log.jsonl"  # nested dir auto-created
    log = AuditLog(str(path))
    row = log.record(
        session_id="s",
        leader_email="l",
        tool_name="t",
        parameters={},
        decision_id="d",
        verdict="allow",
        evaluated_policies=[],
        response_record_count=0,
        duration_ms=0,
    )
    assert row["decision_id"] == "d"
    assert path.exists()
