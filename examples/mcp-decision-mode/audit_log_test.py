"""Unit tests for audit_log: hashing determinism + Layer 1 schema correctness +
turnkey central-store shipping (success / sink-down / breaker / fail-open)."""

from __future__ import annotations

import json
from datetime import datetime

from audit_log import (
    LAYER1_REQUIRED_FIELDS,
    AuditLog,
    HTTPCentralStoreShipper,
    S3CentralStoreShipper,
    ShipperError,
    _CircuitBreaker,
    _object_key,
    build_audit_row,
    build_shipper_from_env,
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


# --- Central-store shipping -------------------------------------------------


class _FakeShipper:
    """Records shipped rows; can be made to fail to exercise the breaker."""

    name = "fake"

    def __init__(self, fail=False):
        self.fail = fail
        self.shipped = []

    def ship(self, row):
        if self.fail:
            raise ShipperError("sink down")
        self.shipped.append(row)


def _record(log, decision_id="d1", **over):
    args = dict(
        session_id="s",
        leader_email="l",
        tool_name="t",
        parameters={"region": "Jakarta"},
        decision_id=decision_id,
        verdict="allow",
        evaluated_policies=[],
        response_record_count=1,
        duration_ms=1,
    )
    args.update(over)
    return log.record(**args)


def test_record_ships_to_central_store_on_success(tmp_path):
    sink = _FakeShipper()
    log = AuditLog(str(tmp_path / "a.jsonl"), shipper=sink)
    _record(log, decision_id="dec-1")
    assert len(sink.shipped) == 1
    assert sink.shipped[0]["decision_id"] == "dec-1"
    assert log.shipped == 1 and log.ship_failures == 0


def test_record_is_durable_locally_even_when_shipper_down(tmp_path):
    path = tmp_path / "a.jsonl"
    sink = _FakeShipper(fail=True)
    log = AuditLog(str(path), shipper=sink)
    row = _record(log, decision_id="dec-2")
    # Tool path unaffected: the row is returned and written locally.
    assert row["decision_id"] == "dec-2"
    assert len(path.read_text().splitlines()) == 1
    # Ship failure is counted, not raised.
    assert log.shipped == 0 and log.ship_failures == 1


def test_breaker_opens_and_skips_after_threshold(tmp_path):
    sink = _FakeShipper(fail=True)
    log = AuditLog(str(tmp_path / "a.jsonl"), shipper=sink, breaker_threshold=3, breaker_cooldown_s=600)
    for i in range(6):
        _record(log, decision_id=f"d{i}")
    # First 3 attempts fail, then the breaker opens and short-circuits the rest.
    assert log.ship_failures == 3
    assert log.ship_skipped == 3
    # Every row is still durable locally.
    assert len(open(tmp_path / "a.jsonl").read().splitlines()) == 6


def test_breaker_state_machine_recovers():
    clock = {"t": 0.0}
    b = _CircuitBreaker(threshold=2, cooldown_s=10, clock=lambda: clock["t"])
    assert b.allow()
    b.record(False)
    assert b.allow()  # 1 failure, still closed
    b.record(False)   # 2nd failure trips it
    assert not b.allow()
    clock["t"] = 11   # cooldown elapsed
    assert b.allow()      # half-open probe admitted
    assert not b.allow()  # only ONE probe in flight (mirrors the Go breaker)
    b.record(True)    # probe succeeds -> closed
    assert b.allow()


def test_object_key_is_date_partitioned():
    row = {"timestamp": "2026-06-22T09:15:30+00:00", "decision_id": "dec-9"}
    assert _object_key("axonflow/decisions", row) == "axonflow/decisions/2026/06/22/dec-9.json"
    # Falls back gracefully on a bad timestamp / missing id. Missing decision_id
    # falls back to "unknown" (identical to the Go S3 sink, NOT session_id).
    assert _object_key("p", {"timestamp": "nope", "decision_id": "x"}) == "p/unpartitioned/x.json"
    assert _object_key("p", {"timestamp": "2026-06-22T00:00:00+00:00", "session_id": "sess"}) == "p/2026/06/22/unknown.json"


class _FakeS3Client:
    def __init__(self):
        self.puts = []

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        return {}


def test_s3_shipper_puts_ndjson_object():
    client = _FakeS3Client()
    shipper = S3CentralStoreShipper("audit-bucket", "axonflow/decisions", client=client)
    shipper.ship({"timestamp": "2026-06-22T00:00:00+00:00", "decision_id": "dec-7", "verdict": "deny"})
    assert len(client.puts) == 1
    put = client.puts[0]
    assert put["Bucket"] == "audit-bucket"
    assert put["Key"] == "axonflow/decisions/2026/06/22/dec-7.json"
    assert put["ContentType"] == "application/x-ndjson"
    assert put["Body"].endswith(b"\n")
    assert json.loads(put["Body"])["decision_id"] == "dec-7"


def test_s3_shipper_wraps_client_error():
    class _Boom:
        def put_object(self, **_):
            raise RuntimeError("AccessDenied")

    shipper = S3CentralStoreShipper("b", client=_Boom())
    try:
        shipper.ship({"decision_id": "d"})
        assert False, "expected ShipperError"
    except ShipperError as exc:
        assert "s3 put_object failed" in str(exc)


def test_s3_shipper_requires_bucket():
    try:
        S3CentralStoreShipper("", client=_FakeS3Client())
        assert False, "expected ValueError"
    except ValueError:
        pass


class _FakeResp:
    def __init__(self, status):
        self.status_code = status


class _FakeHTTPClient:
    def __init__(self, status=204):
        self.status = status
        self.posted = []

    def post(self, url, content=None, headers=None, timeout=None):
        self.posted.append({"url": url, "content": content, "headers": headers})
        return _FakeResp(self.status)


def test_http_shipper_posts_ndjson():
    client = _FakeHTTPClient(status=204)
    shipper = HTTPCentralStoreShipper("http://collector/v1/audit", client=client)
    shipper.ship({"decision_id": "dec-3", "verdict": "allow"})
    assert len(client.posted) == 1
    assert client.posted[0]["url"] == "http://collector/v1/audit"
    assert client.posted[0]["content"].endswith("\n")
    assert client.posted[0]["headers"]["Content-Type"] == "application/x-ndjson"


def test_http_shipper_raises_on_4xx_5xx():
    shipper = HTTPCentralStoreShipper("http://collector", client=_FakeHTTPClient(status=503))
    try:
        shipper.ship({"decision_id": "d"})
        assert False, "expected ShipperError"
    except ShipperError as exc:
        assert "503" in str(exc)


def test_http_shipper_requires_url():
    try:
        HTTPCentralStoreShipper("", client=_FakeHTTPClient())
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_build_shipper_from_env_disabled_by_default():
    assert build_shipper_from_env({}) is None
    assert build_shipper_from_env({"MCP_AUDIT_SINK": ""}) is None


def test_build_shipper_from_env_s3():
    s = build_shipper_from_env({"MCP_AUDIT_SINK": "s3", "MCP_AUDIT_S3_BUCKET": "bkt"})
    # boto3 may or may not be installed; if absent the build returns None (logged),
    # if present it returns an S3 shipper. Either way it must not raise.
    assert s is None or s.name == "s3"


def test_build_shipper_from_env_http():
    s = build_shipper_from_env({"MCP_AUDIT_SINK": "http", "MCP_AUDIT_HTTP_URL": "http://x/v1"})
    assert s is not None and s.name == "http"


def test_build_shipper_from_env_http_missing_url_disables():
    # Missing URL -> ValueError caught -> disabled (None), never raises.
    assert build_shipper_from_env({"MCP_AUDIT_SINK": "http"}) is None


def test_build_shipper_from_env_unknown_disables():
    assert build_shipper_from_env({"MCP_AUDIT_SINK": "kafka"}) is None
