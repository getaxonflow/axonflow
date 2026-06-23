#!/usr/bin/env python3
"""Runnable end-to-end demo of turnkey Layer-1 central-store shipping.

This proves the "Layer 3 is turnkey" claim without any cloud credentials or
network: it stands up a tiny in-process HTTP receiver (the stand-in for an OTel
collector's HTTP receiver / a BigQuery streaming-insert proxy), points an
``AuditLog`` at it via ``HTTPCentralStoreShipper``, records a couple of governed
tool calls, and shows that every Layer-1 row landed in BOTH the local JSONL
(source of truth) and the central store (the SIEM feed), keyed for correlation.

It also demonstrates the fail-open + circuit-breaker behavior: when the central
store is down, tool calls still succeed and rows are still written locally.

Run it:  python ship_audit_example.py
"""

from __future__ import annotations

import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from audit_log import AuditLog, HTTPCentralStoreShipper


class _Receiver(BaseHTTPRequestHandler):
    """Records every POSTed NDJSON body. Stands in for the central store."""

    received: list[dict] = []
    fail = False  # flip to simulate a down central store

    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        if type(self).fail:
            self.send_response(503)
            self.end_headers()
            return
        for line in body.splitlines():
            if line.strip():
                type(self).received.append(json.loads(line))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args):  # silence the default stderr access log
        pass


def _record_two_calls(audit: AuditLog) -> None:
    audit.record(
        session_id="sess-001",
        leader_email="leader@example.com",
        tool_name="get_merchant_count_by_region",
        parameters={"region": "Jakarta"},
        decision_id="dec-aaa-111",
        verdict="allow",
        evaluated_policies=["indonesia_pii_protection"],
        response_record_count=1,
        duration_ms=6,
        ai_agent="claude-code",
        trace_id="0af7651916cd43dd8448eb211c80319c",
    )
    audit.record(
        session_id="sess-001",
        leader_email="leader@example.com",
        tool_name="get_merchant_count_by_region",
        parameters={"region": "9999999999999999"},  # would carry a NIK in the real flow
        decision_id="dec-bbb-222",
        verdict="deny",
        evaluated_policies=["indonesia_pii_protection"],
        response_record_count=0,
        duration_ms=4,
        ai_agent="claude-code",
        trace_id="b9c7c989f97918e1f3c4d5a6b7e8f901",
    )


def main() -> int:
    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://{host}:{port}/v1/audit"

    failures = 0
    try:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit_log.jsonl"

            # --- Scenario 1: central store UP: rows land locally AND centrally
            shipper = HTTPCentralStoreShipper(url, timeout_s=2.0)
            audit = AuditLog(str(log_path), shipper=shipper)
            _Receiver.received = []
            _Receiver.fail = False
            _record_two_calls(audit)

            local_rows = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
            central_rows = _Receiver.received

            print("=== Scenario 1: central store UP ===")
            print(f"local JSONL rows  : {len(local_rows)}")
            print(f"central-store rows: {len(central_rows)}")
            print(f"shipped / failed / skipped: {audit.shipped} / {audit.ship_failures} / {audit.ship_skipped}")
            for r in central_rows:
                print(f"  shipped decision_id={r['decision_id']} verdict={r['verdict']} session_id={r['session_id']}")

            ok = (
                len(local_rows) == 2
                and len(central_rows) == 2
                and audit.shipped == 2
                and audit.ship_failures == 0
                and {r["decision_id"] for r in local_rows} == {r["decision_id"] for r in central_rows}
            )
            print(f"PASS scenario 1 (local == central, correlated on decision_id): {ok}")
            failures += 0 if ok else 1

            # --- Scenario 2: central store DOWN: fail-open, local rows still written
            _Receiver.fail = True
            log_path2 = Path(tmp) / "audit_log_2.jsonl"
            audit_down = AuditLog(str(log_path2), shipper=HTTPCentralStoreShipper(url, timeout_s=2.0))
            _record_two_calls(audit_down)
            local_rows2 = [json.loads(l) for l in log_path2.read_text().splitlines() if l.strip()]

            print("\n=== Scenario 2: central store DOWN (fail-open) ===")
            print(f"local JSONL rows  : {len(local_rows2)} (tool calls unaffected)")
            print(f"shipped / failed / skipped: {audit_down.shipped} / {audit_down.ship_failures} / {audit_down.ship_skipped}")
            ok2 = len(local_rows2) == 2 and audit_down.shipped == 0 and audit_down.ship_failures >= 1
            print(f"PASS scenario 2 (rows durable locally despite ship failure): {ok2}")
            failures += 0 if ok2 else 1
    finally:
        server.shutdown()
        server.server_close()

    print("\nALL PASS" if failures == 0 else f"\n{failures} SCENARIO(S) FAILED")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
