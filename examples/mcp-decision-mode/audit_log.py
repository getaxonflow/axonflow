"""Structured-JSON audit log writer (Risk Committee audit Layer 1).

Each governed MCP tool invocation writes exactly one JSON line to an append
-only ``audit_log.jsonl``. This is the PEP-side audit record that satisfies
**Layer 1** of a design partner's four-layer audit framework (MCP server logging).
It is produced locally by the MCP server, independent of whether AxonFlow
persists the forwarded context, so the example works end-to-end today.

The four layers, and where each is produced:

  Layer 1  MCP server logging .......... THIS FILE (audit_log.jsonl)
  Layer 2  X-AI-Agent header propagation  mcp_server.py forwards the headers
                                          in the decide() context map; the
                                          values land in the Layer 1 row
                                          (session_id, leader_email, ai_agent)
  Layer 3  BigQuery Cloud Audit Logs → SIEM   AxonFlow decision record
                                          (decision_id) lands in the SIEM and
                                          correlates by session_id (the design
                                          partner's GCP-side config)
  Layer 4  Anomaly alerts ............... SIEM's job once both feeds are in

Layer 1 schema (the Risk Committee's named field set) — every row carries,
at minimum:

    timestamp, session_id, leader_email, tool_name, parameters_hash,
    response_record_count, duration_ms

plus the AxonFlow correlation fields the PoC scope adds for joining to the
decision record: decision_id, verdict, evaluated_policies, and the
forwarded ai_agent identity (Layer 2 evidence).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

# Ordered Layer 1 field set. Kept as a constant so the unit tests assert the
# schema against a single source of truth (and a reviewer can see the exact
# Risk Committee field names in one place).
LAYER1_REQUIRED_FIELDS = (
    "timestamp",
    "session_id",
    "leader_email",
    "tool_name",
    "parameters_hash",
    "response_record_count",
    "duration_ms",
)


def hash_parameters(parameters: dict[str, Any]) -> str:
    """Return a deterministic sha256 hex digest of a tool's arguments.

    Canonicalized with sorted keys + compact separators so the same arguments
    always hash to the same value regardless of dict ordering. The PoC logs
    the *hash* (not the raw arguments) so the audit trail proves which call
    was made without persisting argument values that may carry PII.
    """
    canonical = json.dumps(parameters, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_audit_row(
    *,
    session_id: str,
    leader_email: str,
    tool_name: str,
    parameters: dict[str, Any],
    decision_id: str,
    verdict: str,
    evaluated_policies: list[str],
    response_record_count: int,
    duration_ms: int,
    ai_agent: str = "",
    trace_id: str = "",
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build one Layer 1 audit row (pure function, no I/O).

    ``timestamp`` defaults to the current UTC time in RFC 3339 / ISO 8601.
    Field order matches LAYER1_REQUIRED_FIELDS first, then the AxonFlow
    correlation fields, so the on-disk JSONL reads top-to-bottom as the
    Risk Committee schema.
    """
    return {
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "leader_email": leader_email,
        "tool_name": tool_name,
        "parameters_hash": hash_parameters(parameters),
        "response_record_count": response_record_count,
        "duration_ms": duration_ms,
        # AxonFlow decision correlation (join key to the SIEM decision record).
        "decision_id": decision_id,
        "verdict": verdict,
        "evaluated_policies": list(evaluated_policies),
        "trace_id": trace_id,
        # Layer 2 evidence: the AI-agent identity forwarded to the PDP.
        "ai_agent": ai_agent,
    }


class AuditLog:
    """Append-only JSONL audit writer for Layer 1 records."""

    def __init__(self, path: str):
        self.path = path

    def record(
        self,
        *,
        session_id: str,
        leader_email: str,
        tool_name: str,
        parameters: dict[str, Any],
        decision_id: str,
        verdict: str,
        evaluated_policies: list[str],
        response_record_count: int,
        duration_ms: int,
        ai_agent: str = "",
        trace_id: str = "",
    ) -> dict[str, Any]:
        """Write one audit row and return it (for testing / inline assertions)."""
        row = build_audit_row(
            session_id=session_id,
            leader_email=leader_email,
            tool_name=tool_name,
            parameters=parameters,
            decision_id=decision_id,
            verdict=verdict,
            evaluated_policies=evaluated_policies,
            response_record_count=response_record_count,
            duration_ms=duration_ms,
            ai_agent=ai_agent,
            trace_id=trace_id,
        )
        line = json.dumps(row, separators=(",", ":"))
        # One open-append-flush per row keeps the file durable + line-atomic
        # for the demo. A production sink would batch + ship to the central
        # store (OTel collector / S3 / BigQuery), but the row shape is the same.
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return row
