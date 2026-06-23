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

Layer 1 schema (the Risk Committee's named field set): every row carries,
at minimum:

    timestamp, session_id, leader_email, tool_name, parameters_hash,
    response_record_count, duration_ms

plus the AxonFlow correlation fields the PoC scope adds for joining to the
decision record: decision_id, verdict, evaluated_policies, and the
forwarded ai_agent identity (Layer 2 evidence).

Turnkey central-store shipping
------------------------------
The local JSONL is the durable Layer-1 record. To make **Layer 3** turnkey
rather than "a documented integration step", an ``AuditLog`` can additionally
ship each row to a central store (S3, or any OTel-collector / BigQuery HTTP
ingestion endpoint) so the row lands next to BigQuery Cloud Audit Logs and a
SIEM can join them on ``decision_id`` / ``session_id``. Set ``MCP_AUDIT_SINK``
(see ``build_shipper_from_env``) and a shipper is attached automatically.

Shipping is **best-effort and fail-open**: the local write is the source of
truth, so a central-store outage never blocks a tool call and never loses the
record (it stays in the JSONL for backfill). Each ship is bounded by a timeout
and guarded by a small circuit breaker so a dead sink stops costing latency.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Protocol

logger = logging.getLogger("axonflow.audit")

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


# ---------------------------------------------------------------------------
# Central-store shipping (Layer 3 turnkey hop)
# ---------------------------------------------------------------------------


class ShipperError(Exception):
    """Raised by a CentralStoreShipper when a single ship fails.

    The shipping wrapper catches this and counts it toward the circuit breaker;
    it is never propagated into the tool-call path.
    """


class CentralStoreShipper(Protocol):
    """A durable sink for Layer-1 rows. ``ship`` performs one synchronous send
    and raises ``ShipperError`` on failure; the AuditLog wraps it in a circuit
    breaker, so an implementation need not."""

    name: str

    def ship(self, row: dict[str, Any]) -> None: ...


class _CircuitBreaker:
    """Tiny consecutive-failure breaker mirroring the Go exporter's: after
    ``threshold`` failures it opens for ``cooldown`` seconds, short-circuiting
    ships so a dead sink stops costing latency. The clock is injectable for
    deterministic tests."""

    def __init__(self, threshold: int, cooldown_s: float, clock=time.monotonic):
        self._threshold = max(1, threshold)
        self._cooldown = max(0.0, cooldown_s)
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._probing = False  # a half-open probe is currently in flight

    def allow(self) -> bool:
        if self._opened_at is None:
            return True
        if self._clock() - self._opened_at >= self._cooldown:
            # Cooldown elapsed: admit exactly one probe (half-open), matching the
            # Go breaker. Every other caller is held until the probe reports back.
            if self._probing:
                return False
            self._probing = True
            return True
        return False

    def record(self, success: bool) -> None:
        self._probing = False
        if success:
            self._failures = 0
            self._opened_at = None
            return
        self._failures += 1
        if self._opened_at is not None:
            # A half-open probe failed: restart the cooldown.
            self._opened_at = self._clock()
        elif self._failures >= self._threshold:
            self._opened_at = self._clock()


def _object_key(prefix: str, row: dict[str, Any]) -> str:
    """Build a date-partitioned object key ``<prefix>/<YYYY>/<MM>/<DD>/<id>.json``
    matching the Go S3 sink exactly, so both producers land in one queryable
    layout. A missing decision_id falls back to ``"unknown"`` (identical to the
    Go sink) rather than to session_id, so the two never diverge."""
    partition = "unpartitioned"
    ts = row.get("timestamp")
    if isinstance(ts, str) and ts:
        try:
            partition = datetime.fromisoformat(ts).astimezone(timezone.utc).strftime("%Y/%m/%d")
        except ValueError:
            partition = "unpartitioned"
    ident = str(row.get("decision_id") or "unknown").strip() or "unknown"
    return f"{prefix.strip('/')}/{partition}/{ident}.json"


class S3CentralStoreShipper:
    """Ships each Layer-1 row to S3 as one NDJSON object, keyed by a date
    partition + decision_id. Mirrors the platform Go S3 sink so the central
    store has one consistent layout regardless of which side wrote the row.

    boto3 is an optional dependency: it is imported lazily so the example runs
    without it when no S3 sink is configured. The client is injectable for tests.
    """

    name = "s3"

    def __init__(self, bucket: str, prefix: str = "axonflow/decisions", *, client=None, timeout_s: float = 5.0):
        if not bucket:
            raise ValueError("S3 audit sink requires a bucket")
        self._bucket = bucket
        self._prefix = prefix or "axonflow/decisions"
        self._timeout_s = timeout_s
        if client is not None:
            self._client = client
        else:
            try:
                import boto3  # noqa: PLC0415 - lazy optional dependency
                from botocore.config import Config
            except ImportError as exc:  # pragma: no cover - exercised only without boto3
                raise ShipperError("boto3 is required for the s3 audit sink (pip install boto3)") from exc
            cfg = Config(connect_timeout=timeout_s, read_timeout=timeout_s, retries={"max_attempts": 1})
            self._client = boto3.client("s3", config=cfg)

    def ship(self, row: dict[str, Any]) -> None:
        body = (json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            self._client.put_object(
                Bucket=self._bucket,
                Key=_object_key(self._prefix, row),
                Body=body,
                ContentType="application/x-ndjson",
            )
        except Exception as exc:  # noqa: BLE001 - any boto/client error is a ship failure
            raise ShipperError(f"s3 put_object failed: {exc}") from exc


class HTTPCentralStoreShipper:
    """Ships each Layer-1 row as one NDJSON line over HTTP POST to a central
    store ingestion endpoint: an OTel collector's HTTP receiver, a BigQuery
    streaming-insert proxy / Cloud Function, or any log-ingest URL. Reuses the
    example's existing ``httpx`` dependency (no raw socket code).
    """

    name = "http"

    def __init__(self, url: str, *, headers: dict[str, str] | None = None, timeout_s: float = 5.0, client=None):
        if not url:
            raise ValueError("HTTP audit sink requires a URL")
        self._url = url
        self._headers = {"Content-Type": "application/x-ndjson", **(headers or {})}
        self._timeout_s = timeout_s
        self._client = client  # injectable for tests; else httpx is used per-call

    def ship(self, row: dict[str, Any]) -> None:
        body = json.dumps(row, separators=(",", ":")) + "\n"
        try:
            if self._client is not None:
                resp = self._client.post(self._url, content=body, headers=self._headers, timeout=self._timeout_s)
            else:
                import httpx  # noqa: PLC0415 - already a runtime dependency

                resp = httpx.post(self._url, content=body, headers=self._headers, timeout=self._timeout_s)
            status = resp.status_code
        except Exception as exc:  # noqa: BLE001 - network/timeout is a ship failure
            raise ShipperError(f"http post failed: {exc}") from exc
        if status >= 400:
            raise ShipperError(f"http post returned {status}")


def build_shipper_from_env(env: dict[str, str] | None = None) -> CentralStoreShipper | None:
    """Construct the central-store shipper selected by ``MCP_AUDIT_SINK``.

    Returns ``None`` (shipping disabled) when the var is empty/unset, the
    default, so the example's behavior is unchanged unless an operator opts in.
    A misconfigured sink logs a warning and returns ``None`` rather than raising,
    so a bad central-store config never blocks the MCP server from starting.

      MCP_AUDIT_SINK=s3    + MCP_AUDIT_S3_BUCKET[/_PREFIX]
      MCP_AUDIT_SINK=http  + MCP_AUDIT_HTTP_URL[/_HEADER (k=v, comma-separated)]
    """
    env = env if env is not None else os.environ
    kind = (env.get("MCP_AUDIT_SINK") or "").strip().lower()
    if not kind:
        return None
    try:
        timeout_s = float(env.get("MCP_AUDIT_SINK_TIMEOUT_MS", "5000")) / 1000.0
        if kind == "s3":
            return S3CentralStoreShipper(
                bucket=env.get("MCP_AUDIT_S3_BUCKET", "").strip(),
                prefix=env.get("MCP_AUDIT_S3_PREFIX", "axonflow/decisions").strip(),
                timeout_s=timeout_s,
            )
        if kind == "http":
            headers: dict[str, str] = {}
            raw_headers = env.get("MCP_AUDIT_HTTP_HEADER", "").strip()
            if raw_headers:
                for pair in raw_headers.split(","):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        headers[k.strip()] = v.strip()
            return HTTPCentralStoreShipper(
                url=env.get("MCP_AUDIT_HTTP_URL", "").strip(),
                headers=headers or None,
                timeout_s=timeout_s,
            )
        logger.warning("unknown MCP_AUDIT_SINK=%r (supported: s3, http); central-store shipping disabled", kind)
        return None
    except (ValueError, ShipperError) as exc:
        logger.warning("audit sink %r setup failed (%s): central-store shipping disabled", kind, exc)
        return None


class AuditLog:
    """Append-only JSONL audit writer for Layer 1 records.

    When a ``shipper`` is attached, each recorded row is also shipped to the
    central store (best-effort, after the durable local write). Shipping is
    bounded by a circuit breaker so a dead sink degrades gracefully.
    """

    def __init__(
        self,
        path: str,
        shipper: CentralStoreShipper | None = None,
        *,
        breaker_threshold: int = 5,
        breaker_cooldown_s: float = 30.0,
    ):
        self.path = path
        self.shipper = shipper
        self._breaker = _CircuitBreaker(breaker_threshold, breaker_cooldown_s)
        # Lightweight counters so a runnable example / test can assert behavior.
        self.shipped = 0
        self.ship_failures = 0
        self.ship_skipped = 0

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
        # One open-append-flush per row keeps the file durable + line-atomic.
        # The local JSONL is the source of truth; the central-store ship below
        # is an additional best-effort durable hop for the SIEM.
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        self._ship(row)
        return row

    def _ship(self, row: dict[str, Any]) -> None:
        """Best-effort central-store ship. Never raises into the caller: the row
        is already locally durable, so a shipping failure is logged and counted
        but never blocks the tool call."""
        if self.shipper is None:
            return
        if not self._breaker.allow():
            self.ship_skipped += 1
            return
        try:
            self.shipper.ship(row)
        except Exception as exc:  # noqa: BLE001 - fail-open: local row already written
            self._breaker.record(False)
            self.ship_failures += 1
            logger.warning(
                "central-store ship failed (sink=%s decision_id=%s): %s",
                getattr(self.shipper, "name", "?"),
                row.get("decision_id", ""),
                exc,
            )
            return
        self._breaker.record(True)
        self.shipped += 1
