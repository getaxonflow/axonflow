"""AxonFlow Decision Mode client for the MCP-server PEP example.

This module is the thin client an MCP server uses to call AxonFlow as a
Policy Decision Point (PDP). The MCP server is the Policy Enforcement Point
(PEP): it calls ``decide()`` *before* returning any data to Claude, then
enforces the verdict (deny / apply obligations) on its side.

Decision API contract (source of truth: ``platform/agent/decision_handler.go``):

  POST /api/v1/decide
  Request:
    {
      "stage": "tool",                       # llm | tool | agent
      "caller_identity": {
        "gateway_id": "mcp-decision-mode-<tool>",
        "tenant_id":  "<tenant>"
      },
      "target":  {"type": "tool", "tool": "<tool>"},
      "query":   "<text the PDP evaluates>",
      "context": {"x-ai-agent": "...", ...}  # forwarded identity headers
    }
  Response (HTTP 200):
    {
      "verdict": "allow" | "deny" | "needs_approval",
      "decision_id": "<uuid>",
      "trace_id": "<32-hex>",
      "reasons": [...],
      "obligations": [{"type": "redact_pii", "detail": "..."}],
      "evaluated_policies": [...],
      "stage": "tool",
      "expires_at": "<rfc3339>"
    }

Failure posture: a fintech PEP defaults to FAIL-CLOSED. When the PDP cannot
be reached (network error, timeout, or 5xx), ``decide()`` raises
``PolicyUnavailable`` so the MCP server blocks the tool call rather than
returning ungoverned data. Set ``fail_closed=False`` (or env
``MCP_FAIL_CLOSED=false``) only for non-regulated, availability-first paths.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field

import httpx

DECIDE_PATH = "/api/v1/decide"

VERDICT_ALLOW = "allow"
VERDICT_DENY = "deny"
VERDICT_NEEDS_APPROVAL = "needs_approval"

# Valid stages mirror ADR-056 / isValidStage() in decision_handler.go.
VALID_STAGES = ("llm", "tool", "agent")


@dataclass
class NeedsApproval:
    """Returned when the PDP verdict is ``needs_approval``.

    A value (rather than an exception) because needs_approval is not an error:
    the MCP server should pause and route to a human approver, then resume.
    Detected with ``isinstance(result, NeedsApproval)``.

    It carries the decision identity (decision_id, trace_id, evaluated_policies)
    so the PEP writes a COMPLETE audit row for the paused call. Those are exactly
    the decisions a reviewer must later correlate in the SIEM, so dropping the
    decision_id here would blind the review trail.
    """

    decision_id: str = ""
    trace_id: str = ""
    evaluated_policies: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @classmethod
    def from_result(cls, result: DecideResult) -> NeedsApproval:
        return cls(
            decision_id=result.decision_id,
            trace_id=result.trace_id,
            evaluated_policies=list(result.evaluated_policies),
            reasons=list(result.reasons),
        )


@dataclass
class DecideResult:
    """Parsed verdict from POST /api/v1/decide."""

    verdict: str
    decision_id: str
    trace_id: str
    reasons: list[str] = field(default_factory=list)
    obligations: list[dict] = field(default_factory=list)
    evaluated_policies: list[str] = field(default_factory=list)
    stage: str = ""
    # RFC 3339 cache TTL the PDP offers; a PEP MAY cache the verdict until then.
    expires_at: str = ""
    duration_ms: int = 0

    @property
    def requires_redaction(self) -> bool:
        """True when an allow verdict carries a redact_pii obligation."""
        return any(o.get("type") == "redact_pii" for o in self.obligations)


class PolicyDenied(Exception):
    """Raised when the PDP returns verdict=deny for a real decision.

    Carries the full ``DecideResult`` so the PEP can still write a complete
    audit row (decision_id, evaluated_policies) for the blocked call.
    """

    def __init__(self, result: DecideResult):
        self.result = result
        reason = result.reasons[0] if result.reasons else "policy_denied"
        super().__init__(f"Policy denied: {reason} (decision_id={result.decision_id})")


class PolicyUnavailable(Exception):
    """Raised when the PDP could not be reached and fail-closed is in effect.

    This is the fail-closed posture: an unreachable or degraded PDP blocks
    the tool call. ``detail`` describes the underlying transport failure.
    """

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(f"Policy decision point unavailable (fail-closed): {detail}")


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    """Build the HTTP Basic auth header value the same way the SDK does."""
    raw = f"{client_id}:{client_secret}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def build_decide_request(
    *,
    stage: str,
    query: str,
    tool: str,
    tenant_id: str,
    context: dict | None = None,
) -> dict:
    """Build the POST /api/v1/decide request body (pure, unit-testable).

    ``gateway_id`` is per-tool (``mcp-decision-mode-<tool>``) so the AxonFlow
    audit trail attributes each decision to the specific MCP tool that issued
    it, not a single shared constant.
    """
    if stage not in VALID_STAGES:
        raise ValueError(f"stage must be one of {VALID_STAGES}, got {stage!r}")
    body: dict = {
        "stage": stage,
        "caller_identity": {
            "gateway_id": f"mcp-decision-mode-{tool}",
            "tenant_id": tenant_id,
        },
        "target": {"type": "tool", "tool": tool},
        "query": query,
    }
    if context:
        body["context"] = context
    return body


def parse_decide_response(body: dict, *, duration_ms: int = 0) -> DecideResult:
    """Map a decode-decided JSON body onto a DecideResult (pure function).

    Always returns a result; it does NOT raise on deny. The caller (decide())
    decides whether deny becomes a PolicyDenied exception. Defensive against a
    body missing the always-present fields so a malformed PDP response can't
    crash the PEP.
    """
    return DecideResult(
        verdict=body.get("verdict", VERDICT_DENY),
        decision_id=body.get("decision_id", ""),
        trace_id=body.get("trace_id", ""),
        reasons=list(body.get("reasons") or []),
        obligations=list(body.get("obligations") or []),
        evaluated_policies=list(body.get("evaluated_policies") or []),
        stage=body.get("stage", ""),
        expires_at=body.get("expires_at", ""),
        duration_ms=duration_ms,
    )


class AxonFlowDecideClient:
    """Calls AxonFlow Decision Mode as a Policy Decision Point.

    Both a synchronous ``decide()`` and an async ``decide_async()`` are
    provided so the client drops into either an asyncio MCP server (the
    common case) or a synchronous integration. Both share the same request
    building, response parsing, retry, and fail-open/closed posture.
    """

    def __init__(
        self,
        *,
        agent_url: str,
        client_id: str,
        client_secret: str,
        tenant_id: str,
        timeout: float = 5.0,
        fail_closed: bool = True,
    ):
        self.agent_url = agent_url.rstrip("/")
        self.tenant_id = tenant_id
        self.timeout = timeout
        self.fail_closed = fail_closed
        self._headers = {
            "Authorization": _basic_auth_header(client_id, client_secret),
            "Content-Type": "application/json",
        }

    @property
    def _url(self) -> str:
        return f"{self.agent_url}{DECIDE_PATH}"

    def _resolve(self, result: DecideResult):
        """Turn a parsed verdict into the public return/raise contract."""
        if result.verdict == VERDICT_DENY:
            raise PolicyDenied(result)
        if result.verdict == VERDICT_NEEDS_APPROVAL:
            return NeedsApproval.from_result(result)
        return result

    def _on_transport_failure(self, detail: str) -> DecideResult:
        """Apply the configured posture when the PDP can't be reached.

        Fail-closed (default) raises PolicyUnavailable so the tool is blocked.
        Fail-open returns a synthetic allow so availability is preserved; the
        synthetic result is tagged in ``reasons`` so the audit row records
        that the allow was a fallback, not a real PDP decision.
        """
        if self.fail_closed:
            raise PolicyUnavailable(detail)
        return DecideResult(
            verdict=VERDICT_ALLOW,
            decision_id="",
            trace_id="",
            reasons=[f"pdp_unavailable_fail_open: {detail}"],
        )

    # -- synchronous -------------------------------------------------------
    def decide(
        self,
        *,
        stage: str,
        query: str,
        tool: str,
        context: dict | None = None,
    ):
        """Synchronous decision call. Retries once on a network error."""
        body = build_decide_request(
            stage=stage, query=query, tool=tool, tenant_id=self.tenant_id, context=context
        )
        start = time.monotonic()
        last_err = ""
        # One client reused across the initial try + one retry (avoids paying
        # connection-pool setup twice when the PDP is slow/unreachable).
        with httpx.Client(timeout=self.timeout) as client:
            for _ in range(2):  # initial try + one retry on a network error
                try:
                    resp = client.post(self._url, json=body, headers=self._headers)
                    return self._handle_http(resp, start)
                except httpx.HTTPError as exc:
                    last_err = f"{type(exc).__name__}: {exc}"
        return self._on_transport_failure(last_err)

    # -- asynchronous ------------------------------------------------------
    async def decide_async(
        self,
        *,
        stage: str,
        query: str,
        tool: str,
        context: dict | None = None,
    ):
        """Async decision call. Retries once on a network error."""
        body = build_decide_request(
            stage=stage, query=query, tool=tool, tenant_id=self.tenant_id, context=context
        )
        start = time.monotonic()
        last_err = ""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for _ in range(2):  # initial try + one retry on a network error
                try:
                    resp = await client.post(self._url, json=body, headers=self._headers)
                    return self._handle_http(resp, start)
                except httpx.HTTPError as exc:
                    last_err = f"{type(exc).__name__}: {exc}"
        return self._on_transport_failure(last_err)

    def _handle_http(self, resp: httpx.Response, start: float):
        """Shared HTTP-status handling for both sync and async paths."""
        duration_ms = int((time.monotonic() - start) * 1000)
        # 5xx == PDP degraded (circuit breaker / dependency failure). Treated
        # as unavailable and handed to the configured fail-open/closed posture
        # WITHOUT a retry — a degraded PDP should not be hammered, and the
        # network-error retry above already covers transient connectivity.
        # ADR-056 §Components: the PEP owns the posture.
        if resp.status_code >= 500:
            return self._on_transport_failure(f"HTTP {resp.status_code} from PDP")
        try:
            payload = resp.json()
        except ValueError:
            return self._on_transport_failure(f"non-JSON PDP response (HTTP {resp.status_code})")
        # 4xx == PEP misconfiguration (bad auth, tenant mismatch, bad body).
        # This is not a policy decision; treat it as fail-closed so a
        # misconfigured gateway never silently returns ungoverned data.
        if resp.status_code >= 400:
            err = payload.get("error", f"HTTP {resp.status_code}")
            return self._on_transport_failure(f"PDP rejected request: {err}")
        return self._resolve(parse_decide_response(payload, duration_ms=duration_ms))
