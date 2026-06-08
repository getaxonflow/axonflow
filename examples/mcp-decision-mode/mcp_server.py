"""MCP server that uses AxonFlow Decision Mode as its Policy Decision Point.

This is a reference Policy Enforcement Point (PEP). Claude Code (on a leader's
laptop) calls this MCP server's tools over stdio. Before returning ANY data,
the server calls AxonFlow's ``POST /api/v1/decide`` (the PDP), then enforces
the verdict on its side:

    Claude Code  --stdio-->  MCP server (PEP)  --POST /api/v1/decide-->  AxonFlow (PDP)
                                   |                                         |
                                   |  <----------- verdict + obligations ----+
                                   |
                                   |  deny           -> refuse, return nothing
                                   |  needs_approval -> pause for human approver
                                   |  allow          -> apply obligations, return data
                                   v
                             internal system (stubbed: aggregated views only)
                                   |
                                   v
                             audit_log.jsonl  (Risk Committee Layer 1)

Phase 1 boundary: both tools return AGGREGATED counts only — no individual
merchant records, no KYC, no contact data — matching a design partner's controlled
-pilot data restriction.

Run it:  python mcp_server.py     (speaks MCP over stdio)
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from audit_log import AuditLog
from decide_client import (
    NEEDS_APPROVAL,
    AxonFlowDecideClient,
    PolicyDenied,
    PolicyUnavailable,
)

# --- Stubbed internal data (AGGREGATED ONLY — Phase 1 boundary) -------------
# Stand-in for the BigQuery aggregate-views / CRM merchant-status MCP servers
# in the PoC scope. Hardcoded so the example needs no external dependency.
_MERCHANT_COUNT_BY_REGION = {
    "jakarta": 12873,
    "surabaya": 6210,
    "bandung": 4488,
    "medan": 3127,
    "makassar": 2054,
}
_ONBOARDING_VELOCITY_BY_MONTH = {
    "2026-03": 1840,
    "2026-04": 2115,
    "2026-05": 2477,
}


def _merchant_count_by_region(region: str) -> tuple[str, int]:
    """Aggregated merchant count for a region. Returns (text, record_count)."""
    key = region.strip().lower()
    count = _MERCHANT_COUNT_BY_REGION.get(key)
    if count is None:
        known = ", ".join(sorted(_MERCHANT_COUNT_BY_REGION))
        return (f"No aggregated data for region '{region}'. Known regions: {known}.", 0)
    return (f"Region '{region}': {count} active merchants (aggregated count).", 1)


def _merchant_onboarding_velocity(month: str) -> tuple[str, int]:
    """Aggregated onboarding velocity for a month. Returns (text, record_count)."""
    key = month.strip()
    velocity = _ONBOARDING_VELOCITY_BY_MONTH.get(key)
    if velocity is None:
        known = ", ".join(sorted(_ONBOARDING_VELOCITY_BY_MONTH))
        return (f"No velocity data for month '{month}'. Known months: {known}.", 0)
    return (f"Onboarding velocity for {month}: {velocity} new merchants onboarded.", 1)


# Tool registry — a single source of truth so both server registration and
# the unit tests can assert the governed-tool set without duplication.
GOVERNED_TOOLS = ("get_merchant_count_by_region", "get_merchant_onboarding_velocity")


@dataclass
class LeaderSession:
    """The leader's MCP session identity, forwarded to the PDP as context.

    These three values are the Layer 2 audit evidence: they propagate to the
    PDP in the decide() context map (``x-ai-agent`` / ``x-session-id`` /
    ``x-leader-identity``) and land in the Layer 1 audit row.
    """

    session_id: str
    leader_email: str
    ai_agent: str = "claude-code"

    def context(self) -> dict:
        return {
            "x-ai-agent": self.ai_agent,
            "x-session-id": self.session_id,
            "x-leader-identity": self.leader_email,
        }


class Governor:
    """Wraps every tool call in a PDP decision + a Layer 1 audit record."""

    def __init__(self, client: AxonFlowDecideClient, audit: AuditLog, session: LeaderSession):
        self.client = client
        self.audit = audit
        self.session = session

    async def run_tool(self, tool_name: str, params: dict, produce) -> str:
        """Govern a single tool invocation end-to-end.

        ``produce`` is a zero-arg callable returning ``(text, record_count)``.
        It is only invoked on an allow verdict — denied / unavailable calls
        never touch the internal data.
        """
        start = time.monotonic()
        # The PDP evaluates this query text for PII / injection. Including the
        # raw argument values is what lets AxonFlow catch a NIK/NPWP smuggled
        # into a tool argument and deny the call.
        query = f"Tool {tool_name} called with arguments: {json.dumps(params, sort_keys=True)}"
        verdict = "error"
        decision_id = ""
        trace_id = ""
        evaluated_policies: list[str] = []
        record_count = 0
        reply = ""

        try:
            result = await self.client.decide_async(
                stage="tool", query=query, tool=tool_name, context=self.session.context()
            )
            if result is NEEDS_APPROVAL:
                verdict = "needs_approval"
                reply = (
                    f"⏳ Tool '{tool_name}' requires human approval before it can run. "
                    "The request has been queued for a Risk Committee approver. "
                    "No data was returned."
                )
            else:
                verdict = result.verdict  # "allow"
                decision_id = result.decision_id
                trace_id = result.trace_id
                evaluated_policies = result.evaluated_policies
                text, record_count = produce()
                if result.requires_redaction:
                    # PEP-side obligation enforcement: the PDP told us to redact
                    # PII before returning. The aggregated stubs carry none, so
                    # we annotate; a real PEP would run the masking here.
                    text += "  [obligation:redact_pii applied PEP-side]"
                reply = text
        except PolicyDenied as exc:
            verdict = "deny"
            decision_id = exc.result.decision_id
            trace_id = exc.result.trace_id
            evaluated_policies = exc.result.evaluated_policies
            reason = exc.result.reasons[0] if exc.result.reasons else "policy_denied"
            reply = (
                f"❌ Tool '{tool_name}' was blocked by AxonFlow policy "
                f"(decision_id={decision_id}): {reason}. "
                "The call was NOT executed and no data was returned."
            )
        except PolicyUnavailable as exc:
            # Fail-closed: the PDP could not be reached, so we block the call.
            verdict = "unavailable"
            reply = (
                f"❌ Tool '{tool_name}' was blocked: the AxonFlow policy decision "
                f"point is unavailable ({exc.detail}). Fail-closed posture means "
                "no ungoverned data is returned."
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on any unexpected error
            verdict = "error"
            reply = (
                f"❌ Tool '{tool_name}' was blocked by an unexpected error in the "
                f"policy gate ({type(exc).__name__}). Fail-closed: no data returned."
            )

        duration_ms = int((time.monotonic() - start) * 1000)
        self.audit.record(
            session_id=self.session.session_id,
            leader_email=self.session.leader_email,
            tool_name=tool_name,
            parameters=params,
            decision_id=decision_id,
            verdict=verdict,
            evaluated_policies=evaluated_policies,
            response_record_count=record_count,
            duration_ms=duration_ms,
            ai_agent=self.session.ai_agent,
            trace_id=trace_id,
        )
        return reply


def build_server(governor: Governor) -> FastMCP:
    """Construct the FastMCP server with both governed tools registered."""
    mcp = FastMCP("axonflow-mcp-decision-mode")

    @mcp.tool()
    async def get_merchant_count_by_region(region: str) -> str:
        """Return the aggregated count of active merchants in a region.

        Phase 1 boundary: aggregated count only — no individual merchant
        records. Every call is policy-checked by AxonFlow before data returns.
        """
        return await governor.run_tool(
            "get_merchant_count_by_region",
            {"region": region},
            lambda: _merchant_count_by_region(region),
        )

    @mcp.tool()
    async def get_merchant_onboarding_velocity(month: str) -> str:
        """Return the aggregated onboarding velocity for a month (YYYY-MM).

        Phase 1 boundary: aggregated velocity number only — no individual
        merchant records. Policy-checked by AxonFlow before data returns.
        """
        return await governor.run_tool(
            "get_merchant_onboarding_velocity",
            {"month": month},
            lambda: _merchant_onboarding_velocity(month),
        )

    return mcp


def build_from_env() -> FastMCP:
    """Build a server + governor from environment variables (see .env.example)."""
    fail_closed = os.environ.get("MCP_FAIL_CLOSED", "true").strip().lower() != "false"
    client = AxonFlowDecideClient(
        agent_url=os.environ.get("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.environ.get("AXONFLOW_CLIENT_ID", "mcp-decision-mode-demo"),
        client_secret=os.environ.get("AXONFLOW_CLIENT_SECRET", ""),
        tenant_id=os.environ.get("AXONFLOW_TENANT_ID", "mcp-decision-mode-demo"),
        fail_closed=fail_closed,
    )
    audit = AuditLog(os.environ.get("MCP_AUDIT_LOG_PATH", "audit_log.jsonl"))
    session = LeaderSession(
        session_id=os.environ.get("MCP_SESSION_ID", str(uuid.uuid4())),
        leader_email=os.environ.get("MCP_LEADER_EMAIL", "leader@example.com"),
    )
    return build_server(Governor(client, audit, session))


def main() -> None:
    # Load .env if python-dotenv is installed (optional convenience).
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass
    build_from_env().run(transport="stdio")


if __name__ == "__main__":
    main()
