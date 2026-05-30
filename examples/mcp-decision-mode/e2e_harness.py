"""End-to-end harness: drive the MCP server over stdio as a real MCP client.

This is the runtime-path test. It launches ``mcp_server.py`` as a subprocess,
speaks the MCP protocol over stdio exactly as Claude Code would, calls the
governed tools, and asserts both the tool reply AND the resulting Layer 1
audit row. It exits 0 only if every scenario passes.

Invoked by ``test_e2e.sh`` (which first checks AxonFlow is reachable on :8080).

Scenarios:
  1. Clean call           -> allow  + audit row written
  2. NIK in argument      -> deny   (indonesia_pii_protection) + audit row
  3. NPWP in argument     -> deny   (indonesia_pii_protection)
  4. Context forwarding   -> x-session-id / x-leader-identity / x-ai-agent
                             land in the audit row
  5. PDP unreachable       -> fail-closed block + audit row (verdict=unavailable)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "mcp_server.py")

# Test fixtures (same NIK/NPWP shapes the curl example uses).
NIK = "3174042506780001"
NPWP = "01.234.567.8-901.234"
SESSION_ID = "e2e-session-0001"
LEADER_EMAIL = os.environ.get("MCP_LEADER_EMAIL", "leader@example.com")
UNREACHABLE_URL = "http://127.0.0.1:9"  # nothing listens here -> connect error

_failures: list[str] = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    line = f"  [{status}] {name}"
    if detail:
        line += f" :: {detail}"
    print(line, flush=True)
    if not ok:
        _failures.append(name)


def _server_env(audit_path: str, agent_url: str | None = None) -> dict:
    """Build the subprocess environment for one server instance."""
    env = dict(os.environ)
    env["MCP_AUDIT_LOG_PATH"] = audit_path
    env["MCP_SESSION_ID"] = SESSION_ID
    env["MCP_LEADER_EMAIL"] = LEADER_EMAIL
    env["MCP_FAIL_CLOSED"] = "true"
    if agent_url is not None:
        env["AXONFLOW_AGENT_URL"] = agent_url
    return env


def _read_last_audit(audit_path: str) -> dict:
    with open(audit_path, encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    assert lines, f"no audit rows written to {audit_path}"
    return json.loads(lines[-1])


async def _call(session: ClientSession, tool: str, args: dict) -> str:
    result = await session.call_tool(tool, args)
    return "".join(getattr(c, "text", "") for c in result.content)


async def _run_against(audit_path: str, agent_url: str | None, body) -> None:
    """Open one stdio session to a fresh server instance and run ``body``."""
    params = StdioServerParameters(
        command=sys.executable, args=[SERVER], env=_server_env(audit_path, agent_url)
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await body(session)


async def main() -> int:
    audit_path = os.environ.get("MCP_AUDIT_LOG_PATH", os.path.join(HERE, "audit_log.jsonl"))
    # Start clean so the row assertions read only this run's output.
    if os.path.exists(audit_path):
        os.remove(audit_path)

    # --- Scenarios 1-4 run against the reachable PDP. ---------------------
    async def reachable(session: ClientSession) -> None:
        # Tool registration coverage (the runtime sees both governed tools).
        listed = await session.list_tools()
        names = sorted(t.name for t in listed.tools)
        _check(
            "tools advertised over stdio",
            names == ["get_merchant_count_by_region", "get_merchant_onboarding_velocity"],
            detail=str(names),
        )

        print("\n[1/5] Clean call (expect allow + data)")
        reply = await _call(session, "get_merchant_count_by_region", {"region": "Jakarta"})
        row = _read_last_audit(audit_path)
        _check("clean reply returns data", "active merchants" in reply, detail=reply)
        _check("clean reply not blocked", "blocked" not in reply.lower())
        _check("clean audit verdict=allow", row["verdict"] == "allow", detail=row["verdict"])
        _check("clean audit record_count=1", row["response_record_count"] == 1)

        print("\n[2/5] NIK in argument (expect deny)")
        reply = await _call(session, "get_merchant_count_by_region", {"region": NIK})
        row = _read_last_audit(audit_path)
        _check("NIK reply blocked", "blocked" in reply.lower(), detail=reply)
        _check("NIK audit verdict=deny", row["verdict"] == "deny", detail=row["verdict"])
        _check(
            "NIK policy=indonesia_pii_protection",
            "indonesia_pii_protection" in row["evaluated_policies"],
            detail=str(row["evaluated_policies"]),
        )
        _check("NIK audit record_count=0", row["response_record_count"] == 0)
        _check("NIK decision_id present", bool(row["decision_id"]), detail=row["decision_id"])

        print("\n[3/5] NPWP in argument (expect deny)")
        reply = await _call(session, "get_merchant_onboarding_velocity", {"month": NPWP})
        row = _read_last_audit(audit_path)
        _check("NPWP reply blocked", "blocked" in reply.lower(), detail=reply)
        _check("NPWP audit verdict=deny", row["verdict"] == "deny", detail=row["verdict"])
        _check(
            "NPWP policy=indonesia_pii_protection",
            "indonesia_pii_protection" in row["evaluated_policies"],
            detail=str(row["evaluated_policies"]),
        )

        print("\n[4/5] Context forwarding (x-session-id / x-leader-identity / x-ai-agent)")
        await _call(session, "get_merchant_onboarding_velocity", {"month": "2026-05"})
        row = _read_last_audit(audit_path)
        _check("forwarded session_id in row", row["session_id"] == SESSION_ID, detail=row["session_id"])
        _check("forwarded leader_email in row", row["leader_email"] == LEADER_EMAIL, detail=row["leader_email"])
        _check("forwarded ai_agent in row", row["ai_agent"] == "claude-code", detail=row["ai_agent"])

    await _run_against(audit_path, None, reachable)

    # --- Scenario 5 runs against an unreachable PDP (fail-closed). --------
    print("\n[5/5] PDP unreachable (expect fail-closed block)")

    async def unreachable(session: ClientSession) -> None:
        reply = await _call(session, "get_merchant_count_by_region", {"region": "Jakarta"})
        row = _read_last_audit(audit_path)
        _check("unreachable reply blocked", "blocked" in reply.lower(), detail=reply)
        _check(
            "unreachable audit verdict=unavailable",
            row["verdict"] == "unavailable",
            detail=row["verdict"],
        )
        _check("unreachable record_count=0", row["response_record_count"] == 0)

    await _run_against(audit_path, UNREACHABLE_URL, unreachable)

    print()
    if _failures:
        print(f"=== E2E FAILED: {len(_failures)} assertion(s) failed: {_failures} ===")
        return 1
    print("=== E2E PASSED: all scenarios green ===")
    print(f"\nAudit log written to: {audit_path}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
