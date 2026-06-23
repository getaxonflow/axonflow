# MCP server with AxonFlow Decision Mode

A runnable, ~minimal **Model Context Protocol (MCP) server** that uses AxonFlow
as its **Policy Decision Point (PDP)**. This is the recognizable starting point
for "AxonFlow as the policy gate for your MCP server": Claude Code calls the
MCP server, the MCP server calls AxonFlow before returning any data, and the
MCP server enforces the verdict (deny / apply obligations) on its side.

The MCP server is the **Policy Enforcement Point (PEP)**. AxonFlow is the
**Policy Decision Point (PDP)**. Keeping that boundary explicit is the whole
point of the pattern.

## Architecture

```
 Leader laptop
   ┌─────────────┐    stdio (MCP)    ┌────────────────────────┐
   │ Claude Code │ ───────────────►  │  MCP server  (PEP)     │
   └─────────────┘                   │  mcp_server.py         │
                                     │   • auth + routing     │
          data ◄──────────────────  │   • enforce verdict    │
        (only if allowed)           └───────┬────────────────┘
                                            │  POST /api/v1/decide
                                            ▼
                                     ┌────────────────────────┐
                                     │  AxonFlow agent (PDP)  │
                                     │   • Indonesia PII pack │
                                     │   • prompt-injection   │
                                     │   • policy hierarchy   │
                                     │   • decision record    │
                                     └───────┬────────────────┘
                                            │ verdict + obligations
                          ┌─────────────────┴───────────────────┐
              allow ──────┤  apply obligations (redact PEP-side) ├──► internal system
              deny  ──────┤  refuse, return nothing              │    (stubbed: aggregated
        needs_approval ───┤  pause for human approver            │     views only)
                          └──────────────────────────────────────┘
                                            │
                                            ▼
                                  audit_log.jsonl  (Risk Committee Layer 1)
```

Claude **never** reaches the internal system directly. Every tool call passes
through the PEP, which asks the PDP first.

## Audit-layer mapping

A design partner's Risk Committee defines a four-layer audit framework. This example
produces the first two layers and is the join point for the other two:

| Layer | What it is | Produced by |
|-------|-----------|-------------|
| **Layer 1** | MCP server logging (`timestamp, session_id, leader_email, tool_name, parameters_hash, response_record_count, duration_ms`) | `audit_log.py` → `audit_log.jsonl` |
| **Layer 2** | `X-AI-Agent` / `X-Session-ID` / `X-Leader-Identity` propagation | `mcp_server.py` forwards them in the `decide()` `context` map; values land in the Layer 1 row (`ai_agent`, `session_id`, `leader_email`) |
| **Layer 3** | Decision record → SIEM, correlated to BigQuery Cloud Audit Logs by `decision_id` / `session_id` | AxonFlow decision record (`decision_id` + `trace_id`) exported via OpenTelemetry **and** the Layer 1 row shipped to a central store (see [Turnkey central-store shipping](#turnkey-central-store-shipping-layer-3)); correlate on `decision_id` / `session_id` |
| **Layer 4** | Anomaly alerts (volume, off-hours, bulk retrieval) | SIEM's job once Layer 1 + Layer 3 feeds are joined |

## Turnkey central-store shipping (Layer 3)

The local `audit_log.jsonl` is always written and is the durable source of
truth. To make **Layer 3** turnkey rather than a bespoke pipeline, set
`MCP_AUDIT_SINK` and each row is *also* shipped to a central store, landing next
to BigQuery Cloud Audit Logs so a SIEM joins them on `decision_id` / `session_id`
(see the [Decision Mode SIEM Correlation Recipe](https://enterprise-docs.getaxonflow.com/docs/compliance/decision-mode-siem-recipe)).

```bash
# Ship to an OTel collector / BigQuery proxy / any log-ingest URL (uses httpx):
export MCP_AUDIT_SINK=http
export MCP_AUDIT_HTTP_URL=http://otel-collector:4318/v1/audit

# …or to S3 (objects: <prefix>/<YYYY>/<MM>/<DD>/<decision_id>.json):
export MCP_AUDIT_SINK=s3
export MCP_AUDIT_S3_BUCKET=my-axonflow-audit       # needs: pip install boto3
```

Shipping is **best-effort and fail-open**: if the central store is down, tool
calls still succeed, rows are still written locally, and a small circuit breaker
stops the dead sink from costing latency. It mirrors the platform agent's
built-in exporter (`AXONFLOW_AUDIT_SINK`), so the same record layout lands
whether the agent or this PEP wrote it.

See it run, with no cloud account, against an in-process receiver:

```bash
python ship_audit_example.py
```

It records two governed calls with the central store up (rows land both locally
and centrally, correlated on `decision_id`) and two with it down (rows stay
durable locally), printing a `PASS` line per scenario.

## Quickstart

```bash
# 1. Start AxonFlow (enterprise mode, PII blocking on) and load its credentials:
PII_ACTION=block ./scripts/setup-e2e-testing.sh enterprise   # from repo root
source /tmp/axonflow-e2e-env.sh

# 2. Configure + install this example:
cd examples/mcp-decision-mode
cp .env.example .env                     # then set AXONFLOW_CLIENT_SECRET etc.
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Run the MCP server (speaks MCP over stdio — Claude Code attaches here):
python mcp_server.py
```

Expected: the server starts and waits on stdio. To see it actually decide,
allow, deny, and audit, run the end-to-end smoke test instead:

```bash
./test_e2e.sh
```

which drives the server over stdio as a real MCP client and prints a `PASS`
line per assertion, then dumps the `audit_log.jsonl` it produced (allow rows
and deny rows). Example deny reply Claude would receive:

```
❌ Tool 'get_merchant_count_by_region' was blocked by AxonFlow policy
(decision_id=…): Critical Indonesia PII detected (NIK or NPWP).
The call was NOT executed and no data was returned.
```

## Tools (Phase 1 boundary: aggregated only)

| Tool | Returns |
|------|---------|
| `get_merchant_count_by_region(region)` | Aggregated active-merchant count for a region — no individual records |
| `get_merchant_onboarding_velocity(month)` | Aggregated new-merchant count for a month (`YYYY-MM`) — no individual records |

Both route through one `Governor.run_tool()` → `AxonFlowDecideClient.decide_async()`
helper before any data is produced.

## Failure posture

Default is **fail-closed**: if the PDP can't be reached the tool is blocked and
nothing is returned — the correct default for a regulated fintech gate. A
network error or timeout is retried once; a 5xx (degraded PDP), a 4xx
(misconfiguration), or a non-JSON response is treated as unavailable and
blocked without retry. Set `MCP_FAIL_CLOSED=false` for non-regulated,
availability-first paths (the synthetic allow is tagged in the audit row's
`evaluated_policies`/`reasons` so it's never mistaken for a real verdict).

## Known gotchas

- **AxonFlow must be running and reachable on `:8080`.** `test_e2e.sh` checks
  `/health` and fails fast with a pointer if not.
- **The license key must be set.** `AXONFLOW_CLIENT_SECRET` is the license key
  in enterprise mode; `AXONFLOW_CLIENT_ID` / `AXONFLOW_TENANT_ID` are your
  AxonFlow org identifier. In enterprise mode `caller_identity.tenant_id` must
  match the authenticated identity or the PDP returns 403.
- **Deny verdicts for Indonesian PII require `PII_ACTION=block`.** With the
  default `redact`, NIK/NPWP yield an allow-with-redaction obligation instead
  of a deny.
- **The stdio MCP client is the test harness, not the demo target.** In
  production, Claude Code is the client; `e2e_harness.py` stands in for it so
  the example is testable without a live Claude session.

## Files

| File | Purpose |
|------|---------|
| `mcp_server.py` | The MCP server (PEP): two governed tools + the `Governor` wrapper |
| `decide_client.py` | `AxonFlowDecideClient` — wraps `POST /api/v1/decide` (sync + async) |
| `audit_log.py` | Layer 1 structured-JSON audit writer + turnkey central-store shippers (S3 / HTTP) |
| `ship_audit_example.py` | Runnable demo of central-store shipping against an in-process receiver (no cloud account) |
| `e2e_harness.py` | Real stdio MCP client that drives the server for `test_e2e.sh` |
| `test_e2e.sh` | End-to-end smoke test (5 scenarios) against a live stack |
| `*_test.py` | Unit tests (`pytest`); run `pytest` after `pip install -r requirements-dev.txt` |

## License

AxonFlow is **source-available** under the Business Source License 1.1
(BSL 1.1). See the repository `LICENSE`.
