# Decision Mode — MCP Gateway PEP Adapter

A reference Policy Enforcement Point (PEP) adapter for MCP gateways. It sits
between the MCP client (e.g. an AI agent) and the MCP server (e.g. a Payments
MCP), intercepts `tools/call` requests, and calls AxonFlow's Decision API
(`POST /api/v1/decide`) to enforce policy before forwarding the call.

## How It Works

```
┌──────────┐      JSON-RPC       ┌──────────────┐    POST /api/v1/decide    ┌──────────────┐
│ AI Agent │ ──── tools/call ──▸ │  MCP PEP     │ ────────────────────────▸ │   AxonFlow   │
│          │                     │  Adapter     │ ◂──── verdict + trace_id  │   Agent      │
└──────────┘                     │  (:9090)     │                           └──────────────┘
                                 │              │
                                 │  allow?      │     JSON-RPC forward      ┌──────────────┐
                                 │  ───yes───── │ ────────────────────────▸ │  MCP Server  │
                                 │  ───no────── │ ◂──── tool result         │ (Payments)   │
                                 │  JSON-RPC    │                           └──────────────┘
                                 │  error       │
                                 └──────────────┘
```

### Payments MCP Gateway Use Case

This maps directly to the 3-gateway architecture where the MCP Gateway handles
tool calls between agents and backend services:

```
User: "refund my last order"
  │
  ▼
Agent Gateway ──▸ CS Agent ──▸ MCP Gateway ──▸ Payments MCP
                                    │
                                    ├── tools/call: payments.lookup_transaction
                                    │   └── MCP PEP Adapter calls AxonFlow → allow
                                    │       └── forwarded to Payments MCP → result
                                    │
                                    └── tools/call: payments.process_refund
                                        └── MCP PEP Adapter calls AxonFlow → allow/deny
                                            └── if allowed: forwarded → refund processed
                                            └── if denied: JSON-RPC error returned
```

Each `tools/call` through the MCP Gateway gets a policy check with:
- **SQL injection detection** in tool arguments
- **PII detection** (SSN, credit cards, etc.) in tool arguments
- **Dangerous pattern matching** on serialized arguments
- **W3C trace_id** for end-to-end observability across gateway layers

## Quick Start

```bash
cd poc/
docker compose up -d --build

# Wait for services
docker compose ps  # all healthy

# Run the PoC test harness
./test.sh
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_ADAPTER_LISTEN` | `:9090` | Adapter listen address |
| `MCP_SERVER_URL` | `http://localhost:9091` | Upstream MCP server URL |
| `AXONFLOW_ENDPOINT` | `http://localhost:8080` | AxonFlow agent URL |
| `MCP_GATEWAY_ID` | `mcp-gateway` | Gateway identifier in audit trail |
| `AXONFLOW_CLIENT_ID` | `mcp-adapter` | Client ID for Decision API auth |
| `AXONFLOW_CLIENT_SECRET` | (empty) | Client secret (optional in community mode) |
| `AXONFLOW_ORG_ID` | (empty) | Organization ID |
| `AXONFLOW_TENANT_ID` | (empty) | Tenant ID |
| `MCP_FAIL_MODE` | `closed` | `open` or `closed` — what to do when Decision API is unreachable |
| `MCP_INTERCEPT_METHODS` | `tools/call` | Comma-separated JSON-RPC methods to intercept |
| `MCP_REQUEST_TIMEOUT` | `10s` | HTTP client timeout for Decision API and MCP server calls |

## Decision API Mapping

The adapter maps MCP `tools/call` requests to the Decision API:

| MCP Field | Decision API Field | Example |
|-----------|-------------------|---------|
| `params.name` | `target.tool` | `payments.lookup_transaction` |
| `params.arguments` (serialized) | `query` | `tool_call: payments.lookup_transaction args: {"customer_id":"C-456"}` |
| (constant) | `stage` | `tool` |
| (constant) | `target.type` | `tool` |
| `MCP_GATEWAY_ID` env | `caller_identity.gateway_id` | `payments-mcp-gateway` |

## Verdict Handling

| Decision API Verdict | Adapter Behavior | JSON-RPC Error Code |
|---------------------|------------------|---------------------|
| `allow` | Forward request to MCP server, return result | (no error) |
| `deny` | Return JSON-RPC error with policy reason | `-32001` |
| `needs_approval` | Return JSON-RPC error (HITL required) | `-32002` |
| Decision API unreachable (fail-closed) | Return JSON-RPC error | `-32003` |
| Decision API unreachable (fail-open) | Forward request to MCP server | (no error) |

Deny responses always return HTTP 200 with a JSON-RPC error object — never a
bare HTTP 403. This preserves the JSON-RPC 2.0 contract so MCP clients can
parse the error programmatically.

## Trace Propagation

The adapter propagates W3C `traceparent` headers end-to-end:

1. Inbound `Traceparent` header (if present) is forwarded to the Decision API
2. Decision API returns `trace_id` (reusing the inbound trace or minting a new one)
3. Adapter sets `X-Trace-Id` response header and `Traceparent` on the downstream MCP call

This enables stitching multi-gateway decisions into a single trace in Jaeger,
Datadog, or Grafana Tempo.

## PoC Test Harness

`poc/test.sh` validates 7 scenarios:

1. **Clean tool call** — `payments.lookup_transaction` with safe arguments → allow, forwarded
2. **SQL injection** — UNION SELECT in arguments → deny, blocked before mock
3. **PII in arguments** — SSN in refund reason → deny
4. **trace_id in responses** — X-Trace-Id header present on allow
5. **JSON-RPC error shape** — deny returns `{"jsonrpc":"2.0","id":5,"error":{...}}`, not HTTP 403
6. **Non-intercepted method** — `tools/list` passes through without policy check
7. **Traceparent propagation** — custom traceparent forwarded, trace_id returned

## Building Standalone

```bash
go build -o mcp-adapter .
```

## Project Structure

```
decision-mode-mcp-adapter/
├── main.go              # PEP adapter — JSON-RPC intercept + Decision API client
├── Dockerfile           # Multi-stage build for the adapter
├── go.mod
├── README.md
└── poc/
    ├── docker-compose.yml   # AxonFlow agent + adapter + mock MCP server
    ├── mock_mcp_server.go   # Simulates Payments MCP (lookup + refund tools)
    ├── Dockerfile.mock      # Build for mock server
    └── test.sh              # 7-scenario PoC test harness
```
