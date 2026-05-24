# Decision Mode Adapter

A reference [Policy Enforcement Point (PEP)](https://docs.getaxonflow.com/docs/integration/decision-mode/) adapter that sits in front of any gateway, calls AxonFlow's Decision API on every request, and enforces the verdict. Zero application-code changes required.

The same adapter works across all three gateway layers in the ADR-056 reference architecture: LLM gateway, MCP/tool gateway, and agent gateway. Set `AXONFLOW_STAGE` to match the layer.

## How it works

```
client  →  adapter  →  downstream gateway / service
                ↓
        AxonFlow agent (:8080)
        POST /api/v1/decide
```

1. The adapter intercepts every POST request (OpenAI chat-completion shaped).
2. It extracts the model name and the last user message from the request body.
3. It calls `POST /api/v1/decide` on the AxonFlow agent with the configured stage.
4. Based on the verdict:
   - **allow** — forwards the request downstream, propagates `traceparent`.
   - **deny** — returns a structured JSON error (not a bare 403).
   - **needs_approval** — returns a structured JSON error with the approval reason.
5. On Decision API failure: applies the configured fail-open or fail-closed posture.
   - 4xx errors (bad credentials, rate limit) always block — they are never fail-open eligible.
   - Transport and 5xx errors respect the `AXONFLOW_FAIL_OPEN` setting.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `AXONFLOW_ENDPOINT` | `http://localhost:8080` | AxonFlow agent base URL |
| `AXONFLOW_GATEWAY_ID` | `llm-gateway-poc` | Identifies this PEP in audit logs |
| `AXONFLOW_STAGE` | `llm` | Decision API stage: `llm`, `tool`, or `agent` |
| `AXONFLOW_ORG_ID` | (empty) | Organisation scope for policy evaluation |
| `AXONFLOW_TENANT_ID` | (empty) | Tenant scope for policy evaluation |
| `AXONFLOW_CLIENT_ID` | (empty) | Client credential ID (empty for community mode) |
| `AXONFLOW_CLIENT_SECRET` | (empty) | Client credential secret |
| `AXONFLOW_FAIL_OPEN` | `false` | `true` = forward on transport/5xx failure; `false` = block |
| `DOWNSTREAM_URL` | `http://localhost:9090` | Downstream endpoint to forward allowed requests to |
| `LISTEN_ADDR` | `:8888` | Address the adapter listens on |

## Quick start: LLM Gateway (PoC)

The `poc/` directory contains a Docker Compose harness that runs the full round-trip:

```bash
cd poc
docker compose up -d --build
./test.sh
docker compose down -v
```

The harness starts:
- **AxonFlow agent** (community mode) — the policy decision point
- **Mock LLM** — a minimal OpenAI-shaped endpoint
- **Adapter** (`stage: llm`) — wrapping the mock LLM with policy enforcement

`test.sh` sends four requests (13 assertions, all must pass):
1. Clean request → expect **allow** (200)
2. PII-containing request (SSN + credit card) → expect **deny** (403)
3. SQL injection → expect **deny** (403)
4. Traceparent propagation → expect the supplied `trace_id` in the response

## Quick start: Agent Gateway (PoC)

The same adapter can enforce policy at the agent routing layer. A second compose file adds an agent-gateway adapter alongside the LLM-gateway adapter:

```bash
cd poc
docker compose -f docker-compose.yml -f docker-compose.agent-gateway.yml up -d --build
./test-agent-gateway.sh
docker compose -f docker-compose.yml -f docker-compose.agent-gateway.yml down -v
```

This starts the base services (AxonFlow agent, mock LLM, LLM adapter) plus:
- **Mock agent backend** — simulates an agent routing service
- **Agent adapter** (`stage: agent`, port 8889) — enforces policy on agent-routing requests

`test-agent-gateway.sh` sends four requests verifying the same PII/SQLi enforcement at the agent layer.

## Using as a Go library

```go
import adapter "github.com/getaxonflow/axonflow/examples/integrations/decision-mode-adapter"

// LLM gateway
llmHandler := adapter.Middleware(adapter.Config{
    AxonFlowEndpoint: "http://axonflow:8080",
    GatewayID:        "my-llm-gateway",
    Stage:            "llm",
    FailOpen:         false,
}, yourLLMDownstream)

// Agent gateway (same adapter, different stage)
agentHandler := adapter.Middleware(adapter.Config{
    AxonFlowEndpoint: "http://axonflow:8080",
    GatewayID:        "my-agent-gateway",
    Stage:            "agent",
    FailOpen:         false,
}, yourAgentDownstream)
```

## Running standalone

```bash
go build -o adapter ./cmd/adapter/

# LLM gateway
AXONFLOW_ENDPOINT=http://localhost:8080 \
AXONFLOW_STAGE=llm \
DOWNSTREAM_URL=http://localhost:11434/v1/chat/completions \
./adapter

# Agent gateway
AXONFLOW_ENDPOINT=http://localhost:8080 \
AXONFLOW_STAGE=agent \
AXONFLOW_GATEWAY_ID=agent-gateway \
DOWNSTREAM_URL=http://localhost:9091 \
LISTEN_ADDR=:8889 \
./adapter
```

## Trace correlation

The adapter propagates W3C `traceparent` headers end-to-end:

- If the client sends a `traceparent`, the adapter forwards its `trace_id` to the Decision API, which reuses it for the OTel span. The same `trace_id` is propagated downstream.
- If no `traceparent` is present, the Decision API mints a fresh W3C `trace_id` and the adapter propagates it downstream.
- The response always includes `X-Axonflow-Trace-Id` and `X-Axonflow-Decision-Id` headers for client-side correlation.

In a multi-layer architecture, the same `traceparent` flows through agent → MCP → LLM gateways, with each adapter calling the Decision API. All decisions share one `trace_id` in the audit trail.
