# OpenTelemetry decision tracing

Run AxonFlow with the OpenTelemetry decision tracer turned on, send a
few requests through the Gateway Mode pre-check API, and view the
resulting spans in a local Jaeger UI.

This example exercises Decision Mode's trace-correlation primitive
(ADR-056 §"Trace correlation"). Every policy decision becomes one
OpenTelemetry span; the W3C `trace_id` returned in the pre-check
response is the id a Policy Enforcement Point (PEP) propagates
downstream so multi-gateway decisions stitch into one end-to-end trace.

## Why this matters

In Decision Mode an enterprise's existing gateway layers (agent
gateway, MCP gateway, LLM gateway) each call AxonFlow's decision API
per request. Without a shared correlation id the spans from each
gateway live in separate traces and the operator cannot see one
end-to-end view of a request. The OpenTelemetry `trace_id` returned by
AxonFlow is that shared id. This example shows it being emitted; the
PEP-side propagation is wired in by the adapter and is out of scope
for this walkthrough.

## What's in the box

| Service          | Image                                                | Where                  |
|------------------|------------------------------------------------------|------------------------|
| AxonFlow agent   | (built from this repo)                               | <http://localhost:8080>|
| OTel collector   | `otel/opentelemetry-collector-contrib:0.128.0`       | gRPC :4317, HTTP :4318 |
| Jaeger all-in-one| `jaegertracing/all-in-one:1.66.0`                    | UI <http://localhost:16686> |

## Prerequisites

- Docker + Docker Compose (the rest is pulled).
- No license key required — Community-mode default is fine.

## Boot the stack

From the repo root:

```bash
docker compose -f docker-compose.yml -f docker-compose.otel.yml up -d
```

That overlay (`docker-compose.otel.yml`) does three things:

1. Starts the OTel collector and Jaeger.
2. Sets `AXONFLOW_OTEL_ENDPOINT=otel-collector:4317` on the agent so
   the tracer wires up the OTLP/gRPC exporter instead of the noop
   fallback.
3. Names the agent's service as `axonflow-agent` so Jaeger groups
   spans under that header.

Wait for `axonflow-agent` to report healthy:

```bash
docker compose ps
curl http://localhost:8080/health
```

## Emit a decision

Any call into `POST /api/policy/pre-check` produces one span. The
simplest community-mode request needs only a `client_id` and a
`query`:

```bash
curl -s -X POST http://localhost:8080/api/policy/pre-check \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "otel-demo",
    "query": "Find all customer emails containing acme.com"
  }' | jq
```

The response now includes a `trace_id` field:

```json
{
  "context_id": "...",
  "approved": true,
  "policies": [],
  "expires_at": "...",
  "trace_id": "b3a1f1f3a8c6e0d7..."
}
```

That `trace_id` is what a PEP would echo into the upstream request so
the trace stitches across multiple gateway layers.

## View spans in Jaeger

Open Jaeger UI:

```bash
open http://localhost:16686
```

Or query the API directly:

```bash
curl -s 'http://localhost:16686/api/traces?service=axonflow-agent&limit=5' | jq '.data[].spans[].operationName'
```

You should see `"axonflow.decision"` operation names and the seven
expected attributes on each span:

| Attribute              | Example                                      |
|------------------------|----------------------------------------------|
| `decision.id`          | `b9e02d5f-…`                                 |
| `decision.stage`       | `llm` or `tool`                              |
| `decision.verdict`     | `allow` / `deny` / `needs_approval`          |
| `decision.policy_ids`  | `["p_pii_us", "p_sql_injection"]`            |
| `decision.latency_ms`  | `7`                                          |
| `decision.reasons`     | `"clean"` or `"PII detected: SSN"`           |
| `org.id`               | `local-dev-org`                              |
| `tenant.id`            | `otel-demo`                                  |

## Try a denied decision

A query that triggers RBI PII detection (US SSN) demonstrates the
deny path:

```bash
curl -s -X POST http://localhost:8080/api/policy/pre-check \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "otel-demo",
    "query": "John Smith SSN 123-45-6789"
  }' | jq '.approved, .trace_id, .block_reason'
```

Pull the matching span by `trace_id`:

```bash
TRACE_ID=$(curl -s -X POST http://localhost:8080/api/policy/pre-check \
  -H "Content-Type: application/json" \
  -d '{"client_id":"otel-demo","query":"4111-1111-1111-1111"}' | jq -r .trace_id)
echo "trace_id=$TRACE_ID"
curl -s "http://localhost:16686/api/traces/$TRACE_ID" | jq '.data[0].spans[0].tags[] | select(.key | startswith("decision.") or . == "org.id" or . == "tenant.id")'
```

## Configuration reference

The tracer reads three env vars; all default to safe values.

| Variable                       | Default              | Effect                                                                                          |
|--------------------------------|----------------------|-------------------------------------------------------------------------------------------------|
| `AXONFLOW_OTEL_ENDPOINT`       | empty (noop)         | OTLP/gRPC endpoint. Empty = tracer is the noop impl. Set to `host:port` to enable.              |
| `AXONFLOW_OTEL_SERVICE_NAME`   | `axonflow-agent`     | `service.name` resource attribute. Bump per service when multiple AxonFlow components share a collector. |
| `AXONFLOW_OTEL_SAMPLE_RATE`    | `1.0`                | Head sampling ratio in `[0.0, 1.0]`. Use parent-based — upstream sampling decisions propagate.  |

The runtime never errors on a misconfigured exporter — the tracer
falls back to noop and logs a warning. OTel is observability, not a
hard dependency.

## Tear it down

```bash
docker compose -f docker-compose.yml -f docker-compose.otel.yml down -v
```

## Where to go next

- ADR-056 — Decision Mode architecture, the source of these
  requirements.
- The Decision Mode integration guide on docs.getaxonflow.com covers
  PEP-side propagation and the supported adapter shapes.
