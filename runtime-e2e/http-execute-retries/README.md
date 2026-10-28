# HTTP PUT/DELETE retry statuses: Community runtime verification

This harness starts the real Community Agent, waits for healthy readiness, and
sends seven requests through `POST /mcp/tools/execute`. A local HTTP server
returns controlled response statuses and records each request method/body.
Assertions cover request counts, preserved bodies, final HTTP message and
rows affected. Every MCP response must name the anchored policy engine.

| Case | Original | Fixed |
| --- | --- | --- |
| PUT: 503 then 200 | One request, fails | Two requests, succeeds |
| DELETE: 429 then 204 | One request, fails | Two requests, succeeds |
| PUT: persistent 500, max_retries=2 | One request | Three requests, fails |
| PUT: 404 | One request | One request |
| POST: 503 | One request | One request |
| PATCH: 429 | One request | One request |
| PUT: 200 | One request, succeeds | One request, succeeds |

## Run

Requirements: Go matching platform/go.mod, Python 3 standard library, Docker,
and free local ports 15432/16379. Use a disposable database: the Agent executes
the real migrations. No Enterprise licence or provider credentials are needed.

From the repository root:

```sh
docker run -d --name axonflow-retry-e2e-postgres \
  -p 127.0.0.1:15432:5432 -e POSTGRES_USER=axonflow \
  -e POSTGRES_PASSWORD=local-query-test -e POSTGRES_DB=axonflow postgres:15-alpine
docker run -d --name axonflow-retry-e2e-redis \
  -p 127.0.0.1:16379:6379 redis:7-alpine
docker exec axonflow-retry-e2e-postgres pg_isready -U axonflow -d axonflow
# Proceed after PostgreSQL is ready.
(cd platform && CGO_ENABLED=0 go build -o /tmp/axonflow-retry-agent ./cmd/agent)
AXONFLOW_E2E_DATABASE_URL='postgres://axonflow:local-query-test@127.0.0.1:15432/axonflow?sslmode=disable' \
AXONFLOW_E2E_REDIS_URL='redis://127.0.0.1:16379' \
./runtime-e2e/http-execute-retries/test.sh \
  /tmp/axonflow-retry-agent /tmp/axonflow-retry-results
docker exec axonflow-retry-e2e-postgres psql -U axonflow -d axonflow \
  -c "SELECT connector_name, count(*) FROM mcp_query_audits WHERE connector_name='query-echo' GROUP BY connector_name;"
docker rm -f axonflow-retry-e2e-postgres axonflow-retry-e2e-redis
```

Outputs are agent.log, health.json and results.json. The script uses normal
Community configuration and config-file connector loading, a writable temporary
audit fallback, and the supplied database/Redis. Only the loopback fixture
allows private IPs. It does not inherit provider keys or Enterprise settings.
Telemetry is off; the Agent and fixture shut down after the run.

Executed on Linux, Go 1.26.10, Python 3.12, PostgreSQL 15 and Redis 7. Baseline
and fixed runs used separate databases and each persisted seven MCP audit rows.
An original Agent built with connector.go from upstream 80b9508 reproduces the
three retry failures (invoke `verify.py` directly with the same `--agent` and
`--output` values plus `--expect-regression` to require exactly those failures).
The fixed Agent passes all seven. The MCP endpoint reports success for handled
connector failures too, so top-level success alone is not the test oracle.

Scope: affected Community REST/MCP execute path. No external API, LLM inference,
Enterprise licence, UI/plugin client or unrelated Orchestrator flow is tested.
