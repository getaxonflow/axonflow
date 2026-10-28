# HTTP connector query parameters: Community runtime verification

This test sends HTTP requests through the real Agent's
`POST /mcp/resources/query` endpoint, its authentication and policy path,
connector registry, and HTTP connector to a local echo server. It checks both
the query received by the echo server and the data returned to the caller.
It requires the response's `engine` to be `anchored`.

Four cases cover URL-only parameters, internal-only metadata, additional
parameters, and explicit overrides. The last two repeated `tag` values must
survive unless explicitly overridden. The test waits for `/health` to report
`status: healthy`, not merely HTTP 200 during migration/startup.

## Run

Requirements: Go matching `platform/go.mod`, Python 3 (standard library only),
Docker, and free local ports 15432 and 16379. Use **disposable local databases**:
the real Agent runs the repository's migrations on the supplied database.
No provider credentials or Enterprise licence are required.

From the repository root:

```sh
docker run -d --name axonflow-query-e2e-postgres \
  -p 127.0.0.1:15432:5432 \
  -e POSTGRES_USER=axonflow -e POSTGRES_PASSWORD=local-query-test \
  -e POSTGRES_DB=axonflow postgres:15-alpine
docker run -d --name axonflow-query-e2e-redis \
  -p 127.0.0.1:16379:6379 redis:7-alpine

# Wait for PostgreSQL to accept connections before proceeding.
docker exec axonflow-query-e2e-postgres pg_isready -U axonflow -d axonflow

(cd platform && CGO_ENABLED=0 go build -o /tmp/axonflow-query-e2e-agent ./cmd/agent)

AXONFLOW_E2E_DATABASE_URL='postgres://axonflow:local-query-test@127.0.0.1:15432/axonflow?sslmode=disable' \
AXONFLOW_E2E_REDIS_URL='redis://127.0.0.1:16379' \
./runtime-e2e/http-query-parameters/test.sh \
  /tmp/axonflow-query-e2e-agent \
  /tmp/axonflow-query-e2e-results

# Inspect audit persistence after the test's graceful Agent shutdown.
docker exec axonflow-query-e2e-postgres psql -U axonflow -d axonflow \
  -c "SELECT connector_name, success, count(*) FROM mcp_query_audits WHERE connector_name = 'query-echo' GROUP BY connector_name, success;"

# Remove only these test containers after inspecting results.
docker rm -f axonflow-query-e2e-postgres axonflow-query-e2e-redis
```

The script starts and stops the Agent and local echo server. It saves
`agent.log`, `health.json` and `results.json` in the requested output directory.
It uses normal Community local-development configuration, a config-file HTTP
connector, a temporary writable audit fallback, and the supplied database/Redis.
Only the loopback echo fixture enables `allow_private_ips`. Provider keys and
Enterprise configuration are not inherited. Telemetry is disabled.

## Baseline comparison and scope

Executed on Linux with Go 1.26.10 and Python 3.12, using PostgreSQL 15 and
Redis 7. The original Agent was built with a Go overlay restoring only
`platform/connectors/http/connector.go` from upstream
`80b9508e01147d40a6be6a54611c042efef49705`. Everything else was identical.
Separate databases were used for original and patched Agents.

With the original binary, invoke `verify.py` directly with the same
`--agent` and `--output` values plus `--expect-regression`: it requires exactly the
internal-only and additional-parameter cases to fail their filter assertions,
with both controls passing. The patched binary requires all four to pass.
The original run reproduced both failures; the patched run passed all four.
Both used the anchored engine, and each final run persisted four successful
MCP audit records. A successful MCP status alone does not prove correct filters;
the echo-server and returned-data assertions are what detect this defect.

This verifies the affected REST/MCP request path. It does not exercise LLM
inference, Enterprise licensing, UI/plugin clients, external APIs, or unrelated
Orchestrator workflows.
