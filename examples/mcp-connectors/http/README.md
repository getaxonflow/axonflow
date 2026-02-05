# HTTP Connector Example

This example installs and exercises the built-in HTTP connector by calling the Orchestrator health endpoint.

## Prerequisites

- AxonFlow stack running via `docker compose` (Enterprise or Community)
- Agent reachable at `http://localhost:8080`
- Orchestrator reachable at `http://localhost:8081`

## Environment

- `AXONFLOW_ENDPOINT` (default: `http://localhost:8080`)
- `AXONFLOW_CLIENT_ID` (default: `demo-org`)
- `AXONFLOW_CLIENT_SECRET` (required in enterprise mode)
- `AXONFLOW_TENANT_ID` (optional; defaults to `AXONFLOW_CLIENT_ID`)
- `AXONFLOW_USER_TOKEN` (optional, defaults to `default-user`)
- `AXONFLOW_CONNECTOR_BASE_URL` (default: `http://axonflow-orchestrator:8081`; use `http://localhost:8081` if agent runs outside docker)

## Run (Go)

```bash
cd examples/mcp-connectors/http/go
go run main.go
```

## What It Does

1. Lists available connectors and validates the HTTP connector is present.
2. Installs the HTTP connector (if not installed).
3. Health-checks the connector.
4. Queries `/health` from the Orchestrator via the HTTP connector.

This example validates runtime wiring end-to-end. If it returns "Unauthorized connector access",
the connector was installed in marketplace metadata but not loaded by the agent runtime config.
Fix that by ensuring connector config is available to the runtime (database-backed `connector_configs`
in enterprise mode, or `AXONFLOW_CONFIG_FILE` in community mode).

The example exits with status `1` on any failed assertion.
