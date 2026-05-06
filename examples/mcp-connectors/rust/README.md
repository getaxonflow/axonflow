# MCP Connectors — Rust

Lists installed connectors and runs a governed query through one. Connector queries are dispatched through the agent's proxy with `request_type="mcp-query"` so policy is enforced before the connector is reached.

## Prerequisites

- Rust 1.78+
- AxonFlow stack running locally (community stack includes a Postgres connector)

## Run

```bash
cargo run
```

Set `AXONFLOW_AGENT_URL`, `AXONFLOW_CLIENT_ID`, `AXONFLOW_CLIENT_SECRET` for non-default deployments.
