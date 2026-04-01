# OpenClaw + AxonFlow Governance

Demonstrates AxonFlow governance for OpenClaw tool execution using `@axonflow/openclaw`.

## Prerequisites

- AxonFlow running locally (`docker compose up -d`)
- OpenClaw installed
- `@axonflow/openclaw` installed

## HTTP E2E Tests

Tests the `mcp_check_input` and `mcp_check_output` endpoints with OpenClaw connector types:

```bash
cd http
bash test_openclaw_governance.sh
```

## Plugin Integration

See the [@axonflow/openclaw](https://github.com/getaxonflow/axonflow-openclaw-plugin) repo for the full plugin implementation and configuration guide.

## Connector Type Naming

OpenClaw tools use `openclaw.{toolName}` as the connector type:
- `openclaw.web_fetch` — HTTP requests
- `openclaw.message_sending` — Outbound channel messages (Telegram, Discord, Slack)
- `openclaw.mcp.postgres` — MCP-backed PostgreSQL
- `openclaw.browser` — Browser tool
