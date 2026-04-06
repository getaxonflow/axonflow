# Cursor IDE + AxonFlow Integration Example

Governance for Cursor IDE via the AxonFlow plugin — automatic policy enforcement, PII detection, and audit trails.

## Prerequisites

- AxonFlow running locally (`docker compose up -d`)
- [Cursor IDE](https://cursor.com)
- [AxonFlow Cursor Plugin](https://github.com/getaxonflow/axonflow-cursor-plugin)

## Quick Start

```bash
# 1. Start AxonFlow
docker compose up -d
curl -s http://localhost:8080/health | jq .status

# 2. Clone and load the plugin
git clone https://github.com/getaxonflow/axonflow-cursor-plugin.git
export AXONFLOW_ENDPOINT=http://localhost:8080
export CURSOR_PLUGIN_ROOT=/path/to/axonflow-cursor-plugin
# Load in Cursor via plugin settings
```

## E2E Tests

```bash
# Run the MCP server test suite (tests all 6 governance tools)
./http/test_cursor_mcp_server.sh
```

## What Gets Tested

- MCP server initialize + tools/list
- check_policy: dangerous command blocking, safe command allowing
- check_output: PII detection and redaction
- audit_tool_call: audit trail recording
- list_policies: policy enumeration
- get_policy_stats: governance activity summary
- search_audit_events: individual audit record search

## Links

- [Cursor Integration Guide](https://docs.getaxonflow.com/docs/integration/cursor/)
- [AxonFlow Cursor Plugin](https://github.com/getaxonflow/axonflow-cursor-plugin)
- [Getting Started](https://docs.getaxonflow.com/docs/getting-started/)
