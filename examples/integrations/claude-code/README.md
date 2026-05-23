# Claude Code + AxonFlow Integration Examples

Policy enforcement, PII detection, and audit trails for Claude Code via the MCP server protocol.

## Prerequisites

- AxonFlow running locally (`docker compose up -d`)
- Agent healthy on port 8080

## E2E Test Script

```bash
# Run all 21 E2E tests
./http/test_claude_code_mcp_server.sh
```

Tests cover: initialize, tools/list, check_policy (safe/dangerous/SQLi/reverse shell), check_output (clean/PII), audit_tool_call, list_policies, get_policy_stats, error handling (invalid JSON, wrong Content-Type, unknown method/tool), session management, CORS, and notifications.

## Plugin

The Claude Code plugin package is at [getaxonflow/axonflow-claude-plugin](https://github.com/getaxonflow/axonflow-claude-plugin).

## Documentation

- [Claude Code Integration Guide](https://docs.getaxonflow.com/docs/integration/claude-code/)
- MCP Server PRD: `axonflow-internal-docs/prds/PRD_CLAUDE_CODE_PLUGIN.md` (separate repo)
