# OpenAI Codex + AxonFlow Integration Example

Governance for OpenAI Codex via the AxonFlow plugin — enforcement on Bash via hooks, advisory governance for other tools via skills, and compliance-grade audit trails.

## Prerequisites

- AxonFlow running locally (`docker compose up -d`)
- [OpenAI Codex CLI](https://developers.openai.com/codex/cli)
- [AxonFlow Codex Plugin](https://github.com/getaxonflow/axonflow-codex-plugin)

## Quick Start

```bash
# 1. Start AxonFlow
docker compose up -d
curl -s http://localhost:8080/health | jq .status

# 2. Clone and load the plugin
git clone https://github.com/getaxonflow/axonflow-codex-plugin.git
export AXONFLOW_ENDPOINT=http://localhost:8080
# Load via the Codex plugin system
```

## E2E Tests

```bash
# Run the MCP server test suite (tests all 6 governance tools)
./http/test_codex_mcp_server.sh
```

## Governance Model

| Type | Tool | Mechanism |
|------|------|-----------|
| Enforcement | Bash / exec_command | Hook fires before execution (exit code 2 = block) |
| Advisory | Write, Edit, MCP | Skills instruct agent to call check_policy |
| Audit | All | Automatic for Bash, skill-guided for others |

## Links

- [Codex Integration Guide](https://docs.getaxonflow.com/docs/integration/codex/)
- [AxonFlow Codex Plugin](https://github.com/getaxonflow/axonflow-codex-plugin)
- [Getting Started](https://docs.getaxonflow.com/docs/getting-started/)
