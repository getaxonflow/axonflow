# Claude Code Plugin Install E2E

Install-and-use tests for `axonflow-claude-plugin@v0.5.0` from its GitHub
release. Exercises the `pre-tool-check.sh` hook end-to-end against the
live stack.

## Preconditions

1. Stack up via `./scripts/setup-e2e-testing.sh evaluation`.
2. Plugin fetched via:
   ```bash
   mkdir /tmp/claude-plugin-v0.5.0-e2e && cd /tmp/claude-plugin-v0.5.0-e2e
   curl -sL https://github.com/getaxonflow/axonflow-claude-plugin/archive/refs/tags/v0.5.0.tar.gz | tar xz
   mv axonflow-claude-plugin-0.5.0 plugin
   ```
3. Default credentials: `demo-client:demo-secret`.

## Running

```bash
bash scenario-1-block-context.sh
```

## What the scenario asserts

- Hook stdin receives a Bash tool invocation with a SQLi pattern.
- Hook exits 0 with JSON output per the Claude Code PreToolUse protocol.
- `hookSpecificOutput.permissionDecision == "deny"`.
- `permissionDecisionReason` carries the richer-context markers
  `[decision: <id>, risk: <level>, override available via explain_decision MCP tool]`.

## Why this matters

Claude Code plugin v0.5.0 is already parsing these fields from the MCP
server response. The first post-release E2E run against platform v7.1.0
(before the six-bug patch) showed the response arriving without the
fields — resulting in a terse deny with no explain/override affordance.
Platform v7.1.1 fixes `mcpToolCheckPolicy` to return the full shape;
this scenario locks in the end-to-end path.
