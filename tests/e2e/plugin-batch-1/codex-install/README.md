# Codex Plugin Install E2E

Install-and-use tests for `axonflow-codex-plugin@v0.4.0` from its GitHub
release. Exercises `pre-tool-check.sh` end-to-end against the live stack.

## Preconditions

Plugin fetched via:

```bash
mkdir /tmp/codex-plugin-v0.4.0-e2e && cd /tmp/codex-plugin-v0.4.0-e2e
curl -sL https://github.com/getaxonflow/axonflow-codex-plugin/archive/refs/tags/v0.4.0.tar.gz | tar xz
mv axonflow-codex-plugin-0.4.0 plugin
```

## Running

```bash
bash scenario-1-block-context.sh
```

## What the scenario asserts

Exit 2 + stderr `AxonFlow policy violation` with richer-context markers.
Codex hook exit semantics match Cursor's.

## Why this matters

Same platform fix as Claude Code / Cursor. Codex plugin only hooks
`exec_command` (Bash); non-exec tools rely on MCP skills, which aren't
platform-enforced. This scenario exercises the only platform-enforced
block path Codex has.
