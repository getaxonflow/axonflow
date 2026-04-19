# Cursor Plugin Install E2E

Install-and-use tests for `axonflow-cursor-plugin@v0.5.1` from its GitHub
release. Exercises `pre-tool-check.sh` end-to-end against the live stack.

## Preconditions

Plugin fetched via:

```bash
mkdir /tmp/cursor-plugin-v0.5.1-e2e && cd /tmp/cursor-plugin-v0.5.1-e2e
curl -sL https://github.com/getaxonflow/axonflow-cursor-plugin/archive/refs/tags/v0.5.1.tar.gz | tar xz
mv axonflow-cursor-plugin-0.5.0 plugin
```

## Running

```bash
bash scenario-1-block-context.sh
```

## What the scenario asserts

Cursor hook exit semantics are different from Claude Code:
- Exit 0 with no output = allow
- Exit 2 + stderr message = block

The scenario asserts exit 2 plus stderr containing
`AxonFlow policy violation` + richer-context markers
`[decision: <id>, risk: <level>, override available via ...]`.

## Why this matters

Same platform fix as Claude Code (v7.1.1 extends `mcpToolCheckPolicy`
with richer context). Cursor plugin v0.5.1 already consumes the fields;
this scenario verifies the end-to-end path.
