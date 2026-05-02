#!/usr/bin/env bash
# Regression guard: forbid `${{ toJSON(...) }}` interpolation directly
# into a bash double-quoted string inside a `run:` block.
#
# toJSON renders to pretty-printed multi-line JSON with embedded
# double quotes. When that lands inside a bash `"…"` string, the
# embedded quotes terminate the bash string early and the shell
# parser blows up before jq sees anything well-formed. Symptom is
# `jq: parse error: Invalid literal at line 2, column 13` or
# similar at runtime — only after the workflow has provisioned, run
# tasks, and otherwise burned cost.
#
# This is the bug PR #1814 fixed in scheduled-performance-benchmark.yml's
# Build-report step:
#
#   TID=$(echo "${{ toJSON(steps.test.outputs) }}" | jq -r ...)
#
# Safe alternatives:
#   1. Pass via env var:
#        env:
#          OUTPUTS_JSON: ${{ toJSON(steps.foo.outputs) }}
#        run: |
#          jq ... <<< "$OUTPUTS_JSON"
#   2. Read individual scalar fields one at a time:
#        run: |
#          VAL="${{ steps.foo.outputs.bar }}"
#
# A scalar `${{ steps.x.outputs.y }}` is fine — those rarely contain
# double quotes or newlines. Only multi-value renderers (toJSON,
# fromJSON, format-with-objects) need this guarantee.

set -euo pipefail

WORKFLOW_DIR=".github/workflows"

if [ ! -d "$WORKFLOW_DIR" ]; then
    echo "ℹ️  $WORKFLOW_DIR not present; nothing to validate."
    exit 0
fi

# Match: any double-quote, then ${{, optional space, toJSON(
# i.e. unsafe: "${{ toJSON(...) }}"
HITS=$(grep -nE '"\$\{\{[[:space:]]*toJSON\(' "$WORKFLOW_DIR"/*.yml "$WORKFLOW_DIR"/*.yaml 2>/dev/null || true)

if [ -n "$HITS" ]; then
    echo "❌ Unsafe \${{ toJSON(...) }} interpolation inside a bash double-quoted string:"
    echo "$HITS" | sed 's/^/   /'
    echo ""
    echo "   toJSON renders multi-line JSON with embedded \" characters."
    echo "   The embedded quotes terminate the bash string early; jq sees"
    echo "   a malformed payload and fails with a parse error at runtime."
    echo ""
    echo "   Fix: pass the JSON via an env: clause, then read it with"
    echo "   printf '%s' \"\$VAR\" or <<< \"\$VAR\"."
    exit 1
fi

echo "✅ No unsafe \${{ toJSON(...) }} bash interpolations in $WORKFLOW_DIR/*.yml."
