#!/usr/bin/env bash
# Regression guard: every step-level $GITHUB_OUTPUT key in
# .github/workflows/update-stack.yml that is *consumed* via
# ${{ needs.<job>.outputs.<key> }} elsewhere in the file must also be
# exposed in that job's `outputs:` block. Without the job-level
# declaration, dependent jobs receive an empty string — the logs in
# the producing job look correct, but downstream silently misbehaves.
#
# This is the bug PR #1810 fixed: PR #1808 wrote agent_replicas /
# orchestrator_replicas via the prepare step's `echo ... >> $GITHUB_OUTPUT`
# AND consumed them downstream via `${{ needs.prepare.outputs.agent_replicas }}`
# in the build-params step, but the prepare job's outputs: block didn't
# declare those names — so the build step got "" and the resize was a
# no-op.
#
# The guard:
#   1. Collect every key written to $GITHUB_OUTPUT.
#   2. Collect every key referenced as `needs.<job>.outputs.<key>`.
#   3. The intersection is the set of step outputs that MUST be exposed
#      at the job level. Step outputs not in (2) are consumed only
#      within the same job (e.g. via steps.<id>.outputs.<key>) and
#      legitimately don't need a job-level declaration.
#   4. Collect every key declared in any job's `outputs:` block.
#   5. Anything in (3) that's not in (4) is the bug.

set -euo pipefail

WORKFLOW=".github/workflows/update-stack.yml"

if [ ! -f "$WORKFLOW" ]; then
    echo "❌ $WORKFLOW not found"
    exit 1
fi

# 1. Step-level $GITHUB_OUTPUT writes: `echo "<key>=$VAL" >> $GITHUB_OUTPUT`
STEP_OUTPUTS=$(grep -oE 'echo "([a-z_][a-z_0-9]*)=' "$WORKFLOW" \
    | sed -E 's/echo "([a-z_][a-z_0-9]*)=/\1/' \
    | sort -u)

# 2. Cross-job consumers: `needs.<job>.outputs.<key>`
CONSUMED_OUTPUTS=$(grep -oE 'needs\.[a-z_-]+\.outputs\.[a-z_][a-z_0-9]*' "$WORKFLOW" \
    | sed -E 's/needs\.[a-z_-]+\.outputs\.//' \
    | sort -u)

if [ -z "$STEP_OUTPUTS" ] || [ -z "$CONSUMED_OUTPUTS" ]; then
    echo "ℹ️  No step-level outputs or no cross-job consumers found in $WORKFLOW; nothing to validate."
    exit 0
fi

# 3. Intersection = step outputs that must be exposed at the job level.
MUST_EXPOSE=$(comm -12 <(echo "$STEP_OUTPUTS") <(echo "$CONSUMED_OUTPUTS"))

# 4. Currently declared at the job level (any job's outputs: block).
JOB_OUTPUTS=$(awk '
    /^[[:space:]]*outputs:[[:space:]]*$/ { in_outputs=1; next }
    in_outputs && /^[[:space:]]+[a-z_][a-z_0-9]*:[[:space:]]+\$\{\{/ {
        match($0, /^[[:space:]]+[a-z_][a-z_0-9]*:/)
        key = substr($0, RSTART, RLENGTH)
        gsub(/[[:space:]:]/, "", key)
        print key
        next
    }
    in_outputs && /^[[:space:]]+[a-zA-Z]/ && !/^[[:space:]]+[a-z_][a-z_0-9]*:[[:space:]]+\$\{\{/ {
        in_outputs=0
    }
' "$WORKFLOW" | sort -u)

# 5. Diff: must-expose minus already-declared.
MISSING=$(comm -23 <(echo "$MUST_EXPOSE") <(echo "$JOB_OUTPUTS"))

if [ -n "$MISSING" ]; then
    echo "❌ update-stack.yml writes step-level outputs that are CONSUMED via needs.<job>.outputs.<key>"
    echo "   but are NOT declared in the producing job's outputs: block."
    echo ""
    echo "   Missing declarations:"
    echo "$MISSING" | sed 's/^/   - /'
    echo ""
    echo "   Effect: dependent jobs receive an empty string instead of the value,"
    echo "   while the producing job's logs make it look correct."
    echo "   Pattern: PR #1810 — 5+10 resize was a no-op because of exactly this gap."
    echo ""
    echo "   Add each key to the producing job's outputs: block. Mirror the"
    echo "   existing keys (region, enabled_connectors, …)."
    exit 1
fi

echo "✅ Every cross-job-consumed step output in $WORKFLOW is declared at the job level."
