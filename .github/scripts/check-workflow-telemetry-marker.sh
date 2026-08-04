#!/usr/bin/env bash
# CI lint: every workflow that runs the AxonFlow agent in the GH Actions
# runner (via docker compose / docker run / direct binary / go run) MUST
# declare its telemetry disposition. One of:
#
#   - AXONFLOW_TELEMETRY: 'off' (or "off")                   no telemetry rows emitted
#   - AXONFLOW_LICENSE_KEY: ${{ secrets.AXONFLOW_INTERNAL_LICENSE_* }}  internal license → org_id classifier picks it up
#   - # telemetry-classification: <reason of >= 8 non-space chars>      escape hatch with paper trail
#
# Without one of these, a new workflow silently emits agent heartbeats from
# the GitHub-Actions runner IP (Microsoft Corp / Azure block) and pollutes
# the external-telemetry digest. Pre-PR-3 noise pattern: each
# scheduled-performance-benchmark.yml run leaked 5 Fargate-task heartbeats
# into prod-checkpoint-telemetry-events because its workflow lacked the
# marker. See epic #2047 + the 2026-05-13 audit findings.
#
# Detection — agent-run patterns this lint catches:
#   - `docker compose ... up|run|start ...`         (any number of -f/--env-file flags)
#   - `docker run ... axonflow-(agent|orchestrator) ...`
#   - direct binary invocation: `./platform/agent/agent`, `bin/agent`, `./bin/agent`
#   - `go run .../cmd/agent/...` or `go run .../platform/agent/...`
#
# Marker matching strips '#' comments first to avoid false-positives where a
# documentation comment mentions a secret name without the workflow actually
# wiring it.
#
# Known limitation: marker scope is FILE-WIDE, not per-job. A multi-job
# workflow with marker in job-A and agent in job-B would pass this lint
# but be runtime-broken. Tracked separately for a follow-up YAML-aware pass.

set -euo pipefail

WORKFLOWS_DIR="${1:-.github/workflows}"

if [ ! -d "$WORKFLOWS_DIR" ]; then
    echo "::error::Workflows directory not found: $WORKFLOWS_DIR" >&2
    exit 2
fi

# Pattern 1: workflow runs `docker compose <flags...> up|run|start` of an
# axonflow stack. The flag pattern is greedy on `-X value` pairs.
DOCKER_COMPOSE_PATTERN='docker[ -]compose([ ]+(-[a-zA-Z]|--[a-zA-Z-]+)([ ]+[^ ]+)?)*[ ]+(up|run|start)\b'

# Pattern 2: workflow does `docker run` of the published axonflow image.
DOCKER_RUN_PATTERN='docker[ ]+run([ ]+(-[a-zA-Z]|--[a-zA-Z-]+)([ ]+[^ ]+)?)*[ ]+[^ ]*axonflow-(agent|orchestrator)'

# Pattern 3: direct binary or go-run invocation.
DIRECT_BINARY_PATTERN='(\./)?(platform/agent/agent|platform/orchestrator/orchestrator|bin/agent|bin/orchestrator)\b|go[ ]+run[ ]+[^ ]*(/cmd/agent|/cmd/orchestrator|/platform/agent|/platform/orchestrator)'

# Combined — workflow "runs the agent" if any of these match.
RUNS_AGENT_COMBINED="(${DOCKER_COMPOSE_PATTERN})|(${DOCKER_RUN_PATTERN})|(${DIRECT_BINARY_PATTERN})"

# Marker patterns. Quoting variants accepted: 'off', "off", off (bare YAML).
# 'OFF' / "OFF" rejected (over-strict on purpose — single canonical form
# keeps grep-ability + author muscle memory consistent).
MARKER_TELEMETRY_OFF='AXONFLOW_TELEMETRY:[[:space:]]+(['\''"]?)off\1[[:space:]]*$|AXONFLOW_TELEMETRY=off|AXONFLOW_TELEMETRY="off"'
MARKER_INTERNAL_LICENSE='AXONFLOW_LICENSE_KEY:[[:space:]]+\$\{\{[[:space:]]*secrets\.AXONFLOW_INTERNAL_LICENSE_[A-Z_]+'
# Escape hatch requires >= 8 non-space chars after the colon. "idk" doesn't
# qualify; "ci-only-bench" does. Forces the author to write something
# meaningful enough to be future-readable.
MARKER_ESCAPE_HATCH='#[[:space:]]+telemetry-classification:[[:space:]]+[^[:space:]]{8,}'

violations=0
checked=0
exempt=0

for wf in "$WORKFLOWS_DIR"/*.yml "$WORKFLOWS_DIR"/*.yaml; do
    [ -f "$wf" ] || continue
    checked=$((checked + 1))

    # Skip if the workflow doesn't run the agent.
    if ! grep -qE "$RUNS_AGENT_COMBINED" "$wf"; then
        exempt=$((exempt + 1))
        continue
    fi

    # Strip comment lines before marker matching. A comment that *mentions*
    # `secrets.AXONFLOW_INTERNAL_LICENSE_E2E` for documentation is NOT a
    # real wiring — only an actual env binding satisfies the marker.
    #
    # Written to a TEMP FILE, not piped into grep. Under `set -o pipefail` (line
    # 2), `echo "$body" | grep -q PATTERN` returns 141 for a SUCCESSFUL match
    # once the body outgrows the pipe buffer: grep -q exits the instant it
    # matches, echo takes SIGPIPE on the rest, and pipefail promotes echo's
    # failure to the pipeline status. So a workflow that DOES carry the marker
    # reads as missing it, and the bigger the workflow the more likely it is.
    # Observed on .github/workflows/sdk-smoke-tests.yml (31 KB): the runner
    # logged "line 83: echo: write error: Broken pipe" and the lint reported the
    # marker absent while it was present at line 63.
    body_no_comments_file=$(mktemp)
    grep -v -E '^[[:space:]]*#' "$wf" > "$body_no_comments_file" || true

    has_marker=0
    if grep -qE "$MARKER_TELEMETRY_OFF" "$body_no_comments_file"; then has_marker=1; fi
    if grep -qE "$MARKER_INTERNAL_LICENSE" "$body_no_comments_file"; then has_marker=1; fi
    rm -f "$body_no_comments_file"
    # Escape hatch IS a comment — match against the original file (not the
    # comment-stripped body). Anchor at start-of-line + leading-whitespace
    # so it can't appear inside a string literal.
    if grep -qE "$MARKER_ESCAPE_HATCH" "$wf"; then has_marker=1; fi

    if [ "$has_marker" = "0" ]; then
        echo "::error file=${wf}::Workflow runs an AxonFlow agent but lacks a telemetry marker." >&2
        echo "    Add ONE of:" >&2
        echo "      env:" >&2
        echo "        AXONFLOW_TELEMETRY: 'off'                                                  # default for build/test/smoke" >&2
        echo "      AXONFLOW_LICENSE_KEY: \${{ secrets.AXONFLOW_INTERNAL_LICENSE_<SURFACE> }}     # for telemetry-path tests (PR-2/PR-5 design)" >&2
        echo "      # telemetry-classification: <reason of >= 8 chars>                          # escape hatch (rare)" >&2
        violations=$((violations + 1))
    fi
done

echo "Workflows scanned: ${checked} (agent-running: $((checked - exempt)), exempt: ${exempt})" >&2

if [ "$violations" -gt 0 ]; then
    echo "::error::${violations} workflow(s) missing telemetry marker. Fix per the message above." >&2
    exit 1
fi

echo "All agent-running workflows carry a telemetry marker. ✓" >&2
