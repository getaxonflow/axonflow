#!/usr/bin/env bash
# Regression guard: scheduled-performance-benchmark.yml's report parser must
# emit ONE row per phase (a sustained_load invocation) and surface BOTH
# HTTP-success and policy-correctness columns separately.
#
# Why both: iteration-4 reported "100% Success at 100 RPS" — that figure was
# HTTP-success only; 53% of those requests had the WRONG policy verdict
# (BLOCK-expected got ALLOW). Post-iteration-4 the rule is: "% Success" must
# reflect business correctness OR be renamed and accompanied by a separate
# correctness column. We chose the latter — keep "HTTP 2xx" but add
# "Correctness %" derived from the harness's `Unexpected:` counter.
#
# Why per-phase: daily mode runs two sustained_load invocations (capacity +
# realistic-with-LLM). The pre-fix parser used `head -1` on each grep,
# silently dropping Phase 2's numbers. Phase 2 returning 0 successful
# requests was invisible in the auto-table even though it was a major
# enforcement-failure signal.

set -euo pipefail

WORKFLOW=".github/workflows/scheduled-performance-benchmark.yml"

if [ ! -f "$WORKFLOW" ]; then
    echo "❌ $WORKFLOW not found"
    exit 1
fi

FAILED=0

# 1. Phase splitter must exist — awk slicing on `^Test Type:` lines.
if ! grep -qE '/\^Test Type:\[\[:space:\]\]\+/' "$WORKFLOW"; then
    echo "❌ $WORKFLOW does not split log into per-phase chunks via Test Type: lines"
    FAILED=1
fi

# 2. Helper function `parse_phase_to_table_row` must be defined.
if ! grep -qE '^[[:space:]]*parse_phase_to_table_row\(\)' "$WORKFLOW"; then
    echo "❌ $WORKFLOW does not define parse_phase_to_table_row()"
    FAILED=1
fi

# 3. Both HTTP-success and Correctness columns must be in the table header.
if ! grep -qE '\| Mode \| Phase \| Total req \| HTTP 2xx \| Correctness' "$WORKFLOW"; then
    echo "❌ $WORKFLOW results table does not have separate HTTP 2xx + Correctness columns"
    FAILED=1
fi

# 4. Parser must extract Unexpected count + compute correctness via awk.
if ! grep -qE 'unexpected=\$\(echo "\$block" \| grep -oE .Unexpected:' "$WORKFLOW"; then
    echo "❌ $WORKFLOW parser does not extract Unexpected: count from harness output"
    FAILED=1
fi
if ! grep -qE 'awk -v t="\$total" -v u="\$unexpected"' "$WORKFLOW"; then
    echo "❌ $WORKFLOW parser does not compute Correctness % via awk on (total, unexpected)"
    FAILED=1
fi

# 5. ECR pull retry — launch_with_retry helper present + retries on
#    CannotPullContainerError.
if ! grep -qE '^[[:space:]]*launch_with_retry\(\)' "$WORKFLOW"; then
    echo "❌ $WORKFLOW does not define launch_with_retry() for ECR pull retry"
    FAILED=1
fi
if ! grep -qE 'CannotPullContainerError\|i/o timeout' "$WORKFLOW"; then
    echo "❌ $WORKFLOW launch_with_retry does not detect CannotPullContainerError / i/o timeout"
    FAILED=1
fi

# 6. Parser must NOT use the old `head -1` shortcut on the whole log block
#    for Total Requests / P50 / P95 / P99 anymore — those greps are now
#    PER-PHASE (inside parse_phase_to_table_row, where head -1 is correct).
#    Outside the helper there should be no `head -1` against the FULL log.
#    We approximate this check by ensuring the legacy single-row emission
#    `echo "| $MODE | $TOTAL | ...| $SLO |"` is GONE from the file.
if grep -qE 'echo "\| \$MODE \| \$TOTAL \| \$SUCCESS \| \$P50' "$WORKFLOW"; then
    echo "❌ $WORKFLOW still emits the pre-fix single-row format that lost Phase 2 numbers"
    FAILED=1
fi

# 7. Monthly-cadence workflow inputs must be present:
#    - environment (chooses in-vpc-enterprise vs saas-perf-testing stack)
#    - tls_server_name (LOAD_TEST_TLS_SERVER_NAME for SNI override)
#    - coldstart_window (0 = disabled; >0 = warm-up curve in same run)
for input in environment tls_server_name coldstart_window; do
    if ! grep -qE "^      ${input}:$" "$WORKFLOW"; then
        echo "❌ $WORKFLOW does not declare workflow_dispatch input '${input}' (required for monthly-cadence cross-topology runs)"
        FAILED=1
    fi
done

# 8. ENVIRONMENT must derive from inputs.environment (not hardcoded), so the
#    same workflow can drive both perf stacks.
if ! grep -qE 'ENVIRONMENT:[[:space:]]+\$\{\{ inputs\.environment \|\| .in-vpc-enterprise. \}\}' "$WORKFLOW"; then
    echo "❌ $WORKFLOW ENVIRONMENT env var must derive from inputs.environment with a back-compat default"
    FAILED=1
fi

# 9. Stack-finder must use a generic prefix derived from the env name, not
#    a hardcoded 'axonflow-in-vpc-enterprise-' prefix. Required for the
#    SaaS topology to be findable by the same workflow.
if grep -qE "starts_with\(StackName,[[:space:]]+'axonflow-in-vpc-enterprise-'\)" "$WORKFLOW"; then
    echo "❌ $WORKFLOW still hardcodes the in-vpc-enterprise stack prefix; must use \${ENVIRONMENT}-based prefix for cross-topology support"
    FAILED=1
fi

# 10. Run-task overrides must be built via jq (so multiple env vars including
#     LOAD_TEST_TLS_SERVER_NAME and COLDSTART_WINDOW can be conditionally
#     injected without bash quoting traps).
if ! grep -qE 'OVERRIDES_JSON=\$\(jq' "$WORKFLOW"; then
    echo "❌ $WORKFLOW does not build container overrides via jq (required for safe LOAD_TEST_TLS_SERVER_NAME / COLDSTART_WINDOW injection)"
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "Effect of any of the above gaps: daily-mode benchmarks publish a"
    echo "headline number that hides Phase 2 saturation, or report % Success"
    echo "as HTTP-200 even when policy enforcement is bypassed. Both produce"
    echo "misleading benchmarks (per feedback_perf_success_must_mean_correctness)."
    exit 1
fi

echo "✅ scheduled-performance-benchmark.yml parser splits per phase + surfaces correctness + retries on ECR pull errors."
