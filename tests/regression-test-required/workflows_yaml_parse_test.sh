#!/usr/bin/env bash
# Regression guard: every file under .github/workflows/ must be valid YAML.
#
# This is the bug fix/perf-benchmark-yaml-parse closed:
# scheduled-performance-benchmark.yml had a `gh pr create --body "..."`
# multi-line double-quoted string whose blank line sat at column 1.
# YAML's literal-block scalar (`run: |`) terminates on any non-empty line
# below the block's indent, so the parser saw the bash string's blank
# line as the end of `run:` and tried to read the next bash line as a
# new YAML key — failing with "could not find expected ':'".
#
# Symptom: every push of that workflow showed up in the Actions UI with
# `name = .github/workflows/scheduled-performance-benchmark.yml` (the
# path) instead of "Scheduled Performance Benchmark" (the declared
# `name:`), every run failed before any job started, and
# `gh workflow run …/dispatches` returned HTTP 422 with
# `Workflow does not have 'workflow_dispatch' trigger` — because the
# workflow registration had no parsed `on:` block.
#
# Catching this requires nothing more than running the YAML parser
# against every workflow file. CI runners on GitHub Actions don't do
# this for us — broken workflows just silently fail.

set -euo pipefail

WORKFLOW_DIR=".github/workflows"

if [ ! -d "$WORKFLOW_DIR" ]; then
    echo "ℹ️  $WORKFLOW_DIR not present; nothing to validate."
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ python3 required for YAML parse check"
    exit 1
fi

FAILED=()
while IFS= read -r -d '' f; do
    if ! python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null; then
        FAILED+=("$f")
    fi
done < <(find "$WORKFLOW_DIR" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)

if [ ${#FAILED[@]} -gt 0 ]; then
    echo "❌ The following workflow files do not parse as YAML:"
    for f in "${FAILED[@]}"; do
        echo "   - $f"
        # Re-run, surface only the scanner error and its location lines.
        python3 -c "
import yaml, sys
try:
    yaml.safe_load(open('$f'))
except yaml.YAMLError as e:
    print(e, file=sys.stderr)
    sys.exit(1)
" 2>&1 | sed 's/^/       /'
    done
    echo ""
    echo "   Effect: GitHub Actions cannot register the workflow. Every"
    echo "   push run shows up as a failure with no jobs, and"
    echo "   workflow_dispatch returns HTTP 422 because no triggers parse."
    echo "   Pattern: a multi-line bash double-quoted string inside run: |"
    echo "   whose continuation lines sit at column 1 will end the block."
    exit 1
fi

echo "✅ All ${WORKFLOW_DIR}/*.yml files parse as YAML."
