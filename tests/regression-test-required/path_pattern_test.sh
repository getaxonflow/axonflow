#!/usr/bin/env bash
# Regression test for the file-path matcher in
# .github/workflows/regression-test-required.yml.
#
# Failure mode this test pins:
#   The previous matcher used `(^|/)tests?/` as a directory fallback, which
#   credited ANY added/modified path under tests/ as a regression test —
#   including JSON snapshots, YAML fixtures, markdown helpers, and other
#   non-executable files. A bug-fix PR could satisfy the gate by editing a
#   fixture without adding executable coverage. The matcher now requires a
#   code extension on the directory branch so non-code churn under tests/
#   no longer satisfies the gate.
#
# This test asserts:
#   1. The workflow file's `test_pattern` value is byte-identical to the regex
#      below (so a future drift in either place fails this test).
#   2. The pattern matches every path the gate is supposed to accept.
#   3. The pattern rejects every path the gate is supposed to reject —
#      including the historical loophole cases (fixtures, snapshots, markdown
#      under tests/).
#
# Run locally:
#   bash tests/regression-test-required/path_pattern_test.sh
set -euo pipefail

# Keep this regex byte-identical to the workflow's matcher step.
test_pattern='(_test\.go$|_test\.py$|\.test\.tsx?$|\.spec\.tsx?$|Test\.java$|Tests\.java$|IT\.java$|(^|/)tests?/.*\.(go|py|tsx?|java|sh|rb|rs|kt)$)'

# 0. Workflow-shape assertion — regression for drift between this test and the
# actual workflow.
script_dir="$(cd "$(dirname "$0")" && pwd)"
workflow_file="$script_dir/../../.github/workflows/regression-test-required.yml"
if [[ ! -f "$workflow_file" ]]; then
  echo "FAIL: cannot locate workflow file at $workflow_file"
  exit 1
fi

if ! grep -qF "test_pattern='$test_pattern'" "$workflow_file"; then
  echo "FAIL: workflow file does not assign the expected regex to test_pattern."
  echo "      Expected: test_pattern='$test_pattern'"
  echo "      (this means the regex drifted between this test and the workflow)"
  exit 1
fi
echo "PASS (workflow shape): test_pattern in workflow matches this test"


# Paths the gate MUST accept.
declare -a should_match=(
  # Naming-convention branches
  "platform/agent/policy_test.go"
  "axonflow/handler_test.py"
  "ee/platform/customer-portal-ui/src/page.test.ts"
  "ee/platform/customer-portal-ui/src/page.test.tsx"
  "ee/platform/customer-portal-ui/src/page.spec.ts"
  "ee/platform/customer-portal-ui/src/page.spec.tsx"
  "sdk/src/main/java/com/getaxonflow/FooTest.java"
  "sdk/src/main/java/com/getaxonflow/FooTests.java"
  "sdk/src/main/java/com/getaxonflow/FooIT.java"

  # Code under tests/ or test/ — directory branch
  "tests/integration/foo_test.go"
  "tests/regression-test-required/path_pattern_test.sh"
  "test/foo.go"
  "tests/scripts/runner.py"
  "ee/tests/parity_check.go"
  "service/test/handler_test.java"
  "tests/spec/foo.tsx"
  "tests/feature.rb"
  "tests/integration_test.rs"
  "tests/runner.kt"
)

# Paths the gate MUST reject. Non-code churn under tests/ is the loophole the
# new pattern closes; deletions are handled separately by --diff-filter=AM in
# the workflow itself, not by this regex.
declare -a should_not_match=(
  # Source / non-test code outside tests/
  "platform/agent/handler.go"
  "axonflow/client.py"
  "ee/platform/customer-portal-ui/src/page.tsx"

  # Loophole closures: non-code under tests/
  "tests/snapshots/payload.json"
  "tests/fixtures/data.yaml"
  "tests/fixtures/data.yml"
  "tests/README.md"
  "tests/CHANGELOG.md"
  "tests/integration/expected.txt"
  "test/golden/output.csv"
  "tests/openapi/spec.yaml"
  "tests/.gitkeep"
  "tests/static/image.png"
  "ee/tests/notes.md"

  # Cases that look test-ish but aren't accepted
  "platform/tests-summary.md"      # dash, not /tests/
  "tests"                          # bare dir name, no file
  "src/testing/util.go"            # testing/ ≠ tests/ or test/
  "src/contests/foo.go"            # contests/ matches "tests" as substring; the (^|/) anchor must reject
)

failures=0

for t in "${should_match[@]}"; do
  if [[ "$t" =~ $test_pattern ]]; then
    echo "PASS (match): $t"
  else
    echo "FAIL (expected match): $t"
    failures=$((failures + 1))
  fi
done

for t in "${should_not_match[@]}"; do
  if [[ "$t" =~ $test_pattern ]]; then
    echo "FAIL (expected no match): $t"
    failures=$((failures + 1))
  else
    echo "PASS (no match): $t"
  fi
done

if (( failures > 0 )); then
  echo
  echo "$failures case(s) failed."
  exit 1
fi

echo
echo "All ${#should_match[@]} match + ${#should_not_match[@]} no-match cases passed."
