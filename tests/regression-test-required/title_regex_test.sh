#!/usr/bin/env bash
# Regression test for the title classifier in
# .github/workflows/regression-test-required.yml.
#
# Two failure modes this test pins:
#   1. The previous glob check missed `fix!:` (Conventional Commits "breaking
#      change" form without a scope). The regex below covers it.
#   2. An earlier draft inlined the same regex inside `[[ =~ ... ]]` directly,
#      which triggered `bash: syntax error in conditional expression:
#      unexpected token ')'` on the GitHub-hosted runner. The workflow now
#      stores the pattern in a variable; this test reads the actual workflow
#      file and asserts both that property and that the variable's value
#      matches the regex below.
#
# Run locally:
#   bash tests/regression-test-required/title_regex_test.sh
set -euo pipefail

# Keep this regex byte-identical to the workflow's classifier step.
regex='^fix(\([^)]*\))?!?:'

# 0. Workflow-shape assertions — regression for the inline-regex parser bug.
script_dir="$(cd "$(dirname "$0")" && pwd)"
workflow_file="$script_dir/../../.github/workflows/regression-test-required.yml"
if [[ ! -f "$workflow_file" ]]; then
  echo "FAIL: cannot locate workflow file at $workflow_file"
  exit 1
fi

if ! grep -qF "fix_title_regex='$regex'" "$workflow_file"; then
  echo "FAIL: workflow file does not assign the expected regex to fix_title_regex"
  echo "      (this would mean the regex drifted from this test, or was inlined again)"
  exit 1
fi

if grep -E '\[\[\s*"\$PR_TITLE"\s*=~\s*\^fix' "$workflow_file" >/dev/null; then
  echo "FAIL: workflow inlines the regex into [[ =~ ... ]]; this triggers a"
  echo "      bash parser error on unescaped ')'. Use a variable instead."
  exit 1
fi
echo "PASS (workflow shape): regex stored in fix_title_regex variable"


declare -a should_match=(
  "fix: subject"
  "fix(api): subject"
  "fix!: subject"
  "fix(api)!: subject"
  "fix(api/v2): subject"
  "fix(http,grpc): subject"
)

declare -a should_not_match=(
  "feat: subject"
  "fix subject"
  "fixup: subject"
  "Fix: subject"
  "fix : subject"
  "chore(fix): subject"
)

failures=0

for t in "${should_match[@]}"; do
  if [[ "$t" =~ $regex ]]; then
    echo "PASS (match): $t"
  else
    echo "FAIL (expected match): $t"
    failures=$((failures + 1))
  fi
done

for t in "${should_not_match[@]}"; do
  if [[ "$t" =~ $regex ]]; then
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
