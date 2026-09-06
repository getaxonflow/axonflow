#!/usr/bin/env bash
#
# The synthetic-monitoring templates are TWO stacks now, and the split created
# three ways for them to drift apart silently (#3655).
#
# WHY THE SPLIT EXISTS, because the guard is meaningless without it: `aws
# cloudformation` caps --template-body at 51,200 bytes and the deploy workflow
# uses that form at both validate-template and create-change-set. The combined
# template had reached 50,611 bytes - 589 of headroom - so no change to the
# identity-compat canary could be made without breaking the deploy. The lasting
# fix (package to S3, deploy by URL, 1 MB limit) is #3694; this is the interim.
#
# WHAT THIS GUARDS
#
#   1. BOTH templates stay under the limit. The whole point of the split was
#      headroom, and headroom is spent by ordinary edits. A template that
#      crosses the line fails at deploy time - which is to say, it is validated
#      by the deploy failing, on the stack whose job is to notice failures.
#
#   2. THE PARAMETER LISTS AGREE, IN BOTH DIRECTIONS, PER STACK. A parameter
#      declared and not passed silently takes its CloudFormation Default, or
#      fails the change set if it has none. A parameter PASSED and not declared
#      is rejected by CloudFormation outright. Both are invisible at review: the
#      template is right, the workflow is right, and only the pair is wrong.
#
#   3. THE TWO TEMPLATES DO NOT BOTH DEFINE A RESOURCE. A logical id present in
#      both would be deployed twice under two stack names - two Lambdas, two
#      schedules, two alert streams - and nothing about either template alone
#      says so.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

BASE_TPL='infrastructure/cloudformation/synthetic-monitoring.yaml'
IC_TPL='infrastructure/cloudformation/synthetic-monitoring-identity-compat.yaml'
WORKFLOW='.github/workflows/deploy-synthetic-monitoring.yml'
LIMIT=51200

pass=0
fail=0
ok()  { echo "  ✅ PASS: $1"; pass=$((pass + 1)); }
bad() { echo "  ❌ FAIL: $1"; fail=$((fail + 1)); }

echo "=== synthetic-monitoring: two templates, one deploy ==="

for f in "$BASE_TPL" "$IC_TPL" "$WORKFLOW"; do
  if [ ! -f "$f" ]; then
    echo "  ❌ FAIL: $f is missing; this guard cannot check what it cannot read"
    exit 1
  fi
done

# --- 1. the byte limit -------------------------------------------------------
for f in "$BASE_TPL" "$IC_TPL"; do
  n=$(wc -c < "$f" | tr -d ' ')
  if [ "$n" -le "$LIMIT" ]; then
    ok "$(basename "$f") is ${n} bytes, $((LIMIT - n)) under the --template-body limit"
  else
    bad "$(basename "$f") is ${n} bytes, $((n - LIMIT)) OVER the ${LIMIT}-byte --template-body limit. Every deploy of this stack fails at validate-template. See #3694 for the lasting fix; do not buy room by deleting other people's comments."
  fi
done

# --- 2 and 3: parsed checks --------------------------------------------------
#
# In a Python file rather than a heredoc, because a heredoc that itself contains
# a heredoc terminator is a shape that fails at the shell rather than at the
# check, and this guard is the thing that has to be trustworthy.
python3 "tests/regression-test-required/lib/synthetic_monitoring_two_stacks.py" \
  "$BASE_TPL" "$IC_TPL" "$WORKFLOW"
rc=$?
if [ "$rc" -eq 0 ]; then
  pass=$((pass + 2))
else
  fail=$((fail + 1))
fi

echo ""
echo "Results: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ] || exit 1
echo "All tests passed!"
