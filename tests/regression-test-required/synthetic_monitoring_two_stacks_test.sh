#!/usr/bin/env bash
#
# The synthetic-monitoring templates are THREE stacks now (#3655, then #3602),
# and every split creates the same three ways for them to drift apart silently.
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
# THREE templates since #3602. The third exists for the same reason the second
# did - see the header - and the byte check below is what makes the next squeeze
# visible before it breaks a deploy.
DS_TPL='infrastructure/cloudformation/synthetic-monitoring-decision-shadow.yaml'
WORKFLOW='.github/workflows/deploy-synthetic-monitoring.yml'
LIMIT=51200
# The S3-hosted cap, which is what a template over the body cap is actually
# held to since #3694 - measured against the API, not read from a doc: 1 MB
# (1,048,576) is REJECTED with "Template may not exceed 1000000 bytes in size".
HARD_LIMIT=1000000
# cfn-change-set.sh takes the body path only below 90% of the body cap, so a
# template above this is URL-deployed and its ceiling is HARD_LIMIT.
BODY_PATH_MAX=$(( LIMIT * 90 / 100 ))

pass=0
fail=0
ok()  { echo "  ✅ PASS: $1"; pass=$((pass + 1)); }
bad() { echo "  ❌ FAIL: $1"; fail=$((fail + 1)); }

echo "=== synthetic-monitoring: two templates, one deploy ==="

for f in "$BASE_TPL" "$IC_TPL" "$DS_TPL" "$WORKFLOW"; do
  if [ ! -f "$f" ]; then
    echo "  ❌ FAIL: $f is missing; this guard cannot check what it cannot read"
    exit 1
  fi
done

# --- 1. the byte limit -------------------------------------------------------
for f in "$BASE_TPL" "$IC_TPL" "$DS_TPL"; do
  n=$(wc -c < "$f" | tr -d ' ')
  if [ "$n" -le "$LIMIT" ]; then
    ok "$(basename "$f") is ${n} bytes, $((LIMIT - n)) under the --template-body limit"
  elif (( n <= HARD_LIMIT )); then
    # NOT a failure since #3694: above 90% of the body cap the deploy uploads
    # the template and passes --template-url, whose ceiling is HARD_LIMIT. This
    # check used to fail here and say "every deploy of this stack fails at
    # validate-template", which is no longer true and would have reddened the
    # first template that made use of the headroom this repo just bought it.
    ok "$(basename "$f") is ${n} bytes: URL-deployed, $((HARD_LIMIT - n)) under the ${HARD_LIMIT}-byte S3-hosted limit"
  else
    bad "$(basename "$f") is ${n} bytes, $((n - HARD_LIMIT)) OVER the ${HARD_LIMIT}-byte S3-hosted limit the API enforces (\"Template may not exceed 1000000 bytes in size\"). NEITHER deploy path can carry it. See #3694; do not buy room by deleting other people's comments."
  fi
done

# --- 2 and 3: parsed checks --------------------------------------------------
#
# In a Python file rather than a heredoc, because a heredoc that itself contains
# a heredoc terminator is a shape that fails at the shell rather than at the
# check, and this guard is the thing that has to be trustworthy.
python3 "tests/regression-test-required/lib/synthetic_monitoring_two_stacks.py" \
  "$BASE_TPL" "$IC_TPL" "$DS_TPL" "$WORKFLOW"
rc=$?
if [ "$rc" -eq 0 ]; then
  pass=$((pass + 2))
else
  fail=$((fail + 1))
fi

# ---------------------------------------------------------------------------
# 4. THE BASE CANARY'S MCP STEP AUTHENTICATES.
#
# #3834 rewrote step 2 from `mcpCheckInput` - which the JSON-RPC dispatcher
# does NOT implement, so method-not-found came back as HTTP 200 and the step
# passed hourly while dispatching nothing - to `initialize`, which it does.
#
# That is what broke it. An UNKNOWN method reaches method-not-found and is
# served 200; a KNOWN one is refused at the AUTH LAYER first. So making the
# step honest moved the request behind the auth gate, the credentials were not
# carried with it, and the canary alerted the operator `401 Registration
# required` every hour until #3602's follow-up.
#
# The unauth path's documented tenant-resolution route (`params.context.
# tenant_id`, ADR-050 4, #1881) is the obvious smaller fix and it does NOT
# work - measured against the live stack, it still 401s. That is why this row
# asserts the CREDENTIALS and not a tenant field.
#
# A template-text assertion, in the shape of the rows above: the step-2
# `_request` to /api/v1/mcp-server must carry `basic_auth`.
# ---------------------------------------------------------------------------
echo ""
echo "4. the base canary's MCP step passes credentials"

# The block from the mcp-server request line to the end of that _request call.
mcp_call="$(awk "/'POST', '\/api\/v1\/mcp-server'/,/^ *\)/" "$BASE_TPL")"

if [ -z "$mcp_call" ]; then
  bad "could not find the step-2 _request to /api/v1/mcp-server in $BASE_TPL; the extraction is broken, not the template - every assertion below would pass vacuously"
elif printf '%s' "$mcp_call" | grep -q 'basic_auth=(tenant_id, secret)'; then
  ok "the step-2 MCP request carries basic_auth=(tenant_id, secret)"
else
  bad "the step-2 _request to /api/v1/mcp-server does NOT pass basic_auth. 'initialize' is a method the dispatcher implements, so it is refused at the auth layer with 401 'Registration required' - the canary then alerts hourly against production. Pass the credentials step 1 mints, as the audit-search step does. params.context.tenant_id is NOT a substitute; it was measured against the live stack and still 401s (#3602)."
fi

# ANTI-VACUITY. The extraction must really be the mcp-server call and not, say,
# the audit-search one below it - which also carries basic_auth and would make
# the assertion above pass for the wrong request.
if printf '%s' "$mcp_call" | grep -q 'audit/search'; then
  bad "the extracted block spans past the mcp-server request into audit-search; the assertion above would be satisfied by the WRONG call's credentials"
else
  ok "the extracted block is the mcp-server request alone, not the audit-search call below it"
fi

echo ""
echo "Results: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ] || exit 1
echo "All tests passed!"
