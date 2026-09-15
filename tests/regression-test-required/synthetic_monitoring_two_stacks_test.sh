#!/usr/bin/env bash
#
# The synthetic-monitoring templates are TWO stacks (#3655, then #3602; the
# identity-compat canary's template was retired with the identity comparison in
# v11), and every split creates the same three ways for them to drift apart
# silently.
#
# WHY THE SPLIT EXISTS, because the guard is meaningless without it: `aws
# cloudformation` caps --template-body at 51,200 bytes and the deploy workflow
# uses that form at both validate-template and create-change-set. The combined
# template had reached 50,611 bytes - 589 of headroom - so no change to the
# canary it then carried could be made without breaking the deploy. The lasting
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
#   3. EVERY TEMPLATE SAYS WHAT IT MONITORS. `prod` in these stack names is the
#      monitoring ACCOUNT, not the target: three of the four stacks in
#      us-east-1 named `-prod*` point at the COMMUNITY stack, so an audit by
#      stack name reads the fleet backwards (#3861). Each template emits an
#      unconditional TargetEnvironment - DERIVED from TargetBaseURL, so it
#      cannot disagree with the target the way a name can - and TargetBaseURL
#      verbatim, so one account-wide describe-stacks answers the question with
#      no per-stack Parameters lookup. A new template cannot ship without them -
#      enforced by section 0, which DERIVES the template population from a glob
#      and refuses any file this guard's own list omits. Against a named list
#      alone that sentence was false, which is why it is not one.
#
#   4. THE TWO TEMPLATES DO NOT BOTH DEFINE A RESOURCE. A logical id present in
#      both would be deployed twice under two stack names - two Lambdas, two
#      schedules, two alert streams - and nothing about either template alone
#      says so.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

# Section 5 IMPORTS the parsed half rather than running it, so CPython caches
# its bytecode - and the cache is invalidated on (mtime, SIZE). That pair is
# not enough here: this file was reported green while `_mentions` returned the
# answer of a one-character edit that had already been reverted, because `in `
# and `== ` are the same length and the two writes landed in the same second.
# A guard that answers about source no longer on disk is worse than no guard,
# and the cache buys a required suite nothing.
export PYTHONDONTWRITEBYTECODE=1

BASE_TPL='infrastructure/cloudformation/synthetic-monitoring.yaml'
# The decision-shadow template exists for the reason the split does - see the
# header - and the byte check below is what makes the next squeeze visible
# before it breaks a deploy.
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

for f in "$BASE_TPL" "$DS_TPL" "$WORKFLOW"; do
  if [ ! -f "$f" ]; then
    echo "  ❌ FAIL: $f is missing; this guard cannot check what it cannot read"
    exit 1
  fi
done

# --- 0. discovery: no synthetic-monitoring template is invisible here ---------
#
# The two paths above are POSITIONAL - each has a distinct role below (only
# the base is small enough for validate-template; the parameter agreement is
# per stack) - so they cannot simply become a glob. But a named list is also
# this guard's blind spot, and #3861's third acceptance box is the claim that a
# NEW synthetic-monitoring template cannot ship without saying what it
# monitors. That claim is FALSE against a named list: a fourth template would
# be read by nothing here and the suite would stay green.
#
# So derive the population and refuse what the list does not name. This does
# not check a new template - wiring it in is a judgement about its role - it
# makes shipping one without that wiring impossible, which is the guarantee the
# issue actually asks for.
# The comparison lives in a FUNCTION because section 6 drives it over fixtures.
# Inline, it could only ever run against the real tree - which has exactly the
# templates it names - so deleting the refusal outright left this suite
# green, and my first audit of it read a stale bytecode cache and called it
# guarded. A rule whose only input is already correct asserts nothing.
#
# NOTE FOR #3809: on the community mirror `infrastructure/` is stripped, so the
# existence loop above exits 1 before any of this runs - byte-identically to
# main, this PR does not change it. If that loop is ever softened to a SKIP,
# soften the floor below with it: a stripped tree discovers zero templates and
# the floor would then fire for the one reason it is not meant to catch.
unnamed_templates() {  # $1 = space-padded named list; $@ = discovered paths
  local named="$1"; shift
  local f rc=0
  for f in "$@"; do
    case "$named" in
      *" $f "*) ;;
      *) printf '%s\n' "$f"; rc=1 ;;
    esac
  done
  return "$rc"
}
discovery_floor_ok() { [ "$1" -ge 2 ]; }

discovered=()
for f in infrastructure/cloudformation/synthetic-monitoring*.yaml; do
  [ -e "$f" ] && discovered+=("$f")
done
if ! discovery_floor_ok "${#discovered[@]}"; then
  bad "the synthetic-monitoring*.yaml glob matched ${#discovered[@]} file(s) from $(pwd); the discovery here is broken, not the tree, and a broken discovery reports every future template as checked"
else
  unchecked="$(unnamed_templates " $BASE_TPL $DS_TPL " "${discovered[@]}")" || true
  if [ -n "$unchecked" ]; then
    for f in $unchecked; do
      bad "$f exists and this guard checks NOTHING about it: not its byte budget, not its parameter agreement, not whether it says what it monitors (#3861). Add it to the paths at the top of this file and to the argv of the parsed half; a template nobody checks is how the fleet acquired three stacks named -prod that all watch community."
    done
  else
    ok "all ${#discovered[@]} synthetic-monitoring templates on disk are named by this guard"
  fi
fi

# --- 1. the byte limit -------------------------------------------------------
for f in "$BASE_TPL" "$DS_TPL"; do
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
  "$BASE_TPL" "$DS_TPL" "$WORKFLOW"
rc=$?
if [ "$rc" -eq 0 ]; then
  # THREE parsed checks since #3861 (parameters, resource overlap, target
  # outputs). The count is here because the python prints its own PASS lines
  # and this tally has to agree with them; a stale number understates the
  # suite, which is the direction that makes a later reader think a check is
  # missing.
  pass=$((pass + 3))
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

# ---------------------------------------------------------------------------
# 5. THE TARGET-OUTPUT RULE, DRIVEN OVER FIXTURES (#3861)
#
# The rule above is checked against the REAL templates, which are correct - so
# disabling any of its four conditions changes nothing and the guard stays
# green. Established by doing it: `if False:` on each of `spec is None`,
# `'Condition' in spec`, the derivation check and the floor left this suite
# passing every time.
#
# The controls that "proved" those branches were plants in a real template, run
# by hand. They demonstrated the code works; they pinned nothing. A branch whose
# only evidence is a manual run is a branch with no row - the fourth way a
# control means nothing, and the one a row list cannot show you.
#
# So each branch gets a fixture document and a NAMED assertion here.
#
# On the strength of the `spec is None` row, corrected: an earlier version of
# this note claimed the branch was pinned only by a CRASH, because `if False:`
# lets a None reach `'Condition' in spec` and raises TypeError. That understated
# it. The mutation a real edit looks like - deleting the `problems.append` and
# keeping the `continue` - reds the two rows that name the missing output, with
# their own messages. Both mutations red; only the cruder one reds untidily.
# A limit stated too pessimistically is still a wrong statement about a guard,
# and it invites the next reader to add a row that already exists.
# ---------------------------------------------------------------------------
echo ""
echo "5. the target-output rule, over fixtures"
python3 - <<'PYTGT'
import sys
sys.path.insert(0, "tests/regression-test-required/lib")
from synthetic_monitoring_two_stacks import target_outputs

DERIVED = [0, [".", [2, ["/", "TargetBaseURL"]]]]


def doc(env=True, base=True, condition=None, value=DERIVED, base_value="TargetBaseURL"):
    out = {}
    if env:
        spec = {"Description": "x", "Value": value}
        if condition:
            spec["Condition"] = condition
        out["TargetEnvironment"] = spec
    if base:
        out["TargetBaseURL"] = {"Description": "x", "Value": base_value}
    return {"Outputs": out}


def good(n=3):
    return [("t%d.yaml" % i, doc()) for i in range(n)]


fail = 0


def check(name, problems, want):
    global fail
    joined = " | ".join(problems)
    if want in joined:
        print("  PASS: %s" % name)
    else:
        fail += 1
        print("  FAIL: %s - expected %r, got: %s" % (name, want, joined or "(no problems)"))


def check_clean(name, problems):
    """The other direction: a CORRECT shape must produce nothing.

    A rule that refuses a valid template is not a safe rule - it teaches the
    next author to route around the guard - so the false-refusal side needs its
    own row rather than being assumed from the control.
    """
    global fail
    if problems:
        fail += 1
        print("  FAIL: %s - refused a correct shape: %s" % (name, " | ".join(problems)))
    else:
        print("  PASS: %s" % name)


# The control first: three correct templates must produce NOTHING.
p = target_outputs(good())
if p:
    fail += 1
    print("  FAIL: three correct templates produced problems: %s" % p)
else:
    print("  PASS: three correct templates produce no problem (the rule is not always-red)")

check("a missing TargetEnvironment is named",
      target_outputs(good(2) + [("bad.yaml", doc(env=False))]), "no `TargetEnvironment` output")
check("a missing TargetBaseURL is named",
      target_outputs(good(2) + [("bad.yaml", doc(base=False))]), "no `TargetBaseURL` output")
check("a CONDITIONAL target output is refused",
      target_outputs(good(2) + [("bad.yaml", doc(condition="DeploySomething"))]), "is conditional on")
check("a HARDCODED TargetEnvironment is refused",
      target_outputs(good(2) + [("bad.yaml", doc(value="production-us"))]), "does not derive from")

# The finding this section was extended for: the LABEL was guarded and the URL
# was not, so replacing `Value: !Ref TargetBaseURL` with a literal passed the
# whole suite 14/0 - a hardcoded target one field over from the one #3861 came
# to remove.
check("a HARDCODED TargetBaseURL is refused",
      target_outputs(good(2) + [("bad.yaml", doc(base_value="https://lies.example.com"))]),
      "`TargetBaseURL` does not derive from")

# ...and the two directions the derivation test was wrong in. The loader
# collapses `!Sub 'x-${TargetBaseURL}'` to ONE scalar, which a membership test
# refuses although it plainly derives; and a bare Ref satisfies membership
# while answering the other output's question.
check_clean("a !Sub derivation is ACCEPTED (the test is not membership)",
            target_outputs(good(2) + [("sub.yaml", doc(value="${TargetBaseURL}-suffix"))]))
check("a bare Ref as TargetEnvironment is refused (it repeats the URL)",
      target_outputs(good(2) + [("bare.yaml", doc(value="TargetBaseURL"))]), "is a bare Ref")

# The floor is DERIVED from the population, and this row is what tells the two
# apart: four templates of which one is blind gives 6 examined outputs, which a
# hardcoded `checked < 6` waves through - passing exactly when a new template
# arrives, the moment the floor exists for.
check("the anti-vacuity floor scales with the population, not a hardcoded 6",
      target_outputs(good(3) + [("blind.yaml", {"Outputs": {}})]), "target output(s) were examined")
check("an EMPTY population is refused rather than passing vacuously",
      target_outputs([]), "handed NO templates")

sys.exit(1 if fail else 0)
PYTGT
# SC2181: test the command, not $? - a command substitution or a `local` between
# here and the check would silently retarget it.
if tgt_rc=$?; [ "$tgt_rc" -eq 0 ]; then pass=$((pass + 10)); else fail=$((fail + 1)); fi

echo ""
echo "6. the discovery rule, over fixtures"
# Section 0 runs against a tree that is correct today, so every one of its
# branches was dead as an assertion until this section handed it inputs the
# tree cannot produce.
NAMED=" a/base.yaml a/ds.yaml "
if out="$(unnamed_templates "$NAMED" a/base.yaml a/ds.yaml)" && [ -z "$out" ]; then
  ok "two named templates produce no complaint and rc=0 (the rule is not always-red)"
else
  bad "the discovery rule complained about a fully-named population: '${out}'"
fi
if out="$(unnamed_templates "$NAMED" a/base.yaml a/ds.yaml a/newplane.yaml)"; then
  bad "a template NOT in the named list returned rc=0; a third template would ship unchecked, which is exactly the guarantee #3861 asks for"
elif [ "$out" = "a/newplane.yaml" ]; then
  ok "an unnamed template is refused, and named - by itself, not by the whole list"
else
  bad "an unnamed template was refused but misreported as: '${out}'"
fi
# The space padding is load-bearing: without it a discovered `a/ds.yaml` would
# be accepted by a named `xx/a/ds.yaml.bak`, and the substring case is the one
# a reviewer cannot see by reading the glob.
if out="$(unnamed_templates " xx/a/ds.yaml.bak " a/ds.yaml)"; then
  bad "a path accepted because it is a SUBSTRING of a named one; the case pattern is not anchored on spaces"
else
  ok "a path that is only a substring of a named one is still refused"
fi
if discovery_floor_ok 1; then
  bad "the anti-vacuity floor accepted a 1-file discovery; a glob that stops matching would report every template as checked"
else
  ok "a discovery of fewer than two files trips the anti-vacuity floor"
fi
if discovery_floor_ok 2; then
  ok "a discovery of two files clears the floor (the floor is not always-red)"
else
  bad "the anti-vacuity floor rejects the real population of two"
fi

echo ""
echo "Results: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ] || exit 1
echo "All tests passed!"
