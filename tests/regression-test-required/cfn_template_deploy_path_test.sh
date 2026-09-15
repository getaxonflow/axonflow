#!/usr/bin/env bash
# cfn_template_deploy_path_test.sh - which cap applies to a CloudFormation
# template, and which deploy path carries it (#3694).
#
# WHY THIS EXISTS
#
# CloudFormation caps a template TWICE and the applicable cap depends on how
# the template is passed. Both numbers here are the API's own, measured in
# us-east-1 rather than read from a doc:
#
#   --template-body   "Member must have length less than or equal to 51200"
#   --template-url    "Template may not exceed 1000000 bytes in size"
#
# THE SECOND NUMBER IS WHY THIS TEST IS WORTH HAVING. #3694 said the S3-hosted
# limit is "1 MB". It is 1,000,000, and 1 MB - 1,048,576 - is REJECTED. A
# guard written to 1 MB passes templates CloudFormation refuses, which is a
# fail-open, so the constant is pinned here against the sentence the API
# actually returns.
#
# The rule is a SIZE TEST and not a list: cfn-change-set.sh and
# check-cfn-name-limits.py both read the byte count, so there is no list of
# "URL templates" anywhere that could fall out of step with the deploy.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

SCRIPT='scripts/deploy/cfn-change-set.sh'
GUARD='scripts/testing/check-cfn-name-limits.py'
pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL: $1"; fail=$((fail + 1)); }

for f in "$SCRIPT" "$GUARD"; do
  [ -f "$f" ] || { echo "FATAL: $f not found"; exit 1; }
done

echo "=== CloudFormation template deploy path (#3694) ==="

# ---------------------------------------------------------------------------
# 1. THE CONSTANTS ARE THE MEASURED ONES, in both files.
# ---------------------------------------------------------------------------
grep -q 'HARD_LIMIT=1000000' "$SCRIPT" \
  && ok "the deploy script's hard limit is 1000000" \
  || bad "the deploy script's hard limit is not 1000000; 1 MB (1048576) is REJECTED by the API and a check written to it passes templates CloudFormation refuses"
grep -q 'TEMPLATE_URL_LIMIT = 1000000' "$GUARD" \
  && ok "the guard's URL limit is 1000000" \
  || bad "the guard's URL limit is not 1000000 (see above: 1 MB is not the limit)"
grep -q 'LIMIT=51200' "$SCRIPT" && grep -q 'TEMPLATE_BODY_LIMIT = 51200' "$GUARD" \
  && ok "both carry the measured 51200 body limit" \
  || bad "the 51200 body limit is missing from one of the two files"

# ---------------------------------------------------------------------------
# 2. POSITIVE CONTROLS, BOTH DIRECTIONS. A guard that only tests the side you
#    happen to be on is the invariant-that-cannot-fail shape.
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mk() { python3 - "$1" "$2" <<'PY'
import json, sys
target = int(sys.argv[2])
# A name-bearing property is REQUIRED, not decoration: the guard refuses a
# template with zero of them rather than passing vacuously, so a fixture
# without one reds for a reason that has nothing to do with size.
d = {"AWSTemplateFormatVersion": "2010-09-09", "Metadata": {"pad": ""},
     "Resources": {"T": {"Type": "AWS::SNS::Topic",
                         "Properties": {"TopicName": "probe-topic"}}}}
d["Metadata"]["pad"] = "x" * max(target - len(json.dumps(d)) + 1, 1)
open(sys.argv[1], "w").write(json.dumps(d))
PY
}

# over the HARD limit -> the guard must red
mk "$TMP/over_hard.json" 1000001
if python3 "$GUARD" "$TMP/over_hard.json" >/dev/null 2>&1; then
  bad "a template over 1000000 bytes passed the guard; the API refuses it on BOTH paths, so nothing could deploy it"
else
  ok "a template over the 1000000-byte hard limit reds the guard"
fi

# between the two limits -> allowed, and reported as taking the URL path
mk "$TMP/between.json" 60000
if out="$(python3 "$GUARD" "$TMP/between.json" 2>&1)"; then
  case "$out" in
    *--template-url*) ok "a template between the two limits passes and is reported as URL-deployed" ;;
    *) bad "a template between the two limits passes but the guard does not say it will be URL-deployed; the path change would be invisible in the log" ;;
  esac
else
  bad "a template between 51200 and 1000000 reds the guard; it is deployable by URL and must not fail"
fi

# under the body limit -> allowed, and NOT reported as URL
mk "$TMP/small.json" 1000
if out="$(python3 "$GUARD" "$TMP/small.json" 2>&1)"; then
  case "$out" in
    *--template-url*) bad "a small template is reported as URL-deployed; the body path must stay the default" ;;
    *) ok "a template under the body limit passes and stays on the body path" ;;
  esac
else
  bad "a small template reds the guard"
fi

# ---------------------------------------------------------------------------
# 3. THE URL PATH REFUSES WHEN THE OBJECT IS ABSENT.
#
# This is the test for the run-unique key doing what it claims. A stable key
# would let a failed upload deploy whatever was uploaded last; a per-run key
# means a failed upload leaves nothing to read, and the deploy must stop THERE
# rather than at an ambiguous API error. `TemplateURL must be a supported URL`
# is the same message for a malformed URL, an unsupported form and a key that
# does not resolve, so the refusal has to be local and has to name the object.
# ---------------------------------------------------------------------------
grep -q 'head-object' "$SCRIPT" \
  && ok "the deploy script proves the object exists before calling CloudFormation" \
  || bad "the deploy script does not head-object the uploaded template; an absent object reaches the API as 'TemplateURL must be a supported URL', which is also the error for a malformed or unsupported URL and so says nothing about which"
grep -q 'refusing to deploy' "$SCRIPT" \
  && ok "the refusal names the bucket, key and url rather than deferring to the API" \
  || bad "the deploy script has no local refusal message for an unreadable template object"

# ---------------------------------------------------------------------------
# 4. THE BUCKET IS REQUIRED, NOT GUESSED. An unset TEMPLATE_BUCKET must refuse
#    rather than fall back to some default that could belong to anyone.
# ---------------------------------------------------------------------------
# A dry run's object must be distinguishable from a deploy's. These objects are
# kept to answer "what was this stack running" later; under one prefix that
# answer can return a template a dry run never deployed.
grep -q 'KEY_PREFIX="templates/dry-run"' "$SCRIPT" \
  && ok "a dry run's uploaded template is marked, so it cannot be read later as a deployed one" \
  || bad "a dry run and a real deploy write indistinguishable objects; the forensic claim these objects exist for - what this stack was running - would be answerable with a template that never deployed"

grep -q 'TEMPLATE_BUCKET:?' "$SCRIPT" \
  && ok "an unset TEMPLATE_BUCKET refuses instead of guessing" \
  || bad "the deploy script does not require TEMPLATE_BUCKET on the URL path"

# ---------------------------------------------------------------------------
# 5. A REVIEW_IN_PROGRESS STACK IS CREATED, NOT UPDATED.
#
# A CREATE change set brings the stack SHELL into existence in
# REVIEW_IN_PROGRESS with zero resources; the change set is then deleted and
# the shell survives. On the next run describe-stacks succeeds, so the stack
# "exists", and asking for an UPDATE is refused because there is nothing to
# update.
#
# That sequence is the one the deploy recipe prescribes - dry run, then the
# same command with dry_run=false - so a first deploy done CORRECTLY made its
# own apply impossible. It happened to the decision-shadow stack and needed an
# operator to delete the shell by hand (#3602).
# ---------------------------------------------------------------------------
echo ""
echo "5. a REVIEW_IN_PROGRESS shell is created rather than updated"

grep -q 'REVIEW_IN_PROGRESS' "$SCRIPT" \
  && ok "the deploy script recognises REVIEW_IN_PROGRESS" \
  || bad "the deploy script does not handle REVIEW_IN_PROGRESS; a stack shell left by a dry run makes the subsequent apply impossible, which is the sequence the deploy recipe prescribes (#3602)"

# The state must select CREATE. Asserted on the branch rather than on the
# string alone: the name appearing in a comment is not the behaviour.
if awk '/if \[\[ "\$STATUS" == "REVIEW_IN_PROGRESS" \]\]/,/^  fi$/' "$SCRIPT" | grep -q "CS_TYPE='CREATE'"; then
  ok "REVIEW_IN_PROGRESS selects a CREATE change set"
else
  bad "REVIEW_IN_PROGRESS is mentioned but does not select CS_TYPE=CREATE; an UPDATE against an empty shell is refused by CloudFormation"
fi

# ANTI-VACUITY: the ordinary existing-stack path must still take UPDATE, or the
# assertion above would be satisfied by a script that creates everything.
grep -q "CS_TYPE='UPDATE'" "$SCRIPT" \
  && ok "an ordinary existing stack still takes the UPDATE path" \
  || bad "no UPDATE path remains; every deploy would attempt a CREATE"

echo ""
echo "Results: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ] || exit 1
echo "All tests passed!"
