#!/usr/bin/env bash
# Copyright 2026 AxonFlow
# SPDX-License-Identifier: BUSL-1.1
#
# THE EDITION RESOLUTION IN deploy-synthetic-monitoring.yml, EXERCISED (#3602).
#
# WHY THIS EXISTS
#
# The base canary calls /api/v1/register, which no enterprise stack exposes, so
# it had been firing hourly against production-US for a release. The fix makes
# DeployBaseCanary = BaseCanaryRequested AND NOT TargetIsEnterprise - which is
# only as good as the TargetEdition the workflow computes.
#
# Two revisions of that computation were wrong in the SAME direction, and both
# passed review:
#
#   G10 - the check lived inside a step gated on `decision_shadow_probe != 'off'`,
#         so on the default path it never ran, and where it did it ran AFTER the
#         base stack had been updated.
#   R3  - the check moved to the `stack` step, but on the OVERRIDE path - the
#         only path production-US uses - no edition was derived, target_edition
#         DEFAULTED to 'community', and a redeploy with otherwise-default inputs
#         resolved community against an enterprise stack and re-enabled the
#         canary. Nothing objected, because every input was at its default.
#
# Both are the same class: a resolution that is correct on the path someone
# tested and wrong on the path production uses. A prose argument cannot
# distinguish them, so this runs the real step out of the real workflow file
# against the real input combinations and reads what it resolves.
#
# It executes the workflow's OWN script rather than a copy. A copy would drift,
# and a drifted copy that still passes is worse than no test.
#
# THE OVERRIDE-URL PLACEHOLDER IS DELIBERATELY NOT A *.elb.amazonaws.com STRING.
# tests-hygiene.yml scans all of tests/ for `[a-z0-9-]+\.elb\.amazonaws\.com`
# and refuses it - it cannot tell a placeholder from a real endpoint and should
# not try, because its failure mode is leaking one. This file also reaches the
# community mirror. Nothing here dereferences the URL: the step only regex-checks
# it (`^https?://[^/]+$`), so any scheme+host serves. example.invalid is RFC 2606
# reserved. Same reason and same choice as tests/community-saas/staging_smoke_guard_test.py.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

WORKFLOW='.github/workflows/deploy-synthetic-monitoring.yml'
STEP_ID='stack'
pass=0
fail=0

ok()   { echo "  PASS: $1"; pass=$((pass + 1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail + 1)); }

[ -f "$WORKFLOW" ] || { echo "FATAL: $WORKFLOW not found"; exit 1; }

# ── extract the step's script from the workflow ──────────────────────────────
#
# By step id, through a YAML parser. A grep-based slice would silently take the
# wrong step the day one is inserted above it, and this test's whole value is
# that it runs the script that actually deploys.
SCRIPT="$(mktemp)"
trap 'rm -f "$SCRIPT"' EXIT
python3 - "$WORKFLOW" "$STEP_ID" > "$SCRIPT" <<'PY'
import sys, yaml

class L(yaml.SafeLoader):
    pass

def any_tag(loader, suffix, node):  # noqa: ARG001
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)

L.add_multi_constructor('!', any_tag)

doc = yaml.load(open(sys.argv[1]), Loader=L)
want = sys.argv[2]
for job in (doc.get('jobs') or {}).values():
    for step in (job.get('steps') or []):
        if isinstance(step, dict) and step.get('id') == want:
            sys.stdout.write(step.get('run') or '')
            sys.exit(0)
sys.stderr.write(f"no step with id '{want}' in {sys.argv[1]}\n")
sys.exit(1)
PY
if [ ! -s "$SCRIPT" ]; then
  echo "FATAL: extracted an EMPTY script for step id '$STEP_ID'."
  echo "       Every case below would pass vacuously against nothing."
  exit 1
fi

# ANTI-VACUITY. If the extraction ever silently returns something that is not
# this step, every assertion below is about the wrong text. These two anchors
# are the load-bearing lines of the resolution itself.
for anchor in 'resolve_edition()' 'target_edition=auto'; do
  grep -qF "$anchor" "$SCRIPT" || {
    echo "FATAL: the extracted step does not contain '$anchor'."
    echo "       The extraction is broken, or the resolution moved out of this step."
    exit 1
  }
done

# ── run one case ─────────────────────────────────────────────────────────────
# run_case <label> <want_rc> <want_edition|-> <OVERRIDE_URL> <OVERRIDE_ENV> <CHOICE_URL> <EDITION_INPUT> <DS_PROBE> <IC_PROBE>
run_case() {
  local label="$1" want_rc="$2" want_ed="$3"
  local out gh rc got
  gh="$(mktemp)"
  out="$(OVERRIDE_URL="$4" OVERRIDE_ENV="$5" CHOICE_URL="$6" \
         EDITION_INPUT="$7" DS_PROBE="$8" IC_PROBE="$9" \
         GITHUB_OUTPUT="$gh" bash "$SCRIPT" 2>&1)"
  rc=$?
  got="$(grep '^target_edition=' "$gh" 2>/dev/null | tail -1 | cut -d= -f2-)"
  rm -f "$gh"

  if [ "$rc" != "$want_rc" ]; then
    bad "$label -> exit $rc, want $want_rc"
    echo "$out" | sed 's/^/        /' | head -6
    return
  fi
  if [ "$want_ed" != "-" ] && [ "$got" != "$want_ed" ]; then
    bad "$label -> target_edition='$got', want '$want_ed'"
    echo "$out" | sed 's/^/        /' | head -6
    return
  fi
  ok "$label"
}

# msg_case <label> <want-substring> <must-NOT-substring|-> <OVERRIDE_URL> <OVERRIDE_ENV> <CHOICE_URL> <EDITION_INPUT> <DS_PROBE> <IC_PROBE>
#
# ASSERTS THE MESSAGE, NOT THE EXIT CODE, and that is the whole point of it.
# Every row above checks rc and the resolved edition, and both were CORRECT on
# the override path while the message an operator actually reads was false: it
# said the edition was derived from "the target URL" and printed the UNUSED
# choice default, so a prod-us refusal announced that a community URL was an
# enterprise stack and pointed at an input the run had ignored. An rc-only suite
# passes that forever. A refusal is a message to a person; if the message names
# the wrong input, the refusal has not done its job.
msg_case() {
  local label="$1" want="$2" reject="$3" out gh
  gh="$(mktemp)"
  out="$(OVERRIDE_URL="$4" OVERRIDE_ENV="$5" CHOICE_URL="$6" \
         EDITION_INPUT="$7" DS_PROBE="$8" IC_PROBE="$9" \
         GITHUB_OUTPUT="$gh" bash "$SCRIPT" 2>&1)"
  rm -f "$gh"
  # HERESTRINGS, NOT PIPES. `producer | grep -q` under pipefail is the #3756
  # race - grep -q exits on its first match, the producer takes SIGPIPE, and a
  # pipeline that MATCHED reports 141. no_grep_q_under_pipefail_test scans
  # runtime-e2e/ and scripts/e2e/ only, so it does not cover this file; the
  # hazard does not care about the guard's scope, and `$out` here is a whole
  # step's stderr.
  if ! grep -qF -- "$want" <<<"$out"; then
    bad "$label -> message does not contain '$want'"
    printf '%s\n' "$out" | sed 's/^/        /' | head -6
    return
  fi
  if [ "$reject" != "-" ] && grep -qF -- "$reject" <<<"$out"; then
    bad "$label -> message wrongly contains '$reject'"
    printf '%s\n' "$out" | sed 's/^/        /' | head -6
    return
  fi
  ok "$label"
}

echo "=== deploy-synthetic-monitoring.yml: edition resolution (#3602) ==="
echo ""
echo "-- the case that was the defect --"

# THE ROW THIS TEST WAS ADDED FOR. Every input at its default, override path,
# probes off - the shape of an ordinary production-US redeploy. It used to
# resolve 'community' and re-enable the base canary against an enterprise stack.
run_case "prod-us override, ALL DEFAULTS: derives enterprise, never community" \
  0 enterprise \
  'https://prod-us-agent-alb.example.invalid' 'prod-us' \
  'https://try.getaxonflow.com' 'auto' 'off' ''

# The same shape with the edition stated WRONG. A derivation that exists must
# beat a contradicting input, or the fix is one typo from being undone.
run_case "prod-us override + target_edition=community: REFUSED as a contradiction" \
  1 - \
  'https://prod-us-agent-alb.example.invalid' 'prod-us' \
  'https://try.getaxonflow.com' 'community' 'off' ''

# An env name nothing recognises: refuse rather than default. This is the rule
# that makes the fix durable - a NEW enterprise env added later fails loudly
# instead of inheriting 'community'.
run_case "unknown override env + auto: REFUSED, not defaulted" \
  1 - \
  'https://prod-us-agent-alb.example.invalid' 'somenewenv' \
  'https://try.getaxonflow.com' 'auto' 'off' ''

run_case "unknown override env + explicit enterprise: accepted" \
  0 enterprise \
  'https://prod-us-agent-alb.example.invalid' 'somenewenv' \
  'https://try.getaxonflow.com' 'enterprise' 'off' ''

echo ""
echo "-- the refusal MESSAGE names the input it actually read --"

# The contradiction message on the OVERRIDE path must name env_name_override,
# and must NOT name the choice URL, which that path never reads.
msg_case "contradiction on the override path names env_name_override, not the choice URL" \
  "env_name_override ('prod-us')" 'try.getaxonflow.com' \
  'https://prod-us-agent-alb.example.invalid' 'prod-us' \
  'https://try.getaxonflow.com' 'community' 'off' ''

# The auto-with-no-derivation message must name the value it could not resolve.
msg_case "the auto refusal names the env it could not derive from" \
  "env_name_override ('somenewenv')" '-' \
  'https://prod-us-agent-alb.example.invalid' 'somenewenv' \
  'https://try.getaxonflow.com' 'auto' 'off' ''

# And on the CHOICE path the message must still name the URL, which there IS
# the source - the fix must not make every message say env_name_override.
msg_case "contradiction on the choice path still names the target URL" \
  'the target URL (https://try.getaxonflow.com)' '-' \
  '' '' 'https://try.getaxonflow.com' 'enterprise' 'off' ''

echo ""
echo "-- the choice path still behaves --"

run_case "try.getaxonflow.com + auto: derives community" \
  0 community '' '' 'https://try.getaxonflow.com' 'auto' 'off' ''

run_case "try-staging + auto: derives community" \
  0 community '' '' 'https://try-staging.getaxonflow.com' 'auto' 'off' ''

run_case "try.getaxonflow.com + target_edition=enterprise: REFUSED as a contradiction" \
  1 - '' '' 'https://try.getaxonflow.com' 'enterprise' 'off' ''

echo ""
echo "-- the probe cross-checks run on the auto branch too (the G10 shape) --"

# `auto` must not become the one path that skips these. An early `return` in
# resolve_edition after taking the derivation would make every row here pass
# 0 instead of 1.
run_case "auto=community + decision_shadow_probe=enterprise: REFUSED" \
  1 - '' '' 'https://try.getaxonflow.com' 'auto' 'enterprise' ''

run_case "auto=enterprise + decision_shadow_probe=community-saas: REFUSED" \
  1 - \
  'https://prod-us-agent-alb.example.invalid' 'prod-us' \
  'https://try.getaxonflow.com' 'auto' 'community-saas' ''

run_case "auto=community + identity_compat_probe=enterprise: REFUSED" \
  1 - '' '' 'https://try.getaxonflow.com' 'auto' 'off' 'enterprise'

echo ""
echo "-- the override-pairing rules are unchanged --"

run_case "override URL without env: REFUSED" \
  1 - 'https://prod-us-agent-alb.example.invalid' '' \
  'https://try.getaxonflow.com' 'auto' 'off' ''

run_case "override env without URL: REFUSED" \
  1 - '' 'prod-us' 'https://try.getaxonflow.com' 'auto' 'off' ''

run_case "override URL with a path: REFUSED" \
  1 - 'https://prod-us-agent-alb.example.invalid/x' 'prod-us' \
  'https://try.getaxonflow.com' 'auto' 'off' ''

echo ""
echo "  passed: $pass   failed: $fail"
[ "$fail" -eq 0 ] || exit 1
