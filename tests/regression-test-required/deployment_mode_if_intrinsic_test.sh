#!/usr/bin/env bash
# `scripts/lint-deployment-mode.sh` must resolve `!If [Cond, A, B]` and must check
# BOTH arms.
#
# WHY THIS EXISTS. #3737 put
#   DEPLOYMENT_MODE: !If [IsLicenceTransition, 'community', !Ref DeploymentMode]
# on the marketplace template. The lint's catch-all rejected every `!` intrinsic,
# so `Lint All Modules` went red on main and, because PR CI runs the merge ref,
# on every open PR at once. The !If cannot be removed -- it is the licence
# transition lever shipped to a partner -- so the lint had to learn it.
#
# The danger in teaching a lint a new form is a FAIL-OPEN: accepting the form and
# checking neither arm, or checking only the convenient one. An !If can produce
# EITHER arm at deploy time, so every arm must be a recognised mode. That is the
# property pinned below, in both directions, plus the two refusals.
#
# The lint scans repo-relative roots rather than $PWD, so these cases mutate the
# real template and restore it. A trap restores on ANY exit path, and the test
# fails if the tree is not byte-identical afterwards -- a harness that leaves a
# tracked file mutated is worse than no harness.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1
LINT=scripts/lint-deployment-mode.sh
CFN=ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml
ORIG="!If [IsLicenceTransition, 'community', !Ref DeploymentMode]"
BAK="$(mktemp)"; cp "$CFN" "$BAK"
# `trap restore EXIT INT TERM` is the anti-pattern scripts/lint-trap-handlers-exit.sh
# exists to catch, and it caught this file: a handler that does not exit RETURNS TO
# THE SCRIPT BODY after a SIGINT, so Ctrl-C would carry on mutating the template it
# had just restored. `trap - EXIT` inside the handler stops the still-armed EXIT
# trap running the restore a second time. 130 = 128 + SIGINT, 143 = 128 + SIGTERM.
restore() { trap - EXIT; cp "$BAK" "$CFN"; touch "$CFN"; rm -f "$BAK"; }
trap restore EXIT
trap 'restore; exit 130' INT
trap 'restore; exit 143' TERM

pass=0; fail=0
ok(){ echo "  PASS: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1" >&2; fail=$((fail+1)); }

# The fixture must be present, or every case below is vacuous.
n=$(grep -cF "$ORIG" "$CFN" || true)
if [[ "$n" -ne 2 ]]; then
  echo "::error::expected 2 !If DEPLOYMENT_MODE sites in $CFN, found $n." >&2
  echo "The template changed shape; re-derive this test rather than adjusting the count." >&2
  exit 1
fi
ok "fixture present: 2 !If DEPLOYMENT_MODE sites"

plant(){ python3 - "$CFN" "$ORIG" "$1" <<'PY'
import sys
f,o,m=sys.argv[1],sys.argv[2],sys.argv[3]
s=open(f).read()
assert s.count(o)==2, f"patch must match exactly twice, got {s.count(o)}"
open(f,'w').write(s.replace(o,m))
PY
}

# 1. UNMUTATED must pass. Without this the four refusals below could all be
#    passing because the lint is broken for every input.
cp "$BAK" "$CFN"
if bash "$LINT" >/dev/null 2>&1; then ok "unmutated template passes"; else no "unmutated template does NOT pass"; fi

# 2..5 -- each mutant must red, and with ITS OWN diagnostic, not any red.
check(){ local desc="$1" mut="$2" want="$3"
  cp "$BAK" "$CFN"; plant "$mut" || { no "$desc (patch did not apply)"; return; }
  local out rc
  out=$(bash "$LINT" 2>&1); rc=$?
  if [[ $rc -eq 0 ]]; then no "$desc -- lint PASSED a template it must reject"; return; fi
  if grep -qF "$want" <<<"$out"; then ok "$desc"; else
    no "$desc -- red, but not for the aimed reason (wanted: $want)"; fi
}
check "a bad LITERAL arm is rejected"        "!If [IsLicenceTransition, 'bogus', !Ref DeploymentMode]"                 "(the literal !If arm) is not a recognised DEPLOYMENT_MODE"
check "a bad !Ref arm is rejected"           "!If [IsLicenceTransition, 'community', !Ref NoSuchParam]"                "NoSuchParam"
check "a !Ref in BOTH arms is refused"       "!If [IsLicenceTransition, !Ref DeploymentMode, !Ref DeploymentMode]"     "has a !Ref in BOTH !If arms"
check "a malformed !If is refused"           "!If [IsLicenceTransition, 'community']"                                  "cannot parse"
check "an unrelated intrinsic still red"     "!Sub 'community'"                                                        "uses an intrinsic this lint cannot resolve"

# 6. The harness must leave the tree exactly as it found it.
cp "$BAK" "$CFN"; touch "$CFN"
if git diff --quiet -- "$CFN"; then ok "template restored byte-identical"; else no "template NOT restored -- tree left dirty"; fi

echo "deployment_mode_if_intrinsic: $pass passed, $fail failed"
[[ $fail -eq 0 ]] || exit 1
