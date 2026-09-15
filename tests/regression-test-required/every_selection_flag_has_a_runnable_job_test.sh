#!/usr/bin/env bash
# A CHANGE-DETECTOR SELECTION FLAG IS A PROMISE THAT SOME JOB WILL ACT ON IT.
#
# `tests-executed-census` (#3649) reports RED when the detector selected a flag
# and no job executed. That is the right rule, and it rests on a premise nobody
# had stated: every flag the detector emits on a tier has at least one consumer
# that CAN run on that tier.
#
# The premise was false. `mirror-inputs` had exactly one consumer,
# `community-mirror-simulation`, carrying `github.event_name != 'pull_request'`
# after the 2026-09-04 cost move. So on any PR touching a mirror input the flag
# was true, nothing could act on it, and the census correctly reported "jobs were
# expected and did not run" - fleet-wide, forever, on a condition no author could
# fix in their own branch. Found on #3879 within an hour of the census landing.
#
# THIS GUARD IS THE GENERAL FORM. It does not name mirror-inputs; it derives
# every detector output and every job that reads it, and refuses any flag that
# can be emitted on the pull_request tier with no consumer able to run there.
# Special-casing the one known flag would leave the NEXT one to be found the
# same way - by a worker whose unrelated PR went red.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

# DERIVED, NOT TYPED - and the reason is the sibling guard's, learned the hard way
# one PR earlier. `.github/workflows/test.yml` is EXCLUDED from the community sync
# (sync-community-repo.yml) but THIS FILE IS NOT, so it ships to the public mirror
# and a typed path hard-fails there on a tree where that file is correctly absent.
# Enterprise CI cannot see it: the mirror simulation replays the unit-test and lint
# jobs on the staged copy, never the mirror's own regression runner (#3918).
#
# So: examine every workflow that HAS a change detector, whichever ones happen to
# be present in this checkout. On the mirror that is a smaller set, and the rule
# still holds over it.
# SCOPED TO WORKFLOWS THAT CARRY A CENSUS, because the harm this guard names is
# the census's. A flag with no PR-tier consumer is only a defect where a
# tests-executed-census will then report "jobs were expected and did not run";
# in a workflow with no census nothing reads the discrepancy and nothing reds.
# Widening to every detector was tried and produced ten findings in build.yml and
# build-community.yml, neither of which has a census. EIGHT WERE FALSE - the
# build.yml ones - because this check reads `if:` while those outputs are consumed
# in `env:` and `run:`. THE OTHER TWO ARE REAL: build-community.yml's `agent` and
# `orchestrator` are this exact defect class, live - their detector runs on
# pull_request while their only consumers carry `!= 'pull_request'`. They are
# harmless ONLY because that file carries no census, which is precisely why the
# boundary is drawn at the census rather than at the detector. Stated so this
# scope reads as a deliberate limit and not as a claim that nothing lies outside
# it. A guard that reds main on conditions it has mis-modelled is worse than no
# guard; a guard whose scope is silent about what it excludes is only better by
# accident.
mapfile -t WFS < <(grep -l '^  tests-executed-census:' .github/workflows/*.yml | sort)
if [ "${#WFS[@]}" -eq 0 ]; then
  echo "FAIL: no workflow carries a tests-executed-census; the derivation is broken, not the tree"
  exit 1
fi

python3 - "${WFS[@]}" <<'PYEOF'
import sys, yaml, re

def norm(x):
    """Whitespace-insensitive, so `a!='b'` and `a != 'b'` compare equal."""
    return re.sub(r"\s+", "", str(x))

def excludes_pr(cond):
    """True when this `if:` cannot be satisfied on a pull_request.

    Substring-matching one spelling was the first version, and it could not tell
    the fix from its inverse. Model the two real shapes instead: an explicit
    `!= 'pull_request'`, and an `== '<other event>'`, which excludes a PR just as
    completely. Whitespace is normalised first, so `a!='b'` and `a != 'b'` agree.
    """
    c = norm(cond)
    if "github.event_name!='pull_request'" in c:
        return True
    # An `== '<other event>'` excludes a PR only when it is NOT one arm of a
    # disjunction. `(event=='pull_request' || event=='merge_group') && ...` is the
    # real shape of every detector here, and reading the `==` alone as exclusion
    # made this guard report nine workflows as "detector does not run on PRs" and
    # then trip its own floor. Hand-rolling boolean evaluation is how a simulation
    # ends up simulating something else, so this is deliberately narrow: no `||`
    # anywhere in the condition, or the inference is not drawn at all.
    if "||" not in c:
        for m in re.finditer(r"github\.event_name==('|\")([a-z_]+)\1", c):
            if m.group(2) != "pull_request":
                return True
    return False

def silenced_on_pr(expr):
    """True when the OUTPUT EXPRESSION forces a FALSY value on a pull_request.

    `A && B || C` yields C whenever `A && B` is falsy, so this only silences the
    flag if C is itself falsy. `|| 'true'` is the #3879 condition RESTORED rather
    than fixed, and the first version of this guard reported it as `silenced`.
    """
    e = norm(expr)
    if "github.event_name!='pull_request'" not in e:
        return False
    m = re.search(r"\|\|(.*?)}}", e)
    if not m:
        return False
    return m.group(1).strip().strip("'\"") in ("", "false")

fails = checked = 0
for wf in sys.argv[1:]:
    doc = yaml.safe_load(open(wf)) or {}
    jobs = doc.get("jobs") or {}
    det = jobs.get("detect-changes") or {}
    outputs = det.get("outputs") or {}
    if not outputs:
        continue
    if excludes_pr(str(det.get("if", ""))):
        print(f"  ok: {wf}: the detector itself does not run on pull_request")
        continue
    for name, expr in outputs.items():
        checked += 1
        consumers = [jn for jn, j in jobs.items()
                     if f"outputs.{name}" in str((j or {}).get("if", ""))]
        runnable = [jn for jn in consumers
                    if not excludes_pr(str((jobs[jn] or {}).get("if", "")))]
        if not consumers:
            print(f"FAIL: {wf}: `{name}` is emitted by detect-changes and NO job reads it. "
                  f"A flag nothing consumes cannot be acted on; delete it or wire it up.")
            fails += 1
        elif not runnable and not silenced_on_pr(expr):
            print(f"FAIL: {wf}: `{name}` can be true on a pull_request but its only consumer(s) "
                  f"{consumers} cannot run there. The tests-executed census will then report "
                  f"'jobs were expected and did not run' on every PR touching those paths, and "
                  f"no author can fix it in their own branch. Either give it a PR-tier job, or "
                  f"stop emitting it there with a FALSY fallback - `|| 'true'` is the defect "
                  f"restored, not silenced.")
            fails += 1
        else:
            why = "silenced on the PR tier" if not runnable else f"runnable on PRs via {runnable[0]}"
            print(f"  ok: {wf}: `{name}` - {why}")

if checked < 3:
    print(f"FAIL: only {checked} output(s) examined across {len(sys.argv)-1} workflow(s); "
          f"the derivation is broken rather than the tree")
    sys.exit(1)
if fails:
    print(f"FAILED: {fails} selection flag(s) promise a job that cannot run")
    sys.exit(1)
print(f"PASS: all {checked} selection flags either have a PR-tier consumer or are not emitted there")
PYEOF
