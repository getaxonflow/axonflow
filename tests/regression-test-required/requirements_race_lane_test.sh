#!/usr/bin/env bash
# requirements_race_lane_test.sh - #3689 (ADR-065 gate 10)
#
# THE BUG CLASS: A CONCURRENCY SUITE THAT NOBODY RUNS CONCURRENTLY.
#
# platform/shared/requirements holds every stateful requirement in ADR-065 -
# approval authority, quota reservation, decision-proof single use - and its
# tests race 64 to 96 goroutines against a shared store. Until #3689, none of
# them ran under `-race` in CI: the three race lanes on main covered
# platform/orchestrator, shared/planeshadow + shared/policy, and the decision
# module, and none of them reached shared/requirements. The board was green and
# the detector had never been pointed at the code the gate is about. That is
# the same shape as #3555's own criterion, "wired to an executing CI target,
# not only registered".
#
# It is a ratchet rather than a fix because nothing about the next edit would
# remind anyone. A package renamed out of shared/requirements, a `-race` flag
# dropped while chasing a timeout, or a hand-typed package list that stops
# matching the tree all produce a shorter run and no red.
#
# THE RULES, each pinned in both directions below:
#
#   1. test.yml declares a job that runs `go test -race` over the
#      shared/requirements tree.
#   2. That job DERIVES its package list with `go list`. A typed list is seven
#      things a rename can silently drop, and `go test` on a package that
#      still exists but no longer contains the assertions is not an error.
#   3. That job asserts a floor of at least SEVEN covered packages, and the
#      floor is on packages that RAN (an `ok`/`FAIL` verdict line), not on the
#      length of the list it printed. A floor that can only detect zero is
#      satisfied by a run that covered one.
#   4. The job gates the required Test Summary through BOTH halves: `needs:`
#      and the failure step's `if:`. A job in `needs` that the failure
#      expression never reads is a job whose red stops nothing.
#   5. The seven packages exist on the tree, so the floor is a claim about
#      something rather than an arbitrary number.
#
# Run: bash tests/regression-test-required/requirements_race_lane_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/test.yml"
REQ_DIR="$REPO_ROOT/platform/shared/requirements"

PASS=0
FAIL=0
ok() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== ADR-065 gate 10: the shared/requirements race lane ==="

# The mirror strips test.yml. On a mirror checkout there is nothing to assert
# and nothing to hide; in an enterprise tree a missing workflow is a failure,
# never a skip, so this guard cannot pass vacuously where it is meant to bite.
if [ ! -f "$WORKFLOW" ]; then
  if [ -d "$REPO_ROOT/ee" ]; then
    echo "  FAIL: $WORKFLOW not found in an enterprise tree - this guard cannot vacuously pass"
    exit 1
  fi
  echo "  SKIP: community checkout (no test.yml); this guard runs in the enterprise repository"
  exit 0
fi

if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "  FAIL: PyYAML is unavailable; a guard that cannot parse the workflow must not report success"
  exit 1
fi

# ---------------------------------------------------------------------------
# The census, read from the PARSED workflow.
#
# Parsed rather than grepped: a `run:` body is a YAML scalar whose indentation
# and line folding a regex over the raw file gets wrong, and the question here
# is what the job will execute, not what the file looks like.
# ---------------------------------------------------------------------------
census() {
  local workflow="$1"
  python3 - "$workflow" <<'PY'
import io, re, sys, yaml

path = sys.argv[1]
d = yaml.safe_load(io.open(path, encoding='utf-8').read())
jobs = d.get('jobs') or {}

# COMMENTS ARE STRIPPED BEFORE ANYTHING IS MATCHED. Every rule below is a
# presence check, and a presence check that greps the raw body is satisfied by
# the prose beside the code - including the prose this very lane carries
# explaining what it derives and why.
def code_of(job):
    body = '\n'.join(str((s or {}).get('run', '')) for s in ((job or {}).get('steps') or []))
    return '\n'.join(l for l in body.splitlines() if not l.lstrip().startswith('#'))

# A "requirements race job" is one whose run steps invoke `go test` with the
# race detector over the shared/requirements tree. Identified by BEHAVIOUR
# rather than by job id: a rename of the job must not make this guard stop
# looking. `-race` is matched as its own token after `go test`, so an
# artefact filename that happens to contain the string cannot stand in for
# the flag.
RACE_INVOCATION = re.compile(r'go test\b[^\n]*(?<=\s)-race(?=\s|$)')
found = []
for jid, j in jobs.items():
    code = code_of(j)
    if RACE_INVOCATION.search(code) and 'shared/requirements' in code:
        found.append((jid, j, code))

print('JOBS=%d' % len(found))
if len(found) != 1:
    print('IDS=' + ','.join(j for j, _, _ in found))
    raise SystemExit(0)

jid, job, body = found[0]
print('ID=' + jid)
print('NAME=' + str(job.get('name', '')))

# Rule 2: derived, not typed. The anchor is the COMMAND SUBSTITUTION that
# feeds the list into a variable - not the bare phrase, which also appears in
# the lane's own failure message and would keep matching after the derivation
# was deleted.
derives = bool(re.search(r'[<$]\(\s*go list\b[^)\n]*\./shared/requirements/\.\.\.', body))
print('DERIVES=%d' % int(derives))

# And the packages `go test` is actually handed must be that variable rather
# than literal paths.
race_line = RACE_INVOCATION.search(body)
race_line = body[race_line.start():body.find('\n', race_line.start()) if body.find('\n', race_line.start()) >= 0 else len(body)]
print('RACE_ARGS_EXPANDED=%d' % int(bool(re.search(r'"\$\{[A-Za-z_][A-Za-z0-9_]*\[@\]\}"', race_line))))

# A literal package path anywhere in the lane is the typed list this rule
# forbids. `./shared/requirements/...` (the recursive pattern) is fine; a
# named leaf package is not.
typed = re.findall(r'\./shared/requirements/(?!\.\.\.)[A-Za-z0-9_]+', body)
print('TYPED=' + ','.join(sorted(set(typed))))

# Rule 3: a numeric floor of at least seven, compared against something the
# RUN produced. Both halves are reported so the caller can tell a missing
# floor from a lowered one.
floors = [int(n) for n in re.findall(r'-lt\s+(\d+)', body)]
print('FLOORS=' + ','.join(str(n) for n in floors))
print('COUNTS_VERDICTS=%d' % int('^(ok|FAIL)' in body))

# Rule 4: both halves of the Test Summary gate.
summary = jobs.get('test-summary') or {}
needs = summary.get('needs') or []
if isinstance(needs, str):
    needs = [needs]
print('IN_NEEDS=%d' % int(jid in needs))
fail_if = ''
for s in (summary.get('steps') or []):
    cond = str((s or {}).get('if', ''))
    if 'result' in cond and '!= ' in cond:
        fail_if += cond
print('IN_FAIL_IF=%d' % int(('needs.%s.result' % jid) in fail_if))
PY
}

OUT="$(census "$WORKFLOW")"
get() { printf '%s\n' "$OUT" | sed -n "s/^$1=//p" | head -1; }

njobs="$(get JOBS)"
if [ "${njobs:-0}" != "1" ]; then
  bad "test.yml declares ${njobs:-0} job(s) running -race over shared/requirements, want exactly 1 (ids: $(get IDS))"
  echo ""
  echo "FAILED: $FAIL check(s)"
  exit 1
fi
ok "test.yml declares exactly one race lane over shared/requirements: '$(get ID)' ($(get NAME))"

[ "$(get DERIVES)" = "1" ] &&
  ok "the lane derives its package list with go list ./shared/requirements/..." ||
  bad "the lane does not call 'go list ... ./shared/requirements/...'; a typed list shrinks silently when a package moves"

typed="$(get TYPED)"
[ -z "$typed" ] &&
  ok "the lane names no individual package path" ||
  bad "the lane names individual packages ($typed); derive the list instead"

[ "$(get RACE_ARGS_EXPANDED)" = "1" ] &&
  ok "the race invocation is handed the derived list, not literal paths" ||
  bad "the 'go test -race' line does not expand a derived array; a derivation nothing consumes is decoration"

floors="$(get FLOORS)"
best=0
for n in ${floors//,/ }; do [ "$n" -gt "$best" ] && best="$n"; done
[ "$best" -ge 7 ] &&
  ok "the lane asserts a covered-package floor of $best (>= 7)" ||
  bad "the lane's highest package floor is ${best} (floors seen: ${floors:-none}); ADR-065 gate 10 covers seven packages"

[ "$(get COUNTS_VERDICTS)" = "1" ] &&
  ok "the floor counts per-package verdict lines, so it measures packages that RAN" ||
  bad "the floor does not count 'ok'/'FAIL' verdict lines; a floor over the listed packages says nothing about what executed"

[ "$(get IN_NEEDS)" = "1" ] &&
  ok "test-summary needs the lane" ||
  bad "test-summary does not need '$(get ID)'; its red would not reach the required context"

[ "$(get IN_FAIL_IF)" = "1" ] &&
  ok "test-summary's failure expression reads the lane's result" ||
  bad "test-summary's failure step never reads needs.$(get ID).result; a job in needs that nothing reads stops nothing"

# ---------------------------------------------------------------------------
# Rule 5: the floor is a claim about packages that exist.
# ---------------------------------------------------------------------------
pkgs=0
for d in "$REQ_DIR"/*/; do
  [ -d "$d" ] || continue
  ls "$d"*.go >/dev/null 2>&1 && pkgs=$((pkgs + 1))
done
[ "$pkgs" -ge 7 ] &&
  ok "platform/shared/requirements holds $pkgs Go packages, so the floor of 7 is not an arbitrary number" ||
  bad "platform/shared/requirements holds only $pkgs Go package(s); the floor and the tree disagree"

# ---------------------------------------------------------------------------
# THE GUARD'S OWN FAILING INPUT.
#
# Every check above is a claim that something is present. A parser that had
# stopped finding anything would report all of them as present too, so each
# rule is re-run against a workflow deliberately broken in exactly that rule's
# dimension, and the guard fails if the break is not detected. Without this
# the census could silently degrade into a set of assertions about an empty
# dictionary.
# ---------------------------------------------------------------------------
echo ""
echo "=== the guard's own falsifiability ==="

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

selftest() {
  local name="$1" sed_expr="$2" key="$3" want="$4"
  local f="$TMP/mutant.yml"
  python3 - "$WORKFLOW" "$f" "$sed_expr" <<'PY'
import io, sys
src, dst, expr = sys.argv[1], sys.argv[2], sys.argv[3]
old, new = expr.split('\x1f', 1)
text = io.open(src, encoding='utf-8').read()
if old not in text:
    sys.stderr.write('self-test input %r is not present in the workflow\n' % old)
    raise SystemExit(3)
io.open(dst, 'w', encoding='utf-8').write(text.replace(old, new, 1))
PY
  if [ $? -ne 0 ]; then
    bad "self-test '$name' could not be built; its anchor is no longer in the workflow"
    return
  fi
  local got
  got="$(census "$f" | sed -n "s/^$key=//p" | head -1)"
  if [ "$got" = "$want" ]; then
    ok "self-test '$name': the census reports $key=$got on the broken workflow"
  else
    bad "self-test '$name': the census reports $key=${got:-<empty>} on a workflow broken in that dimension, want $want"
  fi
}

# The race detector dropped while the lane keeps running: the census must
# find zero race jobs, not one.
selftest "race flag dropped" "$(printf 'go test -race -count=1 -tags enterprise\x1fgo test -count=1 -tags enterprise')" JOBS 0
# The derivation replaced by a typed list. The lane's own failure message
# still names the pattern, which is exactly what the anchor must not accept.
selftest "package list typed" "$(printf 'mapfile -t PKGS < <(go list -tags enterprise ./shared/requirements/...)\x1fPKGS=(./shared/requirements/reservation)')" DERIVES 0
# The derived list built but not consumed.
selftest "derived list unused" "$(printf -- '-timeout 15m "${PKGS[@]}"\x1f-timeout 15m ./shared/requirements/...')" RACE_ARGS_EXPANDED 0
# The floor lowered below the seven packages the gate names.
selftest "floor lowered" "$(printf -- '-lt 7 \x1f-lt 1 ')" FLOORS 1,7
# The floor moved off the verdict lines onto the length of the list.
selftest "floor stops measuring what ran" "$(printf -- "grep -cE '^(ok|FAIL)\x1fgrep -cE '^(never)")" COUNTS_VERDICTS 0

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "FAILED: $FAIL check(s), $PASS passed"
  exit 1
fi
echo ""
echo "PASS: $PASS check(s) - the requirements race lane exists, derives its packages, floors what it covered, and gates the summary"
