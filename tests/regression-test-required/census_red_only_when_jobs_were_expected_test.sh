#!/usr/bin/env bash
# Regression guard: the "Tests executed census" (#3649) is RED only when jobs
# were EXPECTED and did not run, and a NOTICE when every skip was by design.
#
# THE BUG CLASS. The first census reddened whenever nothing executed. On a
# path-filtered workflow that is the normal case for most PRs: #3787 and #3788
# carried a red compile-java-examples census because the change detector
# matched no Java path and every job skipped BY DESIGN. Its text also said the
# red "clears when the PR is marked ready", which is true only for the
# draft-tier case. A red that every non-Java PR carries is noise, and noise on
# a required-adjacent check is how a real "jobs were selected and did not run"
# gets waved through. The two cases must be told apart, and only the census's
# own reading of the change detector's OUTPUTS can tell them apart.
#
# THE CONTROL. The census is one Python block, byte-identical in every workflow
# that carries it (one census, not five). This guard extracts it from each
# workflow and runs it against fixtures of `${{ toJSON(needs) }}`:
#   A  detector success, no output true, every job skipped   -> exit 0, ::notice::
#   B  detector success, one output true, every job skipped  -> exit 1, ::error::
#   C  detector skipped (draft tier), every job skipped      -> exit 0, ::notice::
#   D  detector failure, every job skipped                    -> exit 1, ::error::
#   E  a job executed (failure counts as executed)            -> exit 0, no ::error::
#   F  the census needs nothing but the detector              -> exit 1
# A census that cannot fail case B is a census that checks nothing; a census
# that fails case A is the noise this guard retires.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# DERIVED, NOT TYPED, for two reasons that bit in review.
#
# 1. THE MIRROR. `.github/workflows/test.yml` is excluded from the community
#    sync (sync-community-repo.yml), but THIS guard is not - it ships. The
#    public mirror runs tests/regression-test-required/run-all.sh, so a typed
#    list naming test.yml made this guard hard-fail there on a tree where that
#    file is correctly absent. Enterprise CI cannot see it: the mirror
#    simulation replays the unit-test and lint jobs on the staged copy, never
#    the mirror's regression runner.
# 2. A SIXTH CENSUS. A typed list cannot notice a new workflow that grows a
#    drifted census, which is the one thing the identity check below exists to
#    catch.
#
# The floor is what makes this fail closed: derivation that finds nothing must
# not pass silently. Four is the count that survives the sync; enterprise has
# five.
mapfile -t WORKFLOWS < <(grep -l "^  tests-executed-census:" .github/workflows/*.yml | xargs -n1 basename | sort)
if [ "${#WORKFLOWS[@]}" -lt 4 ]; then
  echo "FAIL: found ${#WORKFLOWS[@]} workflow(s) carrying a census, want >= 4; the derivation is broken or the censuses were removed"
  exit 1
fi
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0

extract() { # $1 workflow -> prints the census Python block, de-indented
  awk '/python3 - <<.PY.$/{p=1;next} p&&/^ *PY$/{p=0} p' ".github/workflows/$1" | sed 's/^          //'
}

# One census: every workflow carries the same block.
first=""
for wf in "${WORKFLOWS[@]}"; do
  extract "$wf" > "$TMP/$wf.py"
  if ! grep -q 'Tests executed census' "$TMP/$wf.py"; then
    echo "FAIL: $wf carries no census block (or the extractor stopped seeing it)"; fail=1
  fi
  if [ -z "$first" ]; then first="$wf"; elif ! cmp -s "$TMP/$first.py" "$TMP/$wf.py"; then
    echo "FAIL: the census in $wf differs from the one in $first; there must be ONE census"; fail=1
  fi
done
[ "$fail" -eq 0 ] || exit 1
echo "ok: ${#WORKFLOWS[@]} workflows carry one byte-identical census"

run_case() { # $1 label, $2 needs-json, $3 expected exit, $4 required marker, $5 forbidden marker
  local out rc
  out=$(NEEDS_JSON="$2" CHANGE_DETECTOR=detect-changes GITHUB_STEP_SUMMARY="$TMP/summary.md" python3 "$TMP/$first.py" 2>&1); rc=$?
  if [ "$rc" -ne "$3" ]; then echo "FAIL ($1): exit $rc, want $3"; echo "$out" | sed 's/^/    /'; fail=1; return; fi
  if [ -n "$4" ] && ! grep -q -- "$4" <<< "$out"; then echo "FAIL ($1): output lacks '$4'"; echo "$out" | sed 's/^/    /'; fail=1; return; fi
  if [ -n "$5" ] && grep -q -- "$5" <<< "$out"; then echo "FAIL ($1): output carries '$5'"; echo "$out" | sed 's/^/    /'; fail=1; return; fi
  echo "ok: $1"
}

skipped='{"result":"skipped","outputs":{}}'
run_case "A: detector matched nothing -> NOTICE, exit 0" \
  '{"detect-changes":{"result":"success","outputs":{"java-examples":"false"}},"compile-java-examples":'"$skipped"'}' 0 "::notice::" "::error::"
run_case "B: detector selected a job that did not run -> RED" \
  '{"detect-changes":{"result":"success","outputs":{"java-examples":"true"}},"compile-java-examples":'"$skipped"'}' 1 "::error::" "::notice::"
run_case "C: detector skipped (draft tier) -> NOTICE, exit 0" \
  '{"detect-changes":{"result":"skipped","outputs":{}},"compile-java-examples":'"$skipped"'}' 0 "::notice::" "::error::"
run_case "D: detector itself failed -> RED" \
  '{"detect-changes":{"result":"failure","outputs":{}},"compile-java-examples":'"$skipped"'}' 1 "::error::" "::notice::"
run_case "E: a job executed (even to failure) -> exit 0" \
  '{"detect-changes":{"result":"success","outputs":{"java-examples":"true"}},"compile-java-examples":{"result":"failure","outputs":{}}}' 0 "1 of 1 jobs executed" "::error::"
run_case "F: nothing but the detector in needs -> RED" \
  '{"detect-changes":{"result":"success","outputs":{"go-code":"true"}}}' 1 "counting nothing" ""
# G is the case the acquittal in A cannot distinguish from itself. `success`
# with NO outputs at all is not a path miss: every detector in this repository
# declares at least one output, so a detector reporting success while declaring
# none has broken its own wiring - a renamed step id, a misspelled output key -
# and without this row it would acquit itself on every PR forever, which is the
# permanent-green shape this census exists to refuse. It must be driven, not
# reasoned about: review flipped this branch to exit 0 and the suite still
# passed, because nothing exercised it.
run_case "G: detector succeeded but declared NO outputs -> RED (wiring, not a path miss)" \
  '{"detect-changes":{"result":"success","outputs":{}},"compile-java-examples":'"$skipped"'}' 1 "declared no outputs" "::notice::"

# The retired sentence must stay retired: it was true only for case C.
if grep -q 'clears when the PR is marked ready' "$TMP/$first.py"; then
  echo "FAIL: the census still claims a red clears on the ready flip, which holds only for the draft-tier case"; fail=1
fi

[ "$fail" -eq 0 ] || { echo "FAIL: census_red_only_when_jobs_were_expected_test"; exit 1; }
echo "PASS: the census is red only when jobs were expected and did not run"
