#!/usr/bin/env bash
# Behavioural test for scripts/ci/check-main-guard-freshness.sh (#3730).
#
# WHY IT EXISTS. The script's whole job is to distinguish states that every
# other tool in this repo conflates:
#
#   "this context passed at main's tip"
#   "this context last passed at some ancestor, and the tip has no verdict"
#   "this context last FAILED at some ancestor, and the tip has no verdict"
#   "this context has a newer non-verdict (cancelled/skipped/neutral) sitting
#    on top of an older failure"
#
# The third is what hid a red main for 3.5 days. The fourth is the same defect
# reproduced INSIDE the first draft of the fix, and it is why assertions 9-11
# exist. A test that only checked the happy path would see neither, so every
# assertion below drives a synthetic forge in which the tip deliberately
# carries NO verdict for the watched context - which is the real shape, not a
# contrived one.
#
# PRESENCE IS NOT EXECUTION. The script is wired into
# .github/workflows/main-guard-freshness.yml; this file is what proves the
# thing that workflow runs can actually fail. It is also executed on every PR
# by tests/regression-test-required/run-all.sh.
#
# THE STUB FORGE. `AXF_GH` replaces `gh`. The stub answers the four endpoints
# the script uses - the branch ruleset list, one ruleset, the commit list, and
# per-commit check-runs - from a fixture directory, so every failure path is
# reachable offline and deterministically. A guard whose failure path can only
# be reached by breaking production is not a tested guard.
#
# THE FAKE REPO ROOT. The script locates its inputs relative to its own path,
# so the fixtures that need to vary an INPUT FILE (a missing census module, a
# ruleset that disagrees with the checked-in list, an undispositioned member)
# run the script from a directory tree of symlinks into the real repo, with
# only the file under test replaced. The first draft of this test tried to do
# that by copying the script into a temp directory and running it there; the
# copy's `cd` then landed ABOVE the temp directory, so it exited 2 because
# nothing was where it looked - the right exit code for the wrong reason, and
# a pin that would have survived deleting the check it claimed to test.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
ROOT="$PWD"

SCRIPT="scripts/ci/check-main-guard-freshness.sh"
CENSUS="scripts/ci/lib/main_guard_census.py"
REQUIRED_FILE="tests/regression-test-required/lib/required-contexts-enterprise.txt"
DISPOSITIONS="tests/regression-test-required/lib/main-guard-dispositions.tsv"
for f in "$SCRIPT" "$CENSUS" "$REQUIRED_FILE" "$DISPOSITIONS"; do
  if [ ! -f "$f" ]; then
    echo "FAIL: $f is missing"
    exit 1
  fi
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# ---------------------------------------------------------------------------
# The stub forge. FIXTURE=<dir> with:
#   rulesets           one ruleset id per line (already --jq-projected)
#   ruleset            one required-status-check context per line
#   commits            one sha per line, newest first
#   checks/<sha>       TSV rows: name<TAB>status<TAB>conclusion
# A sha with no file answers empty, which is exactly what a real commit that
# never ran the workflow returns. A MISSING `rulesets` file makes the stub
# exit non-zero, which is how the unreadable-forge path is reached.
# ---------------------------------------------------------------------------
cat > "$work/gh" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
url="$2"
case "$url" in
  *"/rulesets/"*)
    [ -f "$FIXTURE/ruleset" ] || exit 1
    cat "$FIXTURE/ruleset" ;;
  *"/rulesets"*)
    [ -f "$FIXTURE/rulesets" ] || exit 1
    cat "$FIXTURE/rulesets" ;;
  *"/commits?sha="*) cat "$FIXTURE/commits" ;;
  *"/check-runs"*)
    sha="${url#*/commits/}"; sha="${sha%%/check-runs*}"
    [ -f "$FIXTURE/checks/$sha" ] && cat "$FIXTURE/checks/$sha"
    ;;
  *) exit 1 ;;
esac
exit 0
STUB
chmod +x "$work/gh"

# A WATCH context and an ADVISORY context, both taken from the live
# disposition file rather than invented, so a re-disposition of either shows
# up here as a failure instead of silently making an assertion vacuous.
WATCHED="partner ECS template drift-guard"
ADVISORY_CTX="Trivy Configuration Scan"

assert_disposition() { # <context> <WATCH|ADVISORY>
  local ctx="$1" want="$2" key disp
  key=$(python3 "$CENSUS" --repo getaxonflow/axonflow-enterprise \
        | awk -F'\t' -v c="$ctx" '$1=="CONTEXT" && $3==c {print $2; exit}')
  if [ -z "$key" ]; then
    echo "FAIL: no censused job produces the context '$ctx'; this test's fixtures"
    echo "      would assert nothing. Re-point them at a real member."
    exit 1
  fi
  disp=$(grep -v '^[[:space:]]*#' "$DISPOSITIONS" | awk -F'\t' -v k="$key" '$1==k{print $2; exit}')
  if [ "$disp" != "$want" ]; then
    echo "FAIL: '$ctx' ($key) is dispositioned '$disp', but this test needs '$want'."
    exit 1
  fi
  echo "ok: '$ctx' is a live $want member ($key)"
}
assert_disposition "$WATCHED" WATCH
assert_disposition "$ADVISORY_CTX" ADVISORY

# Four commits, newest first. Names are 40 hex-ish characters so the script's
# `${sha:0:9}` truncation has something to truncate.
C1=a000000000000000000000000000000000000001
C2=b000000000000000000000000000000000000002
C3=c000000000000000000000000000000000000003
C4=d000000000000000000000000000000000000004

new_fixture() { # <name>
  local d="$work/$1"
  mkdir -p "$d/checks"
  printf '9199766\n' > "$d/rulesets"
  grep -v '^[[:space:]]*#' "$ROOT/$REQUIRED_FILE" | sed '/^[[:space:]]*$/d' > "$d/ruleset"
  printf '%s\n%s\n%s\n%s\n' "$C1" "$C2" "$C3" "$C4" > "$d/commits"
  echo "$d"
}

run_it() { # <fixture_dir> [repo_root]
  FIXTURE="$1" AXF_GH="$work/gh" DEPTH=10 \
    bash "${2:-$ROOT}/$SCRIPT" 2>&1
}

# A tree of symlinks into the real repo, so the script's own `cd` lands here
# and every input can be replaced individually without touching the real tree.
fake_repo() { # <name>
  local r="$work/$1"
  mkdir -p "$r/scripts/ci" "$r/tests/regression-test-required/lib"
  ln -s "$ROOT/.github" "$r/.github"
  ln -s "$ROOT/scripts/ci/lib" "$r/scripts/ci/lib"
  cp "$ROOT/$SCRIPT" "$r/$SCRIPT"
  cp "$ROOT/$REQUIRED_FILE" "$r/$REQUIRED_FILE"
  cp "$ROOT/$DISPOSITIONS" "$r/$DISPOSITIONS"
  echo "$r"
}

# VERIFY THE EXPERIMENT, not only the outcome. Each fixture below mutates a
# checked-in input file; if the mutation silently no-ops, the assertion that
# follows it reads as a pass while probing nothing. An inert fixture is
# indistinguishable from a working guard, so every mutation is asserted to have
# changed the file.
assert_differs() { # <original> <mutated> <label>
  if cmp -s "$1" "$2"; then
    echo "FAIL: $3 is INERT - the mutated copy is byte-identical to $1,"
    echo "      so the assertion that follows would prove nothing."
    exit 1
  fi
}

fails=0
check() { # <label> <want_exit> <got_exit>
  if [ "$2" -ne "$3" ]; then
    echo "FAIL: $1 - wanted exit $2, got $3"
    fails=$((fails + 1))
    return 1
  fi
  echo "ok: $1"
  return 0
}

# ===========================================================================
# 1. THE DEFECT ITSELF. The tip carries no verdict for the watched context;
#    an ancestor carries a failure. Must FAIL (exit 1).
# ===========================================================================
d=$(new_fixture stale_red)
printf 'Some Other Check\tcompleted\tsuccess\n' > "$d/checks/$C1"
printf '%s\tcompleted\tfailure\n' "$WATCHED" > "$d/checks/$C3"
out=$(run_it "$d"); rc=$?
if check "a stale red at an ancestor fails, even with the tip carrying no verdict" 1 $rc; then
  printf '%s\n' "$out" | grep -q "2 commit(s) BEHIND tip" \
    || { echo "FAIL: the staleness distance was not reported"; printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails+1)); }
  printf '%s\n' "$out" | grep -qF "$WATCHED" \
    || { echo "FAIL: the failing context was not named"; fails=$((fails+1)); }
fi

# ===========================================================================
# 2. THE MIRROR IMAGE, and the one that makes assertion 1 mean something. Same
#    shape, same absent verdict at the tip, but the ancestor PASSED. Must pass.
#    Without this, assertion 1 could be satisfied by a script that fails on
#    any absent tip verdict - which would red every path-filtered guard
#    forever and be useless.
# ===========================================================================
d=$(new_fixture stale_green)
printf 'Some Other Check\tcompleted\tsuccess\n' > "$d/checks/$C1"
printf '%s\tcompleted\tsuccess\n' "$WATCHED" > "$d/checks/$C3"
out=$(run_it "$d"); rc=$?
check "a stale PASS at an ancestor is not a failure" 0 $rc

# ===========================================================================
# 3. RECENCY WINS, in both directions. A newer verdict must override an older
#    one - a script that took the OLDEST verdict, or that failed if ANY commit
#    in the window was red, would pass assertions 1 and 2 and still be wrong.
# ===========================================================================
d=$(new_fixture newer_green)
printf '%s\tcompleted\tsuccess\n' "$WATCHED" > "$d/checks/$C2"
printf '%s\tcompleted\tfailure\n' "$WATCHED" > "$d/checks/$C4"
out=$(run_it "$d"); rc=$?
check "a newer PASS overrides an older failure (not 'any red in the window')" 0 $rc

d=$(new_fixture newer_red)
printf '%s\tcompleted\tfailure\n' "$WATCHED" > "$d/checks/$C2"
printf '%s\tcompleted\tsuccess\n' "$WATCHED" > "$d/checks/$C4"
out=$(run_it "$d"); rc=$?
check "a newer failure overrides an older pass (not 'oldest verdict wins')" 1 $rc

# ===========================================================================
# 4. AN ABSENT VERDICT IS NOT A FAILURE. No commit in the window carries the
#    context at all. Reported, not fatal - a path-filtered job legitimately
#    may not have run. The NOTE must appear, so absence is never silent.
# ===========================================================================
d=$(new_fixture never_ran)
printf 'Some Other Check\tcompleted\tsuccess\n' > "$d/checks/$C1"
out=$(run_it "$d"); rc=$?
if check "a context with no verdict in the window does not fail the check" 0 $rc; then
  printf '%s\n' "$out" | grep -q "no verdict in the last" \
    || { echo "FAIL: absence was not reported"; fails=$((fails+1)); }
fi

# ===========================================================================
# 5. AN INCOMPLETE RUN IS NOT A VERDICT. A queued/in_progress run at the tip
#    must NOT mask a failure at an ancestor. This is the "pend=0 is not
#    everything reported" trap: a script that took the newest ROW rather than
#    the newest COMPLETED row would report this fixture as healthy.
# ===========================================================================
d=$(new_fixture queued_tip)
printf '%s\tqueued\t\n' "$WATCHED" > "$d/checks/$C1"
printf '%s\tcompleted\tfailure\n' "$WATCHED" > "$d/checks/$C3"
out=$(run_it "$d"); rc=$?
check "a queued run at the tip does not mask a completed failure below it" 1 $rc

# ===========================================================================
# 6. Every red conclusion counts as red. Only `failure` being treated as red
#    would let a killed or blocked guard read as healthy.
# ===========================================================================
for concl in failure timed_out action_required startup_failure; do
  d=$(new_fixture "red_$concl")
  printf '%s\tcompleted\t%s\n' "$WATCHED" "$concl" > "$d/checks/$C3"
  out=$(run_it "$d"); rc=$?
  check "a '$concl' verdict counts as red" 1 $rc
done

# ===========================================================================
# 7. A NON-VERDICT MUST NOT SHADOW AN OLDER RED. This is the fail-open the
#    first draft of the reader shipped with: a `cancelled` (routine, from a
#    concurrency cancel or a re-run), `skipped` (routine, from a draft- or
#    label-gated `if:`; and a SKIPPED conclusion satisfies a required context
#    in GitHub's own rollup) or `neutral` conclusion at a NEWER commit was
#    recorded as the most recent verdict, and the script reported PASS over a
#    genuine failure two commits below. Measured: exit 0 for all three, while
#    the same fixture with NOTHING at the tip exited 1.
#
#    A conclusion that is not a decision is not a verdict. The walk continues.
# ===========================================================================
for concl in cancelled skipped neutral stale; do
  d=$(new_fixture "shadow_$concl")
  printf '%s\tcompleted\t%s\n' "$WATCHED" "$concl" > "$d/checks/$C1"
  printf '%s\tcompleted\tfailure\n' "$WATCHED" > "$d/checks/$C3"
  out=$(run_it "$d"); rc=$?
  if check "a '$concl' conclusion at the tip does not shadow an older failure" 1 $rc; then
    printf '%s\n' "$out" | grep -q "2 commit(s) BEHIND tip" \
      || { echo "FAIL: '$concl' was consumed as the most recent verdict"; fails=$((fails+1)); }
  fi
done

# ...and the mirror image: a non-verdict on top of a PASS is still a pass, so
# assertion 7 cannot be satisfied by a script that simply fails on any
# non-verdict conclusion it sees.
d=$(new_fixture shadow_over_green)
printf '%s\tcompleted\tcancelled\n' "$WATCHED" > "$d/checks/$C1"
printf '%s\tcompleted\tsuccess\n' "$WATCHED" > "$d/checks/$C3"
out=$(run_it "$d"); rc=$?
check "a 'cancelled' conclusion over an older PASS is still a pass" 0 $rc

# ===========================================================================
# 8. AN ADVISORY MEMBER'S RED IS REPORTED AND DOES NOT FAIL THE CHECK. This is
#    what keeps the guard from crying wolf: 26 members, 11 of them WATCH. A
#    reader that failed on all 26 would red the board daily for a cold build
#    cache, and a guard that cries wolf gets ignored - which reintroduces the
#    exact defect, because the next real stale red is invisible again.
# ===========================================================================
d=$(new_fixture advisory_red)
printf '%s\tcompleted\tfailure\n' "$ADVISORY_CTX" > "$d/checks/$C3"
out=$(run_it "$d"); rc=$?
if check "an ADVISORY member's stale red does not fail the check" 0 $rc; then
  printf '%s\n' "$out" | grep -q "ADVISORY context(s) are red" \
    || { echo "FAIL: the advisory red was not reported at all - that is hiding it"; fails=$((fails+1)); }
  printf '%s\n' "$out" | grep -qF "$ADVISORY_CTX" \
    || { echo "FAIL: the advisory red did not name the context"; fails=$((fails+1)); }
fi

# ===========================================================================
# 9. FAIL-CLOSED, exit 2, never conflated with a pass. Each way the check can
#    be unable to run must be distinguishable from "all clear".
# ===========================================================================
d=$(new_fixture empty_commits)
: > "$d/commits"
out=$(run_it "$d"); rc=$?
check "an empty commit list exits 2 (could not run), not 0" 2 $rc

d=$(new_fixture one_commit)
printf '%s\n' "$C1" > "$d/commits"
out=$(run_it "$d"); rc=$?
check "a single-commit walk exits 2 - it cannot tell tip from ancestor" 2 $rc

d=$(new_fixture no_rulesets)
rm -f "$d/rulesets"
out=$(run_it "$d"); rc=$?
# CONTRACT CHANGE 2026-09-04, and the reason is in the script header beside the
# exit codes: `administration` is not a GITHUB_TOKEN scope, so an unreadable
# ruleset is the PERMANENT state under the default token, not a transient
# "could not run". Asserting exit 2 here made the scheduled run red for ever
# for a reason unrelated to staleness. The staleness walk needs only
# `checks: read` and still decides the exit code; the unverified reconciliation
# must be ANNOUNCED, which is what is asserted instead.
# Two things must hold, and BOTH are asserted, because either alone is
# satisfiable by the wrong behaviour: exit 2 alone would be the old permanent
# red, and a silent 0 would be an unverified list trusted quietly.
if [ "$rc" = 2 ]; then
  echo "FAIL: an unreadable ruleset must NOT be exit 2 - the staleness walk needs only checks:read and ran"
  fails=$((fails + 1))
else
  echo "ok: an unreadable ruleset does not fail the staleness verdict (got exit $rc, not 2)"
fi
if printf '%s\n' "$out" | grep -q "NOT reconciled against the live ruleset"; then
  echo "ok: the unverified reconciliation is ANNOUNCED, not silent"
else
  echo "FAIL: an unreadable ruleset passed WITHOUT announcing that the list is unverified"
  printf '%s\n' "$out" | sed 's/^/    /'
  fails=$((fails + 1))
fi

d=$(new_fixture empty_ruleset)
: > "$d/ruleset"
out=$(run_it "$d"); rc=$?
if check "a ruleset with zero required contexts exits 2, not 0" 2 $rc; then
  printf '%s\n' "$out" | grep -q "no required status-check context" \
    || { echo "FAIL: exit 2 was for some other reason than the empty ruleset"; fails=$((fails+1)); }
fi

# A missing census module. Run from a fake repo root so the `cd` lands
# somewhere the rest of the inputs still exist - otherwise exit 2 proves only
# that the script was run from the wrong place.
r=$(fake_repo missing_census)
rm "$r/scripts/ci/lib"
mkdir -p "$r/scripts/ci/lib"
d=$(new_fixture missing_census_fx)
printf '%s\tcompleted\tfailure\n' "$WATCHED" > "$d/checks/$C3"
out=$(run_it "$d" "$r"); rc=$?
if check "a missing census module exits 2 - no watch list means nothing verified" 2 $rc; then
  printf '%s\n' "$out" | grep -q "main_guard_census.py is missing" \
    || { echo "FAIL: exit 2 was for some other reason than the missing census"; printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails+1)); }
fi

# ===========================================================================
# 10. THE REQUIRED-CONTEXT LIST IS RECONCILED AGAINST THE LIVE RULESET. The
#     census SUBTRACTS that list, so a stale copy silently changes which jobs
#     are censused as invisible-on-main - a ninth required context widens the
#     class, a renamed one narrows it. A hand-kept literal is the exact
#     author-bounded census this whole check exists to answer.
# ===========================================================================
r=$(fake_repo ruleset_drift)
d=$(new_fixture ruleset_drift_fx)
cp "$d/ruleset" "$work/ruleset.pristine"
printf 'A Ninth Required Context\n' >> "$d/ruleset"
assert_differs "$work/ruleset.pristine" "$d/ruleset" "the ninth-required-context fixture"
out=$(run_it "$d" "$r"); rc=$?
if check "a ruleset with a context the file lacks exits 1" 1 $rc; then
  printf '%s\n' "$out" | grep -q "A Ninth Required Context" \
    || { echo "FAIL: the disagreeing context was not named"; fails=$((fails+1)); }
fi

d=$(new_fixture ruleset_drift2_fx)
# Drop the last context from the fixture ruleset, so the checked-in file lists
# one the ruleset no longer requires.
head -n -1 "$d/ruleset" > "$d/ruleset.trimmed" 2>/dev/null \
  || sed '$d' "$d/ruleset" > "$d/ruleset.trimmed"
mv "$d/ruleset.trimmed" "$d/ruleset"
assert_differs "$work/ruleset.pristine" "$d/ruleset" "the dropped-required-context fixture"
out=$(run_it "$d" "$r"); rc=$?
check "a file listing a context the ruleset no longer requires exits 1" 1 $rc

# ...and the agreeing case, so assertion 10 is not satisfied by a script that
# always fails the reconciliation.
d=$(new_fixture ruleset_agrees)
out=$(run_it "$d"); rc=$?
if check "the checked-in required-context list agrees with the fixture ruleset" 0 $rc; then
  printf '%s\n' "$out" | grep -q "matches the live ruleset" \
    || { echo "FAIL: the reconciliation did not report agreement"; fails=$((fails+1)); }
fi

# ===========================================================================
# 11. EVERY CENSUSED MEMBER MUST BE DISPOSITIONED. An undispositioned member
#     would be silently unwatched, which is this bug class one level up. The
#     visibility test enforces the same equality on the PR tier; enforcing it
#     in the reader too means a hand-edit that skips the test cannot quietly
#     narrow the watch list.
# ===========================================================================
r=$(fake_repo undispositioned)
grep -v 'partner-template-parity' "$ROOT/$DISPOSITIONS" > "$r/$DISPOSITIONS"
assert_differs "$ROOT/$DISPOSITIONS" "$r/$DISPOSITIONS" "the undispositioned-member fixture"
d=$(new_fixture undispositioned_fx)
out=$(run_it "$d" "$r"); rc=$?
if check "a censused member with no disposition exits 2" 2 $rc; then
  printf '%s\n' "$out" | grep -q "partner-template-parity" \
    || { echo "FAIL: the undispositioned member was not named"; fails=$((fails+1)); }
fi

r=$(fake_repo bad_disposition)
# awk rather than sed: a `\t` in a sed LHS is interpreted by GNU sed and, as
# it happens, by the BSD sed on a developer's macOS too - but relying on that
# would make this fixture INERT wherever it is not, and an inert fixture reads
# as a passing assertion. awk splits on a real tab either way, and the
# difference is asserted below.
awk -F'\t' -v OFS='\t' \
  '$1=="infra-validation.yml :: partner-template-parity" { $2="MAYBE" } { print }' \
  "$ROOT/$DISPOSITIONS" > "$r/$DISPOSITIONS"
assert_differs "$ROOT/$DISPOSITIONS" "$r/$DISPOSITIONS" "the bad-token disposition fixture"
d=$(new_fixture bad_disposition_fx)
out=$(run_it "$d" "$r"); rc=$?
if check "an unrecognised disposition token exits 2, not 0" 2 $rc; then
  printf '%s\n' "$out" | grep -q "expected WATCH or ADVISORY" \
    || { echo "FAIL: exit 2 was for some other reason than the bad token"; printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails+1)); }
fi

# ===========================================================================
# 12. THE WATCH LIST IS DERIVED, NOT HARDCODED, and it still contains the
#     guard this was built for. If the census stops producing it, the reader
#     silently stops watching it - so assert the link rather than assuming it.
# ===========================================================================
if ! python3 "$CENSUS" --repo getaxonflow/axonflow-enterprise \
     | grep -qx "MEMBER	infra-validation.yml :: partner-template-parity"; then
  echo "FAIL: the census no longer reports infra-validation.yml :: partner-template-parity,"
  echo "      so the freshness reader is no longer watching the guard it was built for."
  fails=$((fails + 1))
else
  echo "ok: the watch list is derived from the census and still contains the drift-guard"
fi

d=$(new_fixture derived_link)
printf '%s\tcompleted\tfailure\n' "$WATCHED" > "$d/checks/$C3"
out=$(run_it "$d")
if ! printf '%s\n' "$out" | grep -qE "census: [0-9]+ member job\(s\) in [0-9]+ workflows; [0-9]+ WATCH context"; then
  echo "FAIL: the script did not report its census and watch-list sizes - a silent"
  echo "      watch list of zero would otherwise read as a pass"
  fails=$((fails + 1))
else
  echo "ok: the script reports its census and watch-list sizes"
fi

echo ""
if [ "$fails" -ne 0 ]; then
  echo "FAIL: $fails assertion(s) failed"
  exit 1
fi
echo "PASS: the freshness reader distinguishes a stale red from a stale pass, from an absent"
echo "      verdict, and from a non-verdict sitting on top of a red"
