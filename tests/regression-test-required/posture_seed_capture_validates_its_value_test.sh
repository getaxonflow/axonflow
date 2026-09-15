#!/usr/bin/env bash
# posture_seed_capture_validates_its_value_test.sh - #4048 follow-up
#
# THE BUG CLASS: A CAPTURE NOTHING VALIDATES, REPORTING A TRUE-LOOKING FAILURE
# ABOUT THE WRONG SUBSYSTEM.
#
# `psql -tAc "INSERT ... RETURNING policy_id"` writes TWO things to stdout: the
# returned row, and the `INSERT 0 1` command tag. Two posture suites captured
# both and piped them through `tr -d ' \n'`, which welded them into one string.
# Posture run 34573411294 seeded a policy and captured
# `e2e-3059-tenant-a-...-6972INSERT01`.
#
# What made it expensive was not the corruption. It was that nothing checked the
# captured value: both suites guarded with `[ -n "$id" ]`, and a welded id is
# non-empty. So the seed step PASSED, and the failure surfaced ~90 seconds later
# as "policy list does not contain the policy seeded moments ago" - while the
# response body in the same log line plainly CONTAINED the policy. A correct
# subsystem was reported broken, which is the most expensive shape of wrong.
#
# THE RULE THIS PINS, and the second half is the one that matters:
#
#   1. The capture must not be able to absorb a command tag: psql runs with -q,
#      and only the FIRST line of output is taken.
#   2. The captured id must be ASSERTED EQUAL to the policy_id that was seeded.
#      (1) stops this instance. (2) stops the next one - a NOTICE, a warning, a
#      server-side rewrite, or a future psql that words its tag differently.
#
# AND WHY `sed -n '1p'` RATHER THAN `head -1`, which is not cosmetic:
# `head` closes the pipe after one line, so psql can take SIGPIPE writing the
# tag. Under these suites' `set -euo pipefail` that aborts the suite ON the seed
# line with status 141. psql's two lines normally fit the pipe buffer so head
# usually wins that race - "usually" is the flake. `sed -n '1p'` reads to EOF and
# has no race. runtime-e2e/3509's psql_q does use `head -1` and is correct there
# only because that suite runs `set -uo pipefail`, WITHOUT -e. A pattern's
# correctness can live in the shell options of the file it sits in.
#
# Run: bash tests/regression-test-required/posture_seed_capture_validates_its_value_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# The suites whose psql seeds this rule governs. Kept as a list rather than a
# glob: a glob that matches nothing passes vacuously, and the whole point of
# this file is that a check which verifies nothing must not report success.
SUITES=(
  "runtime-e2e/3039_rls_blind_reads/test.sh"
  "runtime-e2e/3059_dynamic_policy_list_tenant_scope/test.sh"
)

echo "=== posture seed captures validate the value they capture (#4048) ==="

# --- anti-vacuity: the subjects must exist before anything is asserted --------
missing=0
for f in "${SUITES[@]}"; do
  [ -r "$f" ] || { bad "subject not readable: $f"; missing=$((missing + 1)); }
done
if [ "$missing" -gt 0 ]; then
  echo ""
  echo "FAILED: $FAIL check(s) - the census had no subjects, so it verified nothing."
  exit 1
fi
ok "censused ${#SUITES[@]} posture suite(s) that seed a policy through psql"

# --- 1. structural: the capture cannot absorb a command tag ------------------
for f in "${SUITES[@]}"; do
  # The seed is the psql invocation that uses RETURNING. Isolate its pipeline
  # tail: the line that closes the SQL string and pipes the result.
  # grep -E, NOT `\|` in a basic-regex grep: `\|` as alternation is a GNU
  # extension, and on a BSD/ugrep host it matches nothing - which would fire the
  # "pipeline not found" branch below as a FALSE failure. The instrument must
  # not be the thing that reports the defect.
  # ANCHORED ON THE SEED'S OWN PIPELINE, not every pipe in the file. An
  # unanchored match returned four unrelated `| head -c` lines from error
  # messages, so the failure diagnostic pointed at code that had nothing to do
  # with the defect - the same "names the wrong subsystem" problem this file
  # exists to stop. The seed is the psql call that uses RETURNING, so the
  # pipeline is the closing line within a few lines after it.
  # A FULL-LINE anchor, and that is load-bearing. A substring match on
  # "RETURNING policy_id" hits the explanatory COMMENT above the seed - which
  # this very change added - so `head -1` anchored on prose and the window that
  # followed was four more lines of prose. The check then reported "<none
  # found>" against a file whose pipeline was correct: a presence check
  # satisfied by my own comment, inside the fix for that class. The SQL appears
  # as a whole line; the comment only ever mentions it mid-sentence.
  seed_line="$(grep -nE '^[[:space:]]+RETURNING policy_id[[:space:]]*$' "$f" | head -1 | cut -d: -f1)"
  if [ -z "$seed_line" ]; then
    bad "$(basename "$(dirname "$f")"): no 'RETURNING policy_id' seed found; this census has no subject in that file"
    continue
  fi
  pipeline="$(sed -n "${seed_line},$((seed_line + 4))p" "$f" | grep -E '\|[[:space:]]*(sed -n|tr -d|head)')"

  if grep -q 'psql .*-q ' "$f"; then
    ok "$(basename "$(dirname "$f")"): psql runs with -q (no command tag on stdout)"
  else
    bad "$(basename "$(dirname "$f")"): psql seed does not pass -q; the INSERT 0 1 tag can reach the capture"
  fi

  if printf '%s' "$pipeline" | grep -q "sed -n '1p'"; then
    ok "$(basename "$(dirname "$f")"): capture takes only the first line via sed -n '1p'"
  else
    bad "$(basename "$(dirname "$f")"): capture does not take the first line with sed -n '1p' (pipeline: ${pipeline:-<none found>})"
  fi

  # head -1 is specifically forbidden in a `set -e` suite: SIGPIPE -> 141.
  if grep -q 'set -euo pipefail' "$f" && printf '%s' "$pipeline" | grep -q 'head -1'; then
    bad "$(basename "$(dirname "$f")"): uses head -1 in a 'set -e' suite; psql can take SIGPIPE writing the tag and abort the suite with 141"
  else
    ok "$(basename "$(dirname "$f")"): no head -1 in the seed capture of a 'set -e' suite"
  fi
done

# --- 2. the load-bearing half: the capture is compared to what was seeded ----
# A `[ -n "$id" ]` guard accepts a corrupted value. The assertion must compare
# the captured id to the policy_id the INSERT was given.
for f in "${SUITES[@]}"; do
  suite="$(basename "$(dirname "$f")")"
  if grep -qE '\[ *"\$(policy_id|id)" *= *"\$(POLICY_PID|pid)" *\]' "$f"; then
    ok "$suite: the captured id is asserted EQUAL to the policy_id that was seeded"
  else
    bad "$suite: the seed capture is not compared to the policy_id it seeded (a -n guard passes a welded value)"
  fi

  # And the weaker guard must not be the ONLY thing standing between a corrupt
  # capture and 90 seconds of unrelated failure.
  if grep -qE '\[ *-n *"\$(policy_id|id)" *\] *\|\| *fail' "$f"; then
    bad "$suite: still relies on a bare [ -n ] guard for the seed capture"
  else
    ok "$suite: no bare [ -n ] seed guard remains"
  fi
done

# --- 3. BEHAVIOURAL: the pipeline shape actually does the job ----------------
# Structure checks above prove the text; this proves the semantics, against the
# exact output shape psql produces. Planted positives included - a check that
# only ever watches the correct case cannot tell a working fix from a fixed test.
PID='e2e-3039-gate-26252-12125'

# The old pipeline, reproduced: row + tag welded, and the -n guard accepts it.
old_capture="$(printf '%s\nINSERT 0 1\n' "$PID" | tr -d ' \n')"
if [ "$old_capture" != "$PID" ] && [ -n "$old_capture" ]; then
  ok "control: the pre-fix pipeline corrupts the id ('$old_capture') AND satisfies [ -n ]"
else
  bad "control did not reproduce the original defect; this test is not measuring what it claims"
fi

# The new pipeline recovers the clean id.
new_capture="$(printf '%s\nINSERT 0 1\n' "$PID" | sed -n '1p' | tr -d '[:space:]')"
if [ "$new_capture" = "$PID" ]; then
  ok "the fixed pipeline recovers the clean policy_id from row+tag output"
else
  bad "the fixed pipeline did not recover the id (got '$new_capture')"
fi

# Planted positives: three corruptions the -n guard accepted, each of which the
# equality assertion must reject.
plant_killed=0
plant_total=0
check_plant() {
  local desc="$1" captured="$2"
  plant_total=$((plant_total + 1))
  if [ "$captured" != "$PID" ]; then
    plant_killed=$((plant_killed + 1))
  else
    bad "planted corruption '$desc' SURVIVED the equality assertion"
  fi
  if [ -z "$captured" ]; then
    bad "planted corruption '$desc' was empty, so it proves nothing about [ -n ]"
  fi
}
check_plant "tag on the first line" "$(printf 'INSERT 0 1\n%s\n' "$PID" | sed -n '1p' | tr -d '[:space:]')"
check_plant "leading NOTICE"        "$(printf 'NOTICE:  identifier truncated\n%s\n' "$PID" | sed -n '1p' | tr -d '[:space:]')"
check_plant "a different id"        "$(printf 'some-other-policy\nINSERT 0 1\n' | sed -n '1p' | tr -d '[:space:]')"
if [ "$plant_killed" -eq 3 ] && [ "$plant_total" -eq 3 ]; then
  ok "all 3 planted corruptions are killed by an equality assertion (each passed the old -n guard)"
else
  bad "only $plant_killed of $plant_total planted corruptions were killed"
fi

# --- 4. the SIGPIPE reason for sed over head, measured not asserted ----------
# Demonstrates why (3)'s pipeline uses sed: under `set -e` + pipefail, head -1
# on a writer that keeps writing returns 141 and would abort the suite.
sigpipe_rc=0
( set -euo pipefail
  v="$( { printf '%s\n' "$PID"; for _ in $(seq 1 20000); do echo pad; done; } | head -1 )"
  echo "$v" >/dev/null
) >/dev/null 2>&1 || sigpipe_rc=$?
sed_rc=0
( set -euo pipefail
  v="$( { printf '%s\n' "$PID"; for _ in $(seq 1 20000); do echo pad; done; } | sed -n '1p' )"
  [ "$v" = "$PID" ]
) >/dev/null 2>&1 || sed_rc=$?
if [ "$sed_rc" -eq 0 ]; then
  ok "sed -n '1p' survives 'set -euo pipefail' against a writer that keeps writing"
else
  bad "sed -n '1p' did not survive 'set -euo pipefail' (rc=$sed_rc) - the chosen pipeline is unsafe here"
fi

# The head -1 half is CORROBORATION, not the rule. The rule - "do not use
# head -1 in a 'set -e' suite" - is enforced structurally in section 1 above,
# which does not depend on winning a race. If the race does not reproduce on a
# given runner, that is a fact about the runner, not a defect in the suites, so
# it is reported and not failed: a check that can red for a reason unrelated to
# its subject is a flake committed on purpose.
if [ "$sigpipe_rc" -ne 0 ]; then
  ok "measured: head -1 aborts under 'set -euo pipefail' (rc=$sigpipe_rc), which is why the capture uses sed"
else
  echo "  NOTE: head -1 did not lose the SIGPIPE race on this host (rc=$sigpipe_rc)."
  echo "        The sed-over-head rule is still enforced structurally above; this"
  echo "        demonstration is corroboration and its absence is not a failure."
fi

echo ""
echo "Checks passed: $PASS"
if [ "$FAIL" -gt 0 ]; then
  echo "FAILED: $FAIL check(s)"
  exit 1
fi
echo "✅ both posture seed captures validate the value they capture."
