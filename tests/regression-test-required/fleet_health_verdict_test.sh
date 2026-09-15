#!/usr/bin/env bash
# fleet_health_verdict_test.sh - drive the fleet monitor's decision through
# every state, including the one nobody can produce on demand.
#
# # WHY THIS TEST EXISTS IN THIS SHAPE
#
# The monitor it guards had never succeeded once: 30 of 30 recent runs failed
# with `NO self-hosted runner is online` because a 403 on an endpoint the token
# cannot reach fell through into the outage branch. A permanent false alarm on
# the one signal that matters makes the TRUE alarm unreadable, and on
# 2026-09-08 the fleet was down for hours while the monitor said what it always
# says (#3912, #3913).
#
# The lesson that shaped this file: a monitor is only worth anything if its
# NEGATIVE has been driven. Going green when the fleet is fine tells you
# nothing you did not already have. So `fleet-verdict.sh` was written to take
# its observation on stdin and perform no I/O and no clock reads, which lets
# this test hand it a fleet that is down - a state that otherwise appears only
# during an outage, which is the worst moment to discover the monitor is wrong.
#
# Run: bash tests/regression-test-required/fleet_health_verdict_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERDICT="${REPO_ROOT}/.github/scripts/fleet-verdict.sh"
[ -f "$VERDICT" ] || { echo "❌ FAIL: $VERDICT not found"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# drive <name> <expected-exit> <must-contain> <must-NOT-contain> <json>
drive() {
  local name="$1" want_rc="$2" want="$3" forbid="$4" json="$5" out rc
  out="$(printf '%s' "$json" | bash "$VERDICT" 2>&1)"; rc=$?
  if [ "$rc" -ne "$want_rc" ]; then
    bad "$name: exit $rc, want $want_rc. Output: ${out:0:200}"
    return
  fi
  if [ -n "$want" ] && ! grep -qF -- "$want" <<<"$out"; then
    bad "$name: exit code right but the text does not contain '$want'. Output: ${out:0:220}"
    return
  fi
  if [ -n "$forbid" ] && grep -qF -- "$forbid" <<<"$out"; then
    bad "$name: the text contains '$forbid', which belongs to a DIFFERENT verdict. Output: ${out:0:220}"
    return
  fi
  ok "$name"
}

echo "=== the fleet is executing work ==="

# A QUIET WINDOW IS NOT AN OUTAGE, and this is the row that proves the monitor
# does not need other people's traffic to return green. corroboration.measured
# is FALSE here - nothing else ran - and that must not be read as "could not
# measure", because the probe answered the question by itself.
drive "a picked-up probe is green even when nothing else ran in the window" \
  0 "was picked up after" "COULD NOT MEASURE" \
  '{"probe_status":"in_progress","waited_seconds":18,"deadline_seconds":300,
    "corroboration":{"measured":false,"detail":"not needed"}}'

drive "a probe that ran to completion is green" \
  0 "The fleet is executing work" "" \
  '{"probe_status":"completed","waited_seconds":42,"deadline_seconds":300,
    "corroboration":{"measured":false,"detail":"not needed"}}'

echo ""
echo "=== THE FLEET IS DOWN - the state this monitor exists for ==="

# Both halves measured: our probe never started AND nothing else started.
drive "a queued probe with zero other starts is an outage, and says so" \
  1 "THE SELF-HOSTED FLEET IS ACCEPTING NO WORK" "COULD NOT MEASURE" \
  '{"probe_status":"queued","waited_seconds":300,"deadline_seconds":300,
    "corroboration":{"measured":true,"started":0,"window_minutes":30}}'

# THE FAILURE TEXT MUST CARRY THE OBSERVATION. The old monitor printed a fixed
# sentence, so a reader could not tell a real outage from its own 403 without
# opening the log.
drive "and the outage text names what was observed: the wait and the window" \
  1 "probe queued 300s; 0 other jobs started in 30m" "" \
  '{"probe_status":"queued","waited_seconds":300,"deadline_seconds":300,
    "corroboration":{"measured":true,"started":0,"window_minutes":30}}'

echo ""
echo "=== a BUSY fleet is not a down fleet ==="

# The false alarm this design is most at risk of reintroducing: a probe can
# queue because every runner is occupied. Calling that an outage would be the
# old defect wearing new clothes.
drive "a queued probe is DEGRADED, not down, when other jobs are starting" \
  0 "DEGRADED" "ACCEPTING NO WORK" \
  '{"probe_status":"queued","waited_seconds":300,"deadline_seconds":300,
    "corroboration":{"measured":true,"started":7,"window_minutes":30}}'

drive "and the degraded text names how many others started" \
  0 "7 other job(s) started in 30m" "" \
  '{"probe_status":"queued","waited_seconds":300,"deadline_seconds":300,
    "corroboration":{"measured":true,"started":7,"window_minutes":30}}'

echo ""
echo "=== 'I could not measure' is NOT 'the fleet is down' ==="

# THE WHOLE POINT. The replaced monitor turned a failed API call into the
# outage sentence. These rows pin that the two are different exit codes AND
# different text, in both directions.
drive "a queued probe with unanswerable corroboration is exit 2, not an outage" \
  2 "COULD NOT MEASURE" "ACCEPTING NO WORK" \
  '{"probe_status":"queued","waited_seconds":300,"deadline_seconds":300,
    "corroboration":{"measured":false,"window_minutes":30,"detail":"the runs list could not be read"}}'

drive "and it repeats the reason it could not answer" \
  2 "the runs list could not be read" "" \
  '{"probe_status":"queued","waited_seconds":300,"deadline_seconds":300,
    "corroboration":{"measured":false,"window_minutes":30,"detail":"the runs list could not be read"}}'

drive "a probe missing from the run's job list is exit 2, not an outage" \
  2 "probe job absent from the run" "ACCEPTING NO WORK" \
  '{"probe_status":"missing","waited_seconds":0,"deadline_seconds":300,
    "corroboration":{"measured":false,"detail":"not needed"}}'

drive "a cancelled probe is exit 2, not an outage" \
  2 "unrecognised probe status" "ACCEPTING NO WORK" \
  '{"probe_status":"cancelled","waited_seconds":60,"deadline_seconds":300,
    "corroboration":{"measured":false,"detail":"not needed"}}'

drive "a malformed observation is exit 2, not an outage" \
  2 "malformed observation" "ACCEPTING NO WORK" \
  'this is not json'

echo ""
echo "=== the host-specific remediation is INJECTED, not baked in ==="

# `.github/scripts/*` is copied to the public community mirror while the
# workflow calling it is excluded, so instance identifiers live in the caller.
# Both directions are pinned: present when supplied, and no empty error line
# when it is not - a bare `::error::` would be an alarm with no content.
_down='{"probe_status":"queued","waited_seconds":300,"deadline_seconds":300,
        "corroboration":{"measured":true,"started":0,"window_minutes":30}}'
_out="$(printf '%s' "$_down" | FLEET_REMEDIATION="check the spot request" bash "$VERDICT" 2>&1)"
if grep -qF -- "::error::check the spot request" <<<"$_out"; then
  ok "the caller's remediation reaches the outage message"
else
  bad "FLEET_REMEDIATION was set and does not appear in the outage message: ${_out:0:200}"
fi
_out="$(printf '%s' "$_down" | bash "$VERDICT" 2>&1)"
if grep -qE '^::error::[[:space:]]*$' <<<"$_out"; then
  bad "with no FLEET_REMEDIATION the script emits an EMPTY ::error:: line - an alarm with no content"
else
  ok "and with none supplied it emits no empty error line"
fi
# AND THE MIRRORED FILE CARRIES NO HOST DETAIL. This is the property the
# injection exists for, so it is asserted rather than left to the reader.
if grep -qE "axonflow-ci-runner-spot|us-east-1b|infrastructure/ci-runners" "$VERDICT"; then
  bad "$VERDICT names a host, region or infrastructure path, and it is copied to the PUBLIC mirror"
else
  ok "the mirrored decider names no host, region or infrastructure path"
fi

echo ""
echo "=== the four verdicts are mutually distinguishable ==="

# A reader - or a notification - must be able to tell them apart from the last
# line alone. Same-text-different-cause is the defect being removed, so this
# asserts the summary lines are pairwise different rather than trusting that
# four branches produce four sentences.
summaries=()
for json in \
  '{"probe_status":"in_progress","waited_seconds":5,"deadline_seconds":300,"corroboration":{"measured":false}}' \
  '{"probe_status":"queued","waited_seconds":300,"deadline_seconds":300,"corroboration":{"measured":true,"started":4,"window_minutes":30}}' \
  '{"probe_status":"queued","waited_seconds":300,"deadline_seconds":300,"corroboration":{"measured":true,"started":0,"window_minutes":30}}' \
  '{"probe_status":"queued","waited_seconds":300,"deadline_seconds":300,"corroboration":{"measured":false,"window_minutes":30}}'
do
  summaries+=("$(printf '%s' "$json" | bash "$VERDICT" 2>&1 | tail -1)")
done
uniq_count="$(printf '%s\n' "${summaries[@]}" | sort -u | wc -l | tr -d ' ')"
if [ "$uniq_count" -eq 4 ]; then
  ok "all four verdicts end in a distinct summary line"
else
  bad "only $uniq_count of 4 verdict summary lines are distinct; a reader cannot tell them apart: ${summaries[*]}"
fi

# ANTI-VACUITY. Every row above asserts on output, so a decider that printed
# nothing and exited 0 would fail them - but a decider that could not be
# EXECUTED would skip silently in a suite that only counted failures.
if [ "$((PASS + FAIL))" -lt 15 ]; then
  bad "only $((PASS + FAIL)) assertions ran; this file declares 15 or more, so something was skipped"
fi

echo ""
echo "  passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
