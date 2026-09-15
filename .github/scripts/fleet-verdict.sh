#!/usr/bin/env bash
# fleet-verdict.sh - decide whether the self-hosted fleet is executing work.
#
# Reads one JSON observation on stdin and prints a verdict. It performs NO API
# calls and no clock reads, which is the whole point: the workflow gathers the
# observation, this decides, and a test can hand it any state including the one
# nobody can produce on demand - a fleet that is down.
#
# # WHY THE OBSERVATION IS A PROBE AND NOT A RUNNER COUNT
#
# The previous monitor asked `/actions/runners` for the runner list. That
# endpoint needs runner ADMINISTRATION scope, which the default GITHUB_TOKEN
# cannot be granted through a `permissions:` block at all - `administration` is
# not one of the keys the block accepts - so `actions: read` neither does nor
# can cover it. Every run got HTTP 403 and fell into its own "NO self-hosted
# runner is online" branch: 30 of 30 recent runs failed with the exact text a
# real outage prints, so the true alarm was indistinguishable from the noise
# (#3912, #3913). It never succeeded once.
#
# A runner list is a DECLARATION. What we care about is whether a job targeting
# the fleet's labels can START, which is the running system and which
# `actions: read` genuinely covers via a run's own jobs.
#
# # WHY A PROBE RATHER THAN COUNTING RECENT COMPLETIONS
#
# Counting completions cannot tell a DEAD fleet from a QUIET one: both show
# zero. The workflow therefore submits its own job onto the fleet's labels, so
# there is always demand to observe. "Nobody asked" stops being a possible
# explanation for silence.
#
# # THE THIRD STATE, WHICH IS THE ONE THAT MAKES THIS HONEST
#
# A probe can also queue because the fleet is BUSY, and a monitor that calls
# saturation an outage is the false alarm we are removing, wearing new clothes.
# So when the probe is still queued at the deadline the workflow asks a second
# question - has any OTHER job on these labels started recently? - and the
# four verdicts are kept apart:
#
#   picked up            -> the fleet is executing work.                 exit 0
#   queued, others ran   -> saturated, not down. Degraded, not an alarm. exit 0
#   queued, nothing ran  -> the fleet is accepting no work.              exit 1
#   could not measure    -> an API call failed. NOT a fleet verdict.     exit 2
#
# The last is deliberately its own exit code and its own text. The defect being
# removed is precisely a failed API call rendered as "the fleet is down".
#
# Usage:  fleet-verdict.sh < observation.json
set -uo pipefail

obs="$(cat)"
if ! jq -e . >/dev/null 2>&1 <<<"$obs"; then
  echo "::error::fleet-verdict: the observation is not valid JSON, so nothing was decided."
  echo "COULD NOT MEASURE: malformed observation"
  exit 2
fi

get() { jq -r "$1 // empty" <<<"$obs"; }

probe="$(get .probe_status)"
waited="$(get .waited_seconds)"
deadline="$(get .deadline_seconds)"
labels="$(get .labels)"
measured="$(jq -r '.corroboration.measured // false' <<<"$obs")"
others_started="$(jq -r '.corroboration.started // 0' <<<"$obs")"
window="$(jq -r '.corroboration.window_minutes // 0' <<<"$obs")"
detail="$(jq -r '.corroboration.detail // empty' <<<"$obs")"

[ -n "$probe" ] || { echo "::error::fleet-verdict: no probe_status in the observation."; \
                     echo "COULD NOT MEASURE: no probe_status"; exit 2; }
[ -n "$labels" ] || labels="[self-hosted, linux, x64, axonflow]"

# ── the probe never got a record at all ──────────────────────────────────
# Not a fleet statement: the run's own job list did not contain the probe, so
# the thing that would have carried the evidence is missing.
if [ "$probe" = "missing" ]; then
  echo "::error::COULD NOT MEASURE: the probe job does not appear in this run's job list," \
       "so nothing was observed about ${labels}. This is a defect in the monitor or in the" \
       "jobs API response, NOT a statement about the fleet - do not read it as an outage."
  echo "COULD NOT MEASURE: probe job absent from the run"
  exit 2
fi

# ── the probe started: the fleet is executing work ───────────────────────
if [ "$probe" = "in_progress" ] || [ "$probe" = "completed" ]; then
  echo "OK: a job targeting ${labels} was picked up after ${waited}s (probe status: ${probe})."
  echo "The fleet is executing work, which is the property this monitor exists to check."
  exit 0
fi

# ── still queued at the deadline ─────────────────────────────────────────
if [ "$probe" != "queued" ]; then
  echo "::error::COULD NOT MEASURE: the probe reported status '${probe}', which this monitor" \
       "does not know how to read. Cancelled or skipped probes are not fleet verdicts."
  echo "COULD NOT MEASURE: unrecognised probe status '${probe}'"
  exit 2
fi

if [ "$measured" != "true" ]; then
  echo "::error::COULD NOT MEASURE: the probe was still queued after ${waited}s, and the" \
       "corroborating query - has any other job on ${labels} started in the last" \
       "${window}m - could not be answered${detail:+ (${detail})}. A queued probe ALONE" \
       "cannot tell a dead fleet from a busy one, so no fleet verdict is issued here."
  echo "COULD NOT MEASURE: corroboration unavailable"
  exit 2
fi

if [ "${others_started:-0}" -gt 0 ]; then
  echo "::warning::DEGRADED, not down: the probe waited ${waited}s without being picked up," \
       "but ${others_started} other job(s) on ${labels} started in the last ${window}m." \
       "The fleet is executing work and is slow to reach this job - saturation, not an outage." \
       "If this repeats, capacity is the question, not availability."
  echo "DEGRADED: probe queued ${waited}s; ${others_started} other job(s) started in ${window}m"
  exit 0
fi

echo "::error::THE SELF-HOSTED FLEET IS ACCEPTING NO WORK. A probe job on ${labels} was still" \
     "QUEUED after ${waited}s (deadline ${deadline}s), and ZERO other jobs on those labels" \
     "started anywhere in this repository in the last ${window}m. Both halves were measured;" \
     "this is not an inference from silence."
echo "::error::Every job targeting those labels is queueing rather than failing, so nothing" \
     "else goes red and work simply stops moving."
# THE REMEDIATION IS INJECTED, NOT WRITTEN HERE, and that is a distribution
# decision rather than a style one. `.github/scripts/*` is copied to the PUBLIC
# community mirror while the workflow that calls this is excluded from it, so
# host names, regions and instance identifiers belong in the caller. It also
# keeps this file a pure decision function that a test can drive anywhere.
[ -n "${FLEET_REMEDIATION:-}" ] && echo "::error::${FLEET_REMEDIATION}"
echo "FLEET DOWN: probe queued ${waited}s; 0 other jobs started in ${window}m"
exit 1
