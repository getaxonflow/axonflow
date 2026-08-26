#!/usr/bin/env bash
# Regression test for the v9.13.0 preflight work (#3071 Tier: upgrade tooling).
#
# scripts/deployment/v9_self_hosted_preflight.sh is the script an operator runs
# BEFORE pulling a new image, on a stack that is still serving traffic. Its
# whole value is that a green run means something. Three ways it could stop
# meaning something, all of which have actually happened in this repository's
# history, are pinned here:
#
#   1. A result crossing a `$(...)` boundary. `X=$(psql_q "…")` runs psql in a
#      SUBSHELL, so the exit status is lost and a FAILED query is byte-identical
#      to a query that legitimately returned no rows. Every "0 affected
#      policies" the script prints would then also be what a dropped connection
#      looks like. The query layer returns through globals for exactly this
#      reason, and this test fails if a `$(psql...)` ever reappears.
#
#   2. Existence probes reading information_schema. information_schema is
#      PRIVILEGE-FILTERED — it shows only objects the connecting role holds some
#      privilege on. Measured against a real PostgreSQL 15: a preflight run
#      under a read-only role with no SELECT on dynamic_policies saw the table
#      as ABSENT, skipped the migration-155 check entirely, and printed
#      "core/155 has nothing to repair here" — a confident all-clear derived
#      from a permission error. pg_catalog is not filtered that way, so the
#      table is found, the SELECT raises "permission denied", and the run fails
#      loudly. Fail-closed is the only acceptable direction for this script.
#
#   3. Section numbering drifting from the number of checks, so the banner says
#      "[3/8]" on a script with twelve of them.
#
# Part 4 is the behavioural half: the script's own `--self-test`, which drives
# the DEPLOYMENT_MODE classifier and the numeric helpers with no database. Part
# 5 is the anti-vacuity half — it MUTATES a throwaway copy of the script and
# asserts the self-test goes red. A guard nobody has watched fail is not a
# guard, and this file would otherwise be exactly that: a set of greps that pass
# on any script, including an empty one.
#
# Run locally:
#   bash tests/regression-test-required/preflight_fail_closed_test.sh

# Whole-file: the mutation cases below quote LITERAL source lines from the
# script under test. Expanding them would mutate nothing, which is the one
# outcome this file exists to prevent.
# shellcheck disable=SC2016

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
PREFLIGHT="${REPO_ROOT}/scripts/deployment/v9_self_hosted_preflight.sh"
fail=0

if [ ! -f "${PREFLIGHT}" ]; then
  echo "FAIL: ${PREFLIGHT} not found."
  echo "      It is re-included BY NAME in .github/workflows/sync-community-repo.yml"
  echo "      after /scripts/* is excluded, and named in three published docs pages."
  echo "      If it moved, update both — a rename is never a silent change."
  exit 1
fi

# --- 1. No query result may cross a command-substitution boundary ----------
#
# Matches `$(psql`, `$(psql_exec`, `$(q `, `$(psql_scalar` and the backtick
# spellings. The legitimate uses inside psql_exec itself assign a LOCAL and
# capture the status with `|| PSQL_RC=$?` on the same line, which is the one
# shape that does not lose it — those are `raw=$(...)`, not `$(psql_`.
if grep -nE '\$\(\s*(psql|q)[[:space:]_]|`[[:space:]]*(psql|q)[[:space:]_]' "${PREFLIGHT}" \
     | grep -vE '^[0-9]+:[[:space:]]*#'; then
  echo "FAIL: a psql helper is invoked inside \$(...) (see hits above)."
  echo "      That runs it in a subshell: psql's exit status is discarded and a"
  echo "      failed query becomes indistinguishable from an empty result."
  echo "      Use q/psql_exec, which return through PSQL_OUT/PSQL_RC/Q/QOK."
  fail=1
else
  echo "ok: no query result crosses a command-substitution boundary"
fi

# --- 2. Existence probes must read pg_catalog, not information_schema ------

for fn in table_exists column_exists; do
  body="$(awk -v f="^${fn}\\\\(\\\\) \\\\{" '$0 ~ f {p=1} p {print} p && /^}/ {exit}' "${PREFLIGHT}")"
  if [ -z "${body}" ]; then
    echo "FAIL: ${fn}() not found in ${PREFLIGHT} — the probe was renamed or removed,"
    echo "      and this test would otherwise check nothing and report success."
    fail=1
    continue
  fi
  case "${body}" in
    *information_schema*)
      echo "FAIL: ${fn}() queries information_schema, which is PRIVILEGE-FILTERED."
      echo "      A role without SELECT on a table sees it as ABSENT, so every check"
      echo "      keyed on this probe silently skips and reports a clean result."
      echo "      Query pg_catalog.pg_class / pg_catalog.pg_attribute instead."
      fail=1
      ;;
    *pg_catalog*)
      echo "ok: ${fn}() reads pg_catalog (not privilege-filtered)"
      ;;
    *)
      echo "FAIL: ${fn}() reads neither pg_catalog nor information_schema — this test"
      echo "      no longer knows what it is asserting about. Update it deliberately."
      fail=1
      ;;
  esac
done

# --- 2b. No UNESCAPED backtick that the shell would EXECUTE ---------------
#
# Inside a double-quoted bash string a backtick is command substitution. Writing
# `if dbURL != ""` in a remediation message — as a reviewer naturally would,
# quoting source — makes the script execute it at the exact moment the operator
# most needs to read the message. Nothing else here catches it: `bash -n`
# accepts it, `--self-test` does not render FAIL messages, and the message only
# appears on a stack that is already misconfigured.
#
# The first version of this guard skipped any line beginning with `#`. That is
# wrong twice over, and both were demonstrated: a `#`-leading line INSIDE a
# multi-line double-quoted string is string content, not a comment, so a live
# backtick there was waved through; and a backtick in a TRAILING comment, or
# inside single quotes where it is literal, was flagged — with a remedy that
# would have inserted a backslash into the string.
#
# So this tracks quoting state across the whole file the way the shell does:
# single-quoted spans are literal, double-quoted spans are live, and a `#`
# only opens a comment when it is outside both and at a word boundary.
py_check=$(cat <<'PYEOF'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
hits, i, n = [], 0, len(src)
sq = dq = False          # inside '...' / "..."
line = 1
while i < n:
    c = src[i]
    if c == "\n":
        line += 1; i += 1; continue
    if c == "\\" and not sq:
        i += 2; continue          # escaped: consumes the next char, incl. ` and "
    if c == "'" and not dq:
        sq = not sq; i += 1; continue
    if c == '"' and not sq:
        dq = not dq; i += 1; continue
    if c == "#" and not sq and not dq:
        # A comment only starts at the beginning of a word.
        if i == 0 or src[i-1] in " \t\n;&|()":
            j = src.find("\n", i)
            if j < 0:
                break
            i = j; continue
    if c == "`" and not sq:
        hits.append((line, src[src.rfind("\n", 0, i)+1 : src.find("\n", i)][:100]))
    i += 1
for ln, txt in hits:
    print("%d: %s" % (ln, txt.strip()))
sys.exit(1 if hits else 0)
PYEOF
)
if bt_hits="$(printf '%s' "${py_check}" | python3 - "${PREFLIGHT}")"; then
  echo "ok: no backtick the shell would execute"
else
  echo "FAIL: live backtick(s) — command substitution — in ${PREFLIGHT}:"
  printf '%s\n' "${bt_hits}" | sed 's/^/      /'
  echo "      Inside a double-quoted bash string a backtick runs a command. In a"
  echo "      FAIL/WARN message that means the script executes the operator's"
  echo "      remediation text instead of printing it. Escape it with a backslash,"
  echo "      or move it into single quotes."
  fail=1
fi

# --- 2c. The aggregate query-failure backstop must still be wired ----------
#
# `q()` recording into PSQL_FAILURES, and the final verdict FAILing when that
# array is non-empty, are the two halves of the ONE guard covering the probes
# whose per-call QOK nobody inspects — the role attributes, the failed-migration
# list. Delete either half and those probes go back to failing silently.
#
# Matched as a STATEMENT, not as a substring. The first version accepted the
# text anywhere in q()'s body, so replacing the real append with
# `: "no-op; the real line was PSQL_FAILURES+=(...)"` satisfied it — the mutant
# its own comment claimed to catch.
#
# This is still a shape check and says so. The behavioural proof needs a
# database: run the script under a role with SELECT revoked and the run must
# FAIL and name the query. That is not available on this runner.

q_body="$(awk '/^q\(\) \{/{p=1} p{print} p && /^\}/{exit}' "${PREFLIGHT}")"
if [ -z "${q_body}" ]; then
  echo "FAIL: q() not found in ${PREFLIGHT} — the query helper was renamed, and every"
  echo "      assertion in this section would silently check nothing."
  fail=1
elif printf '%s\n' "${q_body}" | grep -qE '^[[:space:]]*PSQL_FAILURES\+=\('; then
  echo "ok: q() appends to PSQL_FAILURES as a statement"
else
  echo "FAIL: q() has no statement appending to PSQL_FAILURES. A probe whose caller"
  echo "      does not inspect QOK would then fail silently and the run could still"
  echo "      report a clean verdict."
  fail=1
fi

# Tolerant of spacing: the earlier exact-text grep reported the property as
# BROKEN for `[[ ${#PSQL_FAILURES[@]} -gt 0 ]]`, which is identical in meaning.
# A guard whose false positive tells you to undo a correct edit is worse than no
# guard. Anchored to a statement so a commented-out copy cannot satisfy it.
if grep -qE '^[[:space:]]*if[[:space:]]+\[\[[[:space:]]*"?\$\{#PSQL_FAILURES\[@\]\}"?[[:space:]]*-gt[[:space:]]*0[[:space:]]*\]\]' "${PREFLIGHT}" \
   && grep -q 'preflight quer(ies) did not execute' "${PREFLIGHT}"; then
  echo "ok: the final verdict FAILs when any query did not execute"
else
  echo "FAIL: the final verdict no longer fails on a non-empty PSQL_FAILURES."
  echo "      An unexecuted query would be reported as a clean run."
  fail=1
fi

# --- 3. TOTAL_CHECKS must equal the number of section() calls -------------

# Tolerant of a trailing comment. Anchored so a mention inside a string or a
# commented-out copy cannot satisfy it, but `TOTAL_CHECKS=12  # twelve` is a
# legitimate way to write the line and must not be reported as "not declared" —
# the false positive that class of grep produces tells the author to undo a
# correct edit.
declared="$(grep -E '^TOTAL_CHECKS=[0-9]+([[:space:]]*#.*)?$' "${PREFLIGHT}" | head -1 | sed -E 's/^TOTAL_CHECKS=([0-9]+).*$/\1/')"
actual="$(grep -cE '^section "' "${PREFLIGHT}")"
if [ -z "${declared}" ]; then
  echo "FAIL: TOTAL_CHECKS is not declared as a bare integer at the start of a line."
  fail=1
elif [ "${declared}" != "${actual}" ]; then
  echo "FAIL: TOTAL_CHECKS=${declared} but there are ${actual} section() calls."
  echo "      The script prints '[n/${declared}]' on every check, and the script's own"
  echo "      end-of-run assertion will refuse to print a verdict."
  fail=1
else
  echo "ok: TOTAL_CHECKS=${declared} matches ${actual} section() calls"
fi

# --- 4. Behavioural: the script's own self-test ---------------------------

if ! st_out="$(bash "${PREFLIGHT}" --self-test 2>&1)"; then
  echo "FAIL: ${PREFLIGHT} --self-test did not pass:"
  printf '%s\n' "${st_out}" | sed 's/^/      /'
  fail=1
else
  st_assertions="$(printf '%s\n' "${st_out}" | grep -c '^  ok ')"
  # A floor, not an exact count: adding cases must not require editing this
  # file, but a self-test that silently stopped asserting must not pass either.
  # 40 is well below the count today and far above "the harness ran".
  if [ "${st_assertions}" -lt 40 ]; then
    echo "FAIL: --self-test reported only ${st_assertions} passing assertions (expected >= 40)."
    echo "      A self-test that stopped asserting still exits 0."
    fail=1
  else
    echo "ok: --self-test passed ${st_assertions} assertions"
  fi
fi

# --- 5. Anti-vacuity: the self-test must be able to go RED ----------------
#
# Each mutation below is a real way the classifier could be wrong, applied to a
# THROWAWAY COPY. A mutant that does not parse is not credited as killed — a
# non-zero exit from a syntax error is not the assertion firing.

work="$(mktemp -d)"
mutate_and_expect_red() {
  local name="$1" old="$2" new="$3" copy="${work}/${1}.sh" out rc
  cp "${PREFLIGHT}" "${copy}"
  if ! grep -qF -- "${old}" "${copy}"; then
    echo "FAIL: mutation '${name}' could not be applied — the pattern is gone from the"
    echo "      script, so this anti-vacuity case is no longer testing anything."
    fail=1
    return
  fi
  # LITERAL replacement, done with parameter expansion rather than sed or awk.
  # Both of those take a REGEX, and every `old` below contains `[[`, `$` and
  # `(` — so the substitution silently does nothing, the copy stays identical
  # to the original, and every mutation is reported as having SURVIVED. That
  # false alarm is the friendly failure mode; the dangerous one is the same
  # mechanism applied where a no-op reads as success.
  local line prefix suffix applied=0
  : > "${copy}"
  while IFS= read -r line || [ -n "${line}" ]; do
    if [ "${applied}" -eq 0 ] && [ "${line#*"${old}"}" != "${line}" ]; then
      prefix="${line%%"${old}"*}"
      suffix="${line#*"${old}"}"
      line="${prefix}${new}${suffix}"
      applied=1
    fi
    printf '%s\n' "${line}" >> "${copy}"
  done < "${PREFLIGHT}"
  if [ "${applied}" -eq 0 ]; then
    echo "FAIL: mutation '${name}' matched by grep but not by the replacement loop."
    fail=1
    return
  fi
  if cmp -s "${copy}" "${PREFLIGHT}"; then
    echo "FAIL: mutation '${name}' left the copy byte-identical to the original."
    echo "      Nothing was mutated, so a passing self-test proves nothing."
    fail=1
    return
  fi
  if ! bash -n "${copy}" 2>/dev/null; then
    echo "FAIL: mutation '${name}' produced a script that does not parse. It would exit"
    echo "      non-zero for the wrong reason, so it cannot be credited as killed."
    fail=1
    return
  fi
  out="$(bash "${copy}" --self-test 2>&1)"; rc=$?
  if [ "${rc}" -eq 0 ]; then
    echo "FAIL: mutation '${name}' SURVIVED — the self-test still passed with the"
    echo "      classifier broken. The self-test is not discriminating."
    fail=1
  elif ! printf '%s\n' "${out}" | grep -q '^  FAIL '; then
    echo "FAIL: mutation '${name}' exited ${rc} but printed no failing assertion."
    echo "      That is a crash, not a detection."
    fail=1
  else
    echo "ok: mutation '${name}' killed by $(printf '%s\n' "${out}" | grep -c '^  FAIL ') assertion(s)"
  fi
}

exact_match_line='        if [[ "$raw" == "$m" ]]; then MODE_CLASS="recognised"; return 0; fi'
mutate_and_expect_red "accepts-untrimmed" \
  "${exact_match_line}" \
  '        if [[ "$(trim_ws "$raw")" == "$m" ]]; then MODE_CLASS="recognised"; return 0; fi'
mutate_and_expect_red "accepts-any-case" \
  "${exact_match_line}" \
  '        if [[ "$(lower "$raw")" == "$m" ]]; then MODE_CLASS="recognised"; return 0; fi'
mutate_and_expect_red "accepts-substring" \
  "${exact_match_line}" \
  '        if [[ "$raw" == *"$m"* ]]; then MODE_CLASS="recognised"; return 0; fi'
mutate_and_expect_red "unset-becomes-fatal" \
  '    if [[ -z "$raw" ]]; then MODE_CLASS="unset"; return 0; fi' \
  '    if [[ -z "$raw" ]]; then MODE_CLASS="unrecognised"; return 0; fi'

# admin_auth_required (check 16) mirrors isAdminAuthRequired() in
# ee/platform/customer-portal/middleware/admin_auth.go, and check 16 keys its
# WARNING on the answer: whether a blank ADMIN_API_KEY means "every admin route
# answers 500 and break-glass recovery is unusable" or "the admin API is being
# served anonymously". Both statements are about the operator's deployment, so
# each of the three ways the predicate could quietly stop discriminating gets a
# mutant here.
mutate_and_expect_red "production-no-longer-forces-auth" \
  '    if [[ "$env_norm" == "production" ]]; then return 0; fi' \
  '    if [[ "$env_norm" == "prod" ]]; then return 0; fi'
# secretenv.Get trims the key once, so ADMIN_API_KEY="   " is BLANK to the
# portal. Drop the trim and check 16 reports the recovery path as armed on a
# deployment where every admin route answers 500.
mutate_and_expect_red "whitespace-key-counts-as-configured" \
  '    key_norm="$(trim_ws "$3")"' \
  '    key_norm="$3"'
# The platform's switch has a fail-CLOSED default: a mode nobody enumerated
# requires auth. A substring matcher passes every enumerated case and, because
# the list carries the empty-string arm, makes every unknown mode optional.
mutate_and_expect_red "unknown-mode-fails-open" \
  '        if [[ "$mode_norm" == "$m" ]]; then ADMIN_AUTH_REQUIRED=0; return 0; fi' \
  '        if [[ "$mode_norm" == *"$m"* ]]; then ADMIN_AUTH_REQUIRED=0; return 0; fi'

# pg_timeout_to_ms + c17_consider decide check 17's verdict, and check 17 is the
# only FAIL-capable statement this script makes about migration runtime. Every
# way the arithmetic could quietly stop discriminating is a way an operator is
# told their upgrade will complete when it will boot-loop instead, so each gets
# a mutant.
#
# A bare number is MILLISECONDS. Reading it as seconds inflates every configured
# timeout by 1000x and makes the FAIL unreachable.
mutate_and_expect_red "bare-timeout-read-as-seconds" \
  '        *)    num="$v";       unit="ms"  ;;' \
  '        *)    num="$v";       unit="s"   ;;'
# "500ms" must not be read as a number ending in "s". Moving the ms arm below
# the s arm loses three orders of magnitude on every SHOW-normalised value.
mutate_and_expect_red "ms-swallowed-by-the-s-arm" \
  '        *ms)  num="${v%ms}";  unit="ms"  ;;' \
  '        *ms)  num="${v%s}";   unit="s"   ;;'
# A sub-millisecond timeout is the TIGHTEST a deployment can carry. Truncating
# it to 0 reports it as "no timeout configured", which is this check's one
# fail-open direction.
mutate_and_expect_red "sub-millisecond-truncates-to-disabled" \
  '        us)  printf '"'"'%s'"'"' "$(( (10#$num + 999) / 1000 ))" ;;' \
  '        us)  printf '"'"'%s'"'"' "$(( 10#$num / 1000 ))" ;;'
# Zero means DISABLED. Folding it in as a candidate makes it the tightest value
# on every deployment that has correctly turned the timeout off, so check 17
# would FAIL all of them.
mutate_and_expect_red "zero-becomes-the-tightest-timeout" \
  '    [[ "$ms" == "0" ]] && return 0' \
  '    [[ "$ms" == "-1" ]] && return 0'
# An unparseable value must be reported. Dropping the flag silently turns "we
# could not read one of the places a timeout is set" into "none is set".
mutate_and_expect_red "unparseable-timeout-not-flagged" \
  '    C17_SOURCES_UNREADABLE=1  # an unparsed value is not "none configured"' \
  '    C17_SOURCES_UNREADABLE=0  # an unparsed value is not "none configured"'
# The parse guard, inverted: a value that parsed FINE then takes the "could not
# parse" branch, so every real timeout is discarded and the check reports "none
# configured" on a deployment that has one.
mutate_and_expect_red "parse-guard-inverted" \
  '    if ! ms="$(pg_timeout_to_ms "$raw")"; then' \
  '    if ms="$(pg_timeout_to_ms "$raw")"; then'
# The label/value split must survive a label containing a space, which
# pg_db_role_setting really produces. Splitting on whitespace instead of the
# semicolon reintroduces the measured defect.
mutate_and_expect_red "entry-split-on-whitespace" \
  '    IFS='"'"';'"'"'' \
  '    IFS='"'"' '"'"''
# component_names must leave nothing behind for an unknown component, or its
# caller silently gets the PREVIOUS component's container names: a confident
# answer about the wrong container.
mutate_and_expect_red "unknown-component-keeps-stale-names" \
  '    COMP_UPPER=""; COMP_DEFAULT_SVC=""; COMP_ECS_NAMES=""' \
  '    :'

echo
if [ "${fail}" -ne 0 ]; then
  echo "preflight_fail_closed_test.sh: FAILED"
  exit 1
fi
echo "preflight_fail_closed_test.sh: PASSED"
exit 0
