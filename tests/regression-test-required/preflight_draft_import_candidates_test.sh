#!/usr/bin/env bash
# Behavioural test for the upgrade preflight's check 26
# (scripts/deployment/v9_self_hosted_preflight.sh): the per-policy overrides
# that stop applying at the v11 upgrade are WARNED about by count and by name -
# the organization-wide rows v11.0.0's once-only import (migration core/183)
# turns into an unpublished draft, and the tenant-scoped rows it does not
# import at all. None of either is a PASS, and a table this connection cannot
# read, a query that did not run or a schema the preview cannot read is never
# reported as none.
#
# The check's own block is extracted from the script and run against stubs of
# the query helpers, with the script's own is_uint and rls_blocks_all_clear, so
# this drives the code the preflight runs, not a copy of it. Every query the
# block sends must carry the list it counts, C26_CANDIDATES or C26_TENANT_ROWS:
# those strings, and the wrappers around them, are what
# platform/agent/preflight_draft_import_candidates_realpg_test.go runs against
# a migrated database beside the import itself.
#
# Run locally:
#   bash tests/regression-test-required/preflight_draft_import_candidates_test.sh

# Whole-file: the stubs assign RLS_<table>, RLS_STATE, Q and QOK for the check
# block this file evals, and RLS_<table> is read by indirect expansion, so
# the linter sees none of their readers.
# shellcheck disable=SC2034

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PF="$ROOT/scripts/deployment/v9_self_hosted_preflight.sh"

# The block ends at the next check's header or at the section-count check,
# whichever comes first: a check appended after this one must not run here.
BLOCK="$(awk '/^# Check 26 - /{on=1; print; next} on && /^# (Check [0-9]+ - |Internal consistency: every section must have been numbered\.)/{on=0} on' "$PF")"
if ! grep -qE '^C26_CANDIDATES="' <<<"$BLOCK" || ! grep -qE '^C26_TENANT_ROWS="' <<<"$BLOCK"; then
    echo "FAIL: check 26 or its C26_CANDIDATES / C26_TENANT_ROWS query was not found in $PF"
    exit 1
fi

# The script's own helpers, not re-implementations: a stub that agreed with
# the real function would pass whatever the real function does.
HELPERS="$(awk '/^is_uint\(\) \{/{print; next} /^rls_blocks_all_clear\(\) \{/{on=1} on{print} on&&/^\}/{on=0}' "$PF")"
if ! grep -q '^is_uint()' <<<"$HELPERS" || ! grep -q '^rls_blocks_all_clear()' <<<"$HELPERS"; then
    echo "FAIL: is_uint() or rls_blocks_all_clear() was not found in $PF"
    exit 1
fi

failed=0

# run_case NAME EXPECTED [VAR=VALUE ...] - runs check 26 against the stubs,
# configured by the listed assignments, and asserts that it prints exactly one
# verdict, that the verdict starts with EXPECTED, and that no query it sent
# left its list out.
#   TABLES       the tables that exist (default: all three the import reads)
#   MISSING      policy_overrides columns that do not exist
#   RLS_<table>  the row-level-security verdict for that table (default clear)
#   COUNT        the draft list's count query answer, "<rows>|<organizations>"
#   TCOUNT       the tenant-scoped list's count query answer
#   DETAIL       the draft list's listing answer
#   TDETAIL      the tenant-scoped list's listing answer
#   FAILQ        a query label; the query with exactly that label does not run
#   PROBEFAIL    a table whose existence probe does not run (it records a
#                query failure and answers "absent", as table_exists does)
#   WANT_TEXT    a string the printed output must also contain
run_case() {
    local name="$1" expected="$2"
    shift 2
    local out verdicts rc=0
    out="$(
        TABLES="policy_overrides static_policies dynamic_policies"
        MISSING=""
        COUNT="0|0"
        TCOUNT="0|0"
        DETAIL=""
        TDETAIL=""
        FAILQ=""
        PROBEFAIL=""
        RLS_policy_overrides=clear
        RLS_static_policies=clear
        RLS_dynamic_policies=clear
        for kv in "$@"; do printf -v "${kv%%=*}" '%s' "${kv#*=}"; done
        PSQL_FAILURES=()
        eval "$HELPERS"
        section() { :; }
        info() { echo "INFO: $1"; }
        pass() { echo "PASS: $1"; }
        warn() { echo "WARN: $1 | $2"; }
        fail() { echo "FAIL: $1 | $2"; }
        table_exists() {
            if [[ "$1" == "$PROBEFAIL" ]]; then
                PSQL_FAILURES+=("table-exists($1) (psql exit 1): stubbed failure")
                return 1
            fi
            [[ " $TABLES " == *" $1 "* ]]
        }
        column_exists() { [[ " $MISSING " != *" $2 "* ]]; }
        probe_rls() { local v="RLS_$1"; RLS_STATE="${!v}"; }
        q() {
            Q=""
            QOK=0
            local want="$C26_CANDIDATES"
            [[ "$1" == tenant-scoped* ]] && want="$C26_TENANT_ROWS"
            if [[ "$2" != *"$want"* ]]; then echo "SQLMISMATCH: $1"; fi
            if [[ -n "$FAILQ" && "$1" == "$FAILQ" ]]; then
                PSQL_FAILURES+=("$1 (psql exit 1): stubbed failure")
                return 0
            fi
            case "$1" in
                "draft import candidates (count)") Q="$COUNT" ;;
                "tenant-scoped overrides (count)") Q="$TCOUNT" ;;
                "draft import candidates (first 25)") Q="$DETAIL" ;;
                "tenant-scoped overrides (first 25)") Q="$TDETAIL" ;;
                *) echo "UNEXPECTED QUERY: $1" ;;
            esac
            QOK=1
            return 0
        }
        eval "$BLOCK"
    )" || rc=$?
    verdicts="$(grep -E '^(PASS|WARN|FAIL): ' <<<"$out" || true)"
    local want_text=""
    for kv in "$@"; do [[ "$kv" == WANT_TEXT=* ]] && want_text="${kv#WANT_TEXT=}"; done
    if [[ "$rc" -ne 0 ]]; then
        echo "not ok - $name: the check block exited $rc instead of printing a verdict: $out"
        failed=1
    elif grep -qE '^(SQLMISMATCH|UNEXPECTED QUERY): ' <<<"$out"; then
        echo "not ok - $name: $(grep -E '^(SQLMISMATCH|UNEXPECTED QUERY): ' <<<"$out" | head -1)"
        failed=1
    elif [[ "$(grep -c . <<<"$verdicts")" -ne 1 ]]; then
        echo "not ok - $name: want exactly one verdict, got: ${verdicts:-none}"
        failed=1
    elif [[ "$verdicts" != "$expected"* ]]; then
        echo "not ok - $name: want '$expected...', got '$verdicts'"
        failed=1
    elif [[ -n "$want_text" && "$out" != *"$want_text"* ]]; then
        echo "not ok - $name: the output does not contain '$want_text': $out"
        failed=1
    else
        echo "ok - $name"
    fi
}

STOP="per-policy override row(s) will stop applying at the upgrade"
DID_NOT_RUN="FAIL: The per-policy override scan did not complete"
CANNOT_READ="WARN: This connection cannot read the per-policy overrides, so no verdict on the draft import is available"

run_case "no policy_overrides table passes" \
    "PASS: No policy_overrides table on this deployment" \
    'TABLES=static_policies dynamic_policies'
run_case "no row in either list passes" \
    "PASS: No per-policy override will stop applying at the upgrade" \
    'COUNT=0|0' 'TCOUNT=0|0'
run_case "draft rows warn by count, and name each row" \
    "WARN: 3 $STOP: 3 arrive as an unpublished draft, 0 are tenant-scoped and are not imported" \
    'COUNT=3|2' 'DETAIL=org-a: sys_sqli_union_select action block (override 11111111)' \
    'WANT_TEXT=org-a: sys_sqli_union_select action block (override 11111111)'
run_case "tenant-scoped rows alone are never a pass: they stop applying and reach no draft" \
    "WARN: 4 $STOP: 0 arrive as an unpublished draft, 4 are tenant-scoped and are not imported" \
    'TCOUNT=4|2' 'TDETAIL=org-a/tenant-1: sys_sqli_union_select action warn (override 44444444)' \
    'WANT_TEXT=org-a/tenant-1: sys_sqli_union_select action warn (override 44444444)'
run_case "both lists warn together, in one verdict" \
    "WARN: 3 $STOP: 1 arrive as an unpublished draft, 2 are tenant-scoped and are not imported" \
    'COUNT=1|1' 'DETAIL=org-a: x disabled (override 1)' 'TCOUNT=2|1' 'TDETAIL=org-a/t: y action log (override 2)'
run_case "an RLS-blind policy_overrides withholds the verdict" \
    "$CANNOT_READ" \
    'RLS_policy_overrides=blind'
run_case "an RLS-blind join table withholds the verdict too" \
    "$CANNOT_READ" \
    'RLS_static_policies=blind' 'WANT_TEXT=static_policies'
run_case "an RLS state the probe could not read withholds the verdict" \
    "$CANNOT_READ" \
    'RLS_dynamic_policies=unknown'
run_case "a filtered connection that finds none says it saw only part" \
    "WARN: No per-policy override found, but this connection sees only part of the tables the import reads" \
    'RLS_policy_overrides=filtered'
run_case "a filtered connection that finds tenant rows lists them and says the lists are partial" \
    "WARN: 2 $STOP: 0 arrive as an unpublished draft, 2 are tenant-scoped" \
    'RLS_policy_overrides=filtered' 'TCOUNT=2|1' 'TDETAIL=org-a/t: x disabled (override 3)' \
    'WANT_TEXT=sees only part of: policy_overrides'
run_case "a draft count that did not run fails" \
    "$DID_NOT_RUN" \
    'FAILQ=draft import candidates (count)'
run_case "a tenant-scoped count that did not run fails" \
    "$DID_NOT_RUN" \
    'FAILQ=tenant-scoped overrides (count)'
run_case "a draft listing that did not run fails" \
    "$DID_NOT_RUN" \
    'COUNT=2|1' 'FAILQ=draft import candidates (first 25)'
run_case "a tenant-scoped listing that did not run fails" \
    "$DID_NOT_RUN" \
    'TCOUNT=2|1' 'FAILQ=tenant-scoped overrides (first 25)'
run_case "a draft count that is not a number fails" \
    "$DID_NOT_RUN" \
    'COUNT=x|1'
run_case "a tenant-scoped count that is not a number fails" \
    "$DID_NOT_RUN" \
    'TCOUNT=1|y'
run_case "an existence probe that did not run fails rather than reading as no table" \
    "$DID_NOT_RUN" \
    'PROBEFAIL=policy_overrides'
run_case "a join table's existence probe that did not run fails" \
    "$DID_NOT_RUN" \
    'PROBEFAIL=dynamic_policies'
run_case "a schema without a column the import reads cannot be previewed" \
    "WARN: The per-policy override import cannot be previewed on this schema" \
    'MISSING=tool_signature' 'WANT_TEXT=tool_signature'

if [[ "$failed" -ne 0 ]]; then
    echo "preflight_draft_import_candidates_test.sh: FAILED"
    exit 1
fi
echo "preflight_draft_import_candidates_test.sh: PASSED"
