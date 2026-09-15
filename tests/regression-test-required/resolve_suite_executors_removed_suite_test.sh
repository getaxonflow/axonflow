#!/usr/bin/env bash
# resolve_suite_executors_removed_suite_test.sh
#
# A SUITE A PR DELETES IS NOT A SUITE THE PR ADDS (W3-G, #3564).
#
# scripts/e2e/resolve-suite-executors.sh looks every touched suite up in the
# HEAD ledger. A rename moves the ledger row with the directory, so the OLD
# name has no row there and read as ABSENT - "new suite, nothing runs it" - on
# the PR that removed it (3564_per_plane_decision_shadow became
# 3564_per_plane_enforcement). A suite every one of whose touched paths is a
# deletion is now reported as removed and classified no further.
#
# The controls keep the gate's teeth: a deletion beside an ADDED or a MODIFIED
# file under the same unledgered name, and an added file alone, are still new
# suites nothing executes, and a partial deletion inside an executed suite still counts that
# suite as executed. Every case runs the real resolver with --gate, so its exit
# status is asserted beside its output.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESOLVER="$ROOT/scripts/e2e/resolve-suite-executors.sh"
LEDGER="$ROOT/scripts/e2e/runtime_e2e_suites.tsv"
FIXTURE=zz_resolver_fixture_removed_suite
EXECUTED=3564_per_plane_enforcement
failed=0

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; failed=$((failed + 1)); }

# The premises every case rests on, checked rather than assumed.
if awk -F'\t' -v s="$FIXTURE" '$1 == s { found = 1 } END { exit(found ? 0 : 1) }' "$LEDGER"; then
    echo "PREMISE: $FIXTURE has a ledger row, so it cannot stand for an unledgered name" >&2
    exit 2
fi
if ! awk -F'\t' -v s="$EXECUTED" '$1 == s && $2 == "workflow" { found = 1 } END { exit(found ? 0 : 1) }' "$LEDGER"; then
    echo "PREMISE: $EXECUTED is not ledgered as an executed (workflow) suite" >&2
    exit 2
fi

# resolve <name-status lines, \t and \n escaped>: sets OUT and RC.
resolve() {
    OUT="$(printf '%b' "$1" | bash "$RESOLVER" --gate 2>/dev/null)"
    RC=$?
}
field() { sed -n "s/^$1=//p" <<< "$OUT"; }

resolve "D\truntime-e2e/$FIXTURE/test.sh\nD\truntime-e2e/$FIXTURE/README.md\n"
if [ -z "$(field added_unexecuted_suites)" ] && [ "$(field removed_suites_touched)" = "$FIXTURE" ] && [ "$RC" = 0 ]; then
    pass "a suite whose every touched path is a deletion is removed, not added, and --gate passes"
else
    fail "a pure deletion: rc=$RC, $(tr '\n' ' ' <<< "$OUT")"
fi

resolve "D\truntime-e2e/$FIXTURE/test.sh\nA\truntime-e2e/$FIXTURE/new_test.sh\n"
if [ "$(field added_unexecuted_suites)" = "$FIXTURE" ] && [ -z "$(field removed_suites_touched)" ] && [ "$RC" = 1 ]; then
    pass "CONTROL: a deletion beside an added file under the same unledgered name is still a new suite nothing runs"
else
    fail "a deletion plus an added file: rc=$RC, $(tr '\n' ' ' <<< "$OUT")"
fi

resolve "D\truntime-e2e/$FIXTURE/old_helper.sh\nM\truntime-e2e/$FIXTURE/test.sh\n"
if [ "$(field added_unexecuted_suites)" = "$FIXTURE" ] && [ -z "$(field removed_suites_touched)" ] && [ "$RC" = 1 ]; then
    pass "CONTROL: a deletion beside a MODIFIED file under the same unledgered name is not a removal either"
else
    fail "a deletion plus a modified file: rc=$RC, $(tr '\n' ' ' <<< "$OUT")"
fi

resolve "A\truntime-e2e/$FIXTURE/test.sh\n"
if [ "$(field added_unexecuted_suites)" = "$FIXTURE" ] && [ "$RC" = 1 ]; then
    pass "CONTROL: an added file under an unledgered name is still a new suite nothing runs"
else
    fail "an added file alone: rc=$RC, $(tr '\n' ' ' <<< "$OUT")"
fi

resolve "D\truntime-e2e/$EXECUTED/old_helper.sh\nM\truntime-e2e/$EXECUTED/test.sh\n"
if [ "$(field executed_suites_touched)" = 1 ] && [ -z "$(field removed_suites_touched)" ] && [ "$RC" = 0 ]; then
    pass "CONTROL: a partial deletion inside an executed suite still counts that suite as executed"
else
    fail "a partial deletion in $EXECUTED: rc=$RC, $(tr '\n' ' ' <<< "$OUT")"
fi

if [ "$failed" -gt 0 ]; then
    echo "resolve_suite_executors_removed_suite: $failed case(s) failed"
    exit 1
fi
echo "resolve_suite_executors_removed_suite: 5 passed, 0 failed"
