#!/usr/bin/env bash
# absent_verdict_asserts_nothing_test.sh - #3964 / #3997 round 2 / #4001
#
# THE RULE: when a pre-check returns no `approved` field, a suite must not
# derive an expectation from the absent value and then assert against it.
#
# WHAT HAPPENED. runtime-e2e/2642_gateway_precheck_audit checked for the absent
# field, recorded the failure, and DID NOT GUARD WHAT FOLLOWED. Execution fell
# through to the WANT_B ladder, whose `else` arm resolved WANT_B="allowed" from
# the absent field, and `assert_feed` then asserted the audit feed showed
# "allowed" - a FABRICATED EXPECTATION, not merely a confusing second message.
# The suite failed either way and the first message named the real cause, so it
# was cosmetic; but 2642 is `unwired` (#3987) and nothing executes it, which is
# exactly where a misleading second failure sits unread for months.
#
# WHY THIS GUARD EXISTS RATHER THAN A COMMENT. The behaviour was verified once,
# by hand, with a stubbed assertion. A one-off local run proves the state of the
# tree on the day someone typed it. This runs the same drive on every PR, and it
# runs somewhere that actually executes - which is the complaint behind #3987
# for suites that run nowhere.
#
# IT DRIVES THE REAL FILE, NOT A COPY. The decision block is EXTRACTED from
# 2642's test.sh by anchor and executed with stubs. A re-implementation of the
# ladder here would agree with a correct implementation and with a broken one
# equally, which is no test at all: the point is that the shipped text runs.
#
# Run: bash tests/regression-test-required/absent_verdict_asserts_nothing_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="$REPO_ROOT/runtime-e2e/2642_gateway_precheck_audit/test.sh"

fail=0
pass() { echo "  PASS: $1"; }
flunk() { echo "  FAIL: $1"; fail=1; }

[ -f "$SUITE" ] || { echo "INSTRUMENT: $SUITE is absent; nothing to drive"; exit 3; }

# ---------------------------------------------------------------------------
# Extract the decision block: the `-z "$APPR_B"` guard through the `fi` that
# closes it. Anchored on the variable rather than on line numbers, because a
# line number breaks under any edit above it (#3840).
# ---------------------------------------------------------------------------
extract() {   # $1 = suite path -> the block on stdout, or empty
    python3 - "$1" <<'PY'
import re, sys, pathlib
src = pathlib.Path(sys.argv[1]).read_text().split("\n")
start = next((i for i, l in enumerate(src) if l.strip().startswith('if [ -z "$APPR_B" ]')), None)
if start is None:
    sys.exit(0)
# Count `if`/`fi` as TOKENS, not by line prefix. The prefix form missed the
# closing `fi` on `else WANT_B="allowed"; fi`, so depth never returned to zero
# and the extraction ran 54 lines into later sections of the suite - a parser
# with its own idea of the rules parses something else.
# `\bif\b` does not match inside `elif` (no word boundary), so elif is inert.
depth, out = 0, []
for l in src[start:]:
    out.append(l)
    toks = re.findall(r"\b(if|fi)\b", l)
    depth += toks.count("if") - toks.count("fi")
    if depth == 0:
        break
print("\n".join(out))
PY
}

BLOCK="$(extract "$SUITE")"
if [ -z "$BLOCK" ]; then
    echo "INSTRUMENT: could not locate the \`-z \"\$APPR_B\"\` block in $SUITE."
    echo "            The guard cannot pass by failing to find its subject."
    exit 3
fi
echo "extracted $(printf '%s\n' "$BLOCK" | grep -c .) line(s) of shipped decision logic"

# ---------------------------------------------------------------------------
# Drive it. `assert_feed` is stubbed to RECORD rather than assert, so what is
# measured is whether the shipped block reaches an assertion at all.
# ---------------------------------------------------------------------------
drive() {   # $1 = APPR_B, $2 = REDA_B, $3 = block -> "errors=N called=<want|->"
    local appr="$1" reda="$2" block="$3"
    APPR_B="$appr" REDA_B="$reda" BLOCK_TEXT="$block" bash -c '
        errors=0; CID_B="cid-stub"; RESP_B="{}"; WANT_B="__unset__"; CALLED="-"
        assert_feed() { CALLED="$3"; }
        eval "$BLOCK_TEXT" >/dev/null 2>&1
        echo "errors=$errors called=$CALLED"
    '
}

r_absent="$(drive ""      "false" "$BLOCK")"
r_false="$(drive  "false" "false" "$BLOCK")"
r_true="$(drive   "true"  "false" "$BLOCK")"

case "$r_absent" in
    "errors=1 called=-")
        pass "an absent verdict records a failure and asserts NOTHING ($r_absent)" ;;
    *"called=allowed"*)
        flunk "an absent verdict fabricated the expectation 'allowed' and asserted it ($r_absent)" ;;
    *)
        flunk "an absent verdict did not behave as required ($r_absent)" ;;
esac
[ "$r_false" = "errors=0 called=blocked" ] \
    && pass "approved=false still asserts want=blocked ($r_false)" \
    || flunk "approved=false regressed ($r_false)"
[ "$r_true" = "errors=0 called=allowed" ] \
    && pass "approved=true still asserts want=allowed ($r_true)" \
    || flunk "approved=true regressed ($r_true)"

# ---------------------------------------------------------------------------
# CONTROL. The drive above passing says nothing until the defective shape is
# shown to fail it: restore the fall-through by deleting the `else` that guards
# the ladder, and the absent case must fabricate 'allowed' again.
# ---------------------------------------------------------------------------
MUTANT="$(printf '%s\n' "$BLOCK" | python3 -c '
import sys
src = sys.stdin.read().split("\n")
out, dropped = [], False
for l in src:
    if not dropped and l.strip() == "else":
        dropped = True          # drop the guard, restoring the fall-through
        continue
    out.append(l)
# NO `fi` is removed. The `else` belongs to the outer `if`, so dropping it
# leaves the if/fi count balanced and the block valid shell - the else-branch
# simply merges into the then-branch, which IS the fall-through defect. An
# earlier version deleted a `fi` as well; the mutant then failed to parse, eval
# died silently under `>/dev/null 2>&1`, and the control read `errors=0
# called=-`. A mutant that does not compile has not survived, it has crashed,
# and scoring it as "defect not reproduced" is the correct refusal.
print("\n".join(out))
')"
if [ "$MUTANT" = "$BLOCK" ]; then
    flunk "INSTRUMENT: the mutant is identical to the original; the control proves nothing"
else
    r_mut="$(drive "" "false" "$MUTANT")"
    case "$r_mut" in
        *"called=allowed"*) pass "control: without the guard, an absent verdict fabricates 'allowed' ($r_mut)" ;;
        *) flunk "control: the mutant did not reproduce the defect, so the drive above is not testing for it ($r_mut)" ;;
    esac
fi

echo ""
[ "$fail" -eq 0 ] && echo "PASS: an absent verdict asserts nothing, and the check can fail" \
                  || echo "FAIL: see above"
exit "$fail"
