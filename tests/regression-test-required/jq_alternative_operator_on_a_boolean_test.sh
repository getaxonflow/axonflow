#!/usr/bin/env bash
# jq_alternative_operator_on_a_boolean_test.sh - #3964
#
# THE RULE: a shell value read with jq's alternative operator (`//`) must not
# then be compared against "false".
#
# WHY. jq's `//` yields its right-hand side when the left is `null` OR `false`.
# Only those two are falsy in jq - `0` and `""` survive - so the operator is
# safe everywhere except on a boolean, and on a boolean it destroys exactly the
# value a `= "false"` assertion exists to see. Three shapes, all found in this
# tree, and only the first announces itself:
#
#   INVERTED      `.active // true` then `= "false"`. A server that deactivates
#                 CORRECTLY answers {"active": false}, `//` returns `true`, and
#                 the assertion can never pass. ee/examples/scim printed
#                 "[FAIL] Failed to deactivate user" on every success.
#
#   UNOBSERVABLE  `.approved // empty` then `= "false"`. `approved: false` IS
#                 the blocked case and renders as "", so the blocked branch is
#                 unreachable and the suite derives its expectation from a value
#                 it cannot read.
#
#   FAIL-OPEN     `.blocked // false` then `= "false"`. A response with no
#                 `blocked` key at all - an error envelope, a 5xx body - scores
#                 as "not blocked" and the assertion PASSES. This is the one
#                 that lets a real regression through, and it is silent.
#
# THE SAFE IDIOM distinguishes an absent key from a false one:
#
#   jq -r 'if has("blocked") then .blocked else "absent" end'
#
# WHAT THIS DOES NOT FLAG, on purpose. A `//` whose value is compared against
# "true" is SAFE: there both a genuine `false` and an absent field fail the
# comparison, which is the correct direction. Measured when #3964 was filed:
# 118 comparisons against "false" across the tree, and only the ones sourced
# from a `//` default are exposed. Flagging the "true" side would add ~18
# findings that are all correct as they stand.
#
# WHAT THIS DETECTOR CANNOT SEE, all CONFIRMED by planting (#3964 R3). It reads
# a line and the nearest preceding assignment, not a shell parse tree, so these
# shapes carry the defect past it:
#   - `read -r x < <(jq …)` - no `VAR=` assignment at all
#   - a reversed comparison, `[ "false" = "$x" ]`
#   - `case "$x" in false) …` - no `=` operator
#   - an assignment more than 60 lines above its comparison
#   - copy-through: `y="$x"` where `x` came from a `//`
# The census over this tree finds 0 instances of each; they are recorded so the
# next reader knows the bound rather than inferring completeness from a zero.
# `local`/`export`/`declare`/`readonly` prefixes ARE handled, below.
#
# THE ALLOWLIST IS FOR MATCHES THAT ARE NOT THE DEFECT, each with its reason,
# and today it is empty. Its one row excused a `//` applied to ARRAY ELEMENTS
# inside a larger filter whose result is a genuine boolean (3281's seg_leaked),
# which the detector, reading a line and not a jq parse tree, cannot tell
# apart; #4254's restatement of 3281 removed that read. The controls plant
# rows of their own, so the allowlist path stays proven both ways.
#
# Run: bash tests/regression-test-required/jq_alternative_operator_on_a_boolean_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || { echo "cannot enter the repository root"; exit 3; }

fail=0
pass() { echo "  PASS: $1"; }
flunk() { echo "  FAIL: $1"; fail=1; }

scan() {   # $1 = tree root to scan
    python3 - "$@" <<'PY'
import os, re, subprocess, sys, pathlib

root = sys.argv[1]
# ALLOWLIST: (file, variable) -> reason. A row here is a match that is NOT the
# defect and has been checked. Keyed on the pair rather than a line number,
# because a line number breaks on the next comment sweep above it.
ALLOW = {}
# A control plants rows as further arguments, each "file:variable".
for spec in sys.argv[2:]:
    f, _, v = spec.rpartition(":")
    ALLOW[(f, v)] = "planted by a control"

try:
    files = subprocess.run(["git", "ls-files", "*.sh"], cwd=root,
                           capture_output=True, text=True, check=True).stdout.split()
except Exception as exc:                                  # noqa: BLE001
    print(f"INSTRUMENT: git ls-files failed: {exc}")
    sys.exit(3)

if len(files) < 50:
    print(f"INSTRUMENT: only {len(files)} shell files listed; the scan is not reading the tree")
    sys.exit(3)

CMP_FALSE = re.compile(r'"?\$\{?(\w+)\}?"?\s*(?:=|==)\s*"?false"?')
findings, scanned, allowed = [], 0, 0
allow_hits = set()
for rel in files:
    try:
        lines = (pathlib.Path(root) / rel).read_text().split("\n")
    except Exception:                                     # noqa: BLE001
        continue
    scanned += 1
    for i, line in enumerate(lines):
        m = CMP_FALSE.search(line)
        if not m:
            continue
        var = m.group(1)
        # the nearest preceding assignment of that variable
        for j in range(i, max(-1, i - 60), -1):
            a = re.match(r"\s*(?:(?:local|export|declare|readonly)\s+)?" + re.escape(var) + r"=(.*)$", lines[j])
            if not a:
                continue
            origin = a.group(1)
            # `://` stripped first: a URL in the assignment (`curl https://…
            # | jq -r '.x'`) supplies both "jq" and "//" with no alternative
            # operator present, which is a false positive waiting to happen.
            if "jq" in origin and "//" in origin.replace("://", ""):
                if (rel, var) in ALLOW:
                    allowed += 1
                    allow_hits.add((rel, var))
                else:
                    findings.append((rel, j + 1, i + 1, var, origin.strip()[:100]))
            break

# AN UNUSED ALLOWLIST ROW IS NOT PROVEN LOAD-BEARING (#3964 R3). A row whose
# site has been fixed, renamed or deleted silently excuses nothing, and the next
# reader takes it for a live exception. Only rows whose FILE still exists are
# checked, so a fixture tree does not trip this.
stale_allow = [k for k in ALLOW
               if k not in allow_hits and os.path.isfile(os.path.join(root, k[0]))]
print(f"scanned {scanned} shell file(s); {len(findings)} finding(s), {allowed} allowed")
for rel, var in stale_allow:
    print(f"  {rel}: allowlist row for ${var} matched nothing, but the file exists - "
          f"the exception is not load-bearing; delete the row or fix its key")
for rel, oln, cln, var, origin in findings:
    print(f"  {rel}:{oln}: ${var} is read with jq's `//` and compared against \"false\" at line {cln}")
    print(f"      {origin}")
    print("      `//` fires on `false` as well as `null`, so this cannot observe the value it asserts on.")
    print("      Use: jq -r 'if has(\"<key>\") then .<key> else \"absent\" end'")
sys.exit(1 if (findings or stale_allow) else 0)
PY
}

echo "=== the tree ==="
out="$(scan "$REPO_ROOT")"; rc=$?
printf '%s\n' "$out"
case "$rc" in
    0) pass "no shell value read with jq's \`//\` is compared against \"false\"" ;;
    1) flunk "a jq \`//\` default is compared against \"false\" (listed above)" ;;
    *) echo "  INSTRUMENT FAILURE (rc=$rc): the scan could not run, which is not a clean tree"; fail=1 ;;
esac

# ---------------------------------------------------------------------------
# Controls. A detector that finds nothing is indistinguishable from a clean
# tree unless it can be shown to find a planted defect and to spare a planted
# safe use.
# ---------------------------------------------------------------------------
echo ""
echo "=== controls ==="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
seed() {
    rm -rf "$TMP/t"; mkdir -p "$TMP/t"
    ( cd "$TMP/t" && git init -q . && git config user.email t@t && git config user.name t )
    # 60 inert shell files so the instrument's own floor is satisfied
    for n in $(seq 1 60); do printf '#!/bin/sh\ntrue\n' > "$TMP/t/inert_$n.sh"; done
}
expect() {   # $1 = expected rc, $2 = description, $3 = optional required text, $4 = optional planted allowlist row
    local want="$1" desc="$2" needle="${3:-}" plant="${4:-}"
    ( cd "$TMP/t" && git add -A >/dev/null 2>&1 )
    local o; o="$(scan "$TMP/t" ${plant:+"$plant"})"; local got=$?
    if [ "$got" != "$want" ]; then flunk "$desc (expected rc=$want, got rc=$got)"; return; fi
    if [ -n "$needle" ] && ! printf '%s' "$o" | grep -qF "$needle"; then
        flunk "$desc (rc correct but the output never said: $needle)"; return
    fi
    pass "$desc"
}

seed; expect 0 "control: a tree with no jq // comparison is clean"

seed; printf '%s\n' 'x=$(echo "$r" | jq -r ".blocked // false")' '[ "$x" = "false" ] && echo ok' > "$TMP/t/probe.sh"
expect 1 "control: the FAIL-OPEN shape is caught" 'compared against "false"'

seed; printf '%s\n' 'y=$(echo "$r" | jq -r ".active // true")' 'if [ "$y" = "false" ]; then echo ok; fi' > "$TMP/t/probe.sh"
expect 1 "control: the INVERTED shape is caught"

seed; printf '%s\n' 'z=$(echo "$r" | jq -r ".approved // empty")' 'if [ "$z" = "false" ]; then echo ok; fi' > "$TMP/t/probe.sh"
expect 1 "control: the UNOBSERVABLE shape is caught"

seed; printf '%s\n' 'q=$(echo "$r" | jq -r ".blocked // false")' '[ "$q" = "true" ] && echo ok' > "$TMP/t/probe.sh"
expect 0 "control: the same read compared against \"true\" is NOT flagged (both false and absent fail it, the correct direction)"

seed; printf '%s\n' 'w=$(echo "$r" | jq -r "if has(\"blocked\") then .blocked else \"absent\" end")' '[ "$w" = "false" ] && echo ok' > "$TMP/t/probe.sh"
expect 0 "control: the has() idiom is not flagged"

seed; printf '%s\n' 'v=$(grep -c x file)' '[ "$v" = "false" ] && echo ok' > "$TMP/t/probe.sh"
expect 0 "control: a comparison against \"false\" that does not come from jq is not flagged"

# The widened assignment prefix (R3 #3964): local/export/declare/readonly.
seed; printf '%s\n' 'local x=$(echo "$r" | jq -r ".blocked // false")' '[ "$x" = "false" ] && echo ok' > "$TMP/t/probe.sh"
expect 1 "control: a local-prefixed assignment is still seen" 'compared against "false"'
seed; printf '%s\n' 'export y=$(echo "$r" | jq -r ".blocked // false")' '[ "$y" = "false" ] && echo ok' > "$TMP/t/probe.sh"
expect 1 "control: an export-prefixed assignment is still seen"

# A URL supplies both "jq" and "//" with no alternative operator present.
seed; printf '%s\n' 'z=$(curl -s https://example.test/x | jq -r ".blocked")' '[ "$z" = "false" ] && echo ok' > "$TMP/t/probe.sh"
expect 0 "control: an https URL in the assignment is NOT a jq // default"

# THE ALLOWLIST MUST EARN ITS ROW (R3 #3964). Plant a row and its FILE with
# content the row cannot match: the row is then unused while its file exists,
# which is the state that silently excuses nothing.
seed; mkdir -p "$TMP/t/suite" && printf '%s\n' '#!/bin/sh' 'true' > "$TMP/t/suite/test.sh"
expect 1 "control: an allowlist row that matches nothing, while its file exists, is reported" "is not load-bearing" "suite/test.sh:leaked"
# ...and a row whose site DOES match excuses it, while the same site without
# the row is a finding: the row, not the shape, is what spares it.
seed; mkdir -p "$TMP/t/suite" && printf '%s\n' 'leaked="$(echo "$r" | jq -r "[.ids[]? // empty] | length >= 1")"' '[ "$leaked" = "false" ] && echo ok' > "$TMP/t/suite/test.sh"
expect 0 "control: a planted row whose site matches excuses it" "1 allowed" "suite/test.sh:leaked"
seed; mkdir -p "$TMP/t/suite" && printf '%s\n' 'leaked="$(echo "$r" | jq -r "[.ids[]? // empty] | length >= 1")"' '[ "$leaked" = "false" ] && echo ok' > "$TMP/t/suite/test.sh"
expect 1 "control: the same site without the row is a finding" 'compared against "false"'

seed; rm -f "$TMP/t"/inert_*.sh
expect 3 "control: a tree too small to be real is an INSTRUMENT failure (rc 3), not a clean result"

echo ""
[ "$fail" -eq 0 ] && echo "PASS: the jq \`//\` boolean class is closed and the detector is falsifiable" \
                  || echo "FAIL: see above"
exit "$fail"
