#!/usr/bin/env bash
# Tests for lint-pipefail-early-exit-reader.py (#4072)
#
# Run: bash scripts/lint-pipefail-early-exit-reader_test.sh
#
# Model: scripts/lint-policy-table-choke-point_test.sh (fixtures passed as
# arguments so the lint's default scan root is exercised separately; a results
# file consumed at the end rather than trusting set -e to survive an expected
# failure).
#
# Every positive names the LINE it expects, not just "the lint failed": a lint
# that fails for the wrong reason - a different line, a crash - must not pass a
# positive. Every negative is a shape the real tree contains.
#
# shellcheck disable=SC2016
# Fixture shell source is written in SINGLE quotes throughout, deliberately: it
# carries literal `$VAR`, `$(...)` and backticks that must reach the fixture
# unexpanded.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINT="$SCRIPT_DIR/lint-pipefail-early-exit-reader.py"
TEST_TMPDIR=$(mktemp -d)
RESULTS_FILE="$TEST_TMPDIR/results.txt"
trap 'rm -rf "$TEST_TMPDIR"' EXIT

: > "$RESULTS_FILE"

record() { # PASS|FAIL message
  echo "  $1: $2" >> "$RESULTS_FILE"
  if [ "$1" = PASS ]; then echo "  ✅ PASS: $2"; else echo "  ❌ FAIL: $2"; fi
}

# fixture NAME CONTENT - writes $TEST_TMPDIR/NAME/fixture.sh and prints its path.
fixture() {
  mkdir -p "$TEST_TMPDIR/$1"
  printf '%s\n' "$2" > "$TEST_TMPDIR/$1/fixture.sh"
  printf '%s' "$TEST_TMPDIR/$1/fixture.sh"
}

# assert_flags NAME CONTENT LINE - the lint exits 1 and reports fixture.sh:LINE.
assert_flags() {
  local name="$1" file rc=0
  file=$(fixture "$name" "$2")
  python3 "$LINT" "$file" > "$TEST_TMPDIR/out.txt" 2>&1 || rc=$?
  if [ "$rc" -eq 1 ] && grep -qF -- "fixture.sh:$3:" "$TEST_TMPDIR/out.txt"; then
    record PASS "$name"
  else
    record FAIL "$name (want rc=1 and a hit on line $3, got rc=$rc)"
    sed 's/^/      /' "$TEST_TMPDIR/out.txt"
  fi
}

# assert_clean NAME CONTENT - the lint exits 0 on the fixture.
assert_clean() {
  local name="$1" file rc=0
  file=$(fixture "$name" "$2")
  python3 "$LINT" "$file" > "$TEST_TMPDIR/out.txt" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    record PASS "$name"
  else
    record FAIL "$name (want rc=0, got rc=$rc)"
    sed 's/^/      /' "$TEST_TMPDIR/out.txt"
  fi
}

echo "=== Testing lint-pipefail-early-exit-reader.py ==="

echo ""
echo "Flagged: a pipe into an early-exiting reader under pipefail"

# #4072 verbatim.
assert_flags "grep -qx in an if !, the #4072 line" 'set -euo pipefail
if ! printf '"'"'%s\n'"'"' "$SEEN_FILES" | grep -qx "$alfile"; then
  echo stale
fi' 2

assert_flags "grep -qE behind an LC_ALL=C prefix" 'set -euo pipefail
printf '"'"'%s'"'"' "$text" | LC_ALL=C grep -qE '"'"'^x'"'"' && continue' 2

assert_flags "grep -m1 in an assignment" 'set -eo pipefail
first=$(git log --oneline | grep -m1 fix)' 2

assert_flags "grep --quiet with a command writer" 'set -euo pipefail
if docker ps | grep --quiet db; then :; fi' 2

assert_flags "grep -l" 'set -euo pipefail
names=$(cat list | grep -l x)' 2

assert_flags "head -1 in an assignment" 'set -euo pipefail
tip=$(printf '"'"'%s\n'"'"' "$shas" | head -1)' 2

assert_flags "head inside \"\$(...)\" inside double quotes" 'set -euo pipefail
echo "newest: $(ls -t | head -n 1)"' 2

assert_flags "sed with a q command" 'set -euo pipefail
first=$(cmd | sed -n '"'"'1p;q'"'"')' 2

assert_flags "awk with exit outside END" 'set -euo pipefail
cmd | awk '"'"'/x/ { print; exit }'"'"'' 2

assert_flags "a pipe continued onto the next line" 'set -euo pipefail
out=$(cmd --long-flag |
  head -1)' 2

assert_flags "pipefail enabled by its own set command" 'set -e
set -o pipefail
echo "$x" | grep -q y' 3

# The lexer once read a here-string's `<< "$x"` as a heredoc whose delimiter
# never appears, and every line after it as the body - so every hit below the
# first `<<<` in a file went unseen - measured at base, 18 hits in seven
# files under scripts/, five of them with no hit reported at all.
assert_flags "a hit AFTER a here-string is still seen" 'set -euo pipefail
while read -r a; do :; done <<< "$list"
if echo "$reason" | grep -q "Circuit Breaker"; then :; fi' 3

# A file inherits pipefail when it sits under lib/ or is sourced by a script in
# the scan: the options are the caller's (the #3756 semantics, now in the lint).
mkdir -p "$TEST_TMPDIR/inherit/lib" "$TEST_TMPDIR/inherit/sourced"
printf '%s\n' '# no set line of its own' 'ready() {' '  docker logs agent 2>&1 | grep -q started' '}' > "$TEST_TMPDIR/inherit/lib/helper.sh"
printf '%s\n' 'set -euo pipefail' '. "$(dirname "$0")/helpers.sh"' 'if grep -q up <<<"$(state)"; then :; fi' > "$TEST_TMPDIR/inherit/sourced/caller.sh"
printf '%s\n' 'state() { printf up; }' 'is_up() {' '  state | head -1' '}' > "$TEST_TMPDIR/inherit/sourced/helpers.sh"

rc=0
python3 "$LINT" "$TEST_TMPDIR/inherit/lib" > "$TEST_TMPDIR/out.txt" 2>&1 || rc=$?
if [ "$rc" -eq 1 ] && grep -qF -- "lib/helper.sh:3:" "$TEST_TMPDIR/out.txt"; then
  record PASS "a file under lib/ inherits pipefail from the script that sources it"
else
  record FAIL "a file under lib/ (want rc=1 and lib/helper.sh:3, got rc=$rc)"
  sed 's/^/      /' "$TEST_TMPDIR/out.txt"
fi

rc=0
python3 "$LINT" "$TEST_TMPDIR/inherit/sourced" > "$TEST_TMPDIR/out.txt" 2>&1 || rc=$?
if [ "$rc" -eq 1 ] && grep -qF -- "sourced/helpers.sh:3:" "$TEST_TMPDIR/out.txt" \
  && ! grep -qF -- "sourced/caller.sh:" "$TEST_TMPDIR/out.txt"; then
  record PASS "a sourced file outside lib/ inherits pipefail; its caller's here-string is clean"
else
  record FAIL "a sourced helper (want rc=1, helpers.sh:3 and no caller.sh hit, got rc=$rc)"
  sed 's/^/      /' "$TEST_TMPDIR/out.txt"
fi

# lib/ is judged below the scan root, so a checkout that happens to live under
# some .../lib/... does not put every script in scope.
mkdir -p "$TEST_TMPDIR/lib/checkout/root"
printf '%s\n' 'echo "$x" | grep -q y' > "$TEST_TMPDIR/lib/checkout/root/plain.sh"
rc=0
python3 "$LINT" "$TEST_TMPDIR/lib/checkout/root" > "$TEST_TMPDIR/out.txt" 2>&1 || rc=$?
if [ "$rc" -eq 0 ] && grep -qF "0 in pipefail scope" "$TEST_TMPDIR/out.txt"; then
  record PASS "a lib/ directory ABOVE the scan root puts nothing in scope"
else
  record FAIL "a lib/ above the scan root (want rc=0 and 0 in scope, got rc=$rc)"
  sed 's/^/      /' "$TEST_TMPDIR/out.txt"
fi

assert_flags "a pipe ending its line continues past a trailing comment" 'set -euo pipefail
echo "$x" |   # the reader is on the next line
  grep -q sample' 2

assert_flags "a backslash-continued statement reports its first line" 'set -euo pipefail
docker logs agent 2>&1 \
  | head -n 5' 2

rc=0
file=$(fixture "readers filter" 'set -euo pipefail
tip=$(git log | head -1)')
python3 "$LINT" --readers grep "$file" > "$TEST_TMPDIR/out.txt" 2>&1 || rc=$?
if [ "$rc" -eq 0 ] && grep -qF "[grep 0]" "$TEST_TMPDIR/out.txt"; then
  record PASS "--readers grep does not report a head"
else
  record FAIL "--readers grep (want rc=0 over a head-only file, got rc=$rc)"
  sed 's/^/      /' "$TEST_TMPDIR/out.txt"
fi
rc=0
python3 "$LINT" --readers head "$file" > "$TEST_TMPDIR/out.txt" 2>&1 || rc=$?
if [ "$rc" -eq 1 ] && grep -qF -- "fixture.sh:2:" "$TEST_TMPDIR/out.txt"; then
  record PASS "--readers head does report it (the filter is not a blanket clean)"
else
  record FAIL "--readers head (want rc=1 and fixture.sh:2, got rc=$rc)"
fi
rc=0
python3 "$LINT" --readers grep,tail "$file" > "$TEST_TMPDIR/out.txt" 2>&1 || rc=$?
if [ "$rc" -eq 2 ]; then
  record PASS "--readers with an unknown kind is an error"
else
  record FAIL "--readers grep,tail (want rc=2, got rc=$rc)"
fi

echo ""
echo "Not flagged"

assert_clean "a pipe inside a remote double-quoted command" 'set -euo pipefail
ssh host "docker ps | grep -q db"
ssm_exec "$ip" "docker logs agent 2>&1 | grep -q started" 30'

assert_clean "a pipe inside single quotes" 'set -euo pipefail
docker run img sh -c '"'"'ls | head -1'"'"''

assert_clean "a pipe inside heredoc bodies" 'set -euo pipefail
cat <<EOF
cmd | grep -q x
EOF
cat <<'"'"'EOF'"'"'
cmd | head -1
EOF
	cat <<-EOF
	cmd | head -1
	EOF'

assert_clean "|| is not a pipe" 'set -euo pipefail
test -f a || head -1 b'

assert_clean "a file that never enables pipefail" 'set -eu
echo "$x" | grep -q y'

assert_clean "set -o pipefail named only inside a string" 'echo "run with set -o pipefail"
echo "$x" | grep -q y'

assert_clean "grep -c reads all input" 'set -euo pipefail
n=$(cmd | grep -c foo)'

assert_clean "grep with output discarded reads all input" 'set -euo pipefail
if cmd | grep foo >/dev/null; then :; fi'

assert_clean "the prescribed fixes" 'set -euo pipefail
if ! grep -qxF -- "$alfile" <<<"$SEEN_FILES"; then :; fi
tip=$(printf '"'"'%s\n'"'"' "$shas" | sed -n '"'"'1p'"'"')
cmd | awk '"'"'END { exit 1 }'"'"''

assert_clean "a pipe in a comment" 'set -euo pipefail
# printf x | grep -q y'

assert_clean "a case pattern alternative" 'set -euo pipefail
case "$cmd" in
  tail|head) echo reader ;;
esac'

echo ""
echo "The default scan"

rc=0
(cd / && python3 "$LINT") > "$TEST_TMPDIR/out.txt" 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then
  record PASS "a no-argument run from / scans the repository's scripts/ and is clean"
else
  record FAIL "a no-argument run from / (want rc=0, got rc=$rc)"
  sed 's/^/      /' "$TEST_TMPDIR/out.txt"
fi

rc=0
python3 "$LINT" "$TEST_TMPDIR/does-not-exist" > "$TEST_TMPDIR/out.txt" 2>&1 || rc=$?
if [ "$rc" -eq 2 ]; then
  record PASS "a path that does not exist is an error, not a clean scan"
else
  record FAIL "a missing path (want rc=2, got rc=$rc)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
PASS=$(grep -c "^  PASS:" "$RESULTS_FILE" || true)
FAIL=$(grep -c "^  FAIL:" "$RESULTS_FILE" || true)
TOTAL=$((PASS + FAIL))
echo "Results: $PASS/$TOTAL passed, $FAIL/$TOTAL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$FAIL" -gt 0 ]; then
  grep "FAIL:" "$RESULTS_FILE"
  exit 1
fi

echo "All tests passed!"
