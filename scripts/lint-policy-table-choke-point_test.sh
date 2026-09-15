#!/usr/bin/env bash
# Tests for lint-policy-table-choke-point.sh
#
# Run: bash scripts/lint-policy-table-choke-point_test.sh
# Requires: the script under test at scripts/lint-policy-table-choke-point.sh
#
# Model: scripts/lint-deployment-mode_test.sh (fixture dirs passed as $1 so
# the lint's ROOT-from-BASH_SOURCE default is exercised separately from the
# fixtures; assert_pass/assert_fail helpers; a results file consumed at the
# end rather than trusting set -e to survive an expected failure).
#
# shellcheck disable=SC2016
# Fixture Go source is passed to mk_go_file in SINGLE quotes throughout this
# file, deliberately: the fixtures contain literal `$1`, backtick-quoted SQL,
# and Go template syntax that must NOT be shell-expanded. SC2016 ("expressions
# don't expand in single quotes") is exactly the behavior wanted here, so it
# is disabled file-wide rather than fought fixture-by-fixture.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/lint-policy-table-choke-point.sh"
TEST_TMPDIR=$(mktemp -d)
RESULTS_FILE="$TEST_TMPDIR/results.txt"
trap 'rm -rf "$TEST_TMPDIR"' EXIT

: > "$RESULTS_FILE"

run_lint_in() {
  local dir="$1"
  bash "$SCRIPT" "$dir" > "$TEST_TMPDIR/last_output.txt" 2>&1
}

assert_pass() {
  local test_name="$1"
  local dir="$2"
  if run_lint_in "$dir"; then
    echo "  PASS: $test_name" >> "$RESULTS_FILE"
    echo "  ✅ PASS: $test_name"
  else
    echo "  FAIL: $test_name (expected pass, got fail)" >> "$RESULTS_FILE"
    echo "  ❌ FAIL: $test_name (expected pass, got fail)"
    sed 's/^/      /' "$TEST_TMPDIR/last_output.txt"
  fi
}

assert_fail() {
  local test_name="$1"
  local dir="$2"
  if run_lint_in "$dir"; then
    echo "  FAIL: $test_name (expected fail, got pass)" >> "$RESULTS_FILE"
    echo "  ❌ FAIL: $test_name (expected fail, got pass)"
  else
    echo "  PASS: $test_name" >> "$RESULTS_FILE"
    echo "  ✅ PASS: $test_name"
  fi
}

# assert_fail_containing: like assert_fail, but also requires a substring in
# the lint's own output — used where a passing negative case for the WRONG
# reason (e.g. the fixture directory tree itself is malformed) would
# otherwise look identical to a correctly-caught violation.
assert_fail_containing() {
  local test_name="$1"
  local dir="$2"
  local needle="$3"
  if run_lint_in "$dir"; then
    echo "  FAIL: $test_name (expected fail, got pass)" >> "$RESULTS_FILE"
    echo "  ❌ FAIL: $test_name (expected fail, got pass)"
    return
  fi
  if grep -qF "$needle" "$TEST_TMPDIR/last_output.txt"; then
    echo "  PASS: $test_name" >> "$RESULTS_FILE"
    echo "  ✅ PASS: $test_name"
  else
    echo "  FAIL: $test_name (failed, but not for the expected reason — missing '$needle')" >> "$RESULTS_FILE"
    echo "  ❌ FAIL: $test_name (failed, but not for the expected reason — missing '$needle')"
    sed 's/^/      /' "$TEST_TMPDIR/last_output.txt"
  fi
}

# mk_go_file DIR RELPATH CONTENT: writes CONTENT to DIR/RELPATH, creating
# parent directories as needed.
mk_go_file() {
  local dir="$1" rel="$2" content="$3"
  mkdir -p "$(dirname "$dir/$rel")"
  printf '%s\n' "$content" > "$dir/$rel"
}

# LOADER_EXPECTED_COUNT is READ OUT OF the script under test, not written here.
#
# It used to be hardcoded, in three places, with a comment telling the next
# person to "keep this stub's count in sync ... if that count ever changes".
# #3490 changed it from 10 to 8 and did not, and this self-test then reported
# SIX failures on origin/main - every case that copies a clean tree, because
# the fixture loader.go carried 10 reads against an allow-list expecting 8.
#
# That is the defect this file exists to catch, committed by this file: a
# hardcoded number about a hardcoded number. Deriving it means the two can
# never disagree again, and a change to the allow-list needs no edit here.
LOADER_EXPECTED_COUNT="$(awk -F'|' '/^platform\/shared\/policy\/loader\.go\|/ { print $2; exit }' "$SCRIPT")"
if ! grep -qE '^[0-9]+$' <<<"$LOADER_EXPECTED_COUNT"; then
  echo "❌ could not read the loader.go expected count out of $SCRIPT (got: '$LOADER_EXPECTED_COUNT')."
  echo "   The ALLOW_LIST_TABLE entry shape changed; this test can no longer derive it and would"
  echo "   otherwise build fixtures against a number nothing checks."
  exit 1
fi
if [ "$LOADER_EXPECTED_COUNT" -lt 2 ]; then
  echo "❌ derived loader.go count is $LOADER_EXPECTED_COUNT; the stub builder needs at least 2"
  exit 1
fi

# mk_loader_query_lines N: N raw reads, split across both tables so the
# fixture mirrors the real file rather than exercising one table's pattern.
mk_loader_query_lines() {
  local n="$1" i static_n
  static_n=$(( (n + 1) / 2 ))
  for i in $(seq 1 "$n"); do
    if [ "$i" -le "$static_n" ]; then
      printf '\tq%d := `SELECT id, policy_id FROM static_policies WHERE tenant_id = $1 AND k = %d`\n' "$i" "$i"
    else
      printf '\tq%d := `SELECT COUNT(*) FROM dynamic_policies WHERE tenant_id = $1 AND k = %d`\n' "$i" "$i"
    fi
  done
  for i in $(seq 1 "$n"); do
    printf '\t_ = q%d\n' "$i"
  done
}

# mk_loader_stub DIR [COUNT]: a platform/shared/policy/loader.go carrying
# exactly COUNT raw reads (default: the allow-listed count), present in every
# fixture so the scan root has SOME platform/ Go content.
#
# #3320: loader.go is no longer identity-exempt in the script under test - it
# is counted in ALLOW_LIST_TABLE like every other file. That table is hardcoded
# in lint-policy-table-choke-point.sh and is NOT parameterized per scan root, so
# every fixture built with this stub is checked against the SAME entry the real
# tree satisfies. The stub therefore carries exactly the allow-listed count,
# purely so the tests that are about OTHER files do not fail on an unrelated
# loader.go miscount.
mk_loader_stub() {
  local dir="$1"
  local count="${2:-$LOADER_EXPECTED_COUNT}"
  mk_go_file "$dir" "platform/shared/policy/loader.go" "package policy

func (l *PolicyLoader) load() {
$(mk_loader_query_lines "$count")}
"
}

echo "=== Testing lint-policy-table-choke-point.sh ==="
echo ""

# --- Test 1: the real repository (this branch) passes -----------------------
echo "Test 1: this branch passes as-is"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
assert_pass "Current branch tree passes the lint" "$REPO_ROOT"

# --- Test 2: a brand-new bespoke reader in a non-allow-listed file FAILS ----
# The important negative case: a lint that cannot fail is worthless. This is
# exactly the #3266 shape — a sixth reader appearing outside the loader.
echo ""
echo "Test 2: a new unlisted direct reader is caught"
T2="$TEST_TMPDIR/t2"
mk_loader_stub "$T2"
mk_go_file "$T2" "platform/orchestrator/new_bespoke_reader.go" 'package orchestrator

func evaluate(tx *sql.Tx) {
	rows, _ := tx.Query(`
		SELECT action FROM static_policies
		WHERE tenant_id = $1
	`)
	_ = rows
}
'
assert_fail_containing "A brand-new bespoke static_policies reader fails" "$T2" \
  "platform/orchestrator/new_bespoke_reader.go"

# --- Test 3: an allow-listed path at its EXACT expected count passes -------
echo ""
echo "Test 3: an allow-listed file at its exact expected count passes"
T3="$TEST_TMPDIR/t3"
mk_loader_stub "$T3"
mk_go_file "$T3" "platform/orchestrator/ojk/readiness.go" 'package ojk

func (s *svc) countIndonesiaPIIPolicies() {
	const q = `SELECT COUNT(*) FROM static_policies WHERE enabled = true`
	_ = q
}
'
assert_pass "readiness.go at its allow-listed count (1) passes" "$T3"

# --- Test 4: an allow-listed file whose count went UP fails -----------------
# A new query silently added to an already-allow-listed file must not sail
# through — this is the whole reason the allow-list is COUNT-keyed rather
# than a bare path list.
echo ""
echo "Test 4: an allow-listed file with an ADDED query fails"
T4="$TEST_TMPDIR/t4"
mk_loader_stub "$T4"
mk_go_file "$T4" "platform/orchestrator/ojk/readiness.go" 'package ojk

func (s *svc) countIndonesiaPIIPolicies() {
	const q = `SELECT COUNT(*) FROM static_policies WHERE enabled = true`
	_ = q
}

func (s *svc) countSomethingElse() {
	const q2 = `SELECT COUNT(*) FROM static_policies WHERE tier = (SqE(quote(tvar)))`
	_ = q2
}
'
assert_fail_containing "readiness.go with a second query (count 1 -> 2) fails" "$T4" \
  "expected 1, found 2"

# --- Test 5: an allow-listed file whose count went DOWN (stale entry) fails -
echo ""
echo "Test 5: an allow-listed file with a REMOVED query fails (stale entry)"
T5="$TEST_TMPDIR/t5"
mk_loader_stub "$T5"
mk_go_file "$T5" "platform/orchestrator/ojk/readiness.go" 'package ojk

func (s *svc) countIndonesiaPIIPolicies() {
	// migrated off static_policies entirely
}
'
assert_fail_containing "readiness.go with its only query removed (count 1 -> 0) fails" "$T5" \
  "found 0"

# --- Test 6: the loader file is COUNTED like every other entry, not exempt -
# #3320: platform/shared/policy/loader.go used to be exempt by IDENTITY
# regardless of count (the previous version of this test asserted exactly that).
# That made the single most-privileged file in the tree the only one with no
# ratchet: a query could be added to it with zero CI signal. loader.go now
# carries its own ALLOW_LIST_TABLE entry and is checked exactly like every other
# allow-listed file. 6a pins that its exact count still passes; 6b pins that
# growing it by one, silently, fails - the negative case that makes 6a mean
# something.
#
# Both numbers are DERIVED from the allow-list, so #3490's kind of change (10 ->
# 8) can never break this test again.
echo ""
echo "Test 6a: platform/shared/policy/loader.go at its exact allow-listed count ($LOADER_EXPECTED_COUNT) passes"
T6A="$TEST_TMPDIR/t6a"
mk_loader_stub "$T6A"
assert_pass "loader.go at its allow-listed count ($LOADER_EXPECTED_COUNT) passes" "$T6A"

echo ""
echo "Test 6b: platform/shared/policy/loader.go with one more, unreviewed query fails"
T6B="$TEST_TMPDIR/t6b"
LOADER_PLUS_ONE=$(( LOADER_EXPECTED_COUNT + 1 ))
mk_loader_stub "$T6B" "$LOADER_PLUS_ONE"
assert_fail_containing "loader.go with one more query (count $LOADER_EXPECTED_COUNT -> $LOADER_PLUS_ONE) fails" "$T6B" \
  "expected $LOADER_EXPECTED_COUNT, found $LOADER_PLUS_ONE"

# --- Test 7: the ALIASED form (`FROM static_policies sp`) is caught --------
# #3296 WS-4 brief flagged this explicitly: loader.go:503 and
# static_policy_repository.go:1323 use the aliased form in the real tree.
echo ""
echo "Test 7: the aliased form FROM static_policies sp is caught"
T7="$TEST_TMPDIR/t7"
mk_loader_stub "$T7"
mk_go_file "$T7" "platform/orchestrator/aliased_reader.go" 'package orchestrator

func f(tx *sql.Tx) {
	rows, _ := tx.Query(`SELECT sp.id FROM static_policies sp WHERE sp.enabled = true`)
	_ = rows
}
'
assert_fail_containing "an aliased FROM static_policies sp read is caught" "$T7" \
  "platform/orchestrator/aliased_reader.go"

# --- Test 8: extra whitespace between FROM and the table name is caught ----
echo ""
echo "Test 8: FROM with extra whitespace before the table name is caught"
T8="$TEST_TMPDIR/t8"
mk_loader_stub "$T8"
mk_go_file "$T8" "platform/orchestrator/whitespace_reader.go" 'package orchestrator

func f(tx *sql.Tx) {
	rows, _ := tx.Query("SELECT id FROM   dynamic_policies WHERE enabled = true")
	_ = rows
}
'
assert_fail_containing "FROM with extra whitespace is caught, not silently missed" "$T8" \
  "platform/orchestrator/whitespace_reader.go"

# --- Test 9: a violation inside a _test.go file is ignored ------------------
echo ""
echo "Test 9: _test.go files are excluded"
T9="$TEST_TMPDIR/t9"
mk_loader_stub "$T9"
mk_go_file "$T9" "platform/orchestrator/whatever_test.go" 'package orchestrator

import "testing"

func TestReadsPolicies(t *testing.T) {
	q := `SELECT * FROM static_policies WHERE tenant_id = $1`
	_ = q
}
'
assert_pass "a raw read confined to a _test.go file does not fail the lint" "$T9"

# --- Test 10: a violation inside a comment (not real SQL) does not count ---
# The exact false-positive class this lint had to design around:
# policy_api_repository.go:126 in the real tree reads "// ... (SELECT FROM
# dynamic_policies ...)" as PROSE, not a query.
echo ""
echo "Test 10: a FROM static_policies / dynamic_policies mention INSIDE A COMMENT is not a violation"
T10="$TEST_TMPDIR/t10"
mk_loader_stub "$T10"
mk_go_file "$T10" "platform/orchestrator/comment_only.go" 'package orchestrator

// This function is gated by `policy_id IN (SELECT FROM dynamic_policies
// WHERE enabled = true)` at the database level, not evaluated here.
func f() {}
'
assert_pass "a comment-only mention of FROM dynamic_policies is not flagged" "$T10"

# --- Test 11: a lookalike table name is NOT matched (word-boundary safe) ---
echo ""
echo "Test 11: a lookalike table name (dynamic_policies_v2) is not matched"
T11="$TEST_TMPDIR/t11"
mk_loader_stub "$T11"
mk_go_file "$T11" "platform/orchestrator/lookalike_reader.go" 'package orchestrator

func f(tx *sql.Tx) {
	rows, _ := tx.Query(`SELECT id FROM dynamic_policies_v2 WHERE enabled = true`)
	_ = rows
}
'
assert_pass "FROM dynamic_policies_v2 (a different table) is not flagged" "$T11"

# --- Test 12: the scan root is the script's own repo, not $PWD -------------
# Same #3170-derived discipline as scripts/lint-deployment-mode.sh's Test 21:
# a no-argument invocation must still resolve to the real repository root,
# not silently scan an empty directory and report vacuous success.
echo ""
echo "Test 12: no-argument invocation is cwd-independent"
if (cd / && bash "$SCRIPT") > /dev/null 2>&1; then
  echo "  PASS: no-argument run from / still scans the repository" >> "$RESULTS_FILE"
  echo "  ✅ PASS: no-argument run from / still scans the repository"
else
  echo "  FAIL: no-argument run from / did not pass (expected the repo to be clean)" >> "$RESULTS_FILE"
  echo "  ❌ FAIL: no-argument run from / did not pass (expected the repo to be clean)"
fi

# --- Test 13: an ee/ file is scanned too, not just platform/ ---------------
echo ""
echo "Test 13: ee/ is scanned, not just platform/"
T13="$TEST_TMPDIR/t13"
mk_loader_stub "$T13"
mk_go_file "$T13" "ee/platform/customer-portal/bespoke_reader.go" 'package portal

func f(tx *sql.Tx) {
	rows, _ := tx.Query(`SELECT id FROM static_policies WHERE tenant_id = $1`)
	_ = rows
}
'
assert_fail_containing "an unlisted reader under ee/ is caught" "$T13" \
  "ee/platform/customer-portal/bespoke_reader.go"

# --- Test 14: an allow-listed file found EARLY in a large scan still counts -
# #4072. The stale-entry check read `printf '%s\n' "$SEEN_FILES" | grep -qx
# "$alfile"` under `set -euo pipefail`. `grep -q` exits at its first match; when
# SEEN_FILES is larger than a pipe buffer and the file is near its start, the
# still-writing printf dies of SIGPIPE (141), pipefail makes that the pipeline's
# status, and `if !` reported "found 0" for a file grep had just found. Measured
# against that line with this fixture: the false "found 0" on every run.
#
# Both directions, so neither half can pass by the other breaking: readiness.go
# is PRESENT with its one read and must NOT be reported stale; overrides_handler.go
# is present with NO read and MUST be. The 1200 unlisted files exist only to
# make SEEN_FILES large - they fail the lint on purpose, under ee/ so they are
# scanned after both allow-listed files.
echo ""
echo "Test 14: an allow-listed file seen early in a SEEN_FILES larger than a pipe buffer is not reported stale (#4072)"
T14="$TEST_TMPDIR/t14"
mk_loader_stub "$T14"
mk_go_file "$T14" "platform/orchestrator/ojk/readiness.go" 'package ojk

func (s *svc) countIndonesiaPIIPolicies() {
	const q = `SELECT COUNT(*) FROM static_policies WHERE enabled = true`
	_ = q
}
'
mk_go_file "$T14" "platform/orchestrator/overrides_handler.go" 'package orchestrator

func resolvePolicyUUID() {}
'
T14_PAD="$(printf 'p%.0s' $(seq 1 90))"
mkdir -p "$T14/ee/zz_bulk"
T14_BYTES=0
for i in $(seq 1 1200); do
  rel="ee/zz_bulk/${T14_PAD}_${i}.go"
  printf 'package bulk\n\nconst q = `SELECT id FROM static_policies`\n' > "$T14/$rel"
  T14_BYTES=$((T14_BYTES + ${#rel} + 1))
done
if [ "$T14_BYTES" -le 65536 ]; then
  echo "  FAIL: Test 14's fixture is ${T14_BYTES} bytes of paths, not larger than a pipe buffer - it would pass vacuously" >> "$RESULTS_FILE"
  echo "  ❌ FAIL: Test 14's fixture is too small (${T14_BYTES} bytes)"
elif run_lint_in "$T14"; then
  echo "  FAIL: Test 14 (expected the unlisted bulk files to fail the lint, got pass)" >> "$RESULTS_FILE"
  echo "  ❌ FAIL: Test 14 (expected fail, got pass)"
elif grep -qF "platform/orchestrator/ojk/readiness.go: expected 1, found 0" "$TEST_TMPDIR/last_output.txt"; then
  echo "  FAIL: Test 14 reported readiness.go stale although its read is present (#4072)" >> "$RESULTS_FILE"
  echo "  ❌ FAIL: readiness.go reported 'found 0' although it was found (#4072)"
elif ! grep -qF "platform/orchestrator/overrides_handler.go: expected 2, found 0" "$TEST_TMPDIR/last_output.txt"; then
  echo "  FAIL: Test 14 did not report overrides_handler.go stale although it has no read" >> "$RESULTS_FILE"
  echo "  ❌ FAIL: the genuinely stale overrides_handler.go entry was not reported"
else
  echo "  PASS: a found file is not stale in a ${T14_BYTES}-byte scan, and a missing read still is" >> "$RESULTS_FILE"
  echo "  ✅ PASS: a found file is not stale in a ${T14_BYTES}-byte scan, and a missing read still is"
fi

# --- Summary ---
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
