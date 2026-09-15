#!/usr/bin/env bash
# docs_deletion_ledger_test.sh - #3818 (v11 documentation-state revamp, lane W2-E)
#
# SUBJECT: scripts/docs/check-docs-ledger.py, and through it the rule that no
# document leaves docs/, technical-docs/ or ee/docs/ without a row in
# technical-docs/archive/README.md naming its successor.
#
# WHY. The v11 revamp consolidates overlapping documents: licence and tenant
# 4->1, RLS 3->1, deployment guides and runbooks 2->1 each, MCP architecture
# 3->1. Each is the right change, and each deletes files that briefs, issues,
# PR bodies and other repositories cite. check-relative-links.py sees only the
# in-repository links; nothing asked where the content went. A consolidation
# with no ledger row is how "never delete valuable content without a
# replacement" becomes a rule nobody can check.
#
# The real-tree run compares against the pull request's base, which the
# workflow passes as DOCS_LEDGER_BASE (the job's checkout is shallow, so the
# checker fetches that one commit). Locally it uses the merge base with
# origin/main. A base that cannot be resolved FAILS: this suite runs only in
# the enterprise repository, where one always exists.
#
# Run: bash tests/regression-test-required/docs_deletion_ledger_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/docs/check-docs-ledger.py"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

if [ ! -d "$REPO_ROOT/technical-docs" ]; then
  echo "SKIP: community checkout; technical-docs/ and its ledger are not synced here"
  exit 0
fi
[ -f "$CHECKER" ] || { echo "  FAIL: $CHECKER is missing; this test cannot vacuously pass"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 missing"; exit 1; }

echo "== the real tree =="
OUT="$(python3 "$CHECKER" --repo-root "$REPO_ROOT" 2>&1)"; RC=$?
echo "$OUT" | sed 's/^/  /'
case $RC in
  0) ok "every document this change removes or moves has a ledger row with a live successor" ;;
  2) bad "the ledger check could not run (no base, or no ledger) - it must not be skipped" ;;
  *) bad "a document left the tree without a ledger row or a live successor (listed above)" ;;
esac

# ---------------------------------------------------------------------------
# CONTROLS, each in a throwaway git repository with its own base commit.
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)" || { echo "  FAIL: mktemp -d"; exit 1; }
trap 'rm -rf "$TMP"' EXIT
GIT=(git -c user.name=ledger-test -c user.email=ledger-test@invalid -c commit.gpgsign=false -c init.defaultBranch=main)

LEDGER_HEAD='# Technical Documentation Archive

## Currently archived

| Archived file | Was at | Why archived | Current doc |
|---|---|---|---|'

fx_new() {
  # $1 fixture name -> FX (dir), FX_BASE (base sha)
  FX="$TMP/$1"
  mkdir -p "$FX/technical-docs/archive" "$FX/docs"
  printf '%s\n' "$LEDGER_HEAD" > "$FX/technical-docs/archive/README.md"
  # The floor is 20 rows; the fixture carries enough history rows to clear it,
  # each naming a file that exists, so no control passes or fails on the floor.
  for i in $(seq 1 20); do
    printf '| `HIST%02d.md` | `technical-docs/` | history | [`../SUCCESSOR.md`](../SUCCESSOR.md) |\n' "$i" \
      >> "$FX/technical-docs/archive/README.md"
  done
  echo "# successor" > "$FX/technical-docs/SUCCESSOR.md"
  echo "# a" > "$FX/technical-docs/A.md"
  echo "# b" > "$FX/technical-docs/B.md"
  mkdir -p "$FX/technical-docs/runbooks"
  echo "# same name, other directory" > "$FX/technical-docs/runbooks/A.md"
  echo "# x" > "$FX/docs/x.md"
  echo "<svg/>" > "$FX/technical-docs/diagram.svg"
  ( cd "$FX" && "${GIT[@]}" init -q . && "${GIT[@]}" add -A && "${GIT[@]}" commit -qm base ) || return 1
  FX_BASE="$(cd "$FX" && "${GIT[@]}" rev-parse HEAD)"
}

fx_row() { printf '%s\n' "$1" >> "$FX/technical-docs/archive/README.md"; }
fx_commit() { ( cd "$FX" && "${GIT[@]}" add -A && "${GIT[@]}" commit -qm head ); }

expect() {
  # $1 label, $2 expected rc, $3 required substring ('' for none), $4 optional base
  # override; a base of NONE runs with no --base and DOCS_LEDGER_BASE unset.
  local label="$1" want="$2" needle="$3" base="${4:-$FX_BASE}" rc=0 out
  if [ "$base" = "NONE" ]; then
    out="$(env -u DOCS_LEDGER_BASE python3 "$CHECKER" --repo-root "$FX" 2>&1)" || rc=$?
  else
    out="$(python3 "$CHECKER" --repo-root "$FX" --base "$base" 2>&1)" || rc=$?
  fi
  if [ "$rc" -eq "$want" ] && { [ -z "$needle" ] || echo "$out" | grep -qF -- "$needle"; }; then
    ok "$label"
  else
    bad "$label (expected rc=$want${needle:+ and '$needle'}, got rc=$rc)"
    echo "$out" | sed 's/^/      | /'
  fi
}

# The count is of DATA rows: the fixture's one header row and separator are not
# ledger entries, so an unchanged fixture must report exactly its 20 history rows.
fx_new c0
expect "control: the printed count is data rows only (20, not 21 with the header)" 0 "docs ledger: 20 ledger row(s)"

fx_new c1; ( cd "$FX" && "${GIT[@]}" rm -q technical-docs/A.md ); fx_commit
expect "control: a deleted document with no ledger row is caught" 1 "technical-docs/A.md was deleted with no row"

fx_new c2; ( cd "$FX" && "${GIT[@]}" rm -q technical-docs/A.md )
fx_row '| `technical-docs/A.md` | merged | [`../SUCCESSOR.md`](../SUCCESSOR.md) |'; fx_commit
expect "control: a row naming the full path and a live successor passes" 0 ""

fx_new c3; ( cd "$FX" && "${GIT[@]}" rm -q technical-docs/A.md )
fx_row '| `technical-docs/A.md` | merged | [`../GONE.md`](../GONE.md) |'; fx_commit
expect "control: a row whose successor does not exist is caught" 1 "names no successor that exists"

fx_new c4; ( cd "$FX" && "${GIT[@]}" mv technical-docs/B.md technical-docs/archive/B.md )
fx_row '| `B.md` | `technical-docs/` | superseded | [`../SUCCESSOR.md`](../SUCCESSOR.md) |'; fx_commit
expect "control: a move into the archive with a name + former-directory row passes" 0 ""

fx_new c5; ( cd "$FX" && "${GIT[@]}" mv docs/x.md docs/y.md ); fx_commit
expect "control: a rename in docs/ (mirrored) with no row is caught" 1 "docs/x.md was moved to docs/y.md"

fx_new c6; ( cd "$FX" && "${GIT[@]}" rm -q technical-docs/diagram.svg ); fx_commit
expect "control (negative): deleting a non-Markdown file needs no row" 0 ""

fx_new c7; ( cd "$FX" && "${GIT[@]}" rm -q technical-docs/runbooks/A.md )
fx_row '| `A.md` | `technical-docs/` | merged | [`../SUCCESSOR.md`](../SUCCESSOR.md) |'; fx_commit
expect "control: a row for the same file name in ANOTHER directory does not excuse a deletion" 1 "technical-docs/runbooks/A.md was deleted with no row"

fx_new c8; rm "$FX/technical-docs/A.md"
expect "control: an uncommitted deletion is caught" 1 "technical-docs/A.md was deleted with no row"

fx_new c9
expect "control: an unresolvable base refuses to pass" 2 "no base commit resolved" "0123456789abcdef0123456789abcdef01234567"

fx_new c10; : > "$FX/technical-docs/archive/README.md"; fx_commit
expect "control: an unreadable ledger refuses to pass" 2 "below the floor"

# #4059: a WRONG match must be refused, not only a missing one. Each of these
# names a path that merely contains, or is contained in, the removed path.
fx_new c11; ( cd "$FX" && "${GIT[@]}" rm -q technical-docs/A.md )
fx_row '| `technical-docs/A.md.old` | merged | [`../SUCCESSOR.md`](../SUCCESSOR.md) |'; fx_commit
expect "control: a row naming a SUPERSTRING of the path (A.md.old) does not record the deletion" 1 "technical-docs/A.md was deleted with no row"

fx_new c12; ( cd "$FX" && "${GIT[@]}" rm -q technical-docs/A.md )
fx_row '| `archive/technical-docs/A.md` | merged | [`../SUCCESSOR.md`](../SUCCESSOR.md) |'; fx_commit
expect "control: a row naming a LONGER path that embeds it does not record the deletion" 1 "technical-docs/A.md was deleted with no row"

fx_new c13; ( cd "$FX" && "${GIT[@]}" rm -q technical-docs/A.md )
fx_row '| `technical-docs/A.md` (merged into the successor) | merged | [`../SUCCESSOR.md`](../SUCCESSOR.md) |'; fx_commit
expect "control (negative): the exact path in backticks beside prose still records it" 0 ""

fx_new c14; ( cd "$FX" && "${GIT[@]}" mv technical-docs/B.md technical-docs/archive/B.md )
fx_row '| `B.md` | `technical-docs/` | superseded | [`B.md`](B.md) |'; fx_commit
expect "control: a moved document recorded as its OWN successor is refused" 1 "names no successor that exists"

fx_new c15; ( cd "$FX" && "${GIT[@]}" mv technical-docs/B.md technical-docs/archive/B.md )
fx_row '| `B.md` | `technical-docs/` | superseded | [`B.md`](B.md), replaced by [`../SUCCESSOR.md`](../SUCCESSOR.md) |'; fx_commit
expect "control (negative): the archived copy beside a real successor still passes" 0 ""

# #4059 item 4: a shallow clone with no origin/main (the manual-dispatch shape)
# must fetch main and resolve, not fail the suite with no base.
fx_new c16
git clone -q --bare "$FX" "$TMP/c16-origin.git"
git clone -q --depth 1 "file://$TMP/c16-origin.git" "$TMP/c16-clone" 2>/dev/null
git -C "$TMP/c16-clone" update-ref -d refs/remotes/origin/main
FX="$TMP/c16-clone"
expect "control: a shallow clone with no origin/main fetches main and resolves a base" 0 "0 document(s) removed or moved" NONE

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
