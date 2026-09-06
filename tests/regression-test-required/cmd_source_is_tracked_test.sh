#!/usr/bin/env bash
# cmd_source_is_tracked_test.sh - #3689
#
# THE BUG CLASS: A .gitignore RULE THAT HIDES A NEW COMMAND'S SOURCE, SILENTLY.
#
# `.gitignore` carries `**/cmd/*/*` to keep built binaries out of the tree, with
# a hand-maintained allow-list of every command whose SOURCE is tracked. A new
# command therefore starts life invisible: `git status` does not list it,
# `git add -A` reports nothing and exits 0, and the omission surfaces later as a
# build error in someone else's checkout - or, worse, as a CI step that names a
# tool the repository does not contain.
#
# It has happened at least three times. The rule's own comment records the
# ext_authz probe (runtime-e2e/2860 failed in CI with a missing package), the
# AuthZEN generator needed its own exception for the same reason, and
# decision-replay (#3689, ADR-065 gate 16) was written, tested, wired into a
# named CI step and staged with `git add -A` before anyone noticed that none of
# its three files were in the index.
#
# The allow-list is not the problem; a deny-by-default rule with named
# exceptions is the right shape for a directory that holds binaries. The problem
# is that FORGETTING an exception is silent. This turns it into a red test.
#
# THE RULE: every directory under a `cmd/` that contains Go source must have
# every one of its Go source files tracked by git. Binaries stay ignored; source
# does not get to be.
#
# Run: bash tests/regression-test-required/cmd_source_is_tracked_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

PASS=0
FAIL=0
ok() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== every cmd/ directory's Go source is tracked ==="

# Discovered from the FILESYSTEM, not from git. Asking git which cmd files it
# knows about would return exactly the tracked ones and pass by construction -
# the census has to look where the ignored file actually is.
mapfile -t sources < <(
  find . -type d \( -name node_modules -o -name .git -o -name vendor -o -name target -o -name .venv \) -prune -o \
    -type f -name '*.go' -path '*/cmd/*/*' -print | sed 's|^\./||' | sort
)

if [ "${#sources[@]}" -eq 0 ]; then
  bad "no Go source was found under any cmd/ directory; this census would pass vacuously"
  echo ""
  echo "FAILED: $FAIL check(s)"
  exit 1
fi
ok "censused ${#sources[@]} Go source file(s) under cmd/ directories"

untracked=()
for f in "${sources[@]}"; do
  # `git ls-files --error-unmatch` is the exact question: is this path IN THE
  # INDEX. `git check-ignore` would answer a different one - a file can be
  # matched by an ignore rule and still be tracked, and tracked is what matters.
  if ! git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    untracked+=("$f")
  fi
done

if [ "${#untracked[@]}" -eq 0 ]; then
  ok "every one of them is tracked"
else
  bad "${#untracked[@]} Go source file(s) under cmd/ are NOT tracked:"
  for f in "${untracked[@]}"; do
    rule="$(git check-ignore -v "$f" 2>/dev/null || echo 'not ignored - simply never added')"
    echo "        $f"
    echo "          $rule"
  done
  echo ""
  echo "  If the file belongs in the repository, add an exception beside the others in .gitignore:"
  echo "      !<dir>/"
  echo "      !<dir>/**"
  echo "  A command whose source is not in the repository cannot be built by anyone else,"
  echo "  and a CI step that names it is a gate discharged by something nobody can see."
fi

# ---------------------------------------------------------------------------
# THE GUARD'S OWN FAILING INPUT.
#
# Both halves above are presence checks and would report success against an
# empty census or a tracking test that always said yes. A file the rule
# genuinely hides is created, and the two mechanisms are checked against it:
# the discovery must FIND it, and the tracking test must call it untracked.
# ---------------------------------------------------------------------------
echo ""
echo "=== the guard's own falsifiability ==="

probe_dir="platform/decision/cmd/zz-guard-probe-$$"
mkdir -p "$probe_dir" || { echo "  FAIL: could not create the probe directory"; exit 1; }
cleanup() { rm -rf "$probe_dir"; }
trap cleanup EXIT
printf 'package main\n\nfunc main() {}\n' > "$probe_dir/main.go"

probe="$probe_dir/main.go"
found=0
while IFS= read -r f; do
  [ "$f" = "$probe" ] && found=1
done < <(
  find . -type d \( -name node_modules -o -name .git -o -name vendor -o -name target -o -name .venv \) -prune -o \
    -type f -name '*.go' -path '*/cmd/*/*' -print | sed 's|^\./||'
)
[ "$found" -eq 1 ] &&
  ok "the census finds a Go file the ignore rule hides" ||
  bad "the census did not find $probe; it is looking somewhere other than where a hidden command lives"

git ls-files --error-unmatch "$probe" >/dev/null 2>&1 &&
  bad "the tracking test reports an untracked probe file as tracked; it cannot fail" ||
  ok "the tracking test reports the untracked probe as untracked"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "FAILED: $FAIL check(s), $PASS passed"
  exit 1
fi
echo ""
echo "PASS: $PASS check(s) - no command's source is hidden by an ignore rule"
