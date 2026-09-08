#!/usr/bin/env bash
# docs_relative_links_test.sh - #3818 (v11 lane W0-C, documentation state)
#
# SUBJECT: scripts/docs/check-relative-links.py, and through it every relative
# markdown link in technical-docs/ and docs/.
#
# WHY IT EXISTS. Nothing checked these. The public site's Docusaurus build sets
# `onBrokenLinks: 'throw'`, but that covers the public docs-site repository, not
# this tree, so 55 of 735 relative links here were broken and had been for months:
#
#   4   pointed at one developer's local disk (`/Users/<name>/Development/tmp/`,
#       `/tmp/`) - unreachable for every other reader, and unrecoverable
#   16  pointed into sibling repositories with `../../../<repo>/` paths, and so
#       resolved only in a checkout where those repositories sit side by side
#   5   used ADR filenames from before the corpus was renumbered
#   4   pointed at a `docs/deployment/RUNBOOK.md` that has never existed - from
#       DEPLOYMENT_GUIDE.md and all three deployment runbooks at once
#   6   customer-facing pages under docs/, which ships to the community mirror
#
# The rest were renamed or merged siblings, and six referenced example YAML
# files a roadmap proposed and nobody ever added.
#
# Run: bash tests/regression-test-required/docs_relative_links_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/docs/check-relative-links.py"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

if [ ! -f "$CHECKER" ]; then
  echo "  FAIL: $CHECKER does not exist; this test cannot vacuously pass"
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 missing; this test must not pass without it"; exit 1; }

# docs/ IS mirrored, technical-docs/ is not. On a community checkout the checker
# runs over docs/ alone, which is the half a community reader can see.
ROOTS=(docs)
[ -d "$REPO_ROOT/technical-docs" ] && ROOTS=(technical-docs docs)

echo "== the real tree: ${ROOTS[*]} =="
OUT="$(python3 "$CHECKER" "$REPO_ROOT" "${ROOTS[@]}" 2>&1)"; RC=$?
echo "$OUT" | sed 's/^/  /'
COUNT="$(echo "$OUT" | sed -n 's/^checked \([0-9]*\) relative links.*/\1/p')"
if [ "${COUNT:-0}" -lt 100 ]; then
  bad "only ${COUNT:-0} links found; the tree has 700+ and this test must not report clean on an empty scan"
elif [ $RC -eq 0 ]; then
  ok "all $COUNT relative links resolve"
else
  bad "broken relative links (listed above)"
fi

# --------------------------------------------------------------------------
# POSITIVE CONTROLS: one per class the sweep actually found, planted on a copy.
# --------------------------------------------------------------------------
TMP="$(mktemp -d)" || { echo "  FAIL: mktemp -d"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

# The scanned roots are COPIED so a control can mutate them; every other
# top-level entry is SYMLINKED so that links out of those roots - and there are
# 34 of them, into ee/, platform/ and examples/ - still resolve. A harness that
# copied only docs/ and technical-docs/ reported those 34 as broken, which is an
# artefact of the harness and would have made the negative control below
# unpassable for the wrong reason.
seed_tree() {
  rm -rf "$TMP/tree"; mkdir -p "$TMP/tree"
  local entry base
  for entry in "$REPO_ROOT"/* "$REPO_ROOT"/.[!.]*; do
    [ -e "$entry" ] || continue
    base="$(basename "$entry")"
    case " ${ROOTS[*]} " in *" $base "*) continue ;; esac
    ln -s "$entry" "$TMP/tree/$base"
  done
  for r in "${ROOTS[@]}"; do cp -R "$REPO_ROOT/$r" "$TMP/tree/$r"; done
}

control() {                      # control <name> <rel-file> <appended-markdown>
  local name="$1" rel="$2" line="$3"
  seed_tree
  printf '\n%s\n' "$line" >> "$TMP/tree/$rel" || { bad "control $name: mutation failed"; return; }
  local out rc
  out="$(python3 "$CHECKER" "$TMP/tree" "${ROOTS[@]}" 2>&1)"; rc=$?
  if [ $rc -eq 1 ] && echo "$out" | grep -q "BROKEN $rel"; then
    ok "control: $name is caught"
  else
    bad "control: $name went UNDETECTED (rc=$rc)"
    echo "$out" | sed 's/^/      /'
  fi
}

control "a link to a renamed sibling" \
        docs/getting-started.md '[Policies](./POLICIES_THAT_MOVED.md)'
control "a link to another developer's local disk" \
        docs/getting-started.md '[Plan](/Users/someone/Development/tmp/PLAN.md)'
control "a link into a sibling repository" \
        docs/getting-started.md '[PRD](../../a-sibling-repo/prds/PRD_X.md)'
control "a root-relative link to a path that does not exist" \
        docs/getting-started.md '[Runbook](/docs/deployment/RUNBOOK.md)'

# --------------------------------------------------------------------------
# THE MIRROR. docs/ syncs to the community repository and technical-docs/ does
# NOT (sync-community-repo.yml excludes it), so a `../technical-docs/...` link
# from a docs/ page resolves here and is DEAD for every community reader - and
# this guard, running on the enterprise tree, would certify it green forever.
#
# Four such links existed. That is the #3807 standing order: a guard that syncs
# to the mirror has to be proven on the mirror's own inputs, not on ours.
#
# Simulated by dropping technical-docs/ and re-running over docs/ alone.
# --------------------------------------------------------------------------
SYNC_WORKFLOW="$REPO_ROOT/.github/workflows/sync-community-repo.yml"
BUILD_MIRROR="$REPO_ROOT/tests/regression-test-required/lib/build_mirror_tree.py"
if [ -d "$REPO_ROOT/technical-docs" ] && [ -f "$SYNC_WORKFLOW" ] && [ -f "$BUILD_MIRROR" ]; then
  # The excluded set is APPLIED BY lib/build_mirror_tree.py, which reads every
  # `--exclude=` value out of the sync workflow and honours all four shapes the
  # workflow uses: whole directories, single FILES, nested paths and globs.
  #
  # The first version of this block parsed `--exclude='<dir>/'` and nothing
  # else - 14 of ~130 rules - and the miss was live: docs/README.md links
  # ./reference/secrets-logging-checklist.md, which the workflow excludes BY
  # FILENAME, and which 404s on the published mirror while docs/README.md
  # returns 200. The simulation reported green. A simulation with its own idea
  # of the rules is a simulation of something else.
  MOUT="$(python3 "$BUILD_MIRROR" "$REPO_ROOT" "$TMP/mirror" 2>&1)"; MRC=$?
  if [ $MRC -ne 0 ]; then
    bad "the mirror tree could not be built: $MOUT"
  else
    echo "  $MOUT"
    LOUT="$(python3 "$CHECKER" "$TMP/mirror" docs 2>&1)"; LRC=$?
    MCOUNT="$(echo "$LOUT" | sed -n 's/^checked \([0-9]*\) relative links.*/\1/p')"
    if [ "${MCOUNT:-0}" -lt 50 ]; then
      bad "the mirror simulation scanned only ${MCOUNT:-0} links; it is not simulating anything"
    elif [ $LRC -eq 0 ]; then
      ok "every docs/ link still resolves on a tree built from the sync workflow's own exclusions"
    else
      bad "docs/ links that are dead on the community mirror:"
      echo "$LOUT" | grep '^BROKEN' | sed 's/^/      /'
      echo "      docs/ ships to the mirror; the paths above do not. Point these at"
      echo "      the public docs site or at a page inside docs/ that also ships."
    fi

    # Control 1: a link into an excluded DIRECTORY.
    printf '\n%s\n' '[Internal](../technical-docs/ARCHITECTURE.md)' \
      >> "$TMP/mirror/docs/getting-started.md"
    if ! python3 "$CHECKER" "$TMP/mirror" docs >/dev/null 2>&1; then
      ok "control: a docs/ link into an excluded directory is caught"
    else
      bad "control: a docs/ link into an excluded directory was NOT caught"
    fi

    # Control 2: a link to an excluded FILE, and to a NESTED excluded path.
    # This is the case the single-segment parser could not see, so it is the one
    # that stops it regressing to that.
    python3 "$BUILD_MIRROR" "$REPO_ROOT" "$TMP/mirror" >/dev/null 2>&1
    printf '\n%s\n%s\n' \
      '[File-level exclude](./reference/secrets-logging-checklist.md)' \
      '[Nested exclude](../examples/circuit-breaker/README.md)' \
      >> "$TMP/mirror/docs/README.md"
    NOUT="$(python3 "$CHECKER" "$TMP/mirror" docs 2>&1)"
    if echo "$NOUT" | grep -q 'secrets-logging-checklist' \
       && echo "$NOUT" | grep -q 'circuit-breaker'; then
      ok "control: links to a file-level and a nested exclude are both caught"
    else
      bad "control: a file-level or nested exclude was NOT modelled"
      echo "$NOUT" | sed 's/^/      /'
    fi
  fi
fi

# A NEGATIVE control. Without it, a checker that flagged everything would pass
# all four controls above and be useless.
seed_tree
printf '\n%s\n' '[Site](https://docs.getaxonflow.com/docs/governance/human-in-the-loop/) and [anchor](#section) and [real](./configuration.md) and [out of root](../examples/README.md)' \
  >> "$TMP/tree/docs/getting-started.md"
# The assertion is that the checker does not flag THESE THREE - not that the
# whole tree is clean, which the first check above already covers. Seeded from
# the real tree, a pre-existing broken link elsewhere would fail this control
# with "the checker flagged a link that is fine", blaming the negative control
# for someone else's defect. Assert on the planted lines only.
NEG="$(python3 "$CHECKER" "$TMP/tree" "${ROOTS[@]}" 2>&1 | grep '^BROKEN' \
       | grep -E 'human-in-the-loop|#section|configuration\.md|examples/README\.md' || true)"
if [ -z "$NEG" ]; then
  ok "control (negative): an https link, a bare anchor, a resolving relative link and an out-of-root link stay green"
else
  bad "control (negative): the checker flagged one of the four planted links, which are all fine"
  echo "$NEG" | sed 's/^/      /'
fi

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
