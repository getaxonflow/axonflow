#!/usr/bin/env bash
# adr_citation_title_test.sh - #3818 (v11 lane W0-E), the code-scope sibling of
# adr_corpus_identity_test.sh
#
# SUBJECT: a citation of an ADR outside technical-docs/architecture-decisions/
# that carries a title beside its number must name the document that holds
# that number now.
#
# THE DEFECT. The on-disk renumber of ADR-001..028 (git: one commit,
# 2026-01-19) moved 24 files without their headings. #3819 fixed every "see
# ADR-NN" inside the ADR directory; outside it, 189 citations in 105 files
# still pointed at whatever document holds the old number today: the old
# single-entry-point number now names MCP Policy Enforcement, the old
# policy-system number now names an implementation plan. Every one of those was
# read against the title beside it and repointed in the PR that adds this
# guard; this file keeps the next one from landing.
#
# WHY THE TITLE AND NOT THE NUMBER. Each renumbered number ALSO names a
# current ADR, so a citation cannot be judged by its number - that is the
# #3819 F1 class, tried on 2026-09-07 and reverted the same day. The title
# beside the token is the one instrument that works: when an ADR's distinctive
# title words (or its filename slug in a link) stand adjacent to `ADR-0NN`
# and belong to a DIFFERENT ADR, the citation is stale. A token with no title
# beside it is not judged here; it was decided once by a reader with the
# rename history and git blame (scripts/docs/find-adr-citations.py --history).
#
# ONE MATCHER. The finder script's own `strict_targets()` is imported, not
# copied, so the sweep and the guard cannot disagree about what a title
# phrase is. Title cores are DERIVED from the corpus (filename slug and H1) on
# every run; nothing here is a hand-kept list.
#
# SCOPE, both halves, because a root rule with a short extension list reads as
# wider than it is (master's R3, MAJOR-1: three identical planted citations,
# one caught in .go and two missed in .ts and a Dockerfile).
#   ROOTS       every top-level directory and file except technical-docs/
#               (W0-C's lane, 323 citations, reported on #3818) and the
#               append-only CHANGELOG.md.
#   FILE TYPES  .go .md .sql .ts .tsx .js .jsx .java .sh .yaml .yml .py .tsv,
#               plus the extension-less Dockerfile and Makefile - derived from
#               a grep of the whole tree for the renumbered range, not assumed.
# The four client languages were the expensive omission: a comment repointed
# in Go and left alone in its byte-identical TypeScript sibling makes the two
# disagree, which is worse for a reader than either state alone.
#
# KNOWN LIMIT. A token preceded in the same clause by ANOTHER ADR's title
# words (a sentence that names two decisions and cites only the second) reads
# as that other ADR; the guard reds it and the sentence is rephrased. None
# exists in the tree.
# On the community mirror technical-docs/ is absent, so there is no corpus to
# derive titles from and this test SKIPs, like adr_corpus_identity_test.sh.
#
# CONTROLS, each on a synthetic tree beside a copy of the real corpus: a
# stale title (red); the same title under its right number (green - the
# F1 class must NOT be flagged); a title with the current name under a
# renumbered number (green); a generic two-word phrase near a token (green -
# the adjacency rule); "Unified Policy Management" beside ADR-017 (green -
# the epic's name is not ADR-019's title); a link whose filename carries
# another ADR's slug (red); a corpus too small to judge (VACUOUS, not clean).
#
# Run: bash tests/regression-test-required/adr_citation_title_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ADR_DIR="$REPO_ROOT/technical-docs/architecture-decisions"
FINDER="$REPO_ROOT/scripts/docs/find-adr-citations.py"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

if [ ! -d "$ADR_DIR" ]; then
  echo "SKIP: community checkout; technical-docs/architecture-decisions/ is not mirrored, so there is no corpus to derive titles from"
  exit 0
fi
[ -f "$FINDER" ] || { echo "  FAIL: $FINDER is missing; the corpus is present and this test cannot vacuously pass"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 missing; this test must not pass without it"; exit 1; }

# check <root> <adr-dir> <min-citations> <min-titled> -> rc 0 clean, 1 stale, 2 vacuous.
# Prints one DEFECT line per stale citation and a summary line. The two floors
# are the anti-vacuity check for the REAL tree: 2,833 citations and 124 titled
# ones on 2026-09-08, 1,727 of the citations in .go files alone. The floors are
# set near the live population (2,600 and 110) rather than at half of it,
# because a scanner that lost every root but `platform/` would still clear a
# floor of 1,500 - master's R3 MINOR-2. A fixture tree passes 0 and 0.
check() {
  python3 - "$1" "$2" "$3" "$4" "$FINDER" <<'PY'
import sys, pathlib, importlib.util
root, adr_dir, min_rows, min_titled, finder = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
spec = importlib.util.spec_from_file_location("finder", finder)
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
except SystemExit as exc:      # the finder refuses a corpus it cannot load
    print(f"VACUOUS: {exc}")
    sys.exit(2)
mod.REPO_ROOT = root
mod.ADR_DIR = adr_dir
try:
    corpus = mod.load_corpus()
except SystemExit as exc:
    print(f"VACUOUS: {exc}")
    sys.exit(2)
rows = mod.find(mod.DEFAULT_ROOTS, corpus)
stale = [r for r in rows if r["suggestion"].startswith("stale") or r["suggestion"].startswith("ambiguous")]
titled = [r for r in rows if r["suggestion"] == "correct"]
print(f"scanned {len(rows)} ADR citations in scope, {len(titled)} carry a matching title, "
      f"{len(stale)} carry a title that names another ADR, corpus of {len(corpus)} numbers")
for r in stale:
    print(f"DEFECT {r['file']}:{r['line']} cites {r['cited']} ({r['current_title']}) but the title beside it "
          f"names {r['phrase_names']}: {r['phrase']}")
if len(rows) < min_rows or len(titled) < min_titled:
    print(f"VACUOUS: {len(rows)} citations (floor {min_rows}), {len(titled)} titled (floor {min_titled}); the scanner is not reading the roots")
    sys.exit(2)
sys.exit(1 if stale else 0)
PY
}

echo "== the real tree =="
OUT="$(check "$REPO_ROOT" "$ADR_DIR" 2600 110)"; RC=$?
echo "$OUT" | sed 's/^/  /'
case $RC in
  0) ok "every ADR citation that carries a title names the ADR that holds its number" ;;
  2) bad "the checker could not judge anything (listed above)" ;;
  *) bad "stale ADR citations (listed above)" ;;
esac

# ---------------------------------------------------------------------------
# CONTROLS on synthetic trees. Each tree is one docs/ file beside a COPY of the
# real corpus, so the title cores under test are the real ones.
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)" || { echo "  FAIL: mktemp -d"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

mk_tree() {   # mk_tree <name> <line-of-text>  -> prints the tree root
  local dir="$TMP/$1"
  rm -rf "$dir"; mkdir -p "$dir/docs" "$dir/technical-docs"
  cp -R "$ADR_DIR" "$dir/technical-docs/architecture-decisions"
  printf '# fixture\n\n%s\n' "$2" > "$dir/docs/fixture.md"
  echo "$dir"
}

expect() {    # expect <want-rc> <label> <tree> [needle]
  local want="$1" label="$2" tree="$3" needle="${4:-}"
  local out rc
  out="$(check "$tree" "$tree/technical-docs/architecture-decisions" 0 0)"; rc=$?
  if [ "$rc" -ne "$want" ]; then
    bad "$label (expected rc=$want, got rc=$rc)"; echo "$out" | sed 's/^/      /'; return
  fi
  if [ -n "$needle" ] && ! printf '%s\n' "$out" | grep -qF -- "$needle"; then
    bad "$label (rc correct but the output never said: $needle)"; echo "$out" | sed 's/^/      /'; return
  fi
  ok "$label"
}

# The plant lines spell the cited number through a variable: this file is
# itself inside the scanned roots, and writing the old number next to the
# title as a literal here would be the very defect it plants.
OLD_SEP="ADR-026"     # the number Single Entry Point was drafted under; MCP Policy Enforcement today
NEW_SEP="ADR-024"     # where Single Entry Point lives now
T="$(mk_tree stale "The agent is the only port ($OLD_SEP: Single Entry Point Architecture).")"
expect 1 "control: a title that names another ADR is caught ($OLD_SEP beside Single Entry Point)" "$T" "names $NEW_SEP"

T="$(mk_tree right "The agent is the only port ($NEW_SEP: Single Entry Point Architecture).")"
expect 0 "control: the same title under its own number passes" "$T"

T="$(mk_tree f1 "Phase-aware enforcement follows $OLD_SEP (MCP Policy Enforcement Architecture).")"
expect 0 "control: a renumbered number cited with its CURRENT title is not flagged (the #3819 F1 class)" "$T"

T="$(mk_tree generic 'The ADR-065 typed policy authoring vocabulary for the customer portal is org-scoped.')"
expect 0 "control: a generic two-word phrase elsewhere on the line is not a title (adjacency)" "$T"

T="$(mk_tree epic 'Static Policies REST API for ADR-017: Unified Policy Management.')"
expect 0 "control: the #530 epic name beside ADR-017 is not read as ADR-019's title" "$T"

T="$(mk_tree link "See [$OLD_SEP](../technical-docs/architecture-decisions/$OLD_SEP-single-entry-point-architecture.md).")"
expect 1 "control: a link whose filename carries another ADR's slug is caught" "$T" "names $NEW_SEP"

T="$(mk_tree before "The Single Entry Point Architecture ($OLD_SEP) makes the agent the only port.")"
expect 1 "control: the title BEFORE the token, with its generic word, is read (the Go-comment form)" "$T" "names $NEW_SEP"

OLD_RCC="ADR-007"     # the number Runtime Connector Configuration was drafted under; V1 licence deprecation today
T="$(mk_tree fullh1 "Connector caching follows $OLD_RCC: Runtime Connector and LLM Provider Configuration.")"
expect 1 "control: a full H1 with an interior stop word is read" "$T" "names ADR-006"

T="$(mk_tree fullh1ok 'Connector caching follows ADR-006: Runtime Connector and LLM Provider Configuration.')"
expect 0 "control: the same full H1 under its own number passes" "$T"

OLD_UPA="ADR-020"     # the number Unified Policy Architecture was drafted under; LLM Provider Routing Control today
T="$(mk_tree shortlong "See $OLD_UPA: Unified Policy Architecture for static and dynamic policies.")"
expect 1 "control: a short title followed by a long clause is still read (the window keeps its generic word)" "$T" "names ADR-019"

T="$(mk_tree shortlongok 'See ADR-019: Unified Policy Architecture for static and dynamic policies.')"
expect 0 "control: the same short title and long clause under its own number passes" "$T"

T="$(mk_tree bare 'Configuration priority is described in ADR-007.')"
expect 0 "control: a bare citation with no title beside it is not judged here" "$T"

# A corpus too small to derive titles from must read as VACUOUS, not clean.
T="$(mk_tree tiny "See $OLD_SEP: Single Entry Point Architecture.")"
find "$T/technical-docs/architecture-decisions" -name 'ADR-0[2-6]*.md' -delete
expect 2 "control: a corpus too small to judge is VACUOUS, not clean" "$T" "VACUOUS"

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
