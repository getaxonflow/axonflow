#!/usr/bin/env bash
# adr_corpus_identity_test.sh - #3818 (v11 lane W0-C, documentation state)
#
# SUBJECT: the identity of every file in technical-docs/architecture-decisions/.
# An ADR is only citable if its number means one document. Two ways that broke,
# both measured on 2026-09-07 and both fixed in the PR that adds this test:
#
#   1. H1 vs FILENAME. 24 of the first 28 ADR files carried an H1 number that
#      contradicted the filename - ADR-001's H1 said "ADR-004", ADR-028's said
#      "ADR-019". The files were renumbered on disk without their headings, so
#      "see ADR-NN" written before the move pointed at whatever document holds
#      the number now. Five such citations were dead links; the rest silently
#      pointed at the wrong decision.
#
#   2. ONE NUMBER, TWO ADRs. ADR-030, ADR-036 and ADR-039 each exist twice.
#      "ADR-036" means either OAuth-vs-governance layers or governance profiles
#      depending on who wrote it.
#
#      THESE THREE ARE GRANDFATHERED, and the guard refuses a FOURTH. Renumbering
#      them was tried on 2026-09-07 and reverted the same day: the three later
#      arrivals moved to 067-069, which fixed the citations in the ADR directory
#      and silently repointed 23 citations in 18 files OUTSIDE it - a public docs
#      page, six Go files, four immutable SQL migrations, two runtime-e2e suites -
#      at whichever document kept the number. A confidently wrong citation is worse
#      than an ambiguous one, because the ambiguous one makes a reader check.
#
#      So the asymmetry is deliberate: an existing collision is expensive to undo
#      and is recorded in README.md; a new one is free to avoid and is refused.
#
# COMPANION DOCUMENTS ARE NOT A COLLISION. ADR-065 has three files: the ADR and
# two companions (a Gate-17 budget annex, a phase sign-off record). The corpus
# distinguishes them by the H1 form, which is the README's stated convention:
#
#     the ADR       # ADR-065: Policy Decision and Identity Control Plane   <- colon
#     a companion   # ADR-065 Phase Sign-off Record                          <- no colon
#
# So this test asserts: every ADR-NNN-*.md file's H1 begins with its own NNN,
# and exactly one file per number uses the colon form.
#
# NOT A LINK CHECKER. Whether `[x](ADR-041-....md)` resolves is checked by
# docs_relative_links_test.sh. This test is about identity only.
#
# Run: bash tests/regression-test-required/adr_corpus_identity_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ADR_DIR="$REPO_ROOT/technical-docs/architecture-decisions"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

if [ ! -d "$ADR_DIR" ]; then
  echo "SKIP: community checkout; technical-docs/architecture-decisions/ is not mirrored"
  exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 missing; this test parses the corpus and must not pass without it"; exit 1; }

# The checker is a function of a DIRECTORY, so the positive control below can
# point it at a planted copy rather than at the real corpus.
check() {
  python3 - "$1" <<'PY'
import re, sys, collections, pathlib

adr_dir = pathlib.Path(sys.argv[1])
files = sorted(adr_dir.glob("ADR-*.md"))
if len(files) < 40:
    print(f"VACUOUS: only {len(files)} ADR files found in {adr_dir}; the corpus has ~70")
    sys.exit(2)

problems = []
claimants = collections.defaultdict(list)

for path in files:
    # Three digits, not "any digits": ADR-30-foo.md keys separately from
    # ADR-030 and would give a taken number a second identity the guard cannot
    # see. README.md's naming convention says NNN; this enforces it.
    if not re.match(r"ADR-\d{3}-", path.name):
        problems.append(f"{path.name}: filename must be ADR-NNN-title.md with a "
                        "three-digit number (README.md, Naming Convention)")
        continue
    file_num = re.match(r"(ADR-\d+)", path.name).group(1)
    h1 = next((l for l in path.read_text().splitlines() if l.startswith("# ")), None)
    if h1 is None:
        problems.append(f"{path.name}: no H1")
        continue
    m = re.match(r"^#\s+(ADR-\d+)(:)?", h1)
    if m is None:
        problems.append(f"{path.name}: H1 does not start with an ADR number: {h1!r}")
        continue
    if m.group(1) != file_num:
        problems.append(f"{path.name}: H1 says {m.group(1)}, filename says {file_num}")
        continue
    if m.group(2):                       # colon form = this file IS the ADR
        claimants[file_num].append(path.name)

# The three collisions that predate this guard, each documented in README.md with
# both claimants named. A number NOT in this set may be claimed once.
GRANDFATHERED = {"ADR-030", "ADR-036", "ADR-039"}

for num, names in sorted(claimants.items()):
    # The exemption is for a PAIR, not for the number. README.md names exactly
    # two claimants per grandfathered number; a THIRD is a new collision on an
    # old number and is refused like any other. Written as a cap rather than a
    # boolean because `num not in GRANDFATHERED` let a third claimant on ADR-036
    # through in silence.
    allowed = 2 if num in GRANDFATHERED else 1
    if len(names) > allowed:
        problems.append(f"{num}: claimed by {len(names)} files ({', '.join(names)}), "
                        f"and at most {allowed} may claim it. Pick an unused number. Do "
                        "NOT renumber an existing ADR to make room - README.md records "
                        "why that was tried and reverted.")

# The grandfathered set must not rot: an entry that no longer collides is a stale
# exemption, and would hide a real collision if that number were reused.
for num in sorted(GRANDFATHERED):
    if len(claimants.get(num, [])) < 2:
        problems.append(f"{num} is listed as a grandfathered collision but is claimed by "
                        f"{len(claimants.get(num, []))} file(s). If it was resolved, remove "
                        "it from GRANDFATHERED and from README.md's collision table.")

print(f"checked {len(files)} ADR files, {len(claimants)} distinct numbers claimed")
for p in problems:
    print(f"DEFECT {p}")
sys.exit(1 if problems else 0)
PY
}

echo "== the real corpus =="
OUT="$(check "$ADR_DIR")"; RC=$?
echo "$OUT" | sed 's/^/  /'
case $RC in
  0) ok "every ADR H1 matches its filename; every number is claimed once, or twice where README.md grandfathers a collision" ;;
  2) bad "the checker found too few ADR files to be checking anything" ;;
  *) bad "ADR corpus identity defects (listed above)" ;;
esac

# ---------------------------------------------------------------------------
# POSITIVE CONTROLS. A guard that has never been seen to fail is not a guard.
# Each control plants ONE defect on a copy of the real corpus and requires red.
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)" || { echo "  FAIL: mktemp -d"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

control() {                       # control <name> <mutation-command...>
  local name="$1"; shift
  rm -rf "$TMP/adr"; cp -R "$ADR_DIR" "$TMP/adr" || { bad "control $name: copy failed"; return; }
  "$@" || { bad "control $name: mutation failed"; return; }
  local out rc
  out="$(check "$TMP/adr")"; rc=$?
  if [ $rc -eq 1 ]; then
    ok "control: $name is caught"
  else
    bad "control: $name went UNDETECTED (rc=$rc)"
    echo "$out" | sed 's/^/      /'
  fi
}

plant_h1_mismatch() {
  local f="$TMP/adr/ADR-019-unified-policy-architecture.md"
  python3 - "$f" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
p.write_text(t.replace("# ADR-019:", "# ADR-020:", 1))
PY
}

# A FOURTH collision, on a number that is not grandfathered.
plant_duplicate_number() {
  cp "$TMP/adr/ADR-019-unified-policy-architecture.md" \
     "$TMP/adr/ADR-019-a-second-claimant.md"
}

# A grandfathered entry that stopped colliding must fail too: a stale exemption
# would let that number be silently reused.
plant_stale_grandfather() {
  rm -f "$TMP/adr/ADR-036-governance-profiles.md"
}

# The exemption is for a PAIR. A third claimant on a grandfathered number is a
# NEW collision on an OLD number, and passed silently until the cap was added.
plant_third_claimant() {
  cp "$TMP/adr/ADR-036-governance-profiles.md" "$TMP/adr/ADR-036-a-third-claimant.md"
}

# A two-digit filename keys separately from its three-digit form, giving a taken
# number a second identity nothing compares.
plant_two_digit_number() {
  cp "$TMP/adr/ADR-019-unified-policy-architecture.md" "$TMP/adr/ADR-19-shorthand.md"
}

plant_missing_number() {
  local f="$TMP/adr/ADR-005-decoupled-deployments.md"
  python3 - "$f" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
p.write_text(t.replace("# ADR-005: ", "# ", 1))
PY
}

control "an H1 number that contradicts the filename" plant_h1_mismatch
control "a FOURTH collision, on a number that is not grandfathered" plant_duplicate_number
control "a grandfathered collision that no longer collides" plant_stale_grandfather
control "a THIRD claimant on a grandfathered number" plant_third_claimant
control "a two-digit ADR filename" plant_two_digit_number
control "an H1 with no ADR number at all" plant_missing_number

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
