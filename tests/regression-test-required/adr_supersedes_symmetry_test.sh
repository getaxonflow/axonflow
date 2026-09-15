#!/usr/bin/env bash
# adr_supersedes_symmetry_test.sh - #3818 (v11 lane W0-C, documentation state)
#
# SUBJECT: "X supersedes Y" is a claim about TWO documents, and it was only ever
# recorded on one of them. The 2026-09-07 audit found eight one-directional
# links, every one of which strands a reader on the stale document:
#
#   ADR-018 -> ADR-019   ADR-041 -> ADR-052/053   ADR-032 -> ADR-014, ADR-007
#   ADR-065 -> ADR-017, ADR-019                   RLS_ARCHITECTURE -> ADR-053
#
# A reader who lands on ADR-019 - 1,158 lines describing the policy model that
# ADR-065 replaces at v11 - was told nothing. Landing on the superseded document
# is the COMMON case: it is the one the old links and the old search results
# point at. The forward link is the one that matters, and it was the missing one.
#
# WHAT IS ASSERTED, and the asymmetry in how it is asserted, which is deliberate:
#
#   A CLAIM is strict. Only the corpus's declared relationship FIELDS count -
#   `**Supersedes:**`, `**Superseded by:**`, `**Superseded in part by:**`, and
#   the `Superseded by ...` clause of a `**Status:**` line. Prose that happens to
#   contain the word near a number is not a claim. The looser first draft of this
#   guard read "ADR-049 - ... old parallel-JSONB version superseded" as ADR-050
#   superseding ADR-049, which is not what that sentence says.
#
#   An ACKNOWLEDGEMENT is loose. The named ADR need only mention the claimant's
#   number within a sentence containing some form of "supersede", in any
#   phrasing and across a wrapped line. ADR-065 records its claim as prose
#   wrapped over two lines; demanding one exact sentence would make this guard a
#   formatting rule instead of a content rule.
#
# Claims with no ADR number in the field ("Supersedes: None", "Superseded
# (2026-05-02)" for a retired process) are not relationships between two
# documents and are skipped.
#
# Run: bash tests/regression-test-required/adr_supersedes_symmetry_test.sh
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

check() {
  python3 - "$1" <<'PY'
import re, sys, pathlib

adr_dir = pathlib.Path(sys.argv[1])
files = {}
for path in sorted(adr_dir.glob("ADR-*.md")):
    num = re.match(r"(ADR-\d+)", path.name).group(1)
    files.setdefault(num, []).append(path)
if len(files) < 40:
    print(f"VACUOUS: only {len(files)} ADR numbers found in {adr_dir}; the corpus has ~68")
    sys.exit(2)

MENTION = re.compile(r"supersed(e|es|ed|ing)", re.I)
# A declared relationship field: `**Supersedes:** ...`, `**Superseded by:** ...`,
# `**Superseded in part by:** ...`. The value is everything after the colon.
FIELD = re.compile(r"^\**\s*(Supersedes|Superseded(?:\s+in\s+part)?\s+by)\s*:?\**\s*:?\s*(.*)$", re.I)
# A `**Status:**` line only claims what follows "superseded by", up to the first
# `;` - ADR-031's status line goes on to say "scope clarified by ADR-050", which
# is a different relationship.
STATUS = re.compile(r"^\**\s*Status\s*:?\**\s*:?\s*(.*)$", re.I)
STATUS_CLAUSE = re.compile(r"supersed(?:ed)?\s+by\s+([^;]*)", re.I)


def claim_targets(line):
    """The ADR numbers this line DECLARES a supersedes relationship with."""
    m = FIELD.match(line.strip())
    if m:
        return re.findall(r"ADR-\d{3}", m.group(2))
    m = STATUS.match(line.strip())
    if m:
        c = STATUS_CLAUSE.search(m.group(1))
        if c:
            return re.findall(r"ADR-\d{3}", c.group(1))
    return []


claims = []          # (source_number, target_number, source_file, line_no, text)
for num, paths in files.items():
    for path in paths:
        for i, line in enumerate(path.read_text().splitlines(), 1):
            # dict.fromkeys, not set(): one claim must report once, and
            # `re.findall` sees the number twice in `[ADR-032 ...](ADR-032-....md)`
            # - once in the link text, once in the target.
            for target in dict.fromkeys(claim_targets(line)):
                if target == num or target not in files:
                    continue
                claims.append((num, target, path.name, i, line.strip()))

problems = []
for src, tgt, fname, lineno, text in claims:
    body = "\n".join(p.read_text() for p in files[tgt]).splitlines()
    # A wrapped sentence counts: scan a two-line window.
    acknowledged = any(
        MENTION.search(body[i]) and src in "\n".join(body[i:i + 2])
        for i in range(len(body))
    )
    if not acknowledged:
        problems.append(
            f"{fname}:{lineno} states a supersedes relationship with {tgt}, but no file for "
            f"{tgt} mentions {src} on a line that says so.\n"
            f"           claim: {text[:150]}"
        )

pairs = {(s, t) for s, t, _, _, _ in claims}
print(f"checked {len(files)} ADR numbers, {len(pairs)} distinct supersedes relationships")
for p in problems:
    print(f"DEFECT {p}")
sys.exit(1 if problems else 0)
PY
}

echo "== the real corpus =="
OUT="$(check "$ADR_DIR")"; RC=$?
echo "$OUT" | sed 's/^/  /'
case $RC in
  0) ok "every supersedes relationship is recorded on both documents" ;;
  2) bad "the checker found too few ADRs to be checking anything" ;;
  *) bad "one-directional supersedes links (listed above)" ;;
esac

# ---------------------------------------------------------------------------
# POSITIVE CONTROLS. The defect this guard exists for is a claim on one document
# with NOTHING on the other, so each control deletes the ACKNOWLEDGEMENT and
# leaves the claim standing. (Deleting the claim instead is not a control: with
# no claim there is nothing to be symmetric about, and the guard correctly stays
# green - which is how the first draft of this control fooled itself.)
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)" || { echo "  FAIL: mktemp -d"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

# <name> <file-to-strip> <number-whose-mention-is-removed> <expect-in-output>
control() {
  local name="$1" target="$2" claimant="$3" expect="$4"
  rm -rf "$TMP/adr"; cp -R "$ADR_DIR" "$TMP/adr" || { bad "control $name: copy failed"; return; }
  python3 - "$TMP/adr/$target" "$claimant" <<'PY'
import re, sys, pathlib
p, claimant = pathlib.Path(sys.argv[1]), sys.argv[2]
lines = p.read_text().splitlines()
kept, i = [], 0
while i < len(lines):
    window = "\n".join(lines[i:i + 2])
    if re.search(r"supersed", lines[i], re.I) and claimant in window:
        i += 1                      # drop the acknowledging line
        continue
    kept.append(lines[i]); i += 1
p.write_text("\n".join(kept) + "\n")
PY
  local out rc
  out="$(check "$TMP/adr")"; rc=$?
  if [ $rc -eq 1 ] && echo "$out" | grep -q "$expect"; then
    ok "control: $name is caught"
  else
    bad "control: $name went UNDETECTED (rc=$rc)"
    echo "$out" | sed 's/^/      /'
  fi
}

# The audit's highest-value gap: ADR-019 says ADR-065 replaces its policy runtime;
# strip ADR-065's own record of that and the reader on ADR-019 is left alone.
control "ADR-065 no longer records superseding ADR-019" \
        ADR-065-policy-decision-and-identity-control-plane.md ADR-019 "ADR-019"
# The gap exactly as the audit found it: ADR-018 says "Superseded by ADR-019"
# and ADR-019 said nothing back.
control "ADR-019 no longer records superseding ADR-018" \
        ADR-019-unified-policy-architecture.md ADR-018 "ADR-018"

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
