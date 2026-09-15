#!/usr/bin/env bash
# licensing_wording_test.sh - #3818 (v11 lane W0-C, documentation state)
#
# SUBJECT: the hard rule that AxonFlow is never described as open source. The
# Community edition is BSL 1.1 SOURCE-AVAILABLE: readable and buildable, subject
# to the licence's use limitation. Calling it open source is a licensing claim,
# not a wording preference, and it is stated as a hard rule in CLAUDE.md and in
# technical-docs/README.md rule 4.
#
# Nothing enforced it. The 2026-09-07 audit found four violations by hand; this
# guard, written to close them, found a fifth the audit had missed:
# ee/docs/MARKETPLACE_METERING_FAQ.md answered "Where can I see the metering
# source code?" with "**A:** AxonFlow metering is open-source!".
#
# WHY A RATCHET AND NOT A GREP. The phrase is legitimate about somebody else -
# Llama, Ollama, Prometheus, NVIDIA NeMo Guardrails, a competitor's MIT licence
# - and about our own BSL change-date sunset, under which each release really
# does convert to Apache 2.0 after four years. A guard that just printed a count
# would be ignored; one that banned the phrase outright would be wrong. So every
# legitimate occurrence is classified once, by hand, in
# lib/licensing-wording-allowlist.tsv, and anything new is red until somebody
# classifies it too.
#
# The allowlist is checked in BOTH directions. An entry whose text is no longer
# in its file fails as well, so the list cannot decay into a blanket exemption
# for a file that has since grown a real violation.
#
# CHANGELOG.md is out of scope: it is an append-only historical record, and its
# entries are what was written at the time.
#
# Run: bash tests/regression-test-required/licensing_wording_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ALLOWLIST="$REPO_ROOT/tests/regression-test-required/lib/licensing-wording-allowlist.tsv"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

[ -f "$ALLOWLIST" ] || { echo "  FAIL: $ALLOWLIST is missing; this test cannot vacuously pass"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 missing; this test must not pass without it"; exit 1; }

check() {
  python3 - "$1" "$ALLOWLIST" <<'PY'
import re, sys, pathlib

root = pathlib.Path(sys.argv[1]).resolve()
allow_path = pathlib.Path(sys.argv[2])

# docs/ and README-class files ship to the community mirror; technical-docs/ and
# ee/docs/ are internal but are still where the claim gets written first.
ROOTS = ["docs", "technical-docs", "ee/docs"]
FILES = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "COMMUNITY_LICENSE_BOUNDARY.md",
         "ee/README.md"]
PHRASE = re.compile(r"open[- ]source|\bOSS\b", re.I)

allow = []          # (path, reason, text)
for line in allow_path.read_text().splitlines():
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    parts = line.split("\t")
    if len(parts) != 3:
        print(f"DEFECT allowlist row is not three tab-separated columns: {line!r}")
        sys.exit(1)
    allow.append(tuple(p.strip() for p in parts))

targets = []
for r in ROOTS:
    d = root / r
    if d.is_dir():
        targets += sorted(d.rglob("*.md"))
for f in FILES:
    if (root / f).is_file():
        targets.append(root / f)
if len(targets) < 30:
    print(f"VACUOUS: only {len(targets)} files in scope under {root}")
    sys.exit(2)

problems, scanned = [], 0
for p in targets:
    rel = p.relative_to(root).as_posix()
    text = p.read_text()
    permitted = [t for (a, _reason, t) in allow if a == rel]
    for i, line in enumerate(text.split("\n"), 1):
        if not PHRASE.search(line):
            continue
        scanned += 1
        if any(t in line for t in permitted):
            continue
        problems.append(f"{rel}:{i}  {line.strip()[:120]}")

# The other direction: an allowlist entry that no longer matches anything.
for a, reason, t in allow:
    f = root / a
    if not f.is_file() or t not in f.read_text():
        problems.append(f"STALE ALLOWLIST ENTRY  {a}  ({reason})  text no longer present: {t[:70]!r}")

print(f"scanned {len(targets)} files, {scanned} occurrence(s) of the phrase, "
      f"{len(allow)} classified in the allowlist")
for pr in problems:
    print(f"DEFECT {pr}")
sys.exit(1 if problems else 0)
PY
}

echo "== the real tree =="
OUT="$(check "$REPO_ROOT")"; RC=$?
echo "$OUT" | sed 's/^/  /'
case $RC in
  0) ok "every 'open source' / 'OSS' occurrence is classified, and no classification is stale" ;;
  2) bad "too few files in scope to be checking anything" ;;
  *) bad "unclassified licensing wording, or a stale allowlist entry (listed above)" ;;
esac

TMP="$(mktemp -d)" || { echo "  FAIL: mktemp -d"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

seed() {
  rm -rf "$TMP/tree"; mkdir -p "$TMP/tree/tests/regression-test-required/lib"
  for r in docs technical-docs ee; do
    [ -d "$REPO_ROOT/$r" ] && cp -R "$REPO_ROOT/$r" "$TMP/tree/$r"
  done
  for f in README.md CONTRIBUTING.md SECURITY.md COMMUNITY_LICENSE_BOUNDARY.md; do
    [ -f "$REPO_ROOT/$f" ] && cp "$REPO_ROOT/$f" "$TMP/tree/$f"
  done
}

# 1. THE REAL DEFECT, as it was actually written in the tree.
seed
printf '\n**A:** AxonFlow metering is open-source!\n' >> "$TMP/tree/ee/docs/MARKETPLACE_METERING_FAQ.md"
OUT2="$(check "$TMP/tree")"; RC2=$?
if [ $RC2 -eq 1 ] && echo "$OUT2" | grep -q 'MARKETPLACE_METERING_FAQ'; then
  ok "control: 'AxonFlow metering is open-source!' is caught"
else
  bad "control: a self-description as open source went UNDETECTED (rc=$RC2)"
  echo "$OUT2" | sed 's/^/      /'
fi

# 2. THE SWAP INTO ANOTHER FILE. A guard pinned to the files that were wrong
#    once is blind to the next file.
seed
printf '\nAxonFlow Community is open source.\n' >> "$TMP/tree/docs/getting-started.md"
OUT3="$(check "$TMP/tree")"; RC3=$?
if [ $RC3 -eq 1 ] && echo "$OUT3" | grep -q 'getting-started'; then
  ok "control: the same claim in a file with no allowlist entry is caught"
else
  bad "control: the claim in a new file went UNDETECTED (rc=$RC3)"
  echo "$OUT3" | sed 's/^/      /'
fi

# 3. THE ALLOWLIST MUST NOT BECOME A FILE-LEVEL EXEMPTION. A file that has a
#    legitimate entry must still be checked for a NEW violation.
seed
printf '\nAxonFlow is open source software.\n' >> "$TMP/tree/ee/docs/OLLAMA_SETUP.md"
OUT4="$(check "$TMP/tree")"; RC4=$?
if [ $RC4 -eq 1 ] && echo "$OUT4" | grep -q 'OLLAMA_SETUP'; then
  ok "control: a new violation in an already-allowlisted file is caught"
else
  bad "control: an allowlisted file exempted a new violation (rc=$RC4)"
  echo "$OUT4" | sed 's/^/      /'
fi

# 4. A STALE ENTRY. If the legitimate line is edited away, the classification
#    must not linger as a silent exemption.
seed
python3 - "$TMP/tree/ee/docs/OLLAMA_SETUP.md" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("Open-source model ecosystem", "Broad model ecosystem"))
PY
OUT5="$(check "$TMP/tree")"; RC5=$?
if [ $RC5 -eq 1 ] && echo "$OUT5" | grep -q 'STALE ALLOWLIST ENTRY'; then
  ok "control: an allowlist entry whose text is gone is caught"
else
  bad "control: a stale allowlist entry went UNDETECTED (rc=$RC5)"
  echo "$OUT5" | sed 's/^/      /'
fi

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
