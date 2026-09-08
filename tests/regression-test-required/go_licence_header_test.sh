#!/usr/bin/env bash
# go_licence_header_test.sh - #3726, #3307 (v11 lane W0-E)
#
# SUBJECT: every Go file in the tree carries exactly one licence statement,
# and it is the one the repository LICENSE makes:
#
#     // Copyright <year> AxonFlow
#     // SPDX-License-Identifier: BUSL-1.1
#
# THE DEFECT. On 2026-09-08, 536 Go files carried that SPDX line followed by
# the Apache-2.0 boilerplate tail (the LICENSE-2.0 URL and the "AS IS"
# warranty paragraph), 18 enterprise-tagged files said "Licensed under the
# Elastic License 2.0", 8 carried a prose BUSL block, 12 a copyright line with
# no identifier, and 439 no header at all. A header that names two licences is
# two licence statements about one file, in a product whose standing rule is
# that it is BUSL 1.1 source-available and never described otherwise. The
# shape came from a template (scripts/add-license-headers.sh pasted the Apache
# block; new files copied their neighbour), and a template defect returns the
# next time somebody pastes, which is why this is a guard and not a sweep.
#
# THE RULE, read from tests/regression-test-required/lib/go_licence_header.py
# (shared with scripts/licence/normalise-go-headers.py, so the rewrite and the
# guard cannot disagree about what a header is): exactly one SPDX tag in the
# whole file, it is the line `// SPDX-License-Identifier: BUSL-1.1` (an
# expression such as "BUSL-1.1 OR MIT" is refused), it sits directly under the
# copyright line before the package clause, no boilerplate sentence or Apache
# URL appears anywhere in the file, and nothing else before the package clause
# names a licence. lib/go-licence-header-exceptions.tsv lists what may differ
# and WHY (the 3 MIT example files, protoc output, and one directory deferred
# while W0-B owns it - 32 files in all, and the list is meant to shrink, never
# grow: a new row is a reviewer's decision, not a way past this guard). Each
# row is checked in both directions: a row matching no file is stale, a
# deferred row whose files have all become canonical has served its purpose, a
# deferred row never excuses a second licence, and an escalated row - the one
# kind that may, because it exists for a licence genuinely in question - can
# neither excuse two SPDX identifiers nor stand without naming the issue the
# ruling is pending on.
#
# THE POSITIVE CONTROL. A zero from a scanner that found nothing is not
# evidence, so the BUSL count is printed and required above a floor. The
# floor is EDITION-AWARE, read off the checked-out tree (lint.yml present and
# sync-community-repo.yml absent = the community mirror), because this file
# syncs to the mirror and is proven against the staged mirror tree
# (scripts/ci/simulate-community-mirror.sh) before every change; the mirror's
# own CI does not execute the regression suite. The enterprise floor is never
# lowered to pass on the staged tree.
#
# CONTROLS. Each plants ONE defect on a copy of the real tree and requires
# red naming the file. The plants that need an exception row build their OWN
# fixture file and row, so no control depends on a real row that is designed
# to expire (round-1 finding: two controls went red exactly when the deferral
# this PR records was honoured).
#
# Run: bash tests/regression-test-required/go_licence_header_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$REPO_ROOT/tests/regression-test-required/lib"
MODULE="$LIB/go_licence_header.py"
EXCEPTIONS="$LIB/go-licence-header-exceptions.tsv"

# Calibration. Enterprise: 2,535 BUSL files on 2026-09-08 at the head that
# added this guard; the brief's floor is 2,000. Community: the staged mirror
# (scripts/ci/simulate-community-mirror.sh) carried 1,492 that day; the floor
# is 1,200. Both mean "the scanner found the population", not "the tree has
# not shrunk"; a tree that halves is somebody else's finding.
ENTERPRISE_FLOOR=2000
COMMUNITY_FLOOR=1200

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

for f in "$MODULE" "$EXCEPTIONS"; do
  [ -f "$f" ] || { echo "  FAIL: $f is missing; this test cannot vacuously pass"; exit 1; }
done
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 missing; a guard that cannot run must not pass"; exit 1; }

# The edition is a property of the checked-out tree, decided the way
# suite_gate_floor_is_edition_aware_test.sh and scripts/lint-hitl-queue-choke-point.sh
# decide it, and never from "the count looks small".
floor_for_tree() {
  if [ -f "$1/.github/workflows/lint.yml" ] && [ ! -f "$1/.github/workflows/sync-community-repo.yml" ]; then
    echo "$COMMUNITY_FLOOR community"
  else
    echo "$ENTERPRISE_FLOOR enterprise"
  fi
}

# check <root> <exceptions-tsv> <floor> -> rc 0 clean, 1 defects, 2 vacuous
check() {
  python3 - "$1" "$2" "$3" "$LIB" <<'PY'
import sys, pathlib
root, tsv, floor, lib = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
sys.path.insert(0, lib)
import go_licence_header as glh

try:
    exceptions = glh.load_exceptions(tsv)
except ValueError as exc:
    print(f"DEFECT exceptions file: {exc}")
    sys.exit(1)
findings, stale = glh.check_tree(root, exceptions)
busl = glh.busl_count(findings)
problems = [f for f in findings if f.problem]
print(f"scanned {len(findings)} Go files, {busl} declare SPDX {glh.CANONICAL_SPDX}, "
      f"{len(problems)} defect(s), {len(stale)} stale exception row(s), {len(exceptions)} rows")
for f in problems:
    print(f"DEFECT {f.path}: {f.problem}")
for s in stale:
    print(f"DEFECT stale exception row: {s}")
if busl < floor:
    print(f"VACUOUS: only {busl} files declare {glh.CANONICAL_SPDX}; the floor is {floor}. "
          "The scanner found too little to be checking anything.")
    sys.exit(2)
sys.exit(1 if problems or stale else 0)
PY
}

read -r FLOOR EDITION <<< "$(floor_for_tree "$REPO_ROOT")"
echo "== the real tree ($EDITION checkout, floor $FLOOR) =="
OUT="$(check "$REPO_ROOT" "$EXCEPTIONS" "$FLOOR")"; RC=$?
echo "$OUT" | sed 's/^/  /'
case $RC in
  0) ok "every Go file carries the canonical BUSL-1.1 header or a reasoned exception, and no exception row is stale" ;;
  2) bad "positive control: the BUSL population is below the $EDITION floor of $FLOOR" ;;
  *) bad "non-canonical licence headers or stale exception rows (listed above)" ;;
esac

# ---------------------------------------------------------------------------
# POSITIVE CONTROLS on a copy of the real tree's Go files.
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)" || { echo "  FAIL: mktemp -d"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

seed() {
  rm -rf "$TMP/tree"
  python3 - "$REPO_ROOT" "$TMP/tree" "$LIB" <<'PY'
import sys, pathlib, shutil
src, dst, lib = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, lib)
import go_licence_header as glh
for p in glh.go_files(src):
    rel = p.relative_to(src)
    (dst / rel).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(p, dst / rel)
PY
  cp "$EXCEPTIONS" "$TMP/exceptions.tsv"
}

# A canonical, non-excepted file to plant on, chosen by the same classifier.
VICTIM="$(python3 - "$REPO_ROOT" "$EXCEPTIONS" "$LIB" <<'PY'
import sys, pathlib
root, tsv, lib = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, lib)
import go_licence_header as glh
exceptions = glh.load_exceptions(tsv)
for f, _ in [glh.check_tree(root, exceptions)]:
    for x in f:
        if x.verdict.ok and x.exception is None and x.path.startswith("platform/"):
            print(x.path); break
PY
)"
[ -n "$VICTIM" ] || { echo "  FAIL: no canonical platform/ file to plant on; the classifier found nothing"; exit 1; }

# control <name> <needle> <mutation...>: plant, run, require rc 1 naming <needle>.
control() {
  local name="$1" needle="$2"; shift 2
  seed
  "$@" || { bad "control $name: mutation failed"; return; }
  local out rc
  out="$(check "$TMP/tree" "$TMP/exceptions.tsv" "$FLOOR")"; rc=$?
  if [ $rc -eq 1 ] && printf '%s\n' "$out" | grep -qF -- "$needle"; then
    ok "control: $name is caught"
  else
    bad "control: $name went UNDETECTED (rc=$rc)"
    printf '%s\n' "$out" | grep -E 'DEFECT|VACUOUS' | head -5 | sed 's/^/      /'
  fi
}

edit_victim() {  # edit_victim <python-expression over t>
  python3 - "$TMP/tree/$VICTIM" "$1" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
p.write_text(eval(sys.argv[2]))
PY
}

APACHE_TAIL='// SPDX-License-Identifier: BUSL-1.1\n//\n//     http://www.apache.org/licenses/LICENSE-2.0\n//\n// Unless required by applicable law or agreed to in writing, software\n// distributed under the License is distributed on an "AS IS" BASIS,\n// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n// See the License for the specific language governing permissions and\n// limitations under the License.'

control "the Apache-2.0 tail re-pasted under the SPDX line ($VICTIM)" "$VICTIM" \
  edit_victim "t.replace('// SPDX-License-Identifier: BUSL-1.1', '$APACHE_TAIL', 1)"

control "a second SPDX line" "$VICTIM" \
  edit_victim "t.replace('// SPDX-License-Identifier: BUSL-1.1', '// SPDX-License-Identifier: BUSL-1.1\n// SPDX-License-Identifier: Apache-2.0', 1)"

control "a header with no SPDX line" "$VICTIM" \
  edit_victim "t.replace('// SPDX-License-Identifier: BUSL-1.1\n', '', 1)"

control "the Elastic License prose re-pasted" "$VICTIM" \
  edit_victim "t.replace('// SPDX-License-Identifier: BUSL-1.1', '// Licensed under the Elastic License 2.0 (ELv2)', 1)"

plant_headerless_file() {
  mkdir -p "$TMP/tree/platform/plant" && printf 'package plant\n\nfunc Plant() {}\n' > "$TMP/tree/platform/plant/plant.go"
}
control "a new file with no header at all (#3307's shape)" "platform/plant/plant.go" plant_headerless_file

# The plants below that need an exception row build their own file AND row,
# so the control keeps working after the real rows expire.
plant_mit_flip() {
  mkdir -p "$TMP/tree/platform/plant-mit"
  printf '// Copyright 2026 AxonFlow\n// SPDX-License-Identifier: BUSL-1.1\n\npackage plantmit\n' > "$TMP/tree/platform/plant-mit/x.go"
  printf 'platform/plant-mit/\tspdx:MIT\ta fixture row for the control\n' >> "$TMP/exceptions.tsv"
}
control "an MIT-listed file that carries BUSL (the row no longer describes the file)" "platform/plant-mit/x.go" plant_mit_flip

plant_row_matching_nothing() {
  printf 'platform/no/such/dir/\tdeferred\ta row that matches nothing\n' >> "$TMP/exceptions.tsv"
}
control "an exception row that matches no file" "matches no file" plant_row_matching_nothing

plant_served_purpose() {
  mkdir -p "$TMP/tree/platform/plant-deferred"
  printf '// Copyright 2026 AxonFlow\n// SPDX-License-Identifier: BUSL-1.1\n\npackage plantdeferred\n' > "$TMP/tree/platform/plant-deferred/x.go"
  printf 'platform/plant-deferred/\tdeferred\ta fixture row whose file is already canonical\n' >> "$TMP/exceptions.tsv"
}
control "a deferred row whose files have all become canonical" "every matching file is canonical" plant_served_purpose

plant_deferred_second_licence() {
  mkdir -p "$TMP/tree/platform/plant-deferred"
  printf '// Copyright 2026 AxonFlow\n%b\n\npackage plantdeferred\n' "$APACHE_TAIL" > "$TMP/tree/platform/plant-deferred/x.go"
  printf 'platform/plant-deferred/\tdeferred\ta fixture row over a file with a second licence\n' >> "$TMP/exceptions.tsv"
}
control "a deferred row over a file that names a second licence (deferral must not excuse it)" "platform/plant-deferred/x.go" plant_deferred_second_licence

control "an SPDX expression (BUSL-1.1 OR MIT)" "$VICTIM" \
  edit_victim "t.replace('// SPDX-License-Identifier: BUSL-1.1', '// SPDX-License-Identifier: BUSL-1.1 OR MIT', 1)"

control "a second SPDX tag inside a block comment before the header" "$VICTIM" \
  edit_victim "'/* SPDX-License-Identifier: Apache-2.0 */\n' + t"

control "an Apache warranty paragraph pasted below the package clause" "$VICTIM" \
  edit_victim "t + '\n// Unless required by applicable law or agreed to in writing, software\n'"

control "a warranty paragraph inside a block comment below the package clause" "$VICTIM" \
  edit_victim "t + '\n/*\n * Unless required by applicable law or agreed to in writing, software\n */\n'"

control "an Elastic licence line indented inside a function body" "$VICTIM" \
  edit_victim "t + '\nfunc plantedLicence() {\n\t// Licensed under the Elastic License 2.0 (ELv2)\n}\n'"

control "an Apache licence line in a block comment below the package clause, without the boilerplate suffix" "$VICTIM" \
  edit_victim "t + '\n/* * Licensed under the Apache License, Version 2.0 */\n'"

control "a copyright line naming another holder" "$VICTIM" \
  edit_victim "t.replace('// SPDX-License-Identifier: BUSL-1.1', '// Copyright 2020 SomeOtherCorp\n// SPDX-License-Identifier: BUSL-1.1', 1)"

control "a bare licence identifier in the header (Apache-2.0)" "$VICTIM" \
  edit_victim "t.replace('// SPDX-License-Identifier: BUSL-1.1', '// SPDX-License-Identifier: BUSL-1.1\n// Also available under Apache-2.0', 1)"

# An `escalated` row excuses a licence QUESTION, not a broken file: two SPDX
# identifiers is not something a ruling can resolve. Round 1 bounded
# `deferred` and left `escalated` with no branch at all, so a row of that kind
# excused anything (master's R3, MAJOR-1).
plant_escalated_two_spdx() {
  mkdir -p "$TMP/tree/platform/plant-escalated"
  printf '// Copyright 2026 AxonFlow\n// SPDX-License-Identifier: BUSL-1.1\n// SPDX-License-Identifier: Apache-2.0\n//\n// Unless required by applicable law or agreed to in writing, software\n\npackage plantescalated\n' > "$TMP/tree/platform/plant-escalated/x.go"
  printf 'platform/plant-escalated/\tescalated\ta fixture row pending a ruling on #3726\n' >> "$TMP/exceptions.tsv"
}
control "an escalated row over a file with TWO SPDX identifiers (a ruling cannot resolve that)" "platform/plant-escalated/x.go" plant_escalated_two_spdx

plant_escalated_without_issue() {
  mkdir -p "$TMP/tree/platform/plant-escalated"
  printf '// Copyright 2026 AxonFlow\n// Licensed under the Elastic License 2.0 (ELv2)\n\npackage plantescalated\n' > "$TMP/tree/platform/plant-escalated/x.go"
  printf 'platform/plant-escalated/\tescalated\tsomebody is thinking about it\n' >> "$TMP/exceptions.tsv"
}
control "an escalated row that names no issue for the pending ruling" "must name the issue" plant_escalated_without_issue

plant_row_without_reason() {
  printf 'platform/plant.go\tdeferred\t\n' >> "$TMP/exceptions.tsv"
}
control "an exception row with no reason" "needs a reason" plant_row_without_reason

# The floor, both ways. A tree of ten canonical files is below either floor.
seed
python3 - "$TMP/tree" "$LIB" <<'PY'
import sys, pathlib, shutil
root, lib = pathlib.Path(sys.argv[1]), sys.argv[2]
sys.path.insert(0, lib)
import go_licence_header as glh
keep = [p for p in glh.go_files(root) if glh.classify(p.read_text()).ok][:10]
for p in glh.go_files(root):
    if p not in keep:
        p.unlink()
PY
OUT="$(check "$TMP/tree" "$TMP/exceptions.tsv" "$FLOOR")"; RC=$?
if [ $RC -eq 2 ] && printf '%s\n' "$OUT" | grep -q VACUOUS; then
  ok "control: a tree below the floor is reported as VACUOUS, not clean"
else
  bad "control: ten files passed as a whole population (rc=$RC)"
fi

# The edition marker decides the floor, both ways, on fixtures that differ
# only by the sync workflow.
mkdir -p "$TMP/ent/.github/workflows" "$TMP/com/.github/workflows"
: > "$TMP/ent/.github/workflows/lint.yml"; : > "$TMP/ent/.github/workflows/sync-community-repo.yml"
: > "$TMP/com/.github/workflows/lint.yml"
[ "$(floor_for_tree "$TMP/ent")" = "$ENTERPRISE_FLOOR enterprise" ] && ok "control: both marker files -> enterprise floor $ENTERPRISE_FLOOR" || bad "control: enterprise tree did not get the enterprise floor"
[ "$(floor_for_tree "$TMP/com")" = "$COMMUNITY_FLOOR community" ] && ok "control: lint.yml alone -> community floor $COMMUNITY_FLOOR" || bad "control: community tree did not get the community floor"
[ "$ENTERPRISE_FLOOR" -gt "$COMMUNITY_FLOOR" ] && ok "control: the enterprise floor is above the community floor" || bad "the enterprise floor has been lowered to the community one"

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
