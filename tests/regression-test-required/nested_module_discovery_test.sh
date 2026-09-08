#!/usr/bin/env bash
# nested_module_discovery_test.sh - #3746 gate (f) for ee/ and examples/ (v11 lane W0-E)
#
# THE RULE: every separate Go module (a go.mod) under ee/ and examples/ is run
# by a job in .github/workflows/test.yml that DISCOVERS it, or is a row in
# tests/regression-test-required/lib/go-module-dispositions.tsv with a
# reason. A module in neither is a suite that lands in the repository and
# never executes, and nothing about adding one would remind anyone (#3699,
# #3574 - the same shape, one module over).
#
# WHAT WAS FOUND (2026-09-08). `unit-tests-ee-modules` was a hand-written list
# of seven; nine other nested modules under ee/platform ran in no job for as
# long as they existed, and none of the 104 Go example modules under
# examples/ and ee/examples/ was ever built by CI (four failed `go vet` on the
# day this guard was written). A list is a census bounded by the day it was
# written; this guard makes the lanes derive their set and holds the
# dispositions file to the tree in both directions.
#
# BOUNDARY (master, 2026-09-08). The ROOT ee module (ee/go.mod) is #3699's
# subject and W1-D's PR: its packages are selected by the enterprise ARMS, and
# whether that selection is by name or by `go test ./...` is theirs. This guard
# is about NESTED modules; the root is a `covered-by:` row so the census is the
# whole set of go.mod files and a second root module cannot appear unnoticed.
#
# HOW A MODULE COUNTS AS RUN, read from the workflow with a YAML parser, code
# lines only (a marker inside a `#` comment is prose):
#   - DERIVED: a job has a run step that `find`s go.mod files under a root
#     that is a prefix of the module's path, `cd`s into a loop variable, runs
#     `go test ... ./...` or `go vet ... ./...`, and reads the dispositions file (so
#     the exclusions it applies are the rows below, not a private list); the
#     module is not a row in that file.
#   - NAMED: a `covered-by:<job>` row, and the named job has a code line
#     `cd <module>` followed by a go test/vet in the same step; the guard
#     prints whether that job's `if:` excludes pull_request explicitly, with
#     the condition, because "covered on main" is not "covered on a PR"
#     (#3832 HIGH-1).
#   - EXCLUDED: an `excluded` row with a reason naming where the debt lives.
#
# THE FILE IS HELD TO THE TREE: a row whose module has no go.mod is stale, a
# row with no reason or a module listed twice is refused, an excluded row must
# name the issue tracking the debt, and every discovering lane must gate
# test-summary in both `needs` and the failure expression.
#
# CONTROLS, on synthetic copies: a new module under a derived root is
# DISCOVERED (green - that is gate (f)); a lane that stops discovering a root
# reds every module under it; a row with no reason; a row for a module that is
# gone; a covered-by row naming a job that never enters the module; a lane
# that stops reading the dispositions file; a workflow the parser rejects is
# an instrument failure, not a clean tree.
#
# On the community mirror test.yml is absent (the sync strips it), so this
# test SKIPs there like community_workflow_twin_parity_test.sh.
#
# Run: bash tests/regression-test-required/nested_module_discovery_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/test.yml"
DISPOSITIONS="$REPO_ROOT/tests/regression-test-required/lib/go-module-dispositions.tsv"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

if [ ! -f "$WORKFLOW" ]; then
  echo "SKIP: community checkout; .github/workflows/test.yml is not mirrored, so there is no lane set to check"
  exit 0
fi
[ -f "$DISPOSITIONS" ] || { echo "  FAIL: $DISPOSITIONS is missing; this test cannot vacuously pass"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 missing; a guard that cannot run must not pass"; exit 1; }
python3 -c 'import yaml' 2>/dev/null || { echo "  FAIL: PyYAML missing; the workflow cannot be parsed, and a guard that cannot run must not pass"; exit 1; }

# check <root> <workflow> <dispositions> -> rc 0 clean, 1 defects, 3 instrument failure.
# Prints one DEFECT line per finding and a summary line.
check() {
  python3 - "$1" "$2" "$3" <<'PY'
import os, re, sys, pathlib
root, wf, tsv = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
try:
    import yaml
    doc = yaml.safe_load(wf.read_text())
except Exception as exc:  # noqa: BLE001 - a scanner error is an instrument failure, not a finding
    print(f"INSTRUMENT: {wf} could not be parsed: {exc!r}")
    sys.exit(3)

SKIP = {"node_modules", "testdata", "vendor", ".git"}
def modules():
    out = []
    for top in ("ee", "examples"):
        d = root / top
        if not d.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(d):
            dirnames[:] = sorted(x for x in dirnames if x not in SKIP)
            if "go.mod" in filenames:
                out.append(pathlib.Path(dirpath).relative_to(root).as_posix())
    return sorted(out)

def code_lines(script):
    """The script with `#` comment lines AND trailing ` # ...` comments removed.

    Round 1 planted `find ee/platform -name go.mod` inside an echo string with
    the dispositions filename in a trailing comment, and it counted as a
    discovering lane. A marker that survives in prose is a marker that
    survives the deletion of the check it stands for.
    """
    out = []
    for l in str(script or "").splitlines():
        if l.strip().startswith("#"):
            continue
        out.append(re.sub(r"\s+#.*$", "", l))
    return "\n".join(out)

# `find` must BEGIN a command: at line start, after `$(`, `(`, `;`, `&&`, `||`
# or `|`. A `find` inside an echo string is prose.
FIND_RE = re.compile(r"(?:^|\$\(|[(;|&]\s*|\|\|\s*)\s*find\s+((?:[A-Za-z0-9_./-]+\s+)+)-name\s+go\.mod", re.M)
CD_LOOP = re.compile(r'cd\s+"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"')
# `go test ./...` or `go vet ./...`, with or without flags between (the ee lane
# passes -tags enterprise); the literal `./...` is what makes it the whole module.
GO_RUN = re.compile(r"\bgo (test|vet)\b[^\n]*\./\.\.\.")
# For a covered-by row any go test/vet after the cd counts: the row asserts the
# MODULE is entered and run; which packages a root-module arm selects inside
# it is #3699's subject, not this guard's.
GO_ANY = re.compile(r"\bgo (test|vet)\b")
TSV_NAME = tsv.name

jobs = doc.get("jobs") or {}
derived = []          # (job, roots, reads_tsv, excludes_pr)
named_cd = {}         # job -> set of `cd <path>` targets followed by go test/vet in the same step
def excludes_pr(job):
    """The job's `if:` names pull_request as an event it does NOT run on.

    Read as text, not evaluated: what is reported is whether the condition
    carries `github.event_name != 'pull_request'`, which is the one spelling
    test.yml uses for its queue-only arms; the raw condition is printed with
    it so a reader is not left with a boolean.
    """
    cond = " ".join(str(job.get("if") or "").split())
    return ("!= 'pull_request'" in cond), cond
# `cd <path>` then, on the same line or a later line of the step, a go test/vet.
CD_NAMED = re.compile(r"(?:^|\(|;|&&)\s*cd\s+([A-Za-z0-9_./-]+)\s*(?:$|;|&&)", re.M)
for name, job in jobs.items():
    cds = set()
    for step in (job.get("steps") or []):
        code = code_lines(step.get("run"))
        for m in FIND_RE.finditer(code):
            roots = m.group(1).split()
            if CD_LOOP.search(code) and GO_RUN.search(code):
                derived.append((name, roots, TSV_NAME in code, excludes_pr(job)))
        for m in CD_NAMED.finditer(code):
            if GO_ANY.search(code[m.end():]):
                cds.add(m.group(1).rstrip("/"))
    named_cd[name] = cds

rows = {}
problems = []
for n, line in enumerate(tsv.read_text().splitlines(), 1):
    if not line.strip() or line.startswith("#"):
        continue
    parts = line.split("\t")
    if len(parts) != 3 or not parts[2].strip():
        problems.append(f"{TSV_NAME}:{n}: a row needs module, disposition and a reason: {line[:80]!r}")
        continue
    mod, disp, reason = (x.strip() for x in parts)
    if not (disp == "excluded" or disp.startswith("covered-by:")):
        problems.append(f"{TSV_NAME}:{n}: unknown disposition {disp!r}")
        continue
    if mod in rows:
        problems.append(f"{TSV_NAME}:{n}: {mod} is listed twice (first at line {rows[mod][2]})")
        continue
    if disp == "excluded" and not re.search(r"#\d+", reason):
        problems.append(f"{TSV_NAME}:{n}: an excluded row must name the issue tracking the debt (#NNNN): {mod}")
        continue
    rows[mod] = (disp, reason, n)

mods = modules()
if len(mods) < 100:
    print(f"VACUOUS: only {len(mods)} go.mod files found under ee/ and examples/ (122 on 2026-09-08; a lost tree is 71 or 34 fewer); discovery is not reading the tree")
    sys.exit(3)

def derived_lanes_for(mod):
    return [(j, roots, reads, pr) for (j, roots, reads, pr) in derived
            if any(mod == r or mod.startswith(r.rstrip("/") + "/") for r in roots)]

covered = 0
for mod in mods:
    lanes = derived_lanes_for(mod)
    if mod in rows:
        disp, reason, n = rows[mod]
        if lanes and disp == "excluded":
            pass   # the lane skips rows; an excluded row inside a derived root is the exclusion mechanism
        if disp.startswith("covered-by:"):
            job = disp.split(":", 1)[1]
            if job not in jobs:
                problems.append(f"{mod}: covered-by names job {job!r}, which test.yml does not declare")
                continue
            if mod not in named_cd.get(job, set()):
                problems.append(f"{mod}: covered-by names {job}, but no code line in that job does `cd {mod}`")
                continue
            excl, cond = excludes_pr(jobs[job])
            tier = "if: excludes pull_request explicitly" if excl else "if: does not exclude pull_request explicitly"
            print(f"NAMED   {mod} <- {job} ({tier}: {cond[:90]})")
        else:
            print(f"EXCLUDED {mod}: {reason[:90]}")
        covered += 1
        continue
    if not lanes:
        problems.append(f"{mod}: runs in NO job - no lane discovers a root above it and {TSV_NAME} has no row for it")
        continue
    good = [l for l in lanes if l[2]]
    if not good:
        problems.append(f"{mod}: discovered by {[l[0] for l in lanes]} but that lane does not read {TSV_NAME}; its exclusions are a private list")
        continue
    covered += 1

for mod, (disp, reason, n) in rows.items():
    if mod not in mods:
        problems.append(f"{TSV_NAME}:{n}: row for {mod}, which has no go.mod under ee/ or examples/; delete the row")

if not derived:
    problems.append("no job in test.yml discovers go.mod files under ee/ or examples/ at all")

# A discovering lane that does not gate test-summary is a lane whose red
# stops nothing: it must be in the summary's `needs` AND its result must be
# read by the failure step's `if:` (the mirrored-module guard's two halves).
summary = jobs.get("test-summary") or {}
needs = summary.get("needs") or []
needs = [needs] if isinstance(needs, str) else list(needs)
fail_expr = " ".join(str(s.get("if") or "") for s in (summary.get("steps") or [])
                     if "needs." in str(s.get("if") or "") and "!= 'success'" in str(s.get("if") or ""))
for lane in sorted({d[0] for d in derived}):
    if lane not in needs:
        problems.append(f"{lane} discovers modules but is not in test-summary's needs; its red stops nothing")
    elif f"needs.{lane}.result" not in fail_expr:
        problems.append(f"{lane} is in test-summary's needs but its result is never read by the failure step's if:")

print(f"scanned {len(mods)} go.mod files under ee/ and examples/, {len(rows)} rows, "
      f"{len(derived)} discovering lane(s) ({', '.join(sorted({d[0] for d in derived}))}), {covered} covered, {len(problems)} defect(s)")
for p in problems:
    print(f"DEFECT {p}")
sys.exit(1 if problems else 0)
PY
}

echo "== the real tree =="
OUT="$(check "$REPO_ROOT" "$WORKFLOW" "$DISPOSITIONS")"; RC=$?
echo "$OUT" | grep -vE '^(NAMED|EXCLUDED)' | sed 's/^/  /'
echo "$OUT" | grep -E '^(NAMED|EXCLUDED)' | sed 's/^/    /'
case $RC in
  0) ok "every go.mod under ee/ and examples/ is discovered by a lane that reads the dispositions file, or is a reasoned row" ;;
  3) bad "the checker could not run (listed above)" ;;
  *) bad "nested-module discovery defects (listed above)" ;;
esac

# ---------------------------------------------------------------------------
# CONTROLS. A synthetic tree holds the real workflow, the real dispositions
# file, and fresh go.mod files; each control mutates one thing.
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)" || { echo "  FAIL: mktemp -d"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

seed() {
  rm -rf "$TMP/t"; mkdir -p "$TMP/t/.github/workflows" "$TMP/t/tests/regression-test-required/lib"
  cp "$WORKFLOW" "$TMP/t/.github/workflows/test.yml"
  cp "$DISPOSITIONS" "$TMP/t/tests/regression-test-required/lib/go-module-dispositions.tsv"
  # Real go.mod layout, no sources: the check reads paths, not code.
  python3 - "$REPO_ROOT" "$TMP/t" <<'PY'
import os, sys, pathlib
src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
SKIP = {"node_modules", "testdata", "vendor", ".git"}
for top in ("ee", "examples"):
    for dirpath, dirnames, filenames in os.walk(src / top):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        if "go.mod" in filenames:
            rel = pathlib.Path(dirpath).relative_to(src)
            (dst / rel).mkdir(parents=True, exist_ok=True)
            (dst / rel / "go.mod").write_text("module x\n")
PY
}
T_WF="$TMP/t/.github/workflows/test.yml"
T_TSV="$TMP/t/tests/regression-test-required/lib/go-module-dispositions.tsv"

expect() {   # expect <want-rc> <label> [needle]
  local want="$1" label="$2" needle="${3:-}" out rc
  out="$(check "$TMP/t" "$T_WF" "$T_TSV")"; rc=$?
  if [ "$rc" -ne "$want" ]; then
    bad "$label (expected rc=$want, got rc=$rc)"; echo "$out" | grep -E 'DEFECT|VACUOUS|INSTRUMENT' | head -4 | sed 's/^/      /'; return
  fi
  if [ -n "$needle" ] && ! printf '%s\n' "$out" | grep -qF -- "$needle"; then
    bad "$label (rc correct but the output never said: $needle)"; echo "$out" | head -5 | sed 's/^/      /'; return
  fi
  ok "$label"
}

# 1. Gate (f) itself: a new module under a discovered root needs no edit anywhere.
seed; mkdir -p "$TMP/t/examples/plantmod" && printf 'module plant\n' > "$TMP/t/examples/plantmod/go.mod"
expect 0 "control: a NEW examples/plantmod/go.mod is discovered without touching any list (gate (f))"
seed; mkdir -p "$TMP/t/ee/platform/plantmod" && printf 'module plant\n' > "$TMP/t/ee/platform/plantmod/go.mod"
expect 0 "control: a NEW ee/platform/plantmod/go.mod is discovered without touching any list (gate (f))"

# 2. A lane that stops discovering a root reds every module under it.
seed; python3 - "$T_WF" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
p.write_text(t.replace("find examples ee/examples -name go.mod", "find examples -name go.mod", 1))
PY
expect 1 "control: a lane that stops discovering ee/examples reds every module under it" "runs in NO job"

# 3. A module in a root NO lane discovers and no row names.
seed; mkdir -p "$TMP/t/ee/plantroot/mod" && printf 'module plant\n' > "$TMP/t/ee/plantroot/mod/go.mod"
expect 1 "control: a module under a root no lane discovers, with no row, is caught" "ee/plantroot/mod: runs in NO job"

# 4. A row with no reason.
seed; printf 'examples/hello-world/go\texcluded\t\n' >> "$T_TSV"
expect 1 "control: a row with no reason is refused" "needs module, disposition and a reason"

# 5. A row for a module that no longer exists.
seed; printf 'ee/platform/no-such-module\texcluded\tit was removed; #3699\n' >> "$T_TSV"
expect 1 "control: a row whose module has no go.mod is stale" "has no go.mod under ee/ or examples/"

# 6. A covered-by row naming a job that never enters the module.
seed; python3 - "$T_TSV" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
p.write_text(t.replace("ee/platform/customer-portal\tcovered-by:unit-tests-enterprise-realpg", "ee/platform/customer-portal\tcovered-by:unit-tests-connectors", 1))
PY
expect 1 "control: a covered-by row naming a job with no \`cd\` into the module is caught" "no code line in that job does \`cd ee/platform/customer-portal\`"

# 7. A lane that stops reading the dispositions file has a private exclusion list.
seed; python3 - "$T_WF" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
p.write_text(t.replace("DISPOSITIONS=tests/regression-test-required/lib/go-module-dispositions.tsv\n          [ -f \"$DISPOSITIONS\" ] || { echo \"::error::$DISPOSITIONS is absent; the exclusion set cannot be read and this step must not pass having guessed\"; exit 1; }\n          for d in examples ee/examples", "DISPOSITIONS=/dev/null\n          for d in examples ee/examples", 1))
PY
expect 1 "control: a discovering lane that no longer reads the dispositions file is caught" "does not read go-module-dispositions.tsv"

# 8. A `find` inside an echo string with the TSV name in a trailing comment is
#    prose, not a lane (round-1 finding).
seed; python3 - "$T_WF" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
t = t.replace("find ee/platform -name go.mod", "true -name go.mod", 1)   # the real lane no longer discovers
plant = """
  plant-echo-find:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "find ee/platform -name go.mod" # go-module-dispositions.tsv
          for m in x; do (cd "$m" && go test ./...); done
"""
p.write_text(t.replace("\n  test-summary:", plant + "\n  test-summary:", 1))
PY
expect 1 "control: a find inside an echo string with the TSV name in a trailing comment is not a discovering lane" "runs in NO job"

# 9. A covered-by job that merely ENTERS the module (cd + ls) does not run it.
seed; python3 - "$T_WF" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
p.write_text(t.replace("cd ee/platform/customer-portal\n          go test -tags enterprise -count=1 -p 4 ./... -timeout 15m", "cd ee/platform/customer-portal\n          ls", 1))
PY
expect 1 "control: a covered-by job whose cd is followed by no go test/vet is caught" "no code line in that job does"

# 10. A discovering lane dropped from test-summary's needs is caught.
seed; python3 - "$T_WF" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
p.write_text(t.replace("unit-tests-ee-modules, unit-tests-example-modules,", "unit-tests-ee-modules,"))
PY
expect 1 "control: a discovering lane that no longer gates test-summary is caught" "not in test-summary's needs"

# 11. A module listed twice, and an excluded row that names no issue.
seed; printf 'examples/hello-world/go\texcluded\tsee #3699\nexamples/hello-world/go\texcluded\tsee #3699 again\n' >> "$T_TSV"
expect 1 "control: a module listed twice is refused" "is listed twice"
seed; printf 'examples/hello-world/go\texcluded\tit is broken\n' >> "$T_TSV"
expect 1 "control: an excluded row that names no tracking issue is refused" "must name the issue"

# 12. A workflow the parser rejects is an instrument failure, never a clean tree.
seed; printf 'jobs:\n  broken: [\n' > "$T_WF"
expect 3 "control: a workflow the YAML scanner rejects is an instrument failure (rc 3), not clean" "INSTRUMENT"

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
