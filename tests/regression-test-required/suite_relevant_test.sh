#!/usr/bin/env bash
# Regression test for .github/scripts/suite-relevant.py - what decides whether
# a suite runs in a merge-queue entry.
#
# WHY IT MATTERS MORE THAN THE USUAL SCOPING GUARD. A wrong `true` costs
# minutes. A wrong `false` merges untested code, because after 2026-09-04 the
# merge queue is the ONLY pre-merge run these suites get. So every undecidable
# input must fail OPEN, and that direction is asserted here rather than
# assumed.
#
# WHAT THIS PINS:
#   1. Fail-open on every undecidable input: no manifest entry, unreadable
#      manifest, an `unconditional:` listing, a missing diff range, a git diff
#      that errors, wrong argument count.
#   2. A real decision on a real git history: a changed file matching a
#      declared path returns true; a diff touching nothing declared returns
#      false; an empty diff returns false.
#   3. Its glob semantics are IDENTICAL to nightly-e2e-dispatch.py's. The two
#      read the same manifest, so if they disagreed a suite would be scoped one
#      way in the queue and another way overnight - the duplication class this
#      repository keeps finding.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
REL="$PWD/.github/scripts/suite-relevant.py"
DISP="$PWD/.github/scripts/nightly-e2e-dispatch.py"

# 3. the two glob implementations must agree, checked before anything else so a
#    drift cannot hide behind a passing behavioural case.
python3 - "$REL" "$DISP" <<'PY'
import importlib.util, sys
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
rel, disp = load("rel", sys.argv[1]), load("disp", sys.argv[2])
cases = ["**/go.mod", "platform/**", "platform/agent/run.go", "runtime-e2e/lib/*.sh",
         "ee/policy-packs/fincrime/**", "a/**/b", "docs/**", "*.md", "x?y",
         "runtime-e2e/**/test.sh"]
files = ["go.mod", "ee/go.mod", "platform/agent/run.go", "platforms/x", "docs/a/b.md",
         "runtime-e2e/lib/a.sh", "runtime-e2e/lib/x/a.sh", "a/b", "a/x/y/b", "xy",
         "x1y", "README.md", "runtime-e2e/3363/test.sh", "ee/policy-packs/fincrime/p.rego"]
bad = [(p, f) for p in cases for f in files
       if bool(rel.glob_to_regex(p).match(f)) != bool(disp.glob_to_regex(p).match(f))]
assert not bad, f"glob implementations disagree on: {bad}"
print(f"ok: glob semantics identical to the dispatcher across {len(cases)*len(files)} pairs")
PY

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github/scripts" "$tmp/platform/agent" "$tmp/docs"
cp "$REL" "$tmp/.github/scripts/"
cat > "$tmp/.github/nightly-suite-paths.yml" <<'YML'
suites:
  scoped-suite.yml:
    - 'platform/agent/run.go'
    - 'runtime-e2e/scoped/**'
  docs-suite.yml:
    - 'docs/**'
unconditional:
  always-suite.yml: no filter has ever existed for it
YML
cd "$tmp"
git init -q .
git -c user.name=t -c user.email=t@t commit -q --allow-empty -m base
BASE=$(git rev-parse HEAD)
echo x > platform/agent/run.go
git add -A && git -c user.name=t -c user.email=t@t commit -qm "touch run.go"
HEAD_SHA=$(git rev-parse HEAD)

r() { python3 .github/scripts/suite-relevant.py "$@" 2>/dev/null | head -1; }
expect() { # $1 label, $2 want(true|false), $3.. args
  local label="$1" want="$2"; shift 2
  local out; out=$(r "$@")
  case "$out" in
    relevant=$want*) echo "  ok   $label -> $want" ;;
    *) echo "  FAIL $label: wanted relevant=$want, got: $out"; exit 1 ;;
  esac
}

echo "2. real decisions on a real history"
expect "changed file matches a declared path" true  scoped-suite.yml "$BASE" "$HEAD_SHA"
expect "diff touches nothing this suite declares" false docs-suite.yml "$BASE" "$HEAD_SHA"
expect "empty diff" false scoped-suite.yml "$HEAD_SHA" "$HEAD_SHA"

echo "1. fail-open on everything undecidable"
expect "no manifest entry"        true unlisted-suite.yml "$BASE" "$HEAD_SHA"
expect "listed unconditional"     true always-suite.yml   "$BASE" "$HEAD_SHA"
expect "empty base sha"           true scoped-suite.yml   ""      "$HEAD_SHA"
expect "empty head sha"           true scoped-suite.yml   "$BASE" ""
expect "unresolvable sha"         true scoped-suite.yml   deadbeefdeadbeef "$HEAD_SHA"
expect "wrong argument count"     true scoped-suite.yml
mv .github/nightly-suite-paths.yml .github/manifest.hidden
expect "manifest missing"         true scoped-suite.yml   "$BASE" "$HEAD_SHA"
printf 'suites: [this is not a mapping\n' > .github/nightly-suite-paths.yml
expect "manifest unparseable"     true scoped-suite.yml   "$BASE" "$HEAD_SHA"
mv .github/manifest.hidden .github/nightly-suite-paths.yml

echo "GITHUB_OUTPUT is well-formed on EVERY path, including the failing ones"
# THE DEFECT THIS PINS, reproduced before it shipped. `reason` can carry a
# newline: a failing `git diff` puts "fatal: ambiguous argument ...\nUse '--'
# to separate" into it, and a bare `reason=<two lines>` writes a second line
# with no key=value shape. The runner REJECTS a malformed GITHUB_OUTPUT and
# errors the step - which inverts this script's whole purpose, because the
# fail-OPEN path would then fail CLOSED and the suite would not run at all.
# So every path is parsed here exactly as the runner parses it.
check_output() { # $1 label, $2 expected relevant, $3.. script args
  local label="$1" want="$2"; shift 2
  local of; of=$(mktemp)
  GITHUB_OUTPUT="$of" python3 .github/scripts/suite-relevant.py "$@" >/dev/null 2>&1 || true
  python3 - "$of" "$want" "$label" <<'PY'
import re, sys
txt, want, label = open(sys.argv[1]).read(), sys.argv[2], sys.argv[3]
lines = txt.split('\n'); i = 0; parsed = {}
while i < len(lines):
    l = lines[i]
    if not l:
        i += 1; continue
    m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)<<(\S+)$', l)
    if m:                                    # delimiter form
        k, d = m.groups(); i += 1; buf = []
        while i < len(lines) and lines[i] != d:
            buf.append(lines[i]); i += 1
        if i >= len(lines):
            print(f"  FAIL {label}: unterminated delimiter for {k}"); sys.exit(1)
        parsed[k] = '\n'.join(buf); i += 1; continue
    if '=' in l:                             # key=value form
        k, v = l.split('=', 1); parsed[k] = v; i += 1; continue
    print(f"  FAIL {label}: malformed GITHUB_OUTPUT line {l[:60]!r} - the runner "
          f"would error the step, turning fail-open into fail-CLOSED"); sys.exit(1)
if parsed.get('relevant') != want:
    print(f"  FAIL {label}: relevant={parsed.get('relevant')!r}, wanted {want!r}"); sys.exit(1)
if 'reason' not in parsed:
    print(f"  FAIL {label}: no reason written"); sys.exit(1)
print(f"  ok   {label} -> parses, relevant={want}")
PY
}
# FIRST, the property directly and deterministically: emit() must never write
# a malformed file FOR ANY reason string. Going through the script and hoping
# git phrases its error with a newline inside the first 120 characters makes
# the test depend on git's wording - a mutant reverting emit() to the bare
# `reason=<raw>` form SURVIVED that version of this check.
python3 - "$REL" <<'PY'
import importlib.util, os, re, sys, tempfile
spec = importlib.util.spec_from_file_location("rel", sys.argv[1])
rel = importlib.util.module_from_spec(spec); spec.loader.exec_module(rel)
HOSTILE = [
    "one line",
    "two\nlines",                                  # the git-diff-error shape
    "fatal: ambiguous argument\nUse '--' to separate paths",
    "tab\tand\nnewline",
    "trailing newline\n",
    "\nleading newline",
    "many\n\n\nblank\n\nlines",
    "a value containing EOF and = signs: k=v EOF",
]
def parse(path):
    lines = open(path).read().split('\n'); i = 0; out = {}
    while i < len(lines):
        l = lines[i]
        if not l:
            i += 1; continue
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)<<(\S+)$', l)
        if m:
            k, d = m.groups(); i += 1; buf = []
            while i < len(lines) and lines[i] != d:
                buf.append(lines[i]); i += 1
            if i >= len(lines):
                raise AssertionError(f"unterminated delimiter for {k}")
            out[k] = '\n'.join(buf); i += 1; continue
        if '=' in l:
            k, v = l.split('=', 1); out[k] = v; i += 1; continue
        raise AssertionError(f"malformed GITHUB_OUTPUT line {l[:70]!r} - the runner "
                             f"would error the step, turning fail-open into fail-CLOSED")
    return out
for reason in HOSTILE:
    for relevant in (True, False):
        fd, path = tempfile.mkstemp(); os.close(fd)
        os.environ["GITHUB_OUTPUT"] = path
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        rel.emit(relevant, reason)
        got = parse(path)
        assert got.get("relevant") == ("true" if relevant else "false"), got
        assert "reason" in got and "\n" not in got["reason"], got
        os.unlink(path)
os.environ.pop("GITHUB_OUTPUT", None)
print(f"  ok   emit() well-formed and single-line for {len(HOSTILE)*2} hostile reason/verdict pairs")
PY

check_output "normal true"            true  scoped-suite.yml "$BASE" "$HEAD_SHA"
check_output "normal false"           false docs-suite.yml   "$BASE" "$HEAD_SHA"
# the path that carries a multi-line git error into the reason
check_output "git diff error (newline in reason)" true scoped-suite.yml deadbeefdeadbeefdeadbeef "$HEAD_SHA"
check_output "no manifest entry"      true  unlisted-suite.yml "$BASE" "$HEAD_SHA"
check_output "wrong argument count"   true  scoped-suite.yml

echo "PASS: suite-relevant decides correctly and fails open on every undecidable input"
