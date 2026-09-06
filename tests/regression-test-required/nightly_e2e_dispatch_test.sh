#!/usr/bin/env bash
# Regression test for .github/scripts/nightly-e2e-dispatch.py - the ONLY
# routine coverage for the post-merge suite tier.
#
# CONTEXT. The 62 stack-booting suites lost their `pull_request` trigger on
# 2026-09-04 (two opt-in gates had cut nothing: 129 billable minutes per push
# before, 133 after). They now run in the merge queue and from this
# dispatcher. If the dispatcher's selector silently matches nothing, the
# suites have no coverage and nothing is red - which is why the selector is
# keyed on a PROPERTY (boots a stack, no PR trigger, dispatchable) rather than
# on a marker string, and why this test asserts against the real tree too.
#
# WHAT IT PINS:
#   1. Glob semantics match GitHub's `paths:` rules: `**` crosses directories,
#      `*` does not, a leading `**/` also matches the repository root, and a
#      literal path matches only itself.
#   2. Selection on a real git history: a suite fires iff a file matching one
#      of its manifest paths changed between --since and HEAD; a suite with no
#      manifest entry always fires; a workflow WITH a pull_request trigger is
#      never in the set (something else runs it); `--all` fires everything.
#   3. Against the real tree, `--dry-run --all` selects the whole fleet
#      (>= 60, including the portal and SDK suites) and dispatches nothing.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
SCRIPT="$PWD/.github/scripts/nightly-e2e-dispatch.py"

# 1. glob semantics --------------------------------------------------------
python3 - "$SCRIPT" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("d", sys.argv[1])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
cases = [
    ("**/go.mod", "go.mod", True), ("**/go.mod", "ee/go.mod", True), ("**/go.mod", "ee/go.modx", False),
    ("platform/**", "platform/agent/run.go", True), ("platform/**", "platforms/x", False),
    ("platform/agent/run.go", "platform/agent/run.go", True), ("platform/agent/run.go", "platform/agent/run.go.bak", False),
    ("runtime-e2e/lib/*.sh", "runtime-e2e/lib/a.sh", True), ("runtime-e2e/lib/*.sh", "runtime-e2e/lib/x/a.sh", False),
    ("ee/policy-packs/fincrime/**", "ee/policy-packs/fincrime/a/b.rego", True),
    ("a/**/b", "a/b", True), ("a/**/b", "a/x/y/b", True),
]
bad = [(p, f, want) for p, f, want in cases if bool(d.glob_to_regex(p).match(f)) != want]
assert not bad, f"glob mismatches: {bad}"
print(f"ok: {len(cases)} glob cases match GitHub paths semantics")
PY

# 2. selection on a real history -------------------------------------------
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github/workflows" "$tmp/platform/agent" "$tmp/docs"

write_suite() {   # $1 name, $2 run-line
  cat > "$tmp/.github/workflows/$1.yml" <<YML
name: $1
on:
  workflow_dispatch:
  push:
    tags: [v*]
jobs:
  main:
    runs-on: ubuntu-latest
    steps:
      - run: $2
YML
}
write_suite suite-a "bash runtime-e2e/a/test.sh"
write_suite suite-b "bash runtime-e2e/b/test.sh"
write_suite full    "docker compose up -d"
for i in 1 2 3 4 5; do write_suite "pad-$i" "bash runtime-e2e/pad/test.sh"; done

# NOT in the nightly set: it has a pull_request trigger, so something else
# routinely runs it. The selector must never pick it up.
cat > "$tmp/.github/workflows/has-pr-trigger.yml" <<'YML'
name: Has PR trigger
on:
  pull_request:
  workflow_dispatch:
jobs:
  y:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
YML
# NOT in the nightly set: this dispatcher could not reach it.
cat > "$tmp/.github/workflows/no-dispatch.yml" <<'YML'
name: No dispatch
on:
  push:
    tags: [v*]
jobs:
  z:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
YML

# suite-a and suite-b are scoped by the manifest; `full` and the five pads
# have no entry, so they are unconditional.
cat > "$tmp/.github/nightly-suite-paths.yml" <<'YML'
suites:
  suite-a.yml:
    - 'platform/agent/run.go'
    - 'runtime-e2e/a/**'
  suite-b.yml:
    - 'docs/**'
YML

git -C "$tmp" init -q
git -C "$tmp" -c user.name=t -c user.email=t@t commit -q --allow-empty -m base
base=$(git -C "$tmp" rev-parse HEAD)
echo x > "$tmp/platform/agent/run.go"
git -C "$tmp" add -A
git -C "$tmp" -c user.name=t -c user.email=t@t commit -qm "touch run.go"

run() { (cd "$tmp" && python3 "$SCRIPT" --dry-run --workflows-dir .github/workflows --repo-root . "$@" 2>/dev/null); }

out=$(run --since "$base")
grep -q '`suite-a.yml`' <<<"$out" || { echo "FAIL: suite-a not selected after run.go changed"; echo "$out"; exit 1; }
grep -q '^| `suite-b.yml`' <<<"$out" && { echo "FAIL: suite-b selected though docs/ did not change"; echo "$out"; exit 1; }
grep -q '`full.yml` | no paths filter' <<<"$out" || { echo "FAIL: a suite with no manifest entry must always fire"; echo "$out"; exit 1; }
grep -q 'has-pr-trigger' <<<"$out" && { echo "FAIL: a workflow with a pull_request trigger is not in the nightly set"; echo "$out"; exit 1; }
grep -q 'no-dispatch' <<<"$out" && { echo "FAIL: a workflow without workflow_dispatch cannot be dispatched"; echo "$out"; exit 1; }
grep -q 'dispatched: \*\*7\*\*' <<<"$out" || { echo "FAIL: expected 7 (suite-a + full + 5 pads)"; echo "$out"; exit 1; }
echo "ok: selection follows the changed files; PR-triggered and undispatchable workflows are excluded"

out=$(run --all)
grep -q 'dispatched: \*\*8\*\*' <<<"$out" || { echo "FAIL: --all should dispatch all 8 in the set"; echo "$out"; exit 1; }
echo "ok: --all dispatches the whole nightly set"

head=$(git -C "$tmp" rev-parse HEAD)
out=$(run --since "$head")
grep -q 'dispatched: \*\*6\*\*' <<<"$out" || { echo "FAIL: with no changes only the 6 unconditional suites should fire"; echo "$out"; exit 1; }
echo "ok: an unchanged main fires only the unconditional suites"

# 3. the real tree ----------------------------------------------------------
out=$(python3 "$SCRIPT" --dry-run --all 2>/dev/null)
n=$(sed -n 's/.*stack-booting workflows: \*\*\([0-9]*\)\*\*.*/\1/p' <<<"$out")
if [ "${n:-0}" -lt 60 ]; then echo "FAIL: real tree selects only ${n:-0} nightly-set workflows (expected >= 60)"; exit 1; fi
for f in e2e-tests.yml sdk-smoke-tests.yml per-plane-decision-shadow-e2e.yml; do
  grep -q "\`$f\`" <<<"$out" || { echo "FAIL: $f not in the nightly set"; exit 1; }
done
grep -q 'dry-run: gh workflow run' <<<"$out" || { echo "FAIL: dry run did not print the dispatch command"; exit 1; }
echo "ok: real tree - $n nightly-set workflows selected in dry run, nothing dispatched"
