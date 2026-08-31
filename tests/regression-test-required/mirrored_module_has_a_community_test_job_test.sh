#!/usr/bin/env bash
# mirrored_module_has_a_community_test_job_test.sh - #3574
#
# A Go module that MIRRORS to the public community repository but whose only
# test workflow does NOT mirror is a module whose entire test suite lands there
# as files that never execute.
#
# That is exactly what happened to platform/decision. The community sync is
# exclude-based: it excludes `.github/workflows/test.yml` by name and excludes
# nothing under `platform/decision`, so on getaxonflow/axonflow the module is
# present and the workflow that runs it is not. Nothing goes red. The
# conformance corpus, the disposition-ledger guard, the tri-state corpus, the
# mutation proofs, the round-trip property and the authoring gates are simply
# absent from the lane that gates an outside contributor's pull request.
#
# It is a silent-mirror defect of the same class as the //go:build strip, and
# the reason it needs a ratchet rather than a fix is that nothing about adding a
# second module would remind anyone: `go test ./...` from platform/ does not
# descend into a separate module, so a new module is invisible to every existing
# job by construction.
#
# THE RULE: every Go module under platform/ that reaches the community mirror
# must be run by a job in a workflow that ALSO reaches the mirror, and that job
# must gate the mirror's own summary check.
#
# EXTENDED (#3574, second pass). Two more findings of the same class:
#
#   - The ROOT platform module was "covered" by three per-service steps that
#     `cd` into orchestrator/, agent/ and connectors/, and only the last says
#     `./...`. Every other package in that module - all of platform/shared/*
#     including the ADR-065 identity plane, every orchestrator and agent
#     subpackage - ran in NO job in the untagged build. Module discovery cannot
#     see inside a module, so the root module now needs its own lane, and this
#     test asserts that lane exists in the mirrored workflow, selects packages
#     by `go list ./...` rather than by name, and carries its identity canary.
#
#   - "Gates the summary" was checked against `needs:` alone. A job in `needs`
#     that the summary's failure expression never reads is a job whose red
#     stops nothing. Both halves are now asserted: needs AND
#     `needs.<job>.result` in the failure step's `if:`.
#
# Run: bash tests/regression-test-required/mirrored_module_has_a_community_test_job_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SYNC_WORKFLOW="$REPO_ROOT/.github/workflows/sync-community-repo.yml"
COMMUNITY_WORKFLOW="$REPO_ROOT/.github/workflows/test-community.yml"

PASS=0
FAIL=0
ok() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== every mirrored platform module must be executed by the mirrored test workflow ==="

if [ ! -f "$COMMUNITY_WORKFLOW" ]; then
  echo "  FAIL: $COMMUNITY_WORKFLOW not found - this test cannot vacuously pass"
  exit 1
fi

# The sync workflow is EXCLUDED from the mirror, so on a mirror checkout it is
# absent. The exclusion analysis below is therefore enterprise-only; the
# execution assertions that follow run in both trees, which is the half that
# matters on the mirror.
HAVE_SYNC=1
[ -f "$SYNC_WORKFLOW" ] || HAVE_SYNC=0

# Discover the separate Go modules under platform/ rather than listing them.
# A listed module is a module somebody has to remember to add, and the whole
# defect this test exists for is that nobody was reminded.
MODULES="$(find "$REPO_ROOT/platform" -name go.mod -not -path '*/node_modules/*' -print0 |
  xargs -0 -n1 dirname |
  sed "s|^$REPO_ROOT/||" |
  sort)"

if [ -z "$MODULES" ]; then
  echo "  FAIL: no Go modules were found under platform/ - the discovery has stopped working"
  exit 1
fi
ok "discovered $(echo "$MODULES" | wc -l | tr -d ' ') Go module(s) under platform/ (anti-vacuity check)"

# The root platform module is run by `unit-tests` in the community workflow
# under its own per-service steps, which predate this rule and are asserted by
# other gates. This test is about the modules that `go test ./...` from
# platform/ cannot reach.
for MODULE in $MODULES; do
  [ "$MODULE" = "platform" ] && continue

  if [ "$HAVE_SYNC" -eq 1 ]; then
    # Does this module reach the mirror at all? An excluded module needs no
    # community job, and asserting one for it would be wrong rather than
    # merely noisy.
    if grep -qF -- "--exclude='$MODULE/'" "$SYNC_WORKFLOW"; then
      ok "$MODULE is excluded from the community sync, so it needs no community test job"
      continue
    fi
  fi

  # The community workflow must actually run this module. Matching on the
  # `cd <module>` the steps perform, rather than on a job name, because a job
  # name is a label and the `cd` is the thing that decides what is tested.
  if grep -qE "^[[:space:]]+cd $MODULE\$" "$COMMUNITY_WORKFLOW"; then
    ok "$MODULE is executed by $(basename "$COMMUNITY_WORKFLOW")"
  else
    bad "$MODULE mirrors to the community repository and no job in $(basename "$COMMUNITY_WORKFLOW") runs it;"
    echo "        its whole test suite would land on the public repo and never execute (#3574)."
  fi
done

# A job that runs the module and is not wired into the summary is a job whose
# red does not stop anything. The summary is the check the mirror's own ruleset
# requires, so "runs" and "gates" are two different claims and both are needed.
if command -v python3 >/dev/null 2>&1; then
  python3 - "$COMMUNITY_WORKFLOW" <<'PY'
import sys

# A missing tool FAILS this half rather than skipping it. A guard keyed on a
# possibly-absent tool silently fails open on exactly the runner where nobody
# is looking; GitHub runners carry PyYAML, so a failure here means the
# environment changed and the wiring assertion stopped running, which is a
# fact someone must see rather than a pass.
try:
    import yaml
except ImportError:
    print("  FAIL: PyYAML is unavailable; the summary-wiring assertion cannot run, and a guard that cannot run must not pass")
    sys.exit(1)

with open(sys.argv[1]) as fh:
    doc = yaml.safe_load(fh)

jobs = doc.get("jobs", {})
summary = jobs.get("test-summary")
if summary is None:
    print("  FAIL: test-community.yml declares no test-summary job")
    sys.exit(1)

needs = summary.get("needs") or []
if isinstance(needs, str):
    needs = [needs]

# The root-module lane. The three per-service steps reach three packages (and
# the connectors tree); this lane must reach the rest by DERIVATION, not by
# name, so a package added tomorrow is in it by default. What is asserted:
#   - a job whose run steps `cd platform` (the module root, not a package),
#   - selects with `go list ./...`,
#   - names platform/shared/identity as its canary (the package this lane was
#     created for; the job asserts at runtime that it is in the selection).
# The canary is matched in its ASSERTION form on non-comment lines only: the
# job's own comment explains the lane in terms of shared/identity, and a
# marker that matches prose is a marker that survives the deletion of the
# check it stands for.
CANARY = "/platform/shared/identity$'"
def code_lines(script):
    return "\n".join(l for l in script.splitlines() if not l.strip().startswith("#"))
root_lane = None
for name, job in jobs.items():
    scripts = [code_lines(str(s.get("run") or "")) for s in (job.get("steps") or [])]
    if any("cd platform\n" in s and "go list ./..." in s and CANARY in s for s in scripts):
        root_lane = name
        break
if root_lane is None:
    print("  FAIL: no job in test-community.yml tests the ROOT platform module by `go list ./...` from `cd platform` with the shared/identity canary;")
    print("        every platform/shared/*, orchestrator/* and agent/* subpackage would mirror and never execute (#3574)")
    sys.exit(1)
print("  PASS: %s tests the root platform module by derivation (go list ./... with the shared/identity canary)" % root_lane)

# Every job that changes directory into a non-root platform module, plus the
# root-module lane, must gate the summary.
missing = []
for name, job in jobs.items():
    if name == "test-summary":
        continue
    steps = job.get("steps") or []
    runs_a_module = any(
        "cd platform/" in (step.get("run") or "") and "cd platform\n" not in (step.get("run") or "")
        for step in steps
    )
    if not runs_a_module and name != root_lane:
        continue
    if name not in needs:
        missing.append(name)

if missing:
    print("  FAIL: these jobs run platform code and do not gate test-summary: %s" % ", ".join(sorted(missing)))
    sys.exit(1)

# `needs` is half of gating. The other half is the failure expression: the
# summary's "fail if any test failed" step reads `needs.<job>.result` for each
# job it gates on, and a job it never reads can be red without the summary
# noticing. The step is found by shape (an `if:` that reads a needs result
# and compares against 'success'), not by its display name.
fail_steps = [
    s for s in (summary.get("steps") or [])
    if "needs." in str(s.get("if") or "") and "!= 'success'" in str(s.get("if") or "")
]
if not fail_steps:
    print("  FAIL: test-summary has no step whose `if:` reads needs.*.result against 'success'; nothing fails the summary")
    sys.exit(1)
fail_expr = " ".join(str(s.get("if")) for s in fail_steps)
unread = [n for n in needs if ("needs.%s.result" % n) not in fail_expr]
if unread:
    print("  FAIL: these jobs are in test-summary's needs but its failure expression never reads their result: %s" % ", ".join(sorted(unread)))
    print("        A job the expression ignores can be red while the required check goes green.")
    sys.exit(1)

# Anti-vacuity: the loops above must have found something to check.
gating = [n for n in needs if n in jobs]
if len(gating) < 2:
    print("  FAIL: test-summary needs only %d known job(s); the wiring check is not looking at anything" % len(gating))
    sys.exit(1)

print("  PASS: every community job that runs platform code gates test-summary in both needs and the failure expression (%d jobs)" % len(gating))
PY
  if [ $? -eq 0 ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
else
  bad "python3 is unavailable; the summary-wiring assertion cannot run, and a guard that cannot run must not pass"
fi

echo ""
echo "  passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
