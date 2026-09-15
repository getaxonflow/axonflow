#!/usr/bin/env bash
# fleet_jobs_never_sparse_checkout_the_workspace_test.sh - no job that runs on
# the self-hosted fleet sparse-checks-out the shared workspace (#4182).
#
# A fleet slot keeps its workspace between jobs. A sparse checkout into it
# leaves core.sparseCheckout=true, a skip-worktree index and
# .git/info/sparse-checkout behind, and on the host's git (2.43) the next
# job's actions/checkout does not undo them: its full checkout fails with
# "Path ... not uptodate; will not remove from working tree", or yields a tree
# with most of the repository missing. Measured on the fleet on 2026-09-13,
# where runner-fleet-health.yml's probe job had left exactly that state.
#
# THE RULE: an actions/checkout step with `sparse-checkout` in a job whose
# `runs-on` names `self-hosted` (a list, a string, or an expression that can
# select it) must check out into its own `path:`, never the workspace itself.
# On a GitHub-hosted runner every job gets a fresh machine, so it may not.
#
# The checker runs against planted workflows first, then against the tree. On
# a community checkout it skips: test.yml is not mirrored, and the mirror has
# no fleet.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ ! -f "$REPO_ROOT/.github/workflows/test.yml" ]; then
  echo "SKIP: community checkout; there is no fleet here and no enterprise workflow set to check"
  exit 0
fi

python3 - "$REPO_ROOT" <<'PY'
import glob
import os
import sys

import yaml

ROOT = sys.argv[1]
WORKSPACE_PATHS = {"", ".", "./", "${{ github.workspace }}"}


def on_the_fleet(job):
    return "self-hosted" in str(job.get("runs-on", ""))


def problems(doc, name):
    out, fleet_jobs = [], 0
    for jn, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict) or not on_the_fleet(job):
            continue
        fleet_jobs += 1
        for st in job.get("steps") or []:
            if not isinstance(st, dict) or not str(st.get("uses", "")).startswith("actions/checkout"):
                continue
            w = st.get("with") or {}
            if w.get("sparse-checkout") is None:
                continue
            path = str(w.get("path") or "").strip()
            if path in WORKSPACE_PATHS or path.rstrip("/") == "${{ github.workspace }}":
                out.append(f"{name}:{jn}: a sparse checkout into the shared workspace on the fleet (step {st.get('name', st.get('uses'))!r}); give it its own path:")
    return out, fleet_jobs


def wf(runs_on, with_block):
    return yaml.safe_load(f"jobs:\n  j:\n    runs-on: {runs_on}\n    steps:\n      - uses: actions/checkout@v6\n        with:\n{with_block}")


SPARSE = "          sparse-checkout: .github/actions/report-main-red\n"
failures = 0
cases = [
    ("a bare sparse checkout on the fleet", wf("[self-hosted, linux, x64, axonflow]", SPARSE), True),
    ("the same with its own path", wf("[self-hosted, linux, x64, axonflow]", SPARSE + "          path: probe\n"), False),
    ("a path that is the workspace itself", wf("[self-hosted, linux, x64, axonflow]", SPARSE + "          path: .\n"), True),
    ("a sparse checkout on a hosted runner", wf("ubuntu-latest", SPARSE), False),
    ("a runs-on expression that can pick the fleet", wf("\"${{ github.repository == 'x/y' && fromJSON('[\\\"self-hosted\\\"]') || 'ubuntu-latest' }}\"", SPARSE), True),
    ("a full checkout on the fleet", wf("[self-hosted, linux, x64, axonflow]", "          fetch-depth: 1\n"), False),
]
for label, doc, want_bad in cases:
    got, _ = problems(doc, "plant.yml")
    if bool(got) != want_bad:
        failures += 1
        print(f"  FAIL: control: {label}: expected {'a finding' if want_bad else 'none'}, got {got}")
    else:
        print(f"  PASS: control: {label}")

found, fleet = [], 0
paths = sorted(glob.glob(os.path.join(ROOT, ".github/workflows/*.yml")) + glob.glob(os.path.join(ROOT, ".github/workflows/*.yaml")))
for p in paths:
    got, n = problems(yaml.safe_load(open(p)) or {}, os.path.basename(p))
    found += got
    fleet += n
if fleet < 1:
    failures += 1
    print("  FAIL: no job in the tree runs on the fleet; the rule is not reading this tree")
for f in found:
    failures += 1
    print("  FAIL: " + f)
if not found and fleet >= 1:
    print(f"  PASS: none of the {fleet} fleet job(s) in {len(paths)} workflow(s) sparse-checks-out the shared workspace")
sys.exit(1 if failures else 0)
PY
