#!/usr/bin/env python3
"""Fail when a workflow on the STAGED community mirror depends on a self-hosted
runner fleet the mirror has not got.

There are TWO ways to depend on the fleet and this checks both.

1. RUNNING ON IT. Measured on mirror PR getaxonflow/axonflow#485: seven checks
   queued for twenty minutes with no runner able to accept them.
   `getaxonflow/axonflow` has ZERO registered runners, and the sync copies
   workflow files verbatim, so a job pinned `[self-hosted, linux, x64,
   axonflow]` here becomes a job over there that does not fail - it QUEUES
   FOREVER. `Lint Summary` and `Test Summary` are required checks on the
   mirror, so the community release blocks on a check that can never report,
   and nothing in the enterprise repository's own CI notices.

   That is the shape worth naming: **the failure is not red, it is absent.** A
   guard that only looks for failures cannot see it, which is why this one
   looks at what the staged tree ASKS FOR rather than at any result.

2. ASKING ABOUT IT. `runner-fleet-health.yml` runs on `ubuntu-latest` - it has
   to, so that it can still report when the fleet is down - and so rule 1 says
   yes about it, correctly and uselessly. What it actually needs is the fleet
   INVENTORY, `GET /repos/{repo}/actions/runners`. On the mirror that is a
   403: the mirror's GITHUB_TOKEN cannot read the runner list. And even with
   access the answer would be "zero online", which is the mirror working as
   designed. It had been red on the PUBLIC repository every 30 minutes -
   23 of the last 30 failed runs there - and blocked nothing, which is exactly
   why it survived. Same verdict as `self-hosted-canary.yml`: a fleet monitor
   for a fleet that does not exist is worse than absent, so exclude it from
   the sync rather than condition it.

   The rule is stated over the workflow's EXECUTABLE content, read off the
   parsed YAML, never over the file text: a text rule is both satisfied and
   tripped by a comment about the endpoint, and this repository has paid for
   that shape in both directions.

Usage:  check-mirror-runner-labels.py <staged-mirror-root>
Exit 0 when every staged workflow is servable by the mirror; 1 otherwise.
"""
import glob
import io
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tests", "regression-test-required", "lib"))
from runs_on_labels import labels_for, schedulable_on_mirror, MIRROR  # noqa: E402

# The self-hosted runner INVENTORY, named by the two ways a workflow reaches
# it: the REST path (`gh api`, `curl`, `actions/github-script` with a raw
# route) and the Octokit method name that `actions/github-script` exposes.
# Both are API identifiers rather than English, so neither can be satisfied by
# a sentence that happens to be about runners.
#
# WHAT THIS RULE DOES NOT SEE, stated here rather than left to be discovered.
# It matches a LITERAL token inside the workflow's own executable strings, so
# three indirections defeat it:
#
#   1. an endpoint assembled at run time (`gh api "$ENDPOINT"`, or a path built
#      by concatenation);
#   2. a `run:` step that invokes a script in the repository which makes the
#      call - the script is not in the workflow document;
#   3. a composite action or a reusable workflow that makes the call in ITS OWN
#      body (the caller's `uses:`/`with:` IS read - see
#      _JOB_LEVEL_EXECUTABLE_KEYS - but the callee's steps are another file).
#
# The alternative - following every invoked script and action - is a call graph,
# and a guard that needs one is a guard nobody trusts. What is bounded here is
# the shape that actually shipped, twice: a `gh api`/`github-script` line
# written directly into the workflow. A reviewer adding a fleet monitor by any
# of the three routes above still has to reason about the mirror, and the sync's
# header entry is where that reasoning goes.
FLEET_INVENTORY_CALLS = ("actions/runners", "listSelfHostedRunners")

# Where a runner would actually execute or receive a string. `name:` and `if:`
# are deliberately NOT read: a step named after the endpoint calls nothing, and
# a guard that reddens on a label is the text-matching failure one layer along.
_EXECUTABLE_KEYS = ("run", "uses", "with", "env")

# A REUSABLE-WORKFLOW CALLER JOB HAS NO STEPS. `jobs.<id>.uses` with
# `jobs.<id>.with` is a whole job expressed at job level, so a scan that only
# walked `steps` skipped it entirely - proved with a fixture that smuggled
# `endpoint: /repos/x/actions/runners` past this checker through a caller job's
# `with:`. Unlike the three indirections named above, this one needs no call
# graph to see: the value is in the document.
_JOB_LEVEL_EXECUTABLE_KEYS = ("uses", "with")


def _scalars(node):
    """Every scalar under `node`, whatever the nesting."""
    if isinstance(node, dict):
        for v in node.values():
            for s in _scalars(v):
                yield s
    elif isinstance(node, (list, tuple)):
        for v in node:
            for s in _scalars(v):
                yield s
    elif node is not None:
        yield str(node)


def fleet_inventory_calls(doc):
    """[(job, step-label, matched-token)] for every call to the runner inventory.

    Read off the parsed document, so comments are excluded by construction
    rather than by a second rule someone has to maintain.
    """
    hits = []
    for jn, j in (doc.get("jobs") or {}).items():
        if not isinstance(j, dict):
            continue
        scopes = [
            ("job env", j.get("env")),
            ("job-level uses/with (a reusable-workflow caller has no steps)",
             {k: j.get(k) for k in _JOB_LEVEL_EXECUTABLE_KEYS if k in j}),
        ]
        steps = j.get("steps") if isinstance(j.get("steps"), list) else []
        for i, st in enumerate(steps):
            if not isinstance(st, dict):
                continue
            label = st.get("name") if isinstance(st.get("name"), str) else "step %d" % (i + 1)
            scopes.append((label, {k: st.get(k) for k in _EXECUTABLE_KEYS if k in st}))
        for label, scope in scopes:
            if scope is None:
                continue
            text = "\n".join(_scalars(scope))
            for token in FLEET_INVENTORY_CALLS:
                if token in text:
                    hits.append((jn, label, token))
    # The workflow-level env is one scope, not one per job.
    top = doc.get("env")
    if top is not None:
        text = "\n".join(_scalars(top))
        for token in FLEET_INVENTORY_CALLS:
            if token in text:
                hits.append(("<workflow env>", "env", token))
    return hits


def main():
    if len(sys.argv) != 2:
        print("usage: check-mirror-runner-labels.py <staged-mirror-root>", file=sys.stderr)
        return 2
    root = sys.argv[1]
    # BOTH EXTENSIONS. GitHub honours `.yaml` as well as `.yml`, so a glob of
    # `*.yml` alone would miss such a workflow SILENTLY - the count would simply
    # be smaller and every assertion would pass. There is no `.yaml` workflow in
    # this tree today; that is the reason to fix it now rather than after one
    # arrives.
    wf = sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml"))
                + glob.glob(os.path.join(root, ".github/workflows/*.yaml")))
    if not wf:
        print("ERROR: no workflows in the staged copy at %s; the sync chain did not "
              "run, so this check would pass by examining nothing" % root, file=sys.stderr)
        return 1

    total, conditional, bad, asks = 0, 0, [], []
    for f in wf:
        try:
            d = yaml.safe_load(io.open(f, encoding="utf-8"))
        except Exception as exc:
            print("ERROR: %s does not parse on the staged copy (%s)"
                  % (os.path.basename(f), str(exc)[:80]), file=sys.stderr)
            return 1
        if not isinstance(d, dict):
            continue
        for jn, j in (d.get("jobs") or {}).items():
            if not isinstance(j, dict):
                continue
            total += 1
            ro = j.get("runs-on")
            if "${{" in str(ro):
                conditional += 1
            if not schedulable_on_mirror(ro):
                bad.append((os.path.basename(f), jn, sorted(labels_for(ro, MIRROR))))
        for jn, label, token in fleet_inventory_calls(d):
            asks.append((os.path.basename(f), jn, label, token))

    print("  staged mirror: %d job(s), %d repository-conditional" % (total, conditional))
    if not bad and not asks:
        print("  ok: every staged job selects a runner the mirror can provide, and")
        print("      no staged workflow reads the self-hosted runner inventory")
        return 0

    if asks:
        print("")
        print("FAIL: %d staged step(s) read the self-hosted runner inventory:" % len(asks))
        for f, jn, label, token in asks:
            print("  %s:%s / %s  ->  %s" % (f, jn, label, token))
        print("")
        print("The mirror has no self-hosted fleet AND its GITHUB_TOKEN cannot read")
        print("the runner list: `gh: Resource not accessible by integration (HTTP 403)`.")
        print("So this cannot pass there, and if it could its verdict would be \"zero")
        print("online\" - the mirror working as designed. Scheduled workflows block no")
        print("PR, so it stays red on a PUBLIC repository indefinitely.")
        print("")
        print("Exclude the workflow in sync-community-repo.yml with its reason, on the")
        print("self-hosted-canary.yml precedent. Do NOT make it repository-conditional:")
        print("a fleet monitor that skips itself on the only repository it can run on")
        print("is a monitor that reports nothing.")

    if not bad:
        return 1

    # TWO CAUSES, TWO REMEDIES, AND THEY MUST NOT SHARE A MESSAGE. A job is
    # unservable either because it ASKS for the fleet, or because its `runs-on`
    # is an expression this checker cannot classify and the unknown case fails
    # closed. The second is often a perfectly hosted job - build.yml's
    # `${{ matrix.arch == 'arm64' && 'ubuntu-24.04-arm' || 'ubuntu-latest' }}`
    # selects two GitHub-hosted runners and neither is self-hosted - so telling
    # its author to exclude the workflow from the mirror is telling them to do
    # the wrong thing, with a guard's authority behind it. A guard that fails is
    # a guard; a guard that confidently prescribes the wrong fix gets obeyed.
    fleet = [(f, jn, ls) for f, jn, ls in bad if "self-hosted" in ls]
    opaque = [(f, jn, ls) for f, jn, ls in bad if "self-hosted" not in ls]

    if opaque:
        print("")
        print("FAIL: %d staged job(s) have a `runs-on` this checker cannot classify:" % len(opaque))
        for f, jn, labels in opaque:
            print("  %s:%s  ->  %s" % (f, jn, labels))
        print("")
        print("These are NOT necessarily fleet jobs, and the remedy is NOT to exclude")
        print("the workflow. An unrecognised expression fails closed because an")
        print("unrecognised shape is where a wrong pass reintroduces the outage - but")
        print("the expression may select hosted runners perfectly well (a matrix")
        print("fan-out over `arch`, for instance, is not a fleet pin).")
        print("")
        print("Fix it by teaching the shared resolver the shape, in")
        print("tests/regression-test-required/lib/runs_on_labels.py (_COND), or by")
        print("rewriting the expression into the repository-conditional form. Exclude")
        print("the workflow from the sync ONLY if it really does depend on the fleet.")

    if not fleet:
        return 1

    print("")
    print("FAIL: %d staged job(s) ask for a runner the mirror has not got:" % len(fleet))
    for f, jn, labels in fleet:
        print("  %s:%s  ->  %s" % (f, jn, labels))
    print("")
    print("The mirror has ZERO self-hosted runners, so these do not fail there -")
    print("they QUEUE FOREVER, and Lint Summary and Test Summary are required")
    print("checks on the mirror. Either exclude the workflow from the sync in")
    print("sync-community-repo.yml with its reason, or select the runner by")
    print("repository:")
    print("")
    print("  runs-on: ${{ github.repository == 'getaxonflow/axonflow-enterprise'")
    print("            && fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"axonflow\"]')")
    print("            || 'ubuntu-latest' }}")
    print("")
    print("An expression this checker cannot parse also fails, deliberately: an")
    print("unrecognised shape is exactly where a wrong pass reintroduces the outage.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
