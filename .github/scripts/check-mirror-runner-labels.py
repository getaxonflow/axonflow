#!/usr/bin/env python3
"""Fail when a job on the STAGED community mirror asks for a runner the mirror
has not got.

THE OUTAGE THIS EXISTS TO PREVENT, measured on mirror PR
getaxonflow/axonflow#485: seven checks queued for twenty minutes with no runner
able to accept them. `getaxonflow/axonflow` has ZERO registered runners, and
the sync copies workflow files verbatim, so a job pinned
`[self-hosted, linux, x64, axonflow]` here becomes a job over there that does
not fail - it QUEUES FOREVER. `Lint Summary` and `Test Summary` are required
checks on the mirror, so the community release blocks on a check that can never
report, and nothing in the enterprise repository's own CI notices.

That is the shape worth naming: **the failure is not red, it is absent.** A
guard that only looks for failures cannot see it, which is why this one looks
at what the staged tree ASKS FOR rather than at any result.

Usage:  check-mirror-runner-labels.py <staged-mirror-root>
Exit 0 when every staged job is schedulable on the mirror; 1 otherwise.
"""
import glob
import io
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tests", "regression-test-required", "lib"))
from runs_on_labels import labels_for, schedulable_on_mirror, MIRROR  # noqa: E402


def main():
    if len(sys.argv) != 2:
        print("usage: check-mirror-runner-labels.py <staged-mirror-root>", file=sys.stderr)
        return 2
    root = sys.argv[1]
    wf = sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml")))
    if not wf:
        print("ERROR: no workflows in the staged copy at %s; the sync chain did not "
              "run, so this check would pass by examining nothing" % root, file=sys.stderr)
        return 1

    total, conditional, bad = 0, 0, []
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

    print("  staged mirror: %d job(s), %d repository-conditional" % (total, conditional))
    if not bad:
        print("  ok: every staged job selects a runner the mirror can provide")
        return 0

    print("")
    print("FAIL: %d staged job(s) ask for a runner the mirror has not got:" % len(bad))
    for f, jn, labels in bad:
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
