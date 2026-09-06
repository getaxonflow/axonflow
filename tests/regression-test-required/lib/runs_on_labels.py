#!/usr/bin/env python3
"""Resolve a workflow job's `runs-on` to the labels it selects, per repository.

WHY THIS EXISTS. The self-hosted fleet is registered on
`getaxonflow/axonflow-enterprise` only. The community mirror
(`getaxonflow/axonflow`) has ZERO registered runners, and the sync copies
workflow files verbatim — so a job pinned `[self-hosted, linux, x64, axonflow]`
in this repository becomes a job on the mirror that can never be scheduled. It
does not fail: it QUEUES, forever, and `Lint Summary` and `Test Summary` are
required checks over there, so the community release blocks on a check that
will never report.

The fix is a repository-conditional `runs-on`, which makes the value an
EXPRESSION STRING rather than a list. Every census that asked
`isinstance(runs_on, list) and 'self-hosted' in runs_on` would then read zero
fleet jobs and pass by seeing nothing — so the guards resolve through here
instead, and get the same counts they had before.

ONE RESOLVER FOR BOTH QUESTIONS, deliberately: "is this on the fleet?" (asked
of this repository) and "can the mirror schedule this?" (asked of the mirror)
are the same function with a different repository argument. Two separately
written matchers is how a census and its control drift apart.
"""
import json
import os
import re

ENTERPRISE = "getaxonflow/axonflow-enterprise"
MIRROR = "getaxonflow/axonflow"

# The one supported conditional shape. Strict on purpose: an expression this
# cannot parse resolves to a sentinel that every caller treats as unsafe,
# rather than to something that looks hosted and quietly passes.
_COND = re.compile(
    r"^\$\{\{\s*github\.repository\s*==\s*'([^']+)'\s*"
    r"&&\s*fromJSON\(\s*'(\[.*?\])'\s*\)\s*"
    r"\|\|\s*'([^']+)'\s*\}\}$",
    re.S,
)

UNPARSEABLE = "<unparseable-runs-on-expression>"


def labels_for(runs_on, repository=ENTERPRISE):
    """The set of runner labels `runs-on` selects when evaluated in `repository`."""
    if runs_on is None:
        return set()
    if isinstance(runs_on, list):
        return {str(x) for x in runs_on}
    s = str(runs_on).strip()
    if "${{" not in s:
        return {s}
    m = _COND.match(s)
    if not m:
        return {UNPARSEABLE}
    repo_true, json_true, false_label = m.groups()
    if repository == repo_true:
        try:
            return {str(x) for x in json.loads(json_true)}
        except Exception:
            return {UNPARSEABLE}
    return {false_label}


def is_fleet(runs_on, repository=ENTERPRISE):
    """True when this job would land on the self-hosted fleet in `repository`."""
    return "self-hosted" in labels_for(runs_on, repository)


def schedulable_on_mirror(runs_on):
    """False when the mirror could never schedule this job.

    The mirror has no self-hosted runners, so a self-hosted label there is a
    job that queues forever. An expression this module cannot parse is also
    False: an unrecognised shape is exactly the case where a wrong `True`
    would reintroduce the outage this guard exists to prevent.
    """
    labels = labels_for(runs_on, MIRROR)
    return "self-hosted" not in labels and UNPARSEABLE not in labels


def conditional(labels=("self-hosted", "linux", "x64", "axonflow"),
                otherwise="ubuntu-latest", repository=ENTERPRISE):
    """The canonical expression, so producers and parsers cannot disagree."""
    return ("${{ github.repository == '%s' && fromJSON('%s') || '%s' }}"
            % (repository, json.dumps(list(labels), separators=(",", ":")), otherwise))


# ---------------------------------------------------------------------------
# WHICH TREE AM I IN? A fleet census is meaningless on the community mirror.
# ---------------------------------------------------------------------------
# The mirror has no fleet, and it carries only ~21 of this repository's ~160
# workflow files, so a census calibrated on the enterprise tree reads a small
# number there and trips its anti-vacuity floor on a tree that is CORRECT.
#
# Both fleet guards already failed that way on a staged mirror before the
# repository-conditional runs-on existed. Nobody saw it, because the mirror's
# own `run-regression-suite` was one of the jobs QUEUED FOREVER for want of a
# self-hosted runner - so making those jobs schedulable would have converted
# seven queued checks into a red REQUIRED check, and the community release
# would still have been blocked.
#
# Keyed on a POSITIVE marker of the enterprise tree, never on a count: `ee/`
# is excluded by the sync by design, so its absence identifies the mirror
# exactly. "The census looks small" is the vacuity hole itself and must never
# be the test.
def is_enterprise_tree(root="."):
    """True in this repository, False in the community mirror's staged copy."""
    return os.path.isdir(os.path.join(root, "ee"))
