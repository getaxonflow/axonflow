#!/usr/bin/env python3
"""Decide whether one suite's inputs changed in a merge-queue entry.

WHY. A merge-queue build used to run all 75 stack-booting suites: 742
job-minutes, ~93 wall-minutes on 8 runner slots, past both `suite-gate`'s
deadline and the ruleset's 60-minute `check_response_timeout_minutes`. That
left no working configuration - advisory meant a red suite merged, required
meant every entry timed out. `merge_group` takes no `paths:` filter, so the
scoping has to happen inside the workflow, which is what this does. It
restores exactly the guard the `pull_request: paths:` filters used to apply,
against the diff the queue entry actually contains.

The path lists come from `.github/nightly-suite-paths.yml`, the same manifest
the nightly dispatcher reads - one definition, two consumers, so a suite
cannot be scoped one way in the queue and another way overnight.

FAIL-OPEN IS THE SAFE DIRECTION HERE, and it is deliberate: anything this
cannot decide - no manifest entry, an unreadable manifest, a diff that will
not compute - returns `true` and the suite RUNS. The cost of a wrong `true`
is minutes; the cost of a wrong `false` is an untested merge.

Usage: suite-relevant.py <suite-filename> <base-sha> <head-sha>
Prints `relevant=true|false` plus a human reason, and writes the same to
GITHUB_OUTPUT when present.
"""
import os
import re
import subprocess
import sys
import uuid

import yaml

MANIFEST = ".github/nightly-suite-paths.yml"


def glob_to_regex(pattern: str) -> re.Pattern:
    """GitHub `paths:` glob -> anchored regex. Kept byte-identical in intent to
    nightly-e2e-dispatch.py's; `test_suite_relevant_matches_dispatcher` pins
    the two against each other so they cannot drift."""
    out = []
    i = 0
    if pattern.startswith("**/"):
        out.append("(?:.*/)?")
        i = 3
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            if i < len(pattern) and pattern[i] == "/":
                out[-1] = "(?:.*/)?"
                i += 1
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def emit(relevant: bool, reason: str) -> int:
    """Write the decision to GITHUB_OUTPUT, never malformed.

    THE BUG THIS EXISTS TO PREVENT, reproduced before it shipped. `reason`
    can carry a newline - a failing `git diff` puts "fatal: ambiguous
    argument ...\nUse '--' to separate" into it - and a bare
    `reason=<two lines>` writes a second line with no `key=value` shape.
    The runner rejects a malformed GITHUB_OUTPUT and ERRORS THE STEP, which
    turns this function's whole purpose inside out: the fail-OPEN path,
    written so an undecidable input still runs the suite, would instead fail
    CLOSED and the suite would not run at all.

    So the reason is collapsed to a single line AND written with the
    delimiter form, which is what GitHub documents for values whose content
    is not controlled. Either alone would do; both, because this is the path
    that must not break.
    """
    val = "true" if relevant else "false"
    one_line = " ".join(str(reason).split())
    print(f"relevant={val}  ({one_line})")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        delim = f"EOF_{uuid.uuid4().hex}"
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"relevant={val}\n")
            fh.write(f"reason<<{delim}\n{one_line}\n{delim}\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"- **{'RUN' if relevant else 'skip'}** — {one_line}\n")
    return 0


def main(argv):
    if len(argv) != 4:
        return emit(True, "wrong argument count; failing open")
    suite, base, head = argv[1], argv[2], argv[3]

    if not base or not head:
        return emit(True, f"no diff range (base={base!r} head={head!r}); failing open")

    try:
        with open(MANIFEST, encoding="utf-8") as fh:
            man = yaml.safe_load(fh) or {}
    except Exception as exc:                                  # noqa: BLE001
        return emit(True, f"manifest unreadable ({exc}); failing open")

    if suite in (man.get("unconditional") or {}):
        return emit(True, "listed unconditional in the manifest")
    paths = (man.get("suites") or {}).get(suite)
    if not paths:
        return emit(True, "no manifest entry, so its inputs are unknown; failing open")

    res = subprocess.run(["git", "diff", "--name-only", f"{base}...{head}"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        return emit(True, f"git diff failed ({res.stderr.strip()[:120]}); failing open")
    changed = [l for l in res.stdout.splitlines() if l]
    if not changed:
        return emit(False, f"no files changed between {base[:9]} and {head[:9]}")

    regexes = [(p, glob_to_regex(p)) for p in paths if not str(p).startswith("!")]
    for f in changed:
        for pattern, rx in regexes:
            if rx.match(f):
                return emit(True, f"{f} matches {pattern}")
    return emit(False, f"none of {len(changed)} changed files match its "
                       f"{len(regexes)} declared paths")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
