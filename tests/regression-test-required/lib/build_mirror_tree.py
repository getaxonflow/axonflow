#!/usr/bin/env python3
"""Build a simulated community-mirror tree by applying the sync workflow's
exclusion list to a real checkout.

WHY THIS IS NOT A LIST IN THE TEST. `sync-community-repo.yml` is the authority
on what reaches the mirror, and it uses at least four shapes of `--exclude=`:

    technical-docs/                        a whole directory
    docs/reference/secrets-logging-checklist.md    a single FILE
    examples/circuit-breaker/              a NESTED directory
    .github/workflows/build-*.yml          a GLOB
    /scripts/*                             anchored, one level only

A first version of the simulation matched `--exclude='<dir>/'` and nothing else.
That is 14 of ~130 rules, and the miss was live: `docs/README.md` links
`./reference/secrets-logging-checklist.md`, which the workflow excludes by
filename. `GET /repos/getaxonflow/axonflow/contents/docs/reference/secrets-logging-checklist.md`
returns 404 while `docs/README.md` returns 200 - a dead link on the published
mirror that the simulation reported green.

A simulation with its own idea of the rules is a simulation of something else.

Usage: build_mirror_tree.py <repo-root> <dest>
Prints the number of rules applied and the number of paths removed.
"""
from __future__ import annotations

import fnmatch
import os
import re
import shutil
import sys
from pathlib import Path

repo = Path(sys.argv[1]).resolve()
dest = Path(sys.argv[2]).resolve()
workflow = repo / ".github/workflows/sync-community-repo.yml"

rules = sorted(set(re.findall(r"--exclude='([^']*)'", workflow.read_text())))
if len(rules) < 50:
    print(f"VACUOUS: parsed only {len(rules)} exclude rules from {workflow.name}; "
          "the workflow has ~130. The simulation would model almost nothing.")
    sys.exit(2)


def excluded(rel: str, is_dir: bool) -> bool:
    """Does any rule exclude this repo-relative path?

    rsync semantics, kept deliberately simple and CONSERVATIVE - when in doubt
    this returns True, so the simulation removes more than the mirror does and
    can only over-report a dead link, never hide one.
    """
    candidates = [rel, "/" + rel]
    if is_dir:
        candidates += [rel + "/", "/" + rel + "/"]
    for rule in rules:
        for cand in candidates:
            if fnmatch.fnmatch(cand, rule) or fnmatch.fnmatch(cand, rule.rstrip("/")):
                return True
            # A directory rule removes everything beneath it.
            if rule.endswith("/") and cand.startswith(rule.lstrip("/")):
                return True
            if rule.endswith("/*") and cand.startswith(rule[:-1].lstrip("/")):
                return True
        # A bare basename rule (`CLAUDE.md*`, `*.pem`) matches at any depth.
        if "/" not in rule and fnmatch.fnmatch(os.path.basename(rel), rule):
            return True
    return False


if dest.exists():
    shutil.rmtree(dest)
dest.mkdir(parents=True)

removed = 0
for entry in sorted(repo.iterdir()):
    name = entry.name
    if name == ".git":
        continue
    if excluded(name, entry.is_dir()):
        removed += 1
        continue
    # docs/ is the tree under test, so it is COPIED and pruned. Everything else
    # is symlinked: a link may legitimately point into it, and copying the whole
    # repository per run is not worth the seconds.
    if name == "docs":
        shutil.copytree(entry, dest / name, symlinks=True)
    else:
        (dest / name).symlink_to(entry)

for path in sorted((dest / "docs").rglob("*"), reverse=True):
    if not path.exists():
        continue
    rel = path.relative_to(dest).as_posix()
    if excluded(rel, path.is_dir()):
        removed += 1
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink()

print(f"applied {len(rules)} exclude rules; removed {removed} top-level entries "
      f"and paths under docs/")
