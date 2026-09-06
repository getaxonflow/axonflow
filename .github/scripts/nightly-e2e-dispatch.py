#!/usr/bin/env python3
"""Dispatch the post-merge suite tier against main, once a day, by what changed.

WHY THIS EXISTS. Sixty-three suites each boot a compose stack (~10 billable
minutes). Until 2026-09-03 they ran on every push of every PR whose diff
touched their `paths:` - 56% of a 17,800-minute day. The 2026-09-03 fix made
them opt-in behind a `ci:e2e` label, and it cut NOTHING: every PR applied the
label within seconds of opening, and per-push cost was 129 minutes before and
133 after. Opt-in cannot restrain spend when the person choosing does not pay
for it. So on 2026-09-04 the `pull_request` trigger was removed from all of
them outright - no label opens what has no PR path - and this dispatcher is
now the ONLY routine coverage they get: every night it runs, against main,
exactly the suites whose `paths:` filter matched a file that changed on main
since the previous run.

SELECTION IS BY A PROPERTY, NOT A MARKER OR A LIST. A workflow is in the
nightly set iff it (a) boots a stack - some `run:` step invokes compose or a
`runtime-e2e/` script - and (b) has no `pull_request` trigger, so nothing else
routinely runs it, and (c) is reachable by `workflow_dispatch`. The previous
version keyed on the literal `'ci:e2e'` in a job `if:`; deleting the label
gates would have silently emptied the nightly set, which is exactly the
disarm-by-improvement class. A suite that gains a PR trigger drops out of the
nightly (and `no_pr_trigger_for_stack_booting_suites_test.sh` refuses it); a
new suite with no PR trigger joins with no edit here.

Usage:
  nightly-e2e-dispatch.py --since <sha> [--ref main] [--all] [--dry-run]
                          [--workflows-dir .github/workflows] [--repo-root .]
Exit status is non-zero if any dispatch failed; a dry run only prints.
"""
import argparse
import glob
import os
import re
import subprocess
import sys

import yaml

BOOTS = re.compile(r"docker[ -]compose|runtime-e2e/\S+\.(sh|py)")


def glob_to_regex(pattern: str) -> re.Pattern:
    """GitHub `paths:` glob -> anchored regex.

    `**` matches any run of characters including `/`; `*` and `?` stop at `/`.
    A leading `**/` also matches the repository root (so `**/go.mod` matches
    `go.mod`), which is how GitHub documents it.
    """
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
                # `a/**/b` must also match `a/b`
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


MANIFEST = ".github/nightly-suite-paths.yml"


def load_manifest(workflows_dir):
    """filename -> paths list, from .github/nightly-suite-paths.yml.

    These lists ARE the `pull_request: paths:` filters the suites used to
    carry; the trigger was removed (2026-09-04) and the filters moved here so
    this dispatcher keeps running each suite only when its own inputs change.
    A suite absent from the manifest is dispatched unconditionally, which is
    the safe direction; the regression guard requires an entry for every suite
    in the nightly set so that cannot happen silently.
    """
    path = os.path.join(os.path.dirname(workflows_dir.rstrip("/")), "nightly-suite-paths.yml")
    if not os.path.exists(path):
        path = MANIFEST
    if not os.path.exists(path):
        # No manifest: every suite becomes unconditional. That is the safe
        # direction, and on the real tree the regression guard refuses it; a
        # synthetic tree (the dispatcher's own test) has no manifest by design.
        print(f"WARNING: no path manifest at {path}; every suite will be dispatched",
              file=sys.stderr)
        return {}
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    return {k: [p for p in v if not str(p).startswith("!")]
            for k, v in (doc.get("suites") or {}).items()}


def boots_a_stack(doc) -> bool:
    """Some `run:` step invokes compose or a runtime-e2e suite script."""
    for job in (doc.get("jobs") or {}).values():
        for step in ((job or {}).get("steps") or []):
            if BOOTS.search(str((step or {}).get("run", ""))):
                return True
    return False


def in_nightly_set(doc) -> bool:
    on = doc.get("on") or doc.get(True) or {}
    if not isinstance(on, dict):
        return False
    if "pull_request" in on:
        return False          # something else routinely runs it
    if "workflow_dispatch" not in on:
        return False          # this dispatcher could not reach it
    return boots_a_stack(doc)


def gated_workflows(workflows_dir):
    manifest = load_manifest(workflows_dir)
    out = []
    for f in sorted(glob.glob(os.path.join(workflows_dir, "*.yml"))):
        with open(f, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict) or not in_nightly_set(doc):
            continue
        base = os.path.basename(f)
        out.append((base, doc.get("name") or base, manifest.get(base)))
    return out


def changed_files(repo_root, since, head="HEAD"):
    res = subprocess.run(
        ["git", "-C", repo_root, "diff", "--name-only", f"{since}..{head}"],
        check=True, capture_output=True, text=True,
    )
    return [l for l in res.stdout.splitlines() if l]


def select(workflows, changed, run_all=False):
    """Yield (file, name, reason) for every workflow to dispatch."""
    for f, name, paths in workflows:
        if run_all:
            yield f, name, "forced (--all)"
        elif paths is None:
            yield f, name, "no paths filter - always runs"
        else:
            regs = [glob_to_regex(p) for p in paths]
            hit = next((c for c in changed if any(r.match(c) for r in regs)), None)
            if hit is not None:
                yield f, name, f"changed: {hit}"


def dispatch(f, ref, dry_run):
    cmd = ["gh", "workflow", "run", f, "--ref", ref]
    if dry_run:
        return True, "dry-run: " + " ".join(cmd)
    res = subprocess.run(cmd, capture_output=True, text=True)
    ok = res.returncode == 0
    return ok, (res.stdout or res.stderr).strip()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", help="commit the day's changes are diffed against (required unless --all)")
    ap.add_argument("--ref", default="main")
    ap.add_argument("--all", action="store_true", help="dispatch every gated workflow regardless of changes")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--workflows-dir", default=".github/workflows")
    ap.add_argument("--repo-root", default=".")
    args = ap.parse_args(argv)
    if not args.all and not args.since:
        ap.error("--since is required unless --all is given")

    workflows = gated_workflows(args.workflows_dir)
    if len(workflows) < 5:
        # Anti-vacuity: a parse change that finds no gated workflow must not
        # read as "nothing changed today".
        print(f"ERROR: only {len(workflows)} post-merge stack-booting workflows found under {args.workflows_dir}", file=sys.stderr)
        return 2

    changed = [] if args.all else changed_files(args.repo_root, args.since)
    chosen = list(select(workflows, changed, run_all=args.all))

    lines = [
        f"### Nightly E2E dispatch ({'dry run' if args.dry_run else 'live'})",
        "",
        f"- post-merge stack-booting workflows: **{len(workflows)}**",
        f"- files changed since `{(args.since or '')[:12]}`: **{len(changed)}**" if not args.all else "- forced: every gated workflow",
        f"- dispatched: **{len(chosen)}**",
        "",
        "| workflow | reason | result |",
        "|---|---|---|",
    ]
    failures = 0
    for f, name, reason in chosen:
        ok, msg = dispatch(f, args.ref, args.dry_run)
        failures += 0 if ok else 1
        lines.append(f"| `{f}` | {reason} | {(msg if args.dry_run else 'ok') if ok else 'FAILED: ' + msg} |")
    skipped = [f for f, _, _ in workflows if f not in {c[0] for c in chosen}]
    if skipped:
        lines += ["", "<details><summary>not dispatched (no matching change)</summary>", ""]
        lines += [f"- `{f}`" for f in skipped]
        lines += ["", "</details>"]
    report = "\n".join(lines)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
