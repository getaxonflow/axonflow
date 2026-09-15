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

# ---------------------------------------------------------------------------
# WHAT COUNTS AS "BOOTS A STACK" - AN INVOCATION, NEVER A MENTION.
#
# The first version of this classifier was `re.compile(r"docker[ -]compose|
# runtime-e2e/\S+\.(sh|py)")` searched over the whole `run:` body. A substring
# anywhere satisfied it, so `.github/workflows/sync-community-repo.yml` - the
# community PUBLISH pipeline, which never runs compose - matched NINE times:
# two prose comments, six `rsync --exclude='docker-compose.*.yml'` filename
# arguments, and one `docker-compose-test` job NAME passed as an argument to
# `run-community-job-in-mirror.sh`. A `nightly-e2e.yml` dispatch with
# `all=true` therefore fired the publish pipeline twice on 2026-09-08 (runs
# 34237273184 and 34250968298), opening getaxonflow/axonflow#490 and #491.
#
# THE FIX IS NOT MORE EXCLUDED SUBSTRINGS - that is the same brittle shape one
# level down, and the next `--exclude=` spelling defeats it. Instead the body
# is reduced to the list of COMMANDS it would execute, and the token must be
# the command word (or, for an interpreter, the script it is handed).
#
# CAN satisfy the check now:
#     docker compose up -d / docker-compose -f x.yml up / ./bin/docker-compose
#     runtime-e2e/foo/test.sh          (executed directly)
#     bash runtime-e2e/foo/test.sh     (handed to an interpreter)
#     FOO=1 cd x && docker compose up  (env prefixes and separators are peeled)
#
# CANNOT satisfy it any more:
#     # a comment naming docker-compose.yml          <- whole-line comments dropped
#     rsync --exclude='docker-compose.test.yml'      <- argument, not command word
#     ... run-community-job-in-mirror.sh docker-compose-test   <- argument, and
#                                                        not the exact command
#     echo "see runtime-e2e/foo/test.sh"             <- argument to echo
#
# KNOWN LIMITS, stated rather than hidden: the reduction is a shell-shaped
# approximation, not a shell parser. It drops whole-line comments only (a
# trailing `# ...` survives, but everything in it is in argument position and
# so cannot satisfy the check anyway); it does not resolve variables, so a
# suite that invokes compose as `"$COMPOSE" up` would be missed - the
# regression guard's real-tree floor is the observable that would catch that
# class shrinking the nightly set.
# ---------------------------------------------------------------------------
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PREFIXES = {"if", "then", "else", "elif", "do", "while", "until", "!", "time",
             "sudo", "exec", "nohup", "command", "env", "eval", "{", "("}
_INTERPRETERS = {"bash", "sh", "zsh", "dash", "python", "python3", "py"}
_RUNTIME_E2E = re.compile(r"(?:^|/)runtime-e2e/\S+\.(?:sh|py)$")
# Shell command separators. `$(` and a backtick open a nested command, so what
# follows them is a command word too.
_SEPARATORS = re.compile(r"\|\||&&|[;|&\n]|\$\(|`")


def _commands(run: str):
    """Reduce a `run:` body to (command_word, args) pairs.

    Whole-line comments are dropped, backslash continuations are joined (so a
    trailing argument on its own line stays an ARGUMENT), the result is split
    on shell separators, and leading `VAR=value` assignments and shell keywords
    are peeled off the front of each command.
    """
    logical, buf = [], ""
    for raw in run.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        logical.append(buf + line)
        buf = ""
    if buf:
        logical.append(buf)
    for line in logical:
        for segment in _SEPARATORS.split(line):
            toks = segment.split()
            i = 0
            while i < len(toks) and (_ENV_ASSIGN.match(toks[i]) or toks[i] in _PREFIXES):
                i += 1
            if i < len(toks):
                yield toks[i].strip("\"'"), toks[i + 1:]


def _first_operand(args, value_flags=()):
    """First non-flag token, skipping flags and the values they consume.

    `value_flags` names the flags that take a separate value (`docker
    --context prod compose up`); without it the flag's VALUE would be read as
    the subcommand and a real invocation would be missed.
    """
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            skip = "=" not in a and a in value_flags
            continue
        return a.strip("\"'")
    return None


# Docker's global flags that consume a following value. Only these can stand
# between `docker` and the `compose` subcommand.
_DOCKER_VALUE_FLAGS = frozenset({
    "--context", "-c", "--config", "--host", "-H", "--log-level", "-l",
    "--tlscacert", "--tlscert", "--tlskey",
})


def invokes_stack_boot(run: str) -> bool:
    """True iff some command in this `run:` body IS a compose or suite call."""
    for cmd, args in _commands(run):
        base = cmd.rsplit("/", 1)[-1]
        if base == "docker-compose":
            return True
        if base == "docker" and _first_operand(args, _DOCKER_VALUE_FLAGS) == "compose":
            return True
        if _RUNTIME_E2E.search(cmd):
            return True
        if base in _INTERPRETERS:
            operand = _first_operand(args)
            if operand and _RUNTIME_E2E.search(operand):
                return True
    return False


# ---------------------------------------------------------------------------
# DEFENCE 2: A WORKFLOW THAT CAN WRITE OUTSIDE THIS REPOSITORY IS NEVER IN THE
# NIGHTLY SET, WHATEVER THE CLASSIFIER ABOVE SAYS.
#
# Operator ruling, 2026-09-09: there is no automated community sync and there
# must not be one - it happens as part of the release train or on demand. A
# TEST SWEEP must never be able to publish. The classifier fix alone is not
# enough: it is a heuristic over free-form shell, and the next edit to a
# publish pipeline that happens to add a compose call would put it back in the
# set. This check is a second, independent reason to refuse, derived from the
# workflow itself rather than from a hand-typed filename list:
#
#   * a `run:` step invoking a forge WRITE verb - git push, gh pr create,
#     gh release create, gh repo sync, git remote add, a `git clone` of a
#     github.com URL, npm publish, twine upload;
#   * a step `uses:` a known publishing action;
#   * `actions/checkout` (or anything) with a `repository:` input - i.e. it
#     checks out some repository other than the one the run belongs to;
#   * a forge credential other than the run-scoped GITHUB_TOKEN. A token's
#     scopes cannot be read from its name, so any non-default GH/PAT/registry
#     credential is treated as write-capable. Fail closed.
#
# Measured on the tree at the time of writing: 16 of 161 workflows carry at
# least one of these signals, and exactly ONE of them - sync-community-repo.yml
# - was in the nightly set. So the property fires, and it removes precisely the
# workflow the operator ruling is about.
#
# Deliberately NOT modelled: cloud-deployment credentials (CLOUDFLARE_API_TOKEN
# and friends). Those workflows do not boot stacks, so they are already out of
# the set, and widening the rule to "uses any secret named *TOKEN*" would start
# dropping genuine e2e suites the day one needs a vendor key. REVISIT WHEN the
# dispatcher's own report first lists a `deploy-*`/`setup-*` workflow among the
# post-merge stack-booting workflows - the count and the names are printed on
# every run, and the regression guard asserts the excluded set is non-empty.
# ---------------------------------------------------------------------------
_FORGE_WRITE = re.compile(
    r"\bgit\s+push\b"
    r"|\bgit\s+remote\s+add\b"
    r"|\bgit\s+clone\s+\S*github\.com/"
    r"|\bgh\s+pr\s+create\b"
    r"|\bgh\s+release\s+create\b"
    r"|\bgh\s+repo\s+sync\b"
    r"|\bnpm\s+publish\b"
    r"|\btwine\s+upload\b"
)
_PUBLISHER_ACTION = re.compile(
    r"peter-evans/create-pull-request"
    r"|softprops/action-gh-release"
    r"|ad-m/github-push-action"
    r"|JamesIves/github-pages-deploy-action"
)
_FORGE_CREDENTIAL = re.compile(
    # THE TRAILING [A-Z0-9_]* IS LOAD-BEARING, and the obvious fix is wrong.
    # Without it the group captures exactly "GITHUB_TOKEN" out of
    # `secrets.GITHUB_TOKEN_ADMIN`, and the equality test below then waves the
    # whole family through - a comment saying "fail closed" over code that fails
    # open on any name with a suffix.
    #
    # Tightening with a `(?![A-Z0-9_])` lookahead instead makes it WORSE, not
    # better: the pattern then fails to match GITHUB_TOKEN_ADMIN at all, and a
    # credential nothing matches is a credential nothing refuses. Measured before
    # this comment was written. The group must span the WHOLE identifier so the
    # equality below compares a complete name against a complete name.
    #
    # The LEADING [A-Z0-9_]* is the same lesson on the other end: without it
    # `secrets.MY_GITHUB_TOKEN` matched nothing and was allowed. Both ends of
    # the identifier have to be spanned, or an affix evades the check.
    r"secrets\.([A-Z0-9_]*(?:GH|GITHUB)[A-Z0-9_]*(?:TOKEN|PAT)[A-Z0-9_]*"
    r"|[A-Z0-9_]+_PAT"
    r"|NPM_TOKEN|PYPI_[A-Z0-9_]*TOKEN|CARGO_[A-Z0-9_]*TOKEN|MAVEN_[A-Z0-9_]*TOKEN)"
)


def _forge_write_verb(cmd: str, args) -> str:
    """The forge-write verb this COMMAND invokes, or '' - never a mention.

    `cmd` is already the command word (defence 1 peeled prefixes and split on
    shell separators), so the subcommand is read positionally from `args`
    instead of being searched for anywhere in the line.
    """
    base = cmd.rsplit("/", 1)[-1]
    a = [x for x in args if not x.startswith("-")]
    if base == "git":
        if a[:1] == ["push"]:
            return "git push"
        if a[:2] == ["remote", "add"]:
            return "git remote add"
        if a[:1] == ["clone"] and any("github.com/" in x for x in args):
            return "git clone github.com/"
    if base == "gh" and a[:2] in (["pr", "create"], ["release", "create"], ["repo", "sync"]):
        return "gh " + " ".join(a[:2])
    if base == "npm" and a[:1] == ["publish"]:
        return "npm publish"
    if base == "twine" and a[:1] == ["upload"]:
        return "twine upload"
    return ""


def writes_outside_this_repo(doc, raw: str = "") -> str:
    """Reason string if this workflow can write outside this repo, else ''.

    `raw` is the workflow's source text; the credential clause reads it
    directly because `${{ secrets.X }}` can appear in any position (job `env`,
    a `with:` input, a step `env`) and re-serialising the parsed document to
    find it would depend on the dumper.
    """
    for job in (doc.get("jobs") or {}).values():
        for step in ((job or {}).get("steps") or []):
            step = step or {}
            run = str(step.get("run", "") or "")
            for cmd, args in _commands(run):
                # MATCH THE COMMAND, NOT THE LINE. Joining cmd and args back into
                # one string and searching it re-creates the defect defence 1 was
                # rewritten to remove, one level down: `echo "  git push --force"`
                # and `grep -rn 'git push' scripts/` both satisfied it, and
                # commit-lint.yml was refused on exactly that echo. The dangerous
                # direction is a false POSITIVE here - a suite wrongly refused
                # loses its only routine coverage and nothing reds, because the
                # floor is a lower bound on the set and no check asserts the
                # reverse inclusion.
                verb = _forge_write_verb(cmd, args)
                if verb:
                    return "forge write: " + verb
            uses = str(step.get("uses", "") or "")
            hit = _PUBLISHER_ACTION.search(uses)
            if hit:
                return "publishing action: " + hit.group(0)
            with_ = step.get("with") or {}
            if isinstance(with_, dict) and with_.get("repository"):
                return "checks out another repository: " + str(with_["repository"])
    for hit in _FORGE_CREDENTIAL.finditer(raw):
        # The run-scoped GITHUB_TOKEN is not a cross-repo credential: it is
        # minted per run and scoped to THIS repository. Every other GH/PAT or
        # registry credential is treated as write-capable, because a token's
        # scopes cannot be read off its name.
        if hit.group(1) == "GITHUB_TOKEN":
            continue
        return "forge credential: secrets." + hit.group(1)
    return ""



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
    """Some `run:` step INVOKES compose or a runtime-e2e suite script.

    See `invokes_stack_boot` for what can and cannot satisfy this: a mention
    in a comment or in argument position no longer can.
    """
    for job in (doc.get("jobs") or {}).values():
        for step in ((job or {}).get("steps") or []):
            if invokes_stack_boot(str((step or {}).get("run", ""))):
                return True
    return False


def in_nightly_set(doc, raw: str = "") -> bool:
    on = doc.get("on") or doc.get(True) or {}
    if not isinstance(on, dict):
        return False
    if "pull_request" in on:
        return False          # something else routinely runs it
    if "workflow_dispatch" not in on:
        return False          # this dispatcher could not reach it
    if writes_outside_this_repo(doc, raw):
        return False          # a test sweep must never be able to publish
    return boots_a_stack(doc)


def gated_workflows(workflows_dir):
    """(nightly set, refused publishers).

    The second list exists so the refusals are OBSERVABLE: it is printed on
    every run, and the regression guard asserts it is not empty. A defence
    that silently stops matching is indistinguishable from a tree that no
    longer contains anything to refuse.
    """
    manifest = load_manifest(workflows_dir)
    out, refused = [], []
    for f in sorted(glob.glob(os.path.join(workflows_dir, "*.yml"))):
        with open(f, encoding="utf-8") as fh:
            raw = fh.read()
        doc = yaml.safe_load(raw)
        if not isinstance(doc, dict):
            continue
        base = os.path.basename(f)
        on = doc.get("on") or doc.get(True) or {}
        why = writes_outside_this_repo(doc, raw)
        if (why and isinstance(on, dict)
                and "pull_request" not in on and "workflow_dispatch" in on):
            # Dispatchable, unattended by any PR run, and able to write outside
            # this repository. Refused on that ground ALONE - deliberately not
            # conditioned on `boots_a_stack`, so the two defences stay
            # independent and this list cannot be emptied by the classifier.
            refused.append((base, why))
        if not in_nightly_set(doc, raw):
            continue
        out.append((base, doc.get("name") or base, manifest.get(base)))
    return out, refused


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

    workflows, refused = gated_workflows(args.workflows_dir)
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
        f"- refused as publish/sync workflows (never dispatched by a test sweep): **{len(refused)}**",
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
    if refused:
        lines += ["", "<details><summary>refused: can write outside this repository</summary>", ""]
        lines += [f"- `{f}` - {why}" for f, why in refused]
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
