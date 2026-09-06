#!/usr/bin/env python3
"""Census: fleet jobs that install an executable to a path all slots share.

Invoked by no_shared_install_path_from_fleet_jobs_test.sh against both the
real tree and its fixtures, so the matcher used to CHECK the repo is byte-for-
byte the one used to prove the matcher works. Two separately-anchored copies
is how the host-ports guard silently skipped 32 declarations.

Usage:  fleet_shared_install_census.py <root>
Prints: line 1  = number of fleet jobs censused (anti-vacuity denominator)
        line 2+ = "<workflow>:<job>\t<rule>\t<matched text>"
"""
import glob
import io
import os
import re
import sys

import yaml

# Every pattern below names a path that is ONE location for all eight runner
# slots, because they share /home/runner and /usr. A partially written binary
# at any of them is exec'd by the losing job as exit 126, "cannot execute".
RULES = [
    (
        "npm-global-install",
        re.compile(r"(?<![\w-])npm\s+(?:install|i|add)\b[^\n]*?(?:\s-g\b|\s--global\b)"),
        "npm's global prefix on the fleet host is /usr, so this writes "
        "/usr/lib/node_modules - one location for all slots",
    ),
    (
        "go-bin-install",
        # `go install pkg@ver` and any installer pointed at $(go env GOPATH)/bin.
        # GOPATH is NOT among the per-slot vars (only GOCACHE/GOMODCACHE are),
        # so it defaults to $HOME/go and resolves to /home/runner/go/bin.
        re.compile(
            r"(?<![\w-])go\s+install\s+\S+@\S+"
            r"|-b\s+\"?\$\(\s*go\s+env\s+GOPATH\s*\)/bin"
            r"|(?<![\w-])GOBIN\s*=\s*\"?(?:\$HOME|~|\$\(\s*go\s+env\s+GOPATH\s*\))"
        ),
        "GOPATH is not set per slot, so this writes /home/runner/go/bin - "
        "one location for all slots",
    ),
    (
        "home-bin-install",
        re.compile(r"-b\s+\"?(?:\$HOME|~|/home/runner)/(?:\.local/)?bin"),
        "an installer aimed at $HOME/bin or ~/.local/bin - /home/runner is "
        "shared by every slot",
    ),
    (
        "pip-user-install",
        re.compile(r"(?<![\w-])pip3?\s+install\b[^\n]*--user"),
        "--user installs into /home/runner/.local, which every slot shares",
    ),
]


def strip_comments(text):
    """Drop shell comments so a rule cannot fire on the prose beside it.

    A `#` inside single or double quotes is data, not a comment - `sed 's/#//'`
    and `grep '#'` are ordinary. Track quote state and only cut at a `#` that
    starts a word outside quotes.
    """
    out = []
    for line in text.split("\n"):
        sq = dq = False
        cut = None
        for i, ch in enumerate(line):
            if ch == "'" and not dq:
                sq = not sq
            elif ch == '"' and not sq:
                dq = not dq
            elif ch == "#" and not sq and not dq and (i == 0 or line[i - 1].isspace()):
                cut = i
                break
        out.append(line if cut is None else line[:cut])
    return "\n".join(out)


def is_fleet(runs_on):
    """True only for the self-hosted fleet.

    The same commands are correct on ubuntu-latest, where the machine is
    discarded after the job - a rule that fires there would be wrong and
    would get ignored.
    """
    if isinstance(runs_on, list):
        return "self-hosted" in runs_on
    if isinstance(runs_on, str):
        return runs_on.strip() == "self-hosted"
    return False


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    censused = 0
    offenders = []
    for path in sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml"))):
        try:
            doc = yaml.safe_load(io.open(path, encoding="utf-8"))
        except Exception:
            continue  # workflows_yaml_parse_test.sh owns unparseable files
        if not isinstance(doc, dict):
            continue
        for job_name, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict) or not is_fleet(job.get("runs-on")):
                continue
            censused += 1
            body = strip_comments(
                "\n".join(
                    s.get("run", "")
                    for s in (job.get("steps") or [])
                    if isinstance(s, dict)
                )
            )
            for rule, pattern, _why in RULES:
                m = pattern.search(body)
                if m:
                    who = "%s:%s" % (os.path.basename(path), job_name)
                    offenders.append(
                        "%s\t%s\t%s" % (who, rule, " ".join(m.group(0).split()))
                    )
    print(censused)
    for line in offenders:
        print(line)


if __name__ == "__main__":
    main()
