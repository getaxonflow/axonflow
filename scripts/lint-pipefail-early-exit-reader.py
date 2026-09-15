#!/usr/bin/env python3
"""A pipe into a reader that exits early must not run under pipefail (#4072).

Usage:
  lint-pipefail-early-exit-reader.py                 scan <repo>/scripts
  lint-pipefail-early-exit-reader.py PATH [PATH...]  scan these files / dirs
  lint-pipefail-early-exit-reader.py --show-quoted   also list the pipes that
                                                     sit inside a double-quoted
                                                     string (not flagged)
  lint-pipefail-early-exit-reader.py --readers grep  report only these reader
                                                     kinds (comma-separated subset
                                                     of grep,head,sed,awk)

THE DEFECT

    set -euo pipefail
    if ! printf '%s\\n' "$SEEN_FILES" | grep -qx "$alfile"; then  # "found 0"

`grep -q` exits at its first match. If the writer still has data to write, it
is killed by SIGPIPE and exits 141, and under `pipefail` the pipeline's status
is that 141 - so `if !` takes the NOT-FOUND branch for a line grep has just
found. The same holds for every reader that stops before end of input: `head`,
`grep -m`, `grep -l`, `sed ...q`, `awk` with `exit`. Whether it fires depends
on how much the writer has left when the reader leaves, so it is green almost
everywhere and red occasionally, with a message that reads like a real finding.
#4072 saw it on `Lint All Modules` as "expected 1, found 0 (entry is stale)"
for a file whose read had not moved. Measured on the construct itself: a
SEEN_FILES larger than a pipe buffer with the allow-listed path near its start
reads "found 0" on nearly every run.

In an assignment under `set -e` the same 141 aborts the script instead:
`tip=$(git log | head -1)`.

WHAT THIS FLAGS

In a `*.sh` file IN PIPEFAIL SCOPE, a pipe `|` or `|&` IN CODE whose right-hand
command is one of the readers below. A file is in pipefail scope when it enables
pipefail itself (a `set` command in code whose options include `-o pipefail`,
e.g. `set -euo pipefail`), when it sits under a `lib/` directory, or when its
file name is the target of a `source` or `.` in any scanned file: a sourced file
inherits its caller's options, and this tree keeps sourced helpers under `lib/`.
The readers:

  grep/egrep/fgrep with -q, -m, -l or -L (in any short-option cluster, e.g.
      -Eq, -qxF) or --quiet, --silent, --max-count, --files-with-matches,
      --files-without-match;
  head, in any form;
  sed whose script carries a q or Q command;
  awk whose program carries `exit` outside an END block.

"In code" is decided by a quote-, comment- and heredoc-aware scan: a `|` inside
single quotes, inside a heredoc body, in a comment, or inside double quotes
(and not inside a `$(...)` or backticks nested in them) is not a pipe of this
shell. `ssh host "docker ps | grep -q x"` runs its pipe in a REMOTE shell that
never set pipefail, so it is not flagged; `--show-quoted` lists those sites so
the decision stays visible. `||` is not a pipe.

A pipe that ends its line continues onto the next, across a trailing comment,
and a hit is reported at the FIRST physical line of its statement, walking back
over backslash continuations, so the report matches an editor.

ONE IMPLEMENTATION, TWO HARNESSES

This file is the only scanner for the class. It used to have a sibling: the awk
scanner inside tests/regression-test-required/no_grep_q_under_pipefail_test.sh
(#3756), which saw sourced and `lib/` files and a trailing `|` but read only
`grep -q`. The two drifted apart (#4081), so that test now drives this file.

  - scripts/lint-pipefail-early-exit-reader_test.sh, run by lint.yml and synced
    to the community mirror: synthetic fixtures, and the default scan of
    scripts/ with every reader.
  - tests/regression-test-required/no_grep_q_under_pipefail_test.sh, run on
    every pull request by run-all.sh and NOT synced: `--readers grep` over
    runtime-e2e/ and scripts/e2e/, which the mirror strips, held to its anchor,
    spellings and control fixtures.

THE FIX IS TO NOT CLOSE THE PIPE EARLY, NOT TO DROP PIPEFAIL

  printf/echo "$VAR" | grep -q P   ->  grep -q P <<<"$VAR"     (no pipe at all)
  cmd | grep -q P                  ->  cmd | grep P >/dev/null (reads all input,
                                       and cmd's own failure still counts)
  cmd | head -1                    ->  cmd | sed -n '1p'

`grep -q P < <(cmd)` is NOT offered: it silences SIGPIPE by discarding cmd's
exit status, which is the thing pipefail was there to keep.

KNOWN LIMITS, stated rather than papered over

  1. File level, not scope level: a file that sets pipefail anywhere is judged
     everywhere, including a function that runs before the `set`, and a
     `set +o pipefail` is not tracked. The error is in the loud direction.
  2. A reader reached indirectly - through a function (`cmd | first_line`), a
     variable (`cmd | $READER`), `xargs`, or a `{ ...; }` group - is not seen.
  3. `read` (`cmd | read -r x`) also stops early and is not in the reader set.
  4. `awk -f progfile` is not opened, so its `exit` is not seen.
  5. Only `*.sh` files are scanned; a `run:` block in a workflow is not.
  6. Sourced scope is matched by BASE NAME across the scan: a sourced
     `health.sh` puts every `health.sh` in scope (the loud direction), and a
     `source "$FILE"` whose target is only a variable names no file (a gap).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The anti-vacuity witness for a default scan. It is a synced lint that runs
# under `set -euo pipefail`, so it exists in this repository AND in the
# community mirror, and a scan that does not reach it - or reaches it and does
# not see its pipefail - has stopped reading the tree correctly.
WITNESS = "scripts/lint-policy-table-choke-point.sh"

SKIP_DIRS = {".git", "node_modules"}


# ─── Lexing ────────────────────────────────────────────────────────────────


class Lexed:
    """The file's text, a per-character code mask, and every pipe found."""

    def __init__(self, text: str):
        self.text = text
        self.code = [False] * len(text)
        # (index, width, in_code, paren_depth): paren_depth is the number of
        # `(` / `$(` groups open at the pipe, used to tell `cmd | head)` closing
        # a group from a `case` pattern like `tail|head)`.
        self.pipes: list[tuple[int, int, bool, int]] = []


def lex(text: str) -> Lexed:
    out = Lexed(text)
    n = len(text)
    i = 0
    # Each frame: (kind, paren_depth_at_open). kinds: code, cmdsub, backtick,
    # dq, param, arith.
    stack: list[list] = [["code", 0]]
    pending_heredocs: list[tuple[str, bool]] = []
    paren_depth = 0

    def top() -> str:
        return stack[-1][0]

    def in_code() -> bool:
        return top() in ("code", "cmdsub", "backtick")

    def word_start(idx: int) -> bool:
        return idx == 0 or text[idx - 1] in " \t\n;&|()<>"

    while i < n:
        c = text[i]
        kind = top()

        if kind in ("code", "cmdsub", "backtick"):
            out.code[i] = True
            if c == "\\" and i + 1 < n:
                if i + 1 < n:
                    out.code[i + 1] = True
                i += 2
                continue
            if c == "\n":
                i += 1
                if pending_heredocs:
                    i = _skip_heredoc_bodies(text, i, pending_heredocs)
                    pending_heredocs = []
                continue
            if c == "#" and word_start(i):
                j = text.find("\n", i)
                i = n if j == -1 else j
                continue
            if c == "'":
                j = text.find("'", i + 1)
                i = n if j == -1 else j + 1
                continue
            if c == "$" and i + 1 < n and text[i + 1] == "'":
                i = _skip_ansi_c(text, i + 2)
                continue
            if c == '"':
                stack.append(["dq", paren_depth])
                i += 1
                continue
            if c == "`":
                if kind == "backtick":
                    stack.pop()
                else:
                    stack.append(["backtick", paren_depth])
                i += 1
                continue
            if text.startswith("$((", i):
                stack.append(["arith", paren_depth])
                i += 3
                continue
            if text.startswith("$(", i):
                paren_depth += 1
                stack.append(["cmdsub", paren_depth])
                i += 2
                continue
            if text.startswith("${", i):
                stack.append(["param", paren_depth])
                i += 2
                continue
            if c == "(":
                paren_depth += 1
                i += 1
                continue
            if c == ")":
                if kind == "cmdsub" and stack[-1][1] == paren_depth:
                    stack.pop()
                paren_depth = max(0, paren_depth - 1)
                i += 1
                continue
            if text.startswith("<<<", i):
                # A here-string, not a heredoc. Stepping over only its first
                # `<` would leave `<< "$var"` behind to read as a heredoc whose
                # delimiter never appears, and the rest of the file as its body.
                i += 3
                continue
            if text.startswith("<<", i):
                m = re.match(r"<<(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([A-Za-z0-9_.-]+))", text[i:])
                if m:
                    delim = m.group(2) if m.group(2) is not None else (
                        m.group(3) if m.group(3) is not None else m.group(4))
                    pending_heredocs.append((delim, m.group(1) == "-"))
                    i += m.end()
                    continue
                i += 2
                continue
            if c == "|":
                if i + 1 < n and text[i + 1] == "|":
                    i += 2
                    continue
                if i > 0 and text[i - 1] == ">":  # >| clobber
                    i += 1
                    continue
                width = 2 if i + 1 < n and text[i + 1] == "&" else 1
                out.pipes.append((i, width, True, paren_depth))
                i += width
                continue
            i += 1
            continue

        if kind == "dq":
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == '"':
                stack.pop()
                i += 1
                continue
            if text.startswith("$((", i):
                stack.append(["arith", paren_depth])
                i += 3
                continue
            if text.startswith("$(", i):
                paren_depth += 1
                stack.append(["cmdsub", paren_depth])
                i += 2
                continue
            if c == "`":
                stack.append(["backtick", paren_depth])
                i += 1
                continue
            if text.startswith("${", i):
                stack.append(["param", paren_depth])
                i += 2
                continue
            if c == "|" and not text.startswith("||", i) and (i == 0 or text[i - 1] != "|"):
                out.pipes.append((i, 1, False, paren_depth))
            i += 1
            continue

        if kind == "param":
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == "}":
                stack.pop()
                i += 1
                continue
            if c == "'":
                j = text.find("'", i + 1)
                i = n if j == -1 else j + 1
                continue
            if c == '"':
                stack.append(["dq", paren_depth])
                i += 1
                continue
            if text.startswith("$(", i) and not text.startswith("$((", i):
                paren_depth += 1
                stack.append(["cmdsub", paren_depth])
                i += 2
                continue
            if text.startswith("${", i):
                stack.append(["param", paren_depth])
                i += 2
                continue
            i += 1
            continue

        if kind == "arith":
            if text.startswith("))", i):
                stack.pop()
                i += 2
                continue
            i += 1
            continue

        i += 1  # unreachable in practice

    return out


def _skip_ansi_c(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "'":
            return i + 1
        i += 1
    return n


def _skip_heredoc_bodies(text: str, i: int, pending: list[tuple[str, bool]]) -> int:
    n = len(text)
    for delim, strip_tabs in pending:
        while i < n:
            j = text.find("\n", i)
            line = text[i:] if j == -1 else text[i:j]
            i = n if j == -1 else j + 1
            if (line.lstrip("\t") if strip_tabs else line) == delim:
                break
    return i


# ─── The right-hand command ────────────────────────────────────────────────


def rhs_words(text: str, start: int) -> tuple[list[str], str]:
    """Words of the simple command after a pipe, with quotes removed, and the
    character that ended the first word ('' when none)."""
    n = len(text)
    i = start
    while i < n:
        if text[i] in " \t\n":
            i += 1
        elif text.startswith("\\\n", i):
            i += 2
        elif text[i] == "#":
            # `cmd |   # note` then the reader on the next line.
            j = text.find("\n", i)
            i = n if j == -1 else j + 1
        else:
            break
    words: list[str] = []
    first_terminator = ""
    while i < n:
        while i < n and text[i] in " \t":
            i += 1
        if text.startswith("\\\n", i):
            i += 2
            continue
        if i >= n or text[i] in "\n;&|)":
            if len(words) == 1 and not first_terminator and i < n:
                first_terminator = text[i]
            break
        buf = []
        while i < n and text[i] not in " \t\n;&|)":
            ch = text[i]
            if ch == "\\" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
            elif ch == "'":
                j = text.find("'", i + 1)
                j = n if j == -1 else j
                buf.append(text[i + 1:j])
                i = j + 1
            elif ch == '"':
                j = i + 1
                while j < n and text[j] != '"':
                    j += 2 if text[j] == "\\" else 1
                buf.append(text[i + 1:j])
                i = j + 1
            elif text.startswith("$(", i):
                depth, j = 0, i + 1
                while j < n:
                    if text[j] == "(":
                        depth += 1
                    elif text[j] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                buf.append(text[i:j + 1])
                i = j + 1
            else:
                buf.append(ch)
                i += 1
        words.append("".join(buf))
        if len(words) == 1 and i < n and text[i] == ")":
            first_terminator = ")"
            break
    return words, first_terminator


_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PREFIXES = {"command", "builtin", "env", "nice", "!"}


def command_of(words: list[str]) -> tuple[str, list[str]]:
    k = 0
    while k < len(words) and (_ASSIGNMENT.match(words[k]) or words[k] in _PREFIXES):
        k += 1
    if k >= len(words):
        return "", []
    return os.path.basename(words[k]), words[k + 1:]


GREP_ARG_OPTS = set("ABCDdefm")  # short options that consume an argument


def grep_exits_early(args: list[str]) -> bool:
    skip_next = False
    for w in args:
        if skip_next:
            skip_next = False
            continue
        if w == "--":
            break
        if w.startswith("--"):
            name = w[2:].split("=", 1)[0]
            if name in ("quiet", "silent", "max-count", "files-with-matches", "files-without-match"):
                return True
            continue
        if w.startswith("-") and len(w) > 1 and not w[1].isdigit():
            for pos, ch in enumerate(w[1:]):
                if ch in "qlL":
                    return True
                if ch == "m":
                    return True
                if ch in GREP_ARG_OPTS:
                    if pos == len(w) - 2:
                        skip_next = True
                    break
    return False


_SED_Q = re.compile(r"(?:^|[;\n{}])\s*(?:(?:\d+|\$|/(?:[^/\\]|\\.)*/)(?:\s*,\s*(?:\d+|\$|/(?:[^/\\]|\\.)*/))?)?\s*!?\s*[qQ]\s*\d*\s*(?:$|[;\n}])")


def sed_exits_early(args: list[str]) -> bool:
    scripts, positional, skip_next, expect_script = [], [], False, False
    for w in args:
        if expect_script:
            scripts.append(w)
            expect_script = False
            continue
        if skip_next:
            skip_next = False
            continue
        if w in ("-e", "--expression"):
            expect_script = True
        elif w.startswith("--expression="):
            scripts.append(w.split("=", 1)[1])
        elif w in ("-f", "--file", "-l"):
            skip_next = True
        elif w.startswith("-") and len(w) > 1:
            continue
        else:
            positional.append(w)
    if not scripts and positional:
        scripts.append(positional[0])
    return any(_SED_Q.search(s) for s in scripts)


def _strip_end_blocks(prog: str) -> str:
    out, i = [], 0
    for m in re.finditer(r"\bEND\s*\{", prog):
        if m.start() < i:
            continue
        out.append(prog[i:m.start()])
        depth, j = 0, m.end() - 1
        while j < len(prog):
            if prog[j] == "{":
                depth += 1
            elif prog[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        i = j + 1
    out.append(prog[i:])
    return "".join(out)


def awk_exits_early(args: list[str]) -> bool:
    skip_next = False
    for w in args:
        if skip_next:
            skip_next = False
            continue
        if w in ("-F", "-v"):
            skip_next = True
            continue
        if w == "-f":
            return False  # limit 4
        if w.startswith("-") and len(w) > 1:
            continue
        return bool(re.search(r"\bexit\b", _strip_end_blocks(w)))
    return False


def reader_kind(words: list[str]) -> str:
    name, args = command_of(words)
    if name in ("grep", "egrep", "fgrep"):
        return "grep" if grep_exits_early(args) else ""
    if name == "head":
        return "head"
    if name in ("sed", "gsed"):
        return "sed" if sed_exits_early(args) else ""
    if name in ("awk", "gawk", "mawk", "nawk"):
        return "awk" if awk_exits_early(args) else ""
    return ""


# ─── pipefail ──────────────────────────────────────────────────────────────


def enables_pipefail(lexed: Lexed) -> bool:
    text = lexed.text
    for m in re.finditer(r"\bset\b", text):
        s = m.start()
        if not lexed.code[s] or (s > 0 and text[s - 1] not in " \t\n;&|({"):
            continue
        end = s
        while end < len(text) and text[end] not in "\n;&|":
            end += 1
        words = text[m.end():end].split()
        for k, w in enumerate(words):
            if w == "pipefail" and k > 0 and re.fullmatch(r"-[A-Za-z]*o", words[k - 1]):
                return True
    return False


_SOURCE_CMD = re.compile(
    r"(?m)(?:^[ \t]*|[;&|({][ \t]*|\b(?:then|do|else)[ \t]+)(?P<cmd>source|\.)[ \t]+")


def sourced_names(lexed: Lexed) -> set[str]:
    """Base names of the files this script sources with `source X` or `. X`,
    read in code only. The target is read as a shell word - quotes removed,
    `$(...)` kept whole - so `. "$(dirname "$0")/helpers.sh"` names helpers.sh."""
    names = set()
    for m in _SOURCE_CMD.finditer(lexed.text):
        if not lexed.code[m.start("cmd")]:
            continue
        words, _ = rhs_words(lexed.text, m.end())
        if not words:
            continue
        name = words[0].rsplit("/", 1)[-1]
        if name:
            names.add(name)
    return names


def under_lib(root: Path, path: Path) -> bool:
    """Whether a directory named lib sits between the scan root's parent and the
    file, so a checkout that happens to live under some `.../lib/...` does not
    put every file in scope."""
    base = root.parent if root.is_dir() else path.parent.parent
    try:
        parts = path.resolve().relative_to(base.resolve()).parts[:-1]
    except ValueError:
        parts = path.parent.parts[-1:]
    return "lib" in parts


# ─── Scanning ──────────────────────────────────────────────────────────────


def line_of(text: str, idx: int) -> tuple[int, str]:
    """The first physical line of the statement holding idx - walking back over
    backslash continuations - and the statement's lines joined."""
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    end = len(text) if end == -1 else end
    while start > 0:
        prev = text.rfind("\n", 0, start - 1) + 1
        if text[prev:start - 1].rstrip(" \t").endswith("\\"):
            start = prev
        else:
            break
    lineno = text.count("\n", 0, start) + 1
    joined = " ".join(part.strip().rstrip("\\").strip() for part in text[start:end].split("\n"))
    return lineno, joined


def find_hits(lexed: Lexed, display: str):
    text = lexed.text
    hits, quoted = [], []
    for idx, width, in_code, depth in lexed.pipes:
        words, term = rhs_words(text, idx + width)
        if not words or words[0] in ("{", "("):
            continue
        if term == ")" and depth == 0 and len(words) == 1:
            continue  # a `case` pattern alternative, e.g. `tail|head)`
        kind = reader_kind(words)
        if not kind:
            continue
        lineno, line = line_of(text, idx)
        (hits if in_code else quoted).append((display, lineno, kind, line.strip()))
    return hits, quoted


def iter_sh(paths: list[Path]):
    """(scan root, file) for every *.sh under the given paths."""
    for p in paths:
        if p.is_file():
            yield p, p
            continue
        for dirpath, dirnames, filenames in os.walk(p):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for f in sorted(filenames):
                if f.endswith(".sh"):
                    yield p, Path(dirpath) / f


READERS = ("grep", "head", "sed", "awk")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*", help="files or directories (default: <repo>/scripts)")
    ap.add_argument("--show-quoted", action="store_true",
                    help="list pipes into an early reader inside a double-quoted string")
    ap.add_argument("--readers", default=",".join(READERS),
                    help="comma-separated reader kinds to report (default: grep,head,sed,awk)")
    opts = ap.parse_args()

    readers = {r.strip() for r in opts.readers.split(",") if r.strip()}
    if not readers or readers - set(READERS):
        print(f"❌ --readers takes a comma-separated subset of {','.join(READERS)}; got {opts.readers!r}")
        return 2

    default_scan = not opts.paths
    roots = [REPO_ROOT / "scripts"] if default_scan else [Path(p) for p in opts.paths]
    for r in roots:
        if not r.exists():
            print(f"❌ {r} does not exist; refusing to report a scan of nothing as clean")
            return 2

    # Two passes: which names are sourced depends on every file in the scan.
    files = []
    for root, f in iter_sh(roots):
        try:
            display = str(f.resolve().relative_to(REPO_ROOT))
        except ValueError:
            display = str(f)
        files.append((root, f, display, lex(f.read_text(encoding="utf-8", errors="replace"))))
    sourced: set[str] = set()
    for _, _, _, lexed in files:
        sourced |= sourced_names(lexed)

    sets_it = inherits = 0
    witness_ok = False
    hits, quoted = [], []
    for root, f, display, lexed in files:
        own = enables_pipefail(lexed)
        inherited = not own and (under_lib(root, f) or f.name in sourced)
        sets_it += own
        inherits += inherited
        if own or inherited:
            h, q = find_hits(lexed, display)
            hits.extend(x for x in h if x[2] in readers)
            quoted.extend(x for x in q if x[2] in readers)
        if display == WITNESS and own:
            witness_ok = True

    if default_scan and not witness_ok:
        print(f"❌ the scan did not reach {WITNESS} as a pipefail file ({len(files)} scanned); "
              "its silence would not be evidence")
        return 2

    for display, lineno, kind, line in hits:
        print(f"{display}:{lineno}: {line}")
    if opts.show_quoted:
        for display, lineno, kind, line in quoted:
            print(f"(quoted, not flagged) {display}:{lineno}: {line}")

    breakdown = ", ".join(f"{k} {sum(1 for h in hits if h[2] == k)}" for k in READERS if k in readers)
    summary = (f"{len(hits)} hit(s) in {len({h[0] for h in hits})} file(s) [{breakdown}]; "
               f"{len(files)} *.sh scanned, {sets_it + inherits} in pipefail scope "
               f"({sets_it} set it, {inherits} under lib/ or sourced), "
               f"{len(quoted)} quoted site(s) not flagged")
    if hits:
        print(f"❌ {summary}")
        print("   A reader that exits before end of input SIGPIPEs its writer, and pipefail turns that")
        print("   141 into the pipeline's status: a found match reads as missing (#4072). See the fixes")
        print("   in this script's header.")
        return 1
    print(f"✅ {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
