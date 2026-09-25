#!/usr/bin/env python3
"""A pipe into a reader that exits early must not run under pipefail (#4072).

Usage:
  lint-pipefail-early-exit-reader.py                 scan <repo>/scripts
  lint-pipefail-early-exit-reader.py PATH [PATH...]  scan these files / dirs
  lint-pipefail-early-exit-reader.py --show-quoted   also list the pipes that
                                                     sit inside a double-quoted
                                                     string (not flagged)
  lint-pipefail-early-exit-reader.py --show-admitted also list the sites whose
                                                     status the shell discards,
                                                     with the reason (admitted)
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

ONLY WHERE THE STATUS IS READ (#4249 row 5665386080)

The 141 is a defect only where something reads the pipeline's status. Where
the shell discards it, the reader has already produced the output that is
used. A site is judged WHERE IT STANDS, and then outward.

A statement - a bare pipeline, or an assignment whose status is its
substitution's - is FLAGGED when its status is read:

  - it is the condition of if/elif/while/until or `!`;
  - it is an operand of && or || (except `|| true` / `|| :`, below), also
    when the operator ends the line before it;
  - it is the last statement before a `}` or `)`: a function or subshell
    returns it (loud: callers are not traced);
  - it is the last statement of an if/for/while/case body (before `fi`,
    `done`, `esac` or `;;`), whose status the compound takes (loud);
  - the next statement - past blank and comment lines - reads $? or
    PIPESTATUS, or is a bare `exit`/`return`;
  - the file sets errexit (`set -e`, `-o errexit`), or is a lib/ or sourced
    file, whose caller's options are unknown WHETHER OR NOT it sets pipefail
    itself;
  - it is the file's last statement: its status is the script's exit status.

The statement's end is found on CODE characters only (the lexer's mask), so a
`;`, `(` or `)` inside a quoted argument does not end it, and a line ending in
a pipe continues onto the next.

A pipe inside a command substitution is judged first INSIDE it: a condition,
an &&/|| operand or a $? read there is a read whatever holds the
substitution - #4072's own shape, `echo "$(if p | grep -q x; ...)"`. Another
statement that is not the body's last is admitted: nothing reads it, and a
substitution does not inherit errexit (unless the file turns on
inherit_errexit). When it IS the body's last statement, its status is the
substitution's, and the substitution is judged by the simple command holding
it. The shell reports a substitution's status only for a command with NO
command name (assignments and redirections alone), and then only the LAST
substitution's. So `x=$(p | head -1)`, `x="a $(p | head -1)"`,
`arr=($(p | head -1))` and `x=$(( $(p | head -1) + 1 ))` are judged as
statements, and these are ADMITTED:

  - a substitution in a word of a command (`fail "... $(p | head -1)"`,
    `[ "$(..)" = x ]`, `FOO=$(..) cmd`): the command's status replaces it;
  - an assignment through local/declare/export/readonly;
  - a substitution that is not the last of an assignment-only command;
  - a pipeline under `|| true` / `|| :`: the author discarded the status;
  - a process substitution `<(...)`: its status is never reported;
  - a statement in a file without errexit that nothing reads.

Every admitted site is counted by reason in the summary and listed by
--show-admitted, so none is silent.

`# pipefail-ok: <reason>` on a flagged statement's first line, or on the line
of its pipe, accepts it, and the report lists it with the reason. An allow
with no reason, and an allow on a line with no flagged site, are findings:
an allow can neither be bare nor outlive the code it was written for.

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
        # pipe index -> (kind, open index) of the innermost command or process
        # substitution holding it, or ("code", -1): what `classify` reads.
        self.frames: dict[int, tuple[str, int]] = {}
        # pipe index -> start of the statement (list element) holding it.
        self.stmt_of: dict[int, int] = {}
        # substitution open index -> (parent Command, index of the word it sits
        # in); and id(Command) -> the open indexes of its substitutions.
        self.subs: dict[int, tuple["Command", int]] = {}
        # substitution open index -> its closing `)` / backtick index, and the
        # (kind, open index) of the frame whose command holds it.
        self.sub_close: dict[int, int] = {}
        self.sub_frame: dict[int, tuple[str, int]] = {}
        self.subs_of: dict[int, list[int]] = {}


CODE_KINDS = ("code", "cmdsub", "backtick", "procsub")


class Command:
    """One simple command at one nesting level: its start, the start of the
    statement (pipeline or list element) it belongs to, and its word spans. A
    substitution's parent Command is complete once lexing ends."""

    __slots__ = ("start", "stmt", "words", "ws")

    def __init__(self, start: int, stmt: int):
        self.start = start
        self.stmt = stmt
        self.words: list[tuple[int, int]] = []
        self.ws: int | None = None


def lex(text: str) -> Lexed:
    out = Lexed(text)
    n = len(text)
    i = 0
    # Each frame: [kind, paren_depth_at_open, open_index, Command|None]. kinds:
    # code, cmdsub, backtick, procsub (each tracks its own simple commands), and
    # dq, param, arith, array (parts of the word their code frame is building).
    stack: list[list] = [["code", 0, -1, Command(0, 0)]]
    pending_heredocs: list[tuple[str, bool]] = []
    paren_depth = 0

    def top() -> str:
        return stack[-1][0]

    def code_frame() -> list:
        for f in reversed(stack):
            if f[0] in CODE_KINDS:
                return f
        return stack[0]

    def word_start(idx: int) -> bool:
        return idx == 0 or text[idx - 1] in " \t\n;&|()<>"

    def touch(idx: int) -> None:
        cmd = code_frame()[3]
        if cmd.ws is None:
            cmd.ws = idx

    def end_word(idx: int) -> None:
        cmd = stack[-1][3]
        if cmd.ws is not None:
            cmd.words.append((cmd.ws, idx))
            cmd.ws = None

    def end_command(idx: int, new_statement: bool, width: int = 1) -> None:
        f = stack[-1]
        end_word(idx)
        f[3] = Command(idx + width, idx + width if new_statement else f[3].stmt)

    def open_sub(kind: str, at: int, depth: int, body: int) -> None:
        pf = code_frame()
        parent = pf[3]
        out.subs[at] = (parent, len(parent.words))
        out.sub_frame[at] = (pf[0], pf[2])
        out.subs_of.setdefault(id(parent), []).append(at)
        stack.append([kind, depth, at, Command(body, body)])

    def close_sub(idx: int) -> None:
        end_word(idx)
        out.sub_close[stack[-1][2]] = idx
        stack.pop()

    while i < n:
        c = text[i]
        kind = top()

        if kind in CODE_KINDS:
            out.code[i] = True
            if c == "\\" and i + 1 < n:
                out.code[i + 1] = True
                if text[i + 1] == "\n":
                    end_word(i)  # a line continuation separates words, like a space
                else:
                    touch(i)
                i += 2
                continue
            if c == "\n":
                end_command(i, True)
                i += 1
                if pending_heredocs:
                    i = _skip_heredoc_bodies(text, i, pending_heredocs)
                    pending_heredocs = []
                continue
            if c in " \t":
                end_word(i)
                i += 1
                continue
            if c == "#" and word_start(i):
                j = text.find("\n", i)
                i = n if j == -1 else j
                continue
            if c == "'":
                touch(i)
                j = text.find("'", i + 1)
                i = n if j == -1 else j + 1
                continue
            if c == "$" and i + 1 < n and text[i + 1] == "'":
                touch(i)
                i = _skip_ansi_c(text, i + 2)
                continue
            if c == '"':
                touch(i)
                stack.append(["dq", paren_depth, i, None])
                i += 1
                continue
            if c == "`":
                if kind == "backtick":
                    close_sub(i)
                else:
                    touch(i)
                    open_sub("backtick", i, paren_depth, i + 1)
                i += 1
                continue
            if text.startswith("$((", i):
                touch(i)
                stack.append(["arith", paren_depth, i, None])
                i += 3
                continue
            if text.startswith("$(", i):
                touch(i)
                paren_depth += 1
                open_sub("cmdsub", i, paren_depth, i + 2)
                i += 2
                continue
            if text.startswith("${", i):
                touch(i)
                stack.append(["param", paren_depth, i, None])
                i += 2
                continue
            if c == "(":
                if i > 0 and text[i - 1] == "=":
                    # `name=(...)`: an array assignment, part of its word.
                    touch(i)
                    stack.append(["array", paren_depth, i, None])
                    i += 1
                    continue
                paren_depth += 1
                if i > 0 and text[i - 1] in "<>":
                    # `<(...)` / `>(...)`: a process substitution, whose status
                    # the shell never reports.
                    touch(i)
                    open_sub("procsub", i - 1, paren_depth, i + 1)
                else:
                    end_command(i, True)
                i += 1
                continue
            if c == ")":
                if kind in ("cmdsub", "procsub") and stack[-1][1] == paren_depth:
                    close_sub(i)
                else:
                    end_command(i, True)
                paren_depth = max(0, paren_depth - 1)
                i += 1
                continue
            if text.startswith("<<<", i):
                # A here-string, not a heredoc. Stepping over only its first
                # `<` would leave `<< "$var"` behind to read as a heredoc whose
                # delimiter never appears, and the rest of the file as its body.
                touch(i)
                i += 3
                continue
            if text.startswith("<<", i):
                touch(i)
                m = re.match(r"<<(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([A-Za-z0-9_.-]+))", text[i:])
                if m:
                    delim = m.group(2) if m.group(2) is not None else (
                        m.group(3) if m.group(3) is not None else m.group(4))
                    pending_heredocs.append((delim, m.group(1) == "-"))
                    i += m.end()
                    continue
                i += 2
                continue
            if c == ";":
                end_command(i, True)
                i += 1
                continue
            if c == "&":
                if (i > 0 and text[i - 1] in "<>") or text.startswith("&>", i):
                    touch(i)  # `2>&1`, `&>file`: part of a redirection word
                    i += 1
                    continue
                width = 2 if text.startswith("&&", i) else 1
                end_command(i, True, width)
                i += width
                continue
            if c == "|":
                if i + 1 < n and text[i + 1] == "|":
                    end_command(i, True, 2)
                    i += 2
                    continue
                if i > 0 and text[i - 1] == ">":  # >| clobber
                    touch(i)
                    i += 1
                    continue
                width = 2 if i + 1 < n and text[i + 1] == "&" else 1
                out.pipes.append((i, width, True, paren_depth))
                held = [f for f in stack if f[0] in ("cmdsub", "backtick", "procsub")]
                out.frames[i] = (held[-1][0], held[-1][2]) if held else ("code", -1)
                out.stmt_of[i] = stack[-1][3].stmt
                end_command(i, False, width)
                i += width
                continue
            touch(i)
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
                stack.append(["arith", paren_depth, i, None])
                i += 3
                continue
            if text.startswith("$(", i):
                paren_depth += 1
                open_sub("cmdsub", i, paren_depth, i + 2)
                i += 2
                continue
            if c == "`":
                open_sub("backtick", i, paren_depth, i + 1)
                i += 1
                continue
            if text.startswith("${", i):
                stack.append(["param", paren_depth, i, None])
                i += 2
                continue
            if c == "|" and not text.startswith("||", i) and (i == 0 or text[i - 1] != "|"):
                out.pipes.append((i, 1, False, paren_depth))
            i += 1
            continue

        if kind in ("param", "array"):
            close = "}" if kind == "param" else ")"
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == close:
                stack.pop()
                i += 1
                continue
            if c == "'":
                j = text.find("'", i + 1)
                i = n if j == -1 else j + 1
                continue
            if c == '"':
                stack.append(["dq", paren_depth, i, None])
                i += 1
                continue
            if text.startswith("$(", i) and not text.startswith("$((", i):
                paren_depth += 1
                open_sub("cmdsub", i, paren_depth, i + 2)
                i += 2
                continue
            if text.startswith("${", i):
                stack.append(["param", paren_depth, i, None])
                i += 2
                continue
            if c == "`":
                open_sub("backtick", i, paren_depth, i + 1)
                i += 1
                continue
            i += 1
            continue

        if kind == "arith":
            if text.startswith("))", i):
                stack.pop()
                i += 2
                continue
            # A substitution inside `$(( ))` runs a command like any other:
            # `x=$(( $(p | head -1) + 1 ))` aborts under errexit.
            if text.startswith("$(", i) and not text.startswith("$((", i):
                paren_depth += 1
                open_sub("cmdsub", i, paren_depth, i + 2)
                i += 2
                continue
            if c == "`":
                open_sub("backtick", i, paren_depth, i + 1)
                i += 1
                continue
            i += 1
            continue

        i += 1  # unreachable in practice

    for f in stack:
        if f[3] is not None and f[3].ws is not None:
            f[3].words.append((f[3].ws, n))
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


def enables_errexit(lexed: Lexed) -> bool:
    """A `set` in code whose options include -e (in any cluster, e.g. -euo) or
    `-o errexit`. File level, like enables_pipefail, and `set +e` is not tracked:
    the error is in the loud direction."""
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
            if re.fullmatch(r"-[A-Za-z]*e[A-Za-z]*", w):
                return True
            if w == "errexit" and k > 0 and re.fullmatch(r"-[A-Za-z]*o", words[k - 1]):
                return True
    return False


# ─── Is the status read? ───────────────────────────────────────────────────
#
# A pipe into an early reader is a DEFECT only where the pipeline's exit status
# is consumed: there the writer's 141 is a wrong answer (#4072) or an abort.
# Where the shell discards the status, the reader has already produced the
# output that is used, and the 141 goes nowhere. Every admitted site is counted
# in the summary under its reason and listed by --show-admitted; none is silent.
# Row 5665386080 (#4249); the rule was ruled by master before it was built.

_ASSIGNMENT_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]*\])?\+?=")
_REDIRECTION = re.compile(r"\d*(?:<<<|<<-?|>>|<>|>\||<&|>&|&>>?|<|>)")
_DECL_BUILTINS = {"local", "declare", "typeset", "export", "readonly"}
_RESERVED_LEAD = {"if", "elif", "while", "until", "then", "do", "else", "!", "{", "time"}
_CONDITION_KEYWORD = re.compile(r"(?:if|elif|while|until|!)(?:\s|$)")
_STATUS_DISCARDED = re.compile(r"\|\|[ \t]*(?:true|:)[ \t]*(?:$|[;#\n)}])")

ADMIT_PROCSUB = "process substitution: the shell never reports its status"
ADMIT_ARGUMENT = "command substitution in a word of a command: the command's status replaces it"
ADMIT_DECLARATION = "assignment through local/declare/export/readonly: the builtin's status replaces the substitution's"
ADMIT_NOT_LAST = "not the last substitution of an assignment-only command: the shell reports the last one's status"
ADMIT_OR_TRUE = "operand of `|| true` / `|| :`: the author discarded the status"
ADMIT_UNREAD = "no errexit and nothing tests it: the status goes nowhere"


def _command_word(text: str, words: list[tuple[int, int]]) -> int:
    """Index of the command's name word, or -1 for a command of assignments and
    redirections only. Leading reserved words (`if`, `then`, `!`, ...) are not
    the name; a redirection operator written apart takes the next word as its
    target."""
    k, skip = 0, False
    while k < len(words) and text[words[k][0]:words[k][1]] in _RESERVED_LEAD:
        k += 1
    for j in range(k, len(words)):
        w = text[words[j][0]:words[j][1]]
        if skip:
            skip = False
            continue
        if _ASSIGNMENT_WORD.match(w):
            continue
        m = _REDIRECTION.match(w)
        if m:
            skip = m.end() == len(w)
            continue
        return j
    return -1


_BODY_END = re.compile(r"(?:fi|done|esac)(?:\s|;|$|\)|#)")
_BARE_EXIT = re.compile(r"(?:exit|return)[ \t]*(?:$|;|#|\n)")
LAST_OF_SUBSTITUTION = object()

ADMIT_SUB_NOT_LAST = ("a statement inside a command substitution that is not its last: "
                      "nothing reads its status")


def _statement_end(lexed: Lexed, idx: int) -> tuple[int, str]:
    """(index, delimiter) where the statement holding idx ends, at depth 0. Only
    CODE characters count (the lexer's mask), so a `;`, `(` or `)` inside a
    quoted argument does not end the statement; a comment runs to its newline;
    a backtick at depth 0 closes the backtick substitution holding idx."""
    text, code = lexed.text, lexed.code
    n, j, depth = len(text), idx, 0
    piped = False  # the last code token was a pipe: a newline continues the pipeline
    while j < n:
        c = text[j]
        if not code[j]:
            piped = False
            j += 1
            continue
        if c == "\\" and j + 1 < n:
            j += 2
            continue
        if c == "#" and (j == 0 or text[j - 1] in " \t\n;"):
            k = text.find("\n", j)
            if k == -1:
                return n, ""
            if piped and depth == 0:
                j = k + 1
                continue
            return k, "\n"
        if c in " \t" or (c == "\n" and piped and depth == 0):
            j += 1
            continue
        if c == "|" and not text.startswith("||", j) and (j == 0 or text[j - 1] != "|"):
            piped = True
            j += 2 if text.startswith("|&", j) else 1
            continue
        piped = False
        if c == "(":
            depth += 1
        elif c == ")":
            if depth == 0:
                return j, ")"
            depth -= 1
        elif depth == 0:
            if c in "\n;":
                return j, c
            if c == "`":
                return j, "`"
            if text.startswith("&&", j) or text.startswith("||", j):
                return j, text[j:j + 2]
        j += 1
    return n, ""


def _next_statement(text: str, j: int) -> int:
    """Index of the next statement's first character after j: past blanks,
    `;`, newlines and whole comment lines."""
    n = len(text)
    while j < n:
        if text[j] in " \t;\n":
            j += 1
        elif text[j] == "#":
            k = text.find("\n", j)
            j = n if k == -1 else k + 1
        else:
            break
    return j


def _judge_statement(lexed: Lexed, start: int, at: int, errexit: bool, what: str,
                     tail: int | None = None, close: int | None = None):
    """(flagged, reason) for a statement - a bare pipeline, or an assignment
    whose status is its command substitution's - starting at `start`, or
    LAST_OF_SUBSTITUTION when it is the last statement of the substitution that
    closes at `close` (its status is then the substitution's). The statement's
    end is looked for from `tail` (default `at`): for an assignment, the end of
    its word, so an array's own `)` is not read as a subshell's."""
    text = lexed.text
    if _CONDITION_KEYWORD.match(text[start:at].lstrip()):
        return True, f"{what} is the condition of if/elif/while/until/!"
    if text[:start].rstrip(" \t\n").endswith(("&&", "||")):
        return True, f"{what} is an operand of && / ||"
    end, delim = _statement_end(lexed, at if tail is None else tail)
    if delim in ("&&", "||"):
        if delim == "||" and _STATUS_DISCARDED.match(text[end:]):
            return False, ADMIT_OR_TRUE
        return True, f"{what} is an operand of && / ||"
    nxt = _next_statement(text, end)
    if close is not None and nxt >= close:
        return LAST_OF_SUBSTITUTION
    after = text[nxt:]
    if after.startswith(("}", ")")) or delim == ")":
        return True, f"{what} ends a function or subshell body, which returns its status"
    if _BODY_END.match(after) or (delim == ";" and text.startswith(";;", end)):
        return True, f"{what} ends the body of an if/for/while/case, which takes its status"
    line = after.split("\n", 1)[0]
    if "$?" in line or "PIPESTATUS" in line:
        return True, "the next statement reads $? or PIPESTATUS"
    if _BARE_EXIT.match(after):
        return True, f"{what} is followed by a bare exit/return, which returns its status"
    if errexit:
        return True, f"{what} under errexit: a 141 aborts the script"
    if not after:
        return True, f"{what} is the file's last statement: its status is the script's exit status"
    return False, ADMIT_UNREAD


def _word(text: str, span: tuple[int, int]) -> str:
    return text[span[0]:span[1]]


def _judge_in_frame(lexed: Lexed, frame: tuple[str, int], start: int, at: int, errexit: bool,
                    what: str, tail: int | None = None) -> tuple[bool, str]:
    """A statement judged where it stands. At top level, by _judge_statement.
    Inside a command substitution, first by its position in the substitution's
    body - a condition, an &&/|| operand or a $? read there is a read, whatever
    holds the substitution (#4072's own shape: `echo "$(if p | grep -q x; ...)"`)
    - and, when it is the body's LAST statement, by what the substitution's
    status then means to the command holding it. Substitutions do not inherit
    errexit (bash's inherit_errexit is off unless a file turns it on)."""
    kind, opened = frame
    if kind == "procsub":
        return False, ADMIT_PROCSUB
    if kind == "code":
        return _judge_statement(lexed, start, at, errexit, what, tail)
    inner_errexit = errexit and "inherit_errexit" in lexed.text
    r = _judge_statement(lexed, start, at, inner_errexit, what, tail, close=lexed.sub_close.get(opened))
    if r is LAST_OF_SUBSTITUTION:
        return _judge_substitution(lexed, opened, errexit)
    flagged, reason = r
    if not flagged and reason == ADMIT_UNREAD:
        return False, ADMIT_SUB_NOT_LAST
    return flagged, reason


def _judge_substitution(lexed: Lexed, opened: int, errexit: bool) -> tuple[bool, str]:
    """Whether the status of the substitution opened at `opened` is read. The
    shell reports it only for a command with no command name - assignments and
    redirections alone - and then only the LAST substitution's: `x="a $(..)"`
    and `arr=($(..))` are judged as statements; `x=$(..) y=$(true)`,
    `FOO=$(..) cmd` and an argument (`fail "$(..)"`) are not."""
    text = lexed.text
    parent, w = lexed.subs[opened]
    name = _command_word(text, parent.words)
    if name >= 0:
        if w > name and _word(text, parent.words[name]) in _DECL_BUILTINS:
            return False, ADMIT_DECLARATION
        return False, ADMIT_ARGUMENT
    if w >= len(parent.words) or not _ASSIGNMENT_WORD.match(_word(text, parent.words[w])):
        return False, ADMIT_ARGUMENT  # a redirection's target
    in_assignments = [o for o in lexed.subs_of.get(id(parent), [])
                      if _ASSIGNMENT_WORD.match(_word(text, parent.words[lexed.subs[o][1]]))]
    if opened != max(in_assignments):
        return False, ADMIT_NOT_LAST
    return _judge_in_frame(lexed, lexed.sub_frame[opened], parent.stmt, opened, errexit, "an assignment",
                           tail=max(parent.words[i][1] for i in range(w, len(parent.words))))


def classify(lexed: Lexed, idx: int, errexit: bool) -> tuple[bool, str]:
    """(flagged, reason) for the code pipe at idx: judged where it stands, and
    outward through every substitution whose status its status becomes."""
    frame = lexed.frames.get(idx, ("code", -1))
    return _judge_in_frame(lexed, frame, lexed.stmt_of.get(idx, 0), idx, errexit, "a statement")


# ─── Inline allow ──────────────────────────────────────────────────────────
#
# `# pipefail-ok: <reason>` on the statement's first line, or on the line the
# pipe is on, accepts a flagged site and lists it in the report. An allow with
# no reason, and an allow that accepts nothing (its line has no flagged site),
# are findings in their own right, so an allow can neither be bare nor outlive
# the code it was written for.

_ALLOW = re.compile(r"#[ \t]*pipefail-ok:(?P<reason>[^\n]*)")


def allows_of(lexed: Lexed) -> dict[int, str]:
    """Line number -> stripped reason, for every allow comment in the file."""
    text, out = lexed.text, {}
    for m in _ALLOW.finditer(text):
        # A comment in code only: not a `#` inside a string or a heredoc body,
        # and not one inside a word (`${#x}`).
        at = m.start()
        if not lexed.code[at] or (at > 0 and text[at - 1] not in " \t\n;&|()<>"):
            continue
        out[text.count("\n", 0, m.start()) + 1] = m.group("reason").strip()
    return out


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


def find_hits(lexed: Lexed, display: str, errexit: bool = True):
    """(hits, quoted, admitted, pipe_lines): hits are the flagged sites, each
    (display, first line, reader, statement, reason, pipe line); admitted the
    sites whose status is discarded, in the same shape."""
    text = lexed.text
    hits, quoted, admitted = [], [], []
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
        pipe_line = text.count("\n", 0, idx) + 1
        if not in_code:
            quoted.append((display, lineno, kind, line.strip(), "", pipe_line))
            continue
        flagged, reason = classify(lexed, idx, errexit)
        (hits if flagged else admitted).append((display, lineno, kind, line.strip(), reason, pipe_line))
    return hits, quoted, admitted


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
    ap.add_argument("--show-admitted", action="store_true",
                    help="list the sites admitted because their status is discarded, with the reason")
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
    hits, quoted, admitted, allowed, allow_findings = [], [], [], [], []
    for root, f, display, lexed in files:
        own = enables_pipefail(lexed)
        inherited = not own and (under_lib(root, f) or f.name in sourced)
        sets_it += own
        inherits += inherited
        allows = allows_of(lexed)
        used: set[int] = set()
        if own or inherited:
            # A lib/ or sourced file cannot know its caller's options, WHETHER OR
            # NOT it sets pipefail itself, so it is judged under errexit: the
            # stricter reading.
            errexit = under_lib(root, f) or f.name in sourced or enables_errexit(lexed)
            h, q, a = find_hits(lexed, display, errexit)
            for x in h:
                at = next((ln for ln in (x[1], x[5]) if ln in allows), None)
                if at is not None:
                    used.add(at)
                    if x[2] in readers:
                        allowed.append(x + (allows[at],))
                elif x[2] in readers:
                    hits.append(x)
            admitted.extend(x for x in a if x[2] in readers)
            quoted.extend(x for x in q if x[2] in readers)
        for ln, why in sorted(allows.items()):
            if not why:
                allow_findings.append(f"{display}:{ln}: pipefail-ok with an empty reason: an allow must say why")
            elif ln not in used:
                allow_findings.append(f"{display}:{ln}: stale pipefail-ok: no flagged pipeline on this line")
        if display == WITNESS and own:
            witness_ok = True

    if default_scan and not witness_ok:
        print(f"❌ the scan did not reach {WITNESS} as a pipefail file ({len(files)} scanned); "
              "its silence would not be evidence")
        return 2

    for display, lineno, kind, line, reason, _ in hits:
        print(f"{display}:{lineno}: {line}")
        print(f"    ^ {reason}")
    for finding in allow_findings:
        print(finding)
    for display, lineno, kind, line, reason, _, why in allowed:
        print(f"(allowed: {why}) {display}:{lineno}: {line}")
    if opts.show_admitted:
        for display, lineno, kind, line, reason, _ in admitted:
            print(f"(admitted: {reason}) {display}:{lineno}: {line}")
    if opts.show_quoted:
        for display, lineno, kind, line, _, _ in quoted:
            print(f"(quoted, not flagged) {display}:{lineno}: {line}")

    breakdown = ", ".join(f"{k} {sum(1 for h in hits if h[2] == k)}" for k in READERS if k in readers)
    reasons: dict[str, int] = {}
    for x in admitted:
        reasons[x[4]] = reasons.get(x[4], 0) + 1
    admitted_by = "; ".join(f"{n} {r}" for r, n in sorted(reasons.items(), key=lambda kv: -kv[1]))
    summary = (f"{len(hits)} hit(s) in {len({h[0] for h in hits})} file(s) [{breakdown}]; "
               f"{len(files)} *.sh scanned, {sets_it + inherits} in pipefail scope "
               f"({sets_it} set it, {inherits} under lib/ or sourced), "
               f"{len(quoted)} quoted site(s) not flagged; "
               f"{len(admitted)} admitted, status discarded ({admitted_by or 'none'}); "
               f"{len(allowed)} allowed by pipefail-ok; {len(allow_findings)} allow finding(s)")
    if allow_findings and not hits:
        print(f"❌ {summary}")
        print("   Every `# pipefail-ok:` must carry a reason and sit on a line with a flagged site.")
        return 1
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
