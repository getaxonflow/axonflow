#!/usr/bin/env bash
# adr065_signoff_record_citations_test.sh - #4039
#
# SUBJECT: every backticked path the ADR-065 phase sign-off record cites is on
# the tree, every test a list item or table row cites is defined in a file that
# same item or row cites, and it cites no line number in the backticked forms
# below.
#
# THE DEFECT. technical-docs/architecture-decisions/ADR-065-phase-signoff-record.md
# read "Gate 15: GAP" and "Gate 19: GAP" after the tree had closed both (gate 15
# in 61897ec09, #3613; gate 19 in 8008ad675, #3697), and neither commit touched
# the record (#4039). The record is
# what a person reads to write the Phase 3 -> 4 entry. A line there that no
# longer describes the tree tells that reader work is outstanding that is done,
# or, after a deletion, that evidence exists that does not.
#
# FILE AND SYMBOL, NEVER A LINE NUMBER. A line number in a document drifts with
# every edit above it, and a guard that checks one either reds on unrelated
# edits or, checked loosely, passes on a citation that moved to the wrong line.
# So the unit here is a list item of the record or a table row. A list item is
# a `- ` line and every line after it up to the next `- ` line, `#` line or
# table row, blank lines included: an unindented paragraph after an item
# belongs to it, and a wrapped line that starts with `#` ends it. Then:
#   - every backticked path must exist, wherever in the record it appears. A
#     path here is a token of letters, digits, `_`, `.` and `-` with at least
#     one slash between them; a leading slash, a glob and a prose line number
#     ("line 120") are not read, so the record does not cite that way;
#   - every backticked `TestName` in an item or a table row must be defined in
#     a .go file that same item or row cites, directly or under a cited
#     directory. Text before the first item, or between a heading and the next
#     item, belongs to no unit, and a test named there is not checked;
#   - any backticked token carrying `:NNN`, `:NNN-MMM` or `#LNNN` fails: it is a
#     line-number citation.
#
# WHAT THIS CANNOT SEE. It does not judge whether a gate's STATUS word is right;
# that is a reading of the evidence, made when the line is written. It makes
# the evidence under every status a checked fact, so a status goes stale only
# together with a citation this test reports.
#
# The checker runs over seventeen planted records first, and each must be judged
# correctly before the real record is read.
#
# Run: bash tests/regression-test-required/adr065_signoff_record_citations_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RECORD="technical-docs/architecture-decisions/ADR-065-phase-signoff-record.md"
cd "$REPO_ROOT" || exit 1

python3 - "$RECORD" <<'PYEOF'
import os
import re
import sys
import tempfile

# A path is any backticked token with a slash in it, a directory's trailing
# slash included. Two alternatives with no nested optional quantifier: the
# first version nested `/?` inside a repeated group, and a token that could not
# close the match (`some/file.go:129`) backtracked exponentially and hung.
PATH = re.compile(r"`([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+/?|[A-Za-z0-9_.-]+/)`")
TEST = re.compile(r"`(Test[A-Za-z0-9_]+)`")
LINE = re.compile(r"`[^`\s]*(?::\d+|#L\d+)[^`]*`")
# Equal to what the record cites today: a parser that stopped seeing its
# citations would check nothing and pass, so a count below either fails. A
# change that drops evidence lowers these in the same diff, where a reviewer
# sees it.
MIN_PATHS, MIN_TESTS = 27, 25


def items(text):
    """The record's citing units: each list item (a line starting `- `, with
    its continuation) and each table row on its own. Table rows count because
    the Phase 3 -> 4 sign-off entry is written into the table."""
    out, cur = [], None
    for line in text.splitlines():
        if line.startswith("- "):
            if cur is not None:
                out.append(cur)
            cur = [line]
        # A heading or a table row ends an item; a blank line does not, because
        # an item can carry an indented paragraph after its own sub-list.
        elif line.startswith(("#", "|")):
            if cur is not None:
                out.append(cur)
                cur = None
            if line.startswith("|"):
                out.append([line])
        elif cur is not None:
            cur.append(line)
    if cur is not None:
        out.append(cur)
    return ["\n".join(i) for i in out]


_READ = {}


def read(path):
    # Cached: an item that cites a directory reads every Go file under it once
    # per cited test otherwise.
    if path not in _READ:
        with open(path, encoding="utf-8", errors="replace") as fh:
            _READ[path] = fh.read()
    return _READ[path]


def check(text, root):
    problems, paths, tests = [], 0, 0
    for m in LINE.finditer(text):
        problems.append("%s cites a line number; cite the file and the symbol, a line drifts" % m.group(0))
    # Existence is checked over the whole record, so a path in a paragraph
    # outside any item is held to the tree as well.
    for p in PATH.findall(text):
        if os.path.exists(os.path.join(root, p)):
            paths += 1
        else:
            problems.append("cited path %s is not on the tree" % p)
    for item in items(text):
        files = []
        for p in PATH.findall(item):
            full = os.path.join(root, p)
            if not os.path.exists(full):
                continue  # reported above
            if os.path.isdir(full):
                for dp, _, fs in os.walk(full):
                    files += [os.path.join(dp, f) for f in fs if f.endswith(".go")]
            elif full.endswith(".go"):
                files.append(full)
        for name in TEST.findall(item):
            tests += 1
            defined = re.compile(r"^func\s+%s\s*\(" % re.escape(name), re.M)
            if not any(defined.search(read(f)) for f in files):
                cited = sorted({os.path.relpath(f, root) for f in files})
                problems.append("%s is not defined in any Go file its item cites (%s)"
                                % (name, ", ".join(cited[:4]) + (" ..." if len(cited) > 4 else "") or "none"))
    return problems, paths, tests


def self_test():
    failures = []
    with tempfile.TemporaryDirectory(prefix="adr065-citations.") as root:
        os.makedirs(os.path.join(root, "a"))
        os.makedirs(os.path.join(root, "c"))
        with open(os.path.join(root, "a", "b_test.go"), "w") as fh:
            fh.write("package a\n\nfunc TestReal(t *testing.T) {}\n")
        with open(os.path.join(root, "c", "d_test.go"), "w") as fh:
            fh.write("package c\n\nfunc TestOther(t *testing.T) {}\n")
        os.makedirs(os.path.join(root, "e", "f"))
        with open(os.path.join(root, "e", "f", "g_test.go"), "w") as fh:
            fh.write("package f\n\nfunc TestDeep(t *testing.T) {}\n")
        cases = [
            ("a correct item passes", "- gate: `TestReal` (`a/b_test.go`)\n", False),
            ("a wrapped item passes", "- gate: `TestReal`\n  holds, in\n  (`a/b_test.go`)\n", False),
            ("a test under a cited directory passes", "- gate: `TestReal` in `a/`\n", False),
            ("a missing path fails", "- gate: `a/gone_test.go`\n", True),
            ("a line-number citation fails", "- gate: `TestReal` (`a/b_test.go:3`)\n", True),
            ("a line range fails", "- gate: `TestReal` (`a/b_test.go:3-5`)\n", True),
            ("a #L anchor fails", "- gate: `TestReal` (`a/b_test.go#L3`)\n", True),
            ("a gone path outside any item fails", "A paragraph citing `a/gone_test.go`.\n", True),
            ("a real path outside any item passes", "A paragraph citing `a/b_test.go`.\n", False),
            ("a directory cited in prose does not widen a test's lookup",
             "- gate: `TestOther` lives in c/, and `a/b_test.go` is cited\n", True),
            ("a multi-segment directory cited in prose does not widen a test's lookup",
             "- gate: `TestDeep` lives in e/f. The cited file is `a/b_test.go`.\n", True),
            ("a test renamed away fails", "- gate: `TestGone` (`a/b_test.go`)\n", True),
            ("a test defined only in a file another item cites fails",
             "- one: `c/d_test.go`\n- two: `TestOther` (`a/b_test.go`)\n", True),
            ("a test with no cited file on its item fails", "- gate: `TestReal` is the evidence\n", True),
            ("a heading ends an item", "- one: `a/b_test.go`\n## next\n`TestReal` alone\n", False),
            ("a table row's gone path fails", "| Phase 3 -> 4 | `a/gone_test.go` | - |\n", True),
            ("a table row's test must be defined in a file that row cites",
             "- one: `a/b_test.go`\n| row | `TestReal` | - |\n", True),
        ]
        for name, text, want_fail in cases:
            problems, _, _ = check(text, root)
            if bool(problems) != want_fail:
                failures.append("%s: want %s, got %s" % (name, "a failure" if want_fail else "none", problems or "none"))
    return failures, len(cases)


failures, n = self_test()
if failures:
    for f in failures:
        print("SELF-TEST FAIL: %s" % f)
    sys.exit(1)
print("self-test: %d planted records judged correctly" % n)

record = sys.argv[1]
problems, paths, tests = check(read(record), ".")
if paths < MIN_PATHS or tests < MIN_TESTS:
    problems.append("only %d paths and %d tests were checked (floors %d and %d); the parser has stopped seeing the "
                    "record's citations" % (paths, tests, MIN_PATHS, MIN_TESTS))
if problems:
    for p in problems:
        print("FAIL: %s" % p)
    print("Update %s in the same change that moved its evidence." % record)
    sys.exit(1)
print("PASS: %d cited paths and %d cited tests in %s resolve on the tree, with no line-number citation"
      % (paths, tests, record))
PYEOF
