"""Go licence-header classifier shared by the rewrite script and the guard (#3726, #3307).

ONE PARSER, TWO CALLERS. scripts/licence/normalise-go-headers.py rewrites a
header and tests/regression-test-required/go_licence_header_test.sh refuses a
non-canonical one. If each carried its own idea of what a header IS, the
rewrite could produce a shape the guard rejects, or the guard could accept a
shape the rewrite would still change - and nothing would say which one was
wrong. So both import this module. It lives under tests/.../lib because that
directory reaches the community mirror and scripts/ does not: the guard is
proven against the staged mirror tree (scripts/ci/simulate-community-mirror.sh)
and must find its parser there, while the rewrite script is enterprise tooling.
(The mirror's own CI does not execute the regression suite; the proof is the
staged run, not a mirror job.)

THE CANONICAL HEADER is two adjacent comment lines, after any build constraint
and its blank line:

    // Copyright 2026 AxonFlow
    // SPDX-License-Identifier: BUSL-1.1

A doc comment may follow in the same paragraph (125 files attach one after a
bare `//`); that is text, not a licence statement, and is left alone. What is
NOT allowed anywhere before the package clause is text naming a second licence
or reproducing a licence's warranty paragraph. On 2026-09-08, 536 files carried
the Apache-2.0 boilerplate tail after that SPDX line, 18 carried "Licensed
under the Elastic License 2.0" with no SPDX line, 8 carried a prose BUSL block,
and 439 had no header at all. A file whose header names two licences is two
licence statements about one file, and AxonFlow's standing rule is that its
code is BUSL 1.1 source-available and never described otherwise.

WHAT THIS MODULE DOES NOT DECIDE. Only lines it recognises as licence
boilerplate are ever deleted (BOILERPLATE_RE). Anything else that looks like a
licence statement and is not the canonical pair makes the file UNRECOGNISED -
a licence-naming phrase inside a doc comment, a copyright line naming another
holder or written with a symbol the pattern does not know, an SPDX expression
("BUSL-1.1 OR MIT"), a tag or boilerplate sentence below the package clause, a
byte-order mark or CRLF endings. The rewrite refuses such a file and the guard
reports it, and a human reads it. A rewrite that deleted a line it did not
understand would be the defect this sweep exists to remove, one level down.

WHAT IS SCANNED WHERE. The SPDX tag and the boilerplate sentences are counted
over the WHOLE file: a second tag or a pasted warranty paragraph below the
package clause is still a second licence statement. The prose patterns
("MIT License", "GPL", "Licensed under") are checked in the pre-package region
only, because a test fixture or a doc comment may legitimately name another
project's licence in the body.

Exceptions live in go-licence-header-exceptions.tsv beside this module. Every
row is a path (exact, a `dir/` prefix, or a `*.ext` glob), a kind, and a
reason, and every row is checked in both directions: a row matching no file is
stale, and a `deferred` row under which every file is already canonical has
served its purpose and must be removed. See the TSV's header for the kinds.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

CANONICAL_SPDX = "BUSL-1.1"

# Directories no header rule applies to. node_modules/ and vendor/ hold other
# people's code; testdata/ is ignored by the Go toolchain by construction and
# holds fixtures whose bytes are the point. Nothing else is excluded on purpose.
SKIP_DIRS = {"node_modules", "vendor", "testdata", ".git"}

BUILD_RE = re.compile(r"^//go:build\b|^// \+build\b")
COPYRIGHT_RE = re.compile(r"^// Copyright (?:\(c\) )?(\d{4})(?:-(\d{4}))? AxonFlow\s*$")
SPDX_ANY = re.compile(r"SPDX-License-Identifier:")
# A single identifier, never an expression: "BUSL-1.1 OR MIT" is two licences.
SPDX_RE = re.compile(r"^// SPDX-License-Identifier: ([A-Za-z0-9.+-]+)$")
# "(c)" alone enumerates cases in doc comments ("(c) load succeeds"); it is a
# copyright mark only with a year beside it.
COPYRIGHT_WORD = re.compile(r"copyright|©|\(c\)\s*\d{4}", re.I)
APACHE_URL = re.compile(r"apache\.org/licenses/LICENSE-2\.0")
PACKAGE_RE = re.compile(r"^package\s+\w+")
BARE_RE = re.compile(r"^//\s*$")

# Every line the rewrite is allowed to DELETE. Each is a sentence of the
# Apache-2.0 boilerplate tail, of the prose BUSL block, of the Elastic License
# 2.0 template (18 enterprise-tagged files carried it on 2026-09-08 although
# ADR-014 rejected ELv2; master's ruling for W0-E: a remnant of a rejected
# option, removed like the Apache tail), or a URL one of them points at.
BOILERPLATE_SENTENCES = (
    r"Licensed under the (Business Source License 1\.1|Apache License, Version 2\.0) \(the \"License\"\);?",
    r"Licensed under the Elastic License 2\.0 \(ELv2\)",
    r"Enterprise features - not available in Community distribution",
    r"you may not use this file except in compliance with the License\.",
    r"You may obtain a copy of the License (at|in the LICENSE file or at)",
    r"https?://www\.apache\.org/licenses/LICENSE-2\.0",
    r"https?://mariadb\.com/bsl11/",
    r"Unless required by applicable law or agreed to in writing, software",
    r"distributed under the License is distributed on an \"AS IS\" BASIS,",
    r"WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied\.",
    r"See the License for the specific language governing permissions and",
    r"limitations under the License\.",
)
# A whole `//` line that is one of those sentences: what the rewrite may delete.
BOILERPLATE_RE = re.compile(r"^//\s*(" + "|".join(BOILERPLATE_SENTENCES) + r")\s*$")
# The sentences unanchored, plus the licence NAMES, for the body scan below the
# package clause: a warranty paragraph inside a /* */ block, an indented `//`
# line inside a function, or "Licensed under the Apache License" in any
# wrapping is still a licence statement. Measured on 2026-09-08: widening the
# body scan to the names reddens no real file.
BODY_LICENCE_RE = re.compile(
    "|".join(BOILERPLATE_SENTENCES)
    + r"|Apache License|Elastic License|MIT License|\bLicensed under\b|General Public License",
    re.I,
)

# Text that names a licence other than the SPDX identifier, or reproduces a
# licence's warranty paragraph. Matched over the whole pre-package region so a
# tail pasted below a doc comment, or inside a /* */ block, is still found.
OTHER_LICENCE_PATTERNS = (
    ("apache.org/licenses", re.compile(r"apache\.org/licenses", re.I)),
    ("Apache License", re.compile(r"Apache License", re.I)),
    ("Elastic License", re.compile(r"Elastic License", re.I)),
    ("MIT License", re.compile(r"\bMIT License\b", re.I)),
    ("GPL", re.compile(r"\bA?L?GPL\b|General Public License", re.I)),
    ("licence identifier", re.compile(r"\b(Apache-2\.0|BSD-[23]-Clause|MPL-2\.0|L?GPL-[23]\.0(?:-or-later|-only)?|AGPL-3\.0(?:-or-later|-only)?)\b")),
    ("Licensed under", re.compile(r"\bLicensed under\b", re.I)),
    ("warranty paragraph", re.compile(r"WITHOUT WARRANTIES OR CONDITIONS|limitations under the License", re.I)),
)


def line_kind(l: str) -> str:
    """C copyright, S spdx, b boilerplate, _ bare `//`, t anything else."""
    if COPYRIGHT_RE.match(l):
        return "C"
    if SPDX_RE.match(l):
        return "S"
    if BARE_RE.match(l):
        return "_"
    if BOILERPLATE_RE.match(l):
        return "b"
    return "t"


@dataclass
class Header:
    """The parsed leading region of a Go file, up to its package clause."""

    lines: list[str]
    build: list[str] = field(default_factory=list)              # constraint lines, verbatim
    paragraphs: list[tuple[int, list[str]]] = field(default_factory=list)  # (start line, `//` lines)
    body_start: int = 0                                          # first line outside the region

    @property
    def licence_index(self) -> int | None:
        for i, (_, para) in enumerate(self.paragraphs):
            if any(line_kind(l) in "CS" for l in para):
                return i
        return None

    def spdx_values(self) -> list[str]:
        return [SPDX_RE.match(l).group(1)
                for _, p in self.paragraphs for l in p if SPDX_RE.match(l)]

    def copyright_line(self) -> str | None:
        for _, p in self.paragraphs:
            for l in p:
                if COPYRIGHT_RE.match(l):
                    return l.rstrip()
        return None

    def region_text(self) -> str:
        return "\n".join(self.lines[: self.body_start])


def parse(text: str) -> Header:
    """Split a Go file into build constraints, leading `//` paragraphs, and body.

    The region ends at the first line that is neither a `//` comment, blank, a
    build constraint, nor inside a `/* */` block - normally `package`. A block
    comment before `package` is not a `//` paragraph (it stays where it is) but
    its text is part of `region_text()`, so the other-licence scan sees it.
    """
    lines = text.split("\n")
    h = Header(lines=lines)
    i = 0
    while i < len(lines) and BUILD_RE.match(lines[i]):
        h.build.append(lines[i])
        i += 1
    if h.build:
        while i < len(lines) and lines[i].strip() == "":
            i += 1
    para: list[str] = []
    para_start = i
    in_block = False
    while i < len(lines):
        l = lines[i]
        if in_block:
            in_block = "*/" not in l
            i += 1
            continue
        if l.startswith("//"):
            if not para:
                para_start = i
            para.append(l)
            i += 1
            continue
        if para:
            h.paragraphs.append((para_start, para))
            para = []
        if l.strip() == "":
            i += 1
            continue
        if l.lstrip().startswith("/*"):
            in_block = "*/" not in l
            i += 1
            continue
        break
    if para:
        h.paragraphs.append((para_start, para))
    h.body_start = i
    return h


def split_licence_paragraph(para: list[str]) -> tuple[list[str], list[str], list[str]]:
    """(text_before, licence_prefix, text_after) for the paragraph holding the header.

    The prefix is the run of licence-kind lines (C, S, boilerplate, bare `//`)
    starting at the first Copyright or SPDX line. Everything after it is doc
    text and is never touched.
    """
    kinds = [line_kind(l) for l in para]
    first = next(i for i, k in enumerate(kinds) if k in "CS")
    end = first
    while end < len(para) and kinds[end] != "t":
        end += 1
    return para[:first], para[first:end], para[end:]


@dataclass
class Verdict:
    path: str
    status: str
    spdx: list[str]
    other_licence: list[str]
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "canonical"


# Statuses the renderer can fix, and what each means.
REWRITABLE = {
    "apache-tail": "SPDX BUSL-1.1 followed by the Apache-2.0 URL and warranty paragraph",
    "prose-licence": "a prose licence block (BUSL, Elastic) and no SPDX line",
    "boilerplate": "boilerplate sentences beside the two canonical lines",
    "no-spdx": "a Copyright line with no SPDX identifier",
    "split-header": "the SPDX line in a different paragraph from the Copyright line",
    "misordered": "Copyright and SPDX present but not adjacent, or in the wrong order",
    "missing-header": "no Copyright or SPDX line before the package clause",
}
# Statuses that need a human or an exception row.
REFUSED = {"multiple-spdx", "other-spdx", "unrecognised"}
# What a `deferred` exception row may excuse: an absent or incomplete header,
# never a second licence.
DEFERRABLE = {"missing-header", "no-spdx", "split-header", "misordered"}


def _other_licence_names(region: str) -> list[str]:
    return [name for name, rx in OTHER_LICENCE_PATTERNS if rx.search(region)]


def classify(text: str, path: str = "") -> Verdict:
    h = parse(text)
    region = h.region_text()
    spdx = h.spdx_values()
    others = _other_licence_names(region)
    if text.startswith("// Code generated") or "\n// Code generated " in region:
        return Verdict(path, "generated", spdx, others, "generated file; the generator owns its header")
    if text.startswith("\ufeff"):
        return Verdict(path, "unrecognised", spdx, others, "byte-order mark before the header")
    if "\r\n" in text:
        return Verdict(path, "unrecognised", spdx, others, "CRLF line endings")
    tags = len(SPDX_ANY.findall(text))
    if tags > 1:
        return Verdict(path, "multiple-spdx", spdx, others, f"{tags} SPDX tags in the file")
    if tags == 1 and not spdx:
        return Verdict(path, "unrecognised", spdx, others,
                       "the SPDX tag is not a single `// SPDX-License-Identifier: <ID>` line before the package clause")
    body = "\n".join(h.lines[h.body_start:])
    if APACHE_URL.search(body) or BODY_LICENCE_RE.search(body):
        return Verdict(path, "unrecognised", spdx, others, "licence boilerplate below the package clause")
    for l in region.split("\n"):
        if COPYRIGHT_WORD.search(l) and not COPYRIGHT_RE.match(l) and not BOILERPLATE_RE.match(l):
            return Verdict(path, "unrecognised", spdx, others,
                           "a copyright line this parser does not know: " + l.strip()[:80])
    li = h.licence_index
    if li is None:
        return Verdict(path, "missing-header", spdx, others, REWRITABLE["missing-header"])
    _, para = h.paragraphs[li]
    before, prefix, after = split_licence_paragraph(para)
    kinds = "".join(line_kind(l) for l in prefix)
    has_boilerplate = "b" in kinds
    # Licence-naming text that is NOT a boilerplate line the renderer may delete
    # is text it would have to keep: refuse.
    kept_text = "\n".join(l for l in region.split("\n") if not BOILERPLATE_RE.match(l))
    if _other_licence_names(kept_text):
        return Verdict(path, "unrecognised", spdx, others,
                       "licence-naming text outside a boilerplate line: " + ", ".join(_other_licence_names(kept_text)))
    if spdx and spdx[0] != CANONICAL_SPDX:
        return Verdict(path, "other-spdx", spdx, others, f"SPDX is {spdx[0]}")
    if not spdx:
        if others:
            return Verdict(path, "prose-licence", spdx, others, "names " + ", ".join(others))
        return Verdict(path, "no-spdx", spdx, others, REWRITABLE["no-spdx"])
    if "S" not in kinds:
        return Verdict(path, "split-header", spdx, others, REWRITABLE["split-header"])
    if "apache.org/licenses" in others or "warranty paragraph" in others:
        return Verdict(path, "apache-tail", spdx, others, "names " + ", ".join(others))
    if has_boilerplate:
        return Verdict(path, "boilerplate", spdx, others, REWRITABLE["boilerplate"])
    canonical = kinds in ("CS", "CS_") and not (kinds == "CS_" and not after)
    if not canonical:
        return Verdict(path, "misordered", spdx, others, f"licence prefix is {kinds!r}; canonical is 'CS'")
    return Verdict(path, "canonical", spdx, others)


def render(text: str, copyright_line: str, spdx: str = CANONICAL_SPDX) -> str:
    """Return `text` with its licence prefix replaced by the two canonical lines.

    Only the licence prefix is replaced (or inserted after the build
    constraints when there is none); doc text in the same paragraph, the
    package clause and the body are carried through byte-for-byte, which the
    rewrite script re-parses and proves before writing.
    """
    h = parse(text)
    lines = list(h.lines)
    header = [copyright_line, f"// SPDX-License-Identifier: {spdx}"]
    li = h.licence_index
    if li is None:
        if h.build:
            i = len(h.build)
            while i < len(lines) and lines[i].strip() == "":
                i += 1
            return "\n".join(lines[: len(h.build)] + [""] + header + [""] + lines[i:])
        return "\n".join(header + [""] + lines)

    start, para = h.paragraphs[li]
    before, prefix, after = split_licence_paragraph(para)
    sep = ["//"] if after and BARE_RE.match(prefix[-1]) else []
    new_para = before + header + sep + after
    lines[start : start + len(para)] = new_para
    # A split header: a later paragraph that is ONLY the SPDX line goes too.
    delta = len(new_para) - len(para)
    for pstart, p in h.paragraphs[li + 1 :]:
        if len(p) == 1 and SPDX_RE.match(p[0]):
            s = pstart + delta
            del lines[s]
            if s < len(lines) and lines[s].strip() == "" and s > 0 and lines[s - 1].strip() == "":
                del lines[s]
            break
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

KINDS = ("spdx", "generated", "deferred", "escalated")


@dataclass
class Exception_:
    pattern: str
    kind: str
    value: str          # for spdx:<ID>; otherwise ""
    reason: str
    matched: int = 0
    canonical: int = 0

    def matches(self, rel: str) -> bool:
        p = self.pattern
        if p.endswith("/"):
            return rel.startswith(p)
        if any(ch in p for ch in "*?["):
            return fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(os.path.basename(rel), p)
        return rel == p


def load_exceptions(tsv: Path) -> list[Exception_]:
    out: list[Exception_] = []
    for n, line in enumerate(tsv.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise ValueError(f"{tsv}:{n}: expected 3 tab-separated columns, got {len(parts)}")
        pattern, kind, reason = (p.strip() for p in parts)
        value = ""
        if kind.startswith("spdx:"):
            kind, value = "spdx", kind.split(":", 1)[1]
        if kind not in KINDS:
            raise ValueError(f"{tsv}:{n}: unknown kind {kind!r}; known: {', '.join(KINDS)}")
        if not reason:
            raise ValueError(f"{tsv}:{n}: every exception needs a reason")
        out.append(Exception_(pattern, kind, value, reason))
    return out


def go_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            if f.endswith(".go"):
                yield Path(dirpath) / f


@dataclass
class Finding:
    path: str
    verdict: Verdict
    exception: Exception_ | None
    problem: str            # "" when the guard accepts the file


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="surrogateescape")


def check_tree(root: Path, exceptions: list[Exception_]) -> tuple[list[Finding], list[str]]:
    """Classify every Go file under root against the exceptions.

    Returns (findings, stale_rows). A finding with an empty `problem` is a file
    the guard accepts.
    """
    findings: list[Finding] = []
    for exc in exceptions:
        exc.matched = exc.canonical = 0
    for p in go_files(root):
        rel = p.relative_to(root).as_posix()
        v = classify(read(p), rel)
        exc = next((e for e in exceptions if e.matches(rel)), None)
        problem = ""
        if exc is not None:
            exc.matched += 1
            if v.ok:
                exc.canonical += 1
            if exc.kind == "spdx":
                if v.spdx != [exc.value] or v.other_licence or v.status in REFUSED - {"other-spdx"}:
                    problem = (f"exception says SPDX {exc.value}, file has {v.spdx or 'none'}"
                               + (f" and names {', '.join(v.other_licence)}" if v.other_licence else "")
                               + (f" ({v.status}: {v.detail})" if v.status in REFUSED - {"other-spdx"} else ""))
            elif exc.kind == "generated" and v.status != "generated":
                problem = "listed as generated but carries no `Code generated` marker"
            elif exc.kind == "escalated":
                # An escalation excuses a header whose LICENCE is genuinely in
                # question while a named ruling is pending; that is what the
                # kind is for, so unlike `deferred` it may excuse a second
                # licence. Two things it may not do: excuse a file carrying
                # two SPDX identifiers, which is not a question anyone can
                # rule on, and stand without naming where the ruling lives.
                # Round 1 bounded `deferred` and left this kind with no branch
                # at all, so a row of it excused anything (master's R3, MAJOR-1).
                if v.status == "multiple-spdx":
                    problem = f"an escalated row cannot excuse {v.status}: {v.detail}"
                elif not re.search(r"#\d+", exc.reason):
                    problem = "an escalated row must name the issue the ruling is pending on (#NNNN)"
            elif exc.kind == "deferred" and not v.ok and v.status not in DEFERRABLE:
                # A deferral excuses a header that is missing or incomplete,
                # never one that names a second licence or that the parser
                # refuses; that is what `escalated` is for, and it is stale
                # the moment the ruling lands.
                problem = f"deferred row excuses only {sorted(DEFERRABLE)}, file is {v.status}: {v.detail}"
        elif not v.ok:
            problem = f"{v.status}: {v.detail}" if v.detail else v.status
        findings.append(Finding(rel, v, exc, problem))

    stale = []
    for exc in exceptions:
        if exc.matched == 0:
            stale.append(f"{exc.pattern} [{exc.kind}] matches no file; remove the row")
        elif exc.kind in ("deferred", "escalated") and exc.canonical == exc.matched:
            stale.append(f"{exc.pattern} [{exc.kind}] every matching file is canonical; remove the row")
    return findings, stale


def busl_count(findings: list[Finding]) -> int:
    return sum(1 for f in findings if f.verdict.spdx == [CANONICAL_SPDX])


def tree_of(rel: str) -> str:
    parts = rel.split("/")
    return "/".join(parts[:2]) if len(parts) > 2 else parts[0]
