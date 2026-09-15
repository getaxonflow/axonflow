#!/usr/bin/env bash
# Regression guard: every fixed absolute path the fleet bootstrap writes into a
# slot's .env must be qualified by the slot index, AND the per-slot $HOME must
# sit under that slot's runner work root.
#
# THE BUG CLASS. Eight runner slots share one host, so a path under
# /home/runner that is not slot-qualified is ONE directory for all eight.
# Instances found and fixed one at a time before the root was named:
#
#   ~/.cache/golangci-lint   763 MB, 57,974 files written in four hours
#   ~/go/bin                 one 41 MB golangci-lint for all eight slots;
#                            a slot exec'ing it mid-write gets exit 126
#   ~/.cache/go-build        "could not import fmt" - reads as a broken import
#   ~/.m2                    "../../../.m2: Cannot mkdir: Permission denied"
#   ~/.local/bin/trivy-bin   one 160 MB trivy; ejected a merge-queue entry
#
# GOCACHE and GOMODCACHE were named individually, which is how the class was
# found and also why it kept recurring: GOPATH was never named, so
# `go env GOPATH` still answered $HOME/go. Setting $HOME per slot moves all of
# them at once - and this guard exists so a future edit cannot add a sixth
# shared path back into the same file.
#
# THE SECOND RULE, AND IT IS NOT A STYLE PREFERENCE. actions/cache stores each
# member as `path.relative(GITHUB_WORKSPACE, file)` and passes `-P -C
# $GITHUB_WORKSPACE` on BOTH create and extract, so anything outside the
# workspace is archived as a `../` escape. This fleet's GITHUB_WORKSPACE is
# /home/runner/work/rN/<repo>/<repo> - one level deeper than GitHub's layout
# because of the rN - so a per-slot $HOME placed anywhere but under
# /home/runner/work/rN puts the SLOT INDEX inside the archive:
#
#   HOME=/home/runner/slots/rN      -> ../../../../slots/r3/.cache/...
#   HOME=/home/runner/work/rN/home  -> ../../home/.cache/...
#
# The first is saved on slot 3 and, restored on slot 7, extracts into slot 3's
# LIVE $HOME while slot 7 gets nothing: ~7/8 misses plus a concurrent write
# over a peer's cache, which is the corruption class the per-slot $HOME exists
# to remove. The second is index-free and still per-slot, because the `-C` on
# extract is the restoring slot's own workspace. Same mechanism as the ~/.m2
# failure in README limitation 2. The work root is also the only tree the
# nightly reaper owns, so a $HOME outside it is a tree nothing reclaims.
#
# WHAT IS CHECKED, and why it is a text check rather than a host check: the
# bootstrap is the only tree artifact that decides this. The live host's state
# is not in the repo, so a guard cannot assert it; what a guard CAN assert is
# that the script which builds any future host writes no shared path. Applying
# it to the running host is a separate, operator-owned step - see the runbook
# in infrastructure/ci-runners/README.md.
#
# THE RULES, each pinned in both directions by a mutation below:
#
#   1. The per-slot loop exists and this guard can read env assignments out of
#      it (NOLOOP / UNPARSED).
#   2. Any value beginning /home/runner/ contains the loop variable ($i).
#      /home/runner/work alone is exempt as the parent the runner is
#      configured with, listed rather than pattern-matched away (SHARED).
#   3. HOME is set, and slot-qualified (NOHOME / SHARED).
#   4. HOME sits under /home/runner/work/$i (OUTSIDE_WORKROOT).
#   5. The nightly reaper computes disk pressure BEFORE its first trim
#      (REAP_NOPRESSURE / REAP_ORDER).
#   6. The reaper never file-trims a Go MODULE cache (MODCACHE_TRIM).
#
# WHY RULES 5 AND 6 ARE IN THIS FILE. Both were review findings on the branch
# that introduced the per-slot $HOME, and both are the kind of correct-looking
# edit a reader cannot tell from the wrong one:
#
#   5. The pressure computation originally sat BELOW the Go-cache loop, so that
#      loop kept a hardcoded `-atime +7` and the pressure tier never reached
#      the Go build cache - the one cache actually filling this disk (#3922).
#      Moving a variable assignment back down is a one-line diff.
#   6. Adding `.gomodcache` to one of the `find -delete` loops reads as an
#      obvious omission being fixed. It is not: deleting ONE .go file out of an
#      extracted module@version tree does not produce a cache miss, it produces
#      `undefined: <Symbol>` inside a third-party module the author never
#      touched. Driven, with the zip still present in cache/download. Removing
#      the whole module@version DIRECTORY is the safe unit and re-extracts
#      offline with GOPROXY=off. Until something implements that (#3922) the
#      module cache is bounded by nothing ON PURPOSE, and this rule says so in
#      code rather than in a comment nobody has to read.
#
# EVERY RULE IS ON THE PROPERTY, NOT ON A SPELLING. An earlier version of this
# guard anchored its controls on the exact literal values in the file, so
# CHANGING HOME to a different but correct per-slot path made the guard
# report "a missing per-slot HOME went unnoticed" - a false red on the fix.
# Control 5 below plants exactly that and asserts the guard stays GREEN.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BOOTSTRAP="$REPO_ROOT/infrastructure/ci-runners/runner-bootstrap.sh"

# The community sync strips infrastructure/ wholesale but does NOT strip this
# directory, so this file ships to the public mirror where the script it reads
# cannot exist. On a mirror checkout there is nothing to assert and nothing to
# hide; in an enterprise tree a missing bootstrap is a failure, never a skip,
# so this guard cannot pass vacuously where it is meant to bite.
if [ ! -f "$BOOTSTRAP" ]; then
  if [ -d "$REPO_ROOT/ee" ]; then
    echo "FAIL: $BOOTSTRAP not found in an enterprise tree - this guard cannot vacuously pass"
    exit 1
  fi
  echo "SKIP: community checkout (no infrastructure/); this guard runs in the enterprise repository"
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "FAIL: python3 is unavailable; a guard that cannot parse the bootstrap must not report success"
  exit 1
fi

check() {
  python3 - "$1" <<'PY'
import io, re, sys

path = sys.argv[1]
src = io.open(path, encoding='utf-8').read()

# The per-slot loop. Everything this guard judges is inside it.
m = re.search(r'^for i in 1 2 3 4 5 6 7 8; do$(.*?)^done$', src, re.M | re.S)
if not m:
    print('0 0')
    print('NOLOOP\tthe per-slot loop was not found; the guard cannot judge anything')
    raise SystemExit(0)
body = m.group(1)

# Only the lines that WRITE env values for a job, i.e. `echo "NAME=value"`.
STRICT = re.compile(r'^[ \t]*echo "([A-Za-z_][A-Za-z0-9_]*)=([^"\n]*)"', re.M)
# [^"\\n] rather than [^"]: in Python a negated class matches a newline, so
# `[^"]*"` would run past the end of the line to the next quote in the file
# and read a multi-line continuation as one tidy assignment.
env_lines = STRICT.findall(body)

# ANTI-VACUITY, and it is a cross-check rather than a magic number. A floor of
# N is cleared by deleting N+1 lines, and the earlier version's floor of 4 sat
# one line below the 6 that were there. This instead counts the same lines with
# a LOOSER pattern: if the loose count exceeds the strict one, the strict regex
# has stopped reading assignments that are still in the file, which is the only
# way this guard degrades into asserting things about an empty list.
LOOSE = re.compile(r'^[ \t]*echo "[A-Za-z_][A-Za-z0-9_]*=', re.M)
loose = len(LOOSE.findall(body))

problems = []
if loose > len(env_lines):
    problems.append('UNPARSED\t-\t%d echo-assignment line(s) in the loop, %d parsed'
                    % (loose, len(env_lines)))

# Directories the runner itself is configured with, allowed unqualified
# because they are parents rather than per-slot state.
EXEMPT = {'/home/runner/work'}

for name, value in env_lines:
    # HOME is judged on its own below, against two rules rather than one.
    if name == 'HOME':
        continue
    if not value.startswith('/home/runner/'):
        continue
    if value.rstrip('/') in EXEMPT:
        continue
    if '$i' not in value:
        problems.append('SHARED\t%s\t%s' % (name, value))

print('%d %d' % (len(env_lines), len(problems)))
for p in problems:
    print(p)

# HOME itself must be set per slot: it is the root the others derive from.
home = [v for n, v in env_lines if n == 'HOME']
if not home:
    print('NOHOME\tHOME\tno per-slot HOME is set, so every $HOME-derived path is shared')
else:
    h = home[0]
    if '$i' not in h:
        print('SHARED\tHOME\t%s' % h)
    # RULE 4, matched on the PROPERTY: the value must be inside this slot's
    # runner work root. Any spelling of the leaf is accepted - what is asserted
    # is the prefix, because that is what makes the actions/cache member
    # index-free and what puts the tree inside the reaper's roots.
    elif not re.match(r'^/home/runner/work/r?\$i(/|$)', h):
        print('OUTSIDE_WORKROOT\tHOME\t%s' % h)

# ---------------------------------------------------------------------------
# THE NIGHTLY REAPER, a different region of the same file: the heredoc the
# bootstrap writes to /etc/cron.daily/runner-reap. The delimiters are matched
# exactly as the README runbook's awk extraction matches them, so this guard
# and that runbook cannot disagree about where the script begins and ends.
# ---------------------------------------------------------------------------
r = re.search(r"^cat > /etc/cron\.daily/runner-reap <<'C'$(.*?)^C$", src, re.M | re.S)
if not r:
    print('NOREAPER\t-\tthe runner-reap heredoc was not found; rules 5 and 6 cannot be judged')
else:
    reaper = r.group(1).split('\n')
    # A comment is not code, and for rule 6 a comment is exactly where these
    # paths are SUPPOSED to appear.
    code = [(n, l) for n, l in enumerate(reaper) if not l.lstrip().startswith('#')]

    free_at = next((n for n, l in code if re.search(r'^\s*FREE_GB=', l)), None)
    del_at = next((n for n, l in code if '-delete' in l), None)
    if free_at is None:
        print('REAP_NOPRESSURE\t-\tthe reaper computes no FREE_GB, so no trim can be pressure-tiered')
    elif del_at is not None and del_at < free_at:
        print('REAP_ORDER\t-\ta `find -delete` at reaper line %d runs before FREE_GB at line %d, '
              'so that trim cannot see disk pressure' % (del_at + 1, free_at + 1))

    for n, l in code:
        if re.search(r'gomodcache|go/pkg/mod', l):
            print('MODCACHE_TRIM\t-\treaper line %d names a Go MODULE cache in code: %s'
                  % (n + 1, l.strip()))
PY
}

verdict() { # verdict <file> -> the rows only
  # CAPTURE THE STATUS DIRECTLY, NEVER THROUGH THE PIPE. The first version was
  # `check "$1" | tail -n +2 | sed ...`, whose exit status is sed's. A python3
  # that died on a mutant printed nothing, verdict emitted nothing, and
  # expect_clean reported CLEAN - a guard reporting success because its own
  # checker crashed. Control 12 plants exactly that.
  local raw st
  raw=$(check "$1"); st=$?
  if [ "$st" -ne 0 ]; then
    printf 'CHECKER_FAILED\t-\tthe checker exited %d on %s\n' "$st" "$1"
    return 0
  fi
  printf '%s\n' "$raw" | tail -n +2 | sed '/^$/d'
}

out=$(check "$BOOTSTRAP") || { echo "FAIL: the check did not run"; exit 1; }
counted=$(printf '%s\n' "$out" | head -1 | cut -d' ' -f1)
problems=$(printf '%s\n' "$out" | tail -n +2 | sed '/^$/d')

echo "ok: read ${counted} env assignment(s) from the per-slot loop"

if [ -n "$problems" ]; then
  echo "FAIL: the fleet bootstrap's per-slot .env is wrong:"
  printf '%s\n' "$problems" | sed 's/^/  /'
  echo ""
  echo "SHARED           - eight slots share one /home/runner, so an unqualified"
  echo "                   path there is ONE directory for all of them. Qualify it"
  echo "                   with the slot index (\$i), or set it under the per-slot"
  echo "                   \$HOME and let it follow."
  echo "NOHOME           - without a per-slot HOME every \$HOME-derived path becomes"
  echo "                   shared again, and none of them appear in this file at all."
  echo "OUTSIDE_WORKROOT - HOME must live under /home/runner/work/r\$i. actions/cache"
  echo "                   archives it as path.relative(GITHUB_WORKSPACE, ...), so a"
  echo "                   HOME outside the work root bakes the slot index into every"
  echo "                   cache member: saved on slot 3, restored on slot 7, it"
  echo "                   extracts into slot 3's live \$HOME and slot 7 gets nothing."
  echo "                   It is also outside every root the nightly reaper trims."
  echo "NOLOOP/UNPARSED  - this guard has stopped reading the file it judges."
  exit 1
fi
echo "ok: every /home/runner path written into a slot's .env is slot-qualified"
echo "ok: the per-slot HOME is under this slot's runner work root"

# ---------------------------------------------------------------------------
# Controls, both directions, on copies of the real script.
#
# Each control (a) plants, (b) proves the plant LANDED and changed the line
# count by exactly the amount it meant to, (c) proves the mutant still PARSES
# as bash - a plant that breaks the syntax would red everything and prove
# nothing - and (d) asserts a NAMED row, or asserts silence where silence is
# the correct answer.
#
# The anchors are SHAPES (`echo "HOME=`), never the literal value in the file.
# A control anchored on a value stops firing the day the value legitimately
# changes, and then reports its own blindness as a defect in the change.
#
# AND EVERY CONTROL MUST MEAN THE SAME THING UNDER BSD AND GNU. This file runs
# on a developer's macOS (BSD sed, BSD grep 2.6.0-FreeBSD) and on the fleet's
# Linux runners (GNU sed 4.9, GNU grep 3.8), and a control whose regex or
# whose mutation is spelled with a construct those two read differently does
# not fail loudly - it silently stops asserting on one of them. Two constructs
# are avoided here for exactly that reason, and both are mechanised rather than
# left to a reader: `\t` in a row pattern (control 13 and $TAB) and `\n` in a
# sed replacement (plant_after and the line-delta assertion in plant_verify).
# ---------------------------------------------------------------------------
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

# SC2016 (info) fires below and every instance is deliberate. (No count is
# stated: the commit that changes one changes the count, and then the comment
# is wrong without anything noticing.)
# (Do not begin this comment with the tool's name - a line starting "# shell"+
#  "check" is parsed as a DIRECTIVE, and an unparseable one is SC1073, an
#  ERROR that stops the whole file being analysed.)
# the plant text must contain a LITERAL $i, because that is the loop
# variable this guard checks for. Expanding it would plant a path with an empty
# index and the control would assert nothing. No `disable` directive is used -
# a mid-file one applies only to the next command and would be decoration.
# `shellcheck -S warning` on this file is clean.

CFAIL=0

# A TAB, BY VALUE, BECAUSE `\t` IN AN ERE IS NOT PORTABLE AND FAILS SILENTLY.
# The rows below are printed by python's '%s\t%s', so the separator is a real
# tab and the pattern that matches it must contain a real tab too. BSD grep
# 2.6.0-FreeBSD (macOS) matches a tab for `\t`; GNU grep 3.8 (this fleet's
# Linux runners, and CI) matches NOTHING - no error, no warning, a count of
# zero. Six controls here shipped with `\t` and every one of them reported
# "went unnoticed" on Linux while printing, on the next line, the very row it
# had failed to match. That is the worst shape a control can fail in: the
# detector fired, the matcher did not, and the red names the control's subject
# rather than the pattern.
TAB=$(printf '\t')

# ...and the rule is MECHANISED rather than remembered, because a `\t` is
# invisible in a diff and its red points somewhere else. This scans the file it
# is GIVEN - control 13 drives it 0 -> 1 on a fixture, then applies it to this
# file. `\s`, `\d` and `\w` are the same divergence in the other direction:
# they are GNU-only and match nothing under BSD.
unportable_row_patterns() { # unportable_row_patterns <file> -> UNPORTABLE rows
  python3 - "$1" <<'UNPORTABLE_PY'
import io, re, sys

src = io.open(sys.argv[1], encoding='utf-8').read()
BAD = re.compile(r'\\[tsdwSDW]')
for n, line in enumerate(src.split('\n'), 1):
    if not re.match(r'\s*expect_row\b', line):
        continue
    if BAD.search(line):
        print('UNPORTABLE\t%d\t%s' % (n, line.strip()))
UNPORTABLE_PY
}

BOOTSTRAP_LINES=$(wc -l < "$BOOTSTRAP" | tr -d ' ')

plant_verify() { # plant_verify <name> <outfile> <must-appear-regex> <line delta>
  local name="$1" out="$2" want="$3" delta="$4" got
  if [ ! -s "$out" ]; then
    echo "FAIL: control '$name' produced no file at all"; CFAIL=1; return 1
  fi
  # THE LINE COUNT IS PART OF THE PLANT, not decoration. A substitution that
  # quietly adds a line, or an added line that collapses onto the one above it,
  # can still satisfy the must-appear regex below while asserting something
  # other than what the control names. Pinning the delta makes those two shapes
  # distinguishable without anyone having to read the mutant.
  got=$(wc -l < "$out" | tr -d ' ')
  if [ "$got" -ne "$((BOOTSTRAP_LINES + delta))" ]; then
    echo "FAIL: control '$name' changed the line count by $((got - BOOTSTRAP_LINES)), not $delta; its result is VOID"
    CFAIL=1; return 1
  fi
  if ! grep -qE "$want" "$out"; then
    echo "FAIL: control '$name' did not mutate anything - the anchor moved"; CFAIL=1; return 1
  fi
  if ! bash -n "$out" 2>/dev/null; then
    echo "FAIL: control '$name' produced a file that does not parse as bash; its result is VOID"
    CFAIL=1; return 1
  fi
  return 0
}

plant() { # plant <name> <outfile> <sed-expr> <must-appear-regex>
  # sed is used ONLY for substitutions that stay on ONE line: `\( \)` and `\1`
  # are BRE in both BSD and GNU sed and produce a byte-identical file, which is
  # what the zero line delta asserts. ANYTHING THAT ADDS A LINE GOES THROUGH
  # plant_after - see its comment for why.
  local name="$1" out="$2" expr="$3" want="$4"
  sed "$expr" "$BOOTSTRAP" > "$out"
  plant_verify "$name" "$out" "$want" 0
}

plant_after() { # plant_after <name> <outfile> <anchor-regex> <new line> <must-appear>
  # PORTABLE BY CONSTRUCTION. The four controls that ADD a line were written as
  # a sed `s|<anchor>|<anchor>\n<new line>|`. GNU sed expands that `\n`, and the
  # sed on this machine (BSD, macOS 26.3) does too - but that has varied by
  # release, it is the one sed construct this file cannot verify on the machine
  # it happens to run on, and a plant that landed as ONE mangled line would
  # still satisfy an unanchored must-appear regex while asserting nothing at
  # all. python3 is the same program on both. `{indent}` in the new line
  # becomes the anchor line's own indentation.
  local name="$1" out="$2" anchor="$3" newline="$4" want="$5" st
  python3 - "$BOOTSTRAP" "$out" "$anchor" "$newline" <<'PLANT_AFTER_PY'
import io, re, sys

src, dst, anchor, new = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
lines = io.open(src, encoding='utf-8').read().split('\n')
rx = re.compile(anchor)
for n, line in enumerate(lines):
    if rx.search(line):
        indent = re.match(r'[ \t]*', line).group(0)
        lines.insert(n + 1, new.replace('{indent}', indent))
        io.open(dst, 'w', encoding='utf-8').write('\n'.join(lines))
        raise SystemExit(0)
raise SystemExit(3)
PLANT_AFTER_PY
  st=$?
  if [ "$st" -ne 0 ]; then
    echo "FAIL: control '$name' found no line matching /$anchor/ - the anchor moved"
    CFAIL=1; return 1
  fi
  plant_verify "$name" "$out" "$want" 1
}
expect_row() { # expect_row <name> <file> <row-regex> <human>
  local name="$1" f="$2" row="$3" human="$4" n
  n=$(verdict "$f" | grep -cE "$row")
  if [ "$n" -ge 1 ]; then
    echo "ok: $human IS caught"
  else
    echo "FAIL: $human went unnoticed (no row matching /$row/)"
    verdict "$f" | sed 's/^/      /'
    CFAIL=1
  fi
}
expect_clean() { # expect_clean <name> <file> <human>
  local f="$2" human="$3" n
  n=$(verdict "$f" | wc -l | tr -d ' ')
  if [ "$n" = "0" ]; then
    echo "ok: $human is correctly reported CLEAN"
  else
    echo "FAIL: $human produced a row; this guard is asserting a spelling, not the property"
    verdict "$f" | sed 's/^/      /'
    CFAIL=1
  fi
}

# 1 - a shared cache path reintroduced. Anchored on the NAME, so it keeps
#     working whatever the current per-slot value is.
plant shared-gocache "$tmp/c1.sh" \
  's|^\( *\)echo "GOCACHE=.*"|\1echo "GOCACHE=/home/runner/.cache/go-build"|' \
  'GOCACHE=/home/runner/\.cache/go-build' &&
  expect_row shared-gocache "$tmp/c1.sh" "^SHARED${TAB}GOCACHE${TAB}" "a reintroduced shared GOCACHE"

# 2 - the per-slot HOME removed entirely.
sed '/^ *echo "HOME=/d' "$BOOTSTRAP" > "$tmp/c2.sh"
if grep -qE '^ *echo "HOME=' "$tmp/c2.sh"; then
  echo "FAIL: control 'no-home' did not remove the HOME line"; CFAIL=1
elif ! bash -n "$tmp/c2.sh" 2>/dev/null; then
  echo "FAIL: control 'no-home' does not parse as bash; its result is VOID"; CFAIL=1
else
  expect_row no-home "$tmp/c2.sh" "^NOHOME${TAB}HOME${TAB}" "removing the per-slot HOME"
fi

# 3 - HOME present but NOT slot-qualified: the pre-change shared state.
plant unqualified-home "$tmp/c3.sh" \
  's|^\( *\)echo "HOME=.*"|\1echo "HOME=/home/runner/home"|' \
  'HOME=/home/runner/home' &&
  expect_row unqualified-home "$tmp/c3.sh" "^SHARED${TAB}HOME${TAB}" "an unqualified HOME"

# 4 - HOME slot-qualified but OUTSIDE the work root. THIS IS THE BLOCKING-2
#     REGRESSION: it is the value this branch was first filed with, and it is
#     invisible to every rule except rule 4.
plant home-outside-workroot "$tmp/c4.sh" \
  's|^\( *\)echo "HOME=.*"|\1echo "HOME=/home/runner/slots/r$i"|' \
  'HOME=/home/runner/slots/r\$i' &&
  expect_row home-outside-workroot "$tmp/c4.sh" "^OUTSIDE_WORKROOT${TAB}HOME${TAB}" \
    "a slot-qualified HOME outside the work root (the actions/cache member would carry the slot index)"

# 5 - A DIFFERENT BUT CORRECT SPELLING must stay green. Without this the guard
#     pins one literal and false-reds the next correct edit.
plant correct-alternate-home "$tmp/c5.sh" \
  's|^\( *\)echo "HOME=.*"|\1echo "HOME=/home/runner/work/r$i/homedir"|' \
  'HOME=/home/runner/work/r\$i/homedir' &&
  expect_clean correct-alternate-home "$tmp/c5.sh" \
    "a different but correct per-slot HOME under the work root"

# 6 - GOCACHE and GOMODCACHE dropped. CLEAN is the correct answer FOR THE RULES
#     THIS GUARD ENFORCES, and it is asserted rather than left to an
#     anti-vacuity floor to catch by accident: both default under $HOME
#     (GOCACHE -> $HOME/.cache/go-build, GOMODCACHE -> $HOME/go/pkg/mod), and
#     with a per-slot $HOME both are therefore slot-qualified, which is all
#     rules 1-4 judge.
#
#     THAT IS NOT A BLESSING TO DROP THEM, and the earlier version of this
#     comment said it was: it justified CLEAN with "the reaper trims
#     $HOME/.cache". True of GOCACHE. FALSE of GOMODCACHE, whose default
#     $HOME/go/pkg/mod is not a reaped root and deliberately cannot be one -
#     see rule 6 above and the reaper's own comment. Dropping GOMODCACHE would
#     move the module cache from an explicit per-slot path to an unreaped one,
#     which is a disk regression this guard is not built to see. Keeping the
#     control CLEAN and the reason CORRECT is the point: a reader must not
#     infer safety from silence.
sed -e '/^ *echo "GOCACHE=/d' -e '/^ *echo "GOMODCACHE=/d' "$BOOTSTRAP" > "$tmp/c6.sh"
if grep -qE '^ *echo "GO(MOD)?CACHE=' "$tmp/c6.sh"; then
  echo "FAIL: control 'no-gocache' did not remove the lines"; CFAIL=1
elif ! bash -n "$tmp/c6.sh" 2>/dev/null; then
  echo "FAIL: control 'no-gocache' does not parse as bash; its result is VOID"; CFAIL=1
else
  expect_clean no-gocache "$tmp/c6.sh" "dropping the now-redundant GOCACHE/GOMODCACHE"
fi

# 7 - the loop header renamed: the parser must SAY it read nothing rather than
#     report every rule as satisfied.
plant loop-gone "$tmp/c7.sh" \
  's|^for i in 1 2 3 4 5 6 7 8; do$|for i in $(seq 1 8); do|' \
  'for i in \$\(seq 1 8\); do' &&
  expect_row loop-gone "$tmp/c7.sh" "^NOLOOP${TAB}" "the per-slot loop being renamed out from under this guard"

# 8 - the echo shape changed so the STRICT parser stops matching while the
#     assignment is still in the file. This is what the anti-vacuity
#     cross-check is for, and a numeric floor cannot see it: the line is
#     still there, so the count does not drop.
python3 - "$BOOTSTRAP" "$tmp/c8.sh" <<'C8'
import io, re, sys
src = io.open(sys.argv[1], encoding="utf-8").read()
# A backslash-newline inside the double quotes: bash still assigns
# GOFLAGS=-modcacherw, `echo "GOFLAGS=` is still on the line so the LOOSE
# pattern counts it, and the STRICT pattern finds no closing quote on the line.
out, n = re.subn(r'^( *)echo "(GOFLAGS)=([^"\n]*)"$',
                 '\\1echo "\\2=\\3\\\\\\n\\1"', src, count=1, flags=re.M)
if n != 1:
    sys.stderr.write("control 8 anchor not found\n"); raise SystemExit(3)
io.open(sys.argv[2], "w", encoding="utf-8").write(out)
C8
if [ ! -s "$tmp/c8.sh" ]; then
  echo "FAIL: control 'unparsed' did not build"; CFAIL=1
elif ! grep -qE '^ *echo "GOFLAGS=' "$tmp/c8.sh"; then
  echo "FAIL: control 'unparsed' did not land - the assignment is gone, not unparsed"; CFAIL=1
elif ! bash -n "$tmp/c8.sh" 2>/dev/null; then
  echo "FAIL: control 'unparsed' does not parse as bash; its result is VOID"; CFAIL=1
else
  expect_row unparsed "$tmp/c8.sh" "^UNPARSED${TAB}" \
    "the strict parser silently losing an assignment the file still contains"
fi

# 10 - the EXEMPT set. /home/runner/work is allowed unqualified because it is
#      the parent the runner is configured with, not per-slot state. Nothing in
#      the bootstrap currently writes it as an env value, so without this
#      control the exemption is dead code that could be deleted or widened with
#      no test noticing. Plant a value of exactly that and require SILENCE.
plant_after exempt-parent "$tmp/c10.sh" \
  '^ *echo "GOFLAGS=' \
  '{indent}echo "RUNNER_WORKROOT=/home/runner/work"' \
  '^ *echo "RUNNER_WORKROOT=/home/runner/work"$' &&
  expect_clean exempt-parent "$tmp/c10.sh" \
    "an env value of exactly /home/runner/work (the exempt parent)"

# 10b - and the exemption must be EXACT, not a prefix. A sibling directory that
#       merely starts with the exempt string is shared state and must still be
#       caught, or the exemption is a hole rather than a carve-out.
plant_after exempt-is-not-a-prefix "$tmp/c10b.sh" \
  '^ *echo "GOFLAGS=' \
  '{indent}echo "SOMEDIR=/home/runner/workspace"' \
  '^ *echo "SOMEDIR=/home/runner/workspace"$' &&
  expect_row exempt-is-not-a-prefix "$tmp/c10b.sh" "^SHARED${TAB}SOMEDIR${TAB}" \
    "a shared path that merely starts with the exempt parent's name"

# 11 - RULE 5: the pressure computation moved below the first trim, which is
#      the exact defect this branch shipped in its first draft. Plant a trim
#      ABOVE FREE_GB rather than moving FREE_GB, because a sed that moves a
#      multi-line block is a mutation nobody can read.
plant_after reap-order "$tmp/c11.sh" \
  '^docker image prune -f$' \
  'find /home/runner/work/r*/.gocache -type f -atime +7 -delete 2>/dev/null' \
  '^find /home/runner/work/r\*/\.gocache -type f -atime \+7 -delete 2>/dev/null$' &&
  expect_row reap-order "$tmp/c11.sh" "^REAP_ORDER${TAB}" \
    "a reaper trim that runs before disk pressure is computed"

# 11b - RULE 5, the other direction: no FREE_GB at all.
plant reap-no-pressure "$tmp/c11b.sh" \
  's|^FREE_GB=.*|FREEGB_DISABLED=1|' \
  '^FREEGB_DISABLED=1' &&
  expect_row reap-no-pressure "$tmp/c11b.sh" "^REAP_NOPRESSURE${TAB}" \
    "a reaper with no pressure computation at all"

# 11c - RULE 6: the module cache added to a file-level trim. This is the
#       plausible-looking edit that turns an unbounded cache into a CORRUPT
#       one, and it is the reason rule 6 exists.
plant_after modcache-trim "$tmp/c11c.sh" \
  '^ *find "\$d" -type d -empty -delete 2>/dev/null$' \
  'find /home/runner/work/r*/.gomodcache -type f -amin +60 -delete 2>/dev/null' \
  '^find /home/runner/work/r\*/\.gomodcache -type f -amin \+60 -delete 2>/dev/null$' &&
  expect_row modcache-trim "$tmp/c11c.sh" "^MODCACHE_TRIM${TAB}" \
    "a file-level trim of the Go module cache"

# 11d - ANTI-VACUITY FOR RULES 5 AND 6. If the reaper heredoc stops being
#       findable, both rules would have nothing to judge and would report
#       nothing - i.e. silence indistinguishable from compliance. Rename the
#       delimiter and require the guard to SAY it lost the script.
plant reaper-gone "$tmp/c11d.sh" \
  "s|^cat > /etc/cron.daily/runner-reap <<'C'\$|cat > /etc/cron.daily/runner-reap <<'REAP'|" \
  "<<'REAP'" &&
  expect_row reaper-gone "$tmp/c11d.sh" "^NOREAPER${TAB}" \
    "the reaper heredoc being renamed out from under rules 5 and 6"

# 12 - THE CHECKER ITSELF FAILING must not read as CLEAN. verdict() used to
#      take its status from the end of a pipe, so a python3 that died printed
#      nothing, verdict emitted nothing, and every expect_clean above passed
#      vacuously. A path that does not exist makes the checker exit non-zero
#      without touching any file.
echo "note: the next two controls deliberately crash the checker on a path that"
echo "      does not exist. A python traceback below is EXPECTED, not a failure."
expect_row checker-crash "$tmp/definitely-not-a-file.sh" "^CHECKER_FAILED${TAB}" \
  "the checker crashing (its status must not be read through a pipe)"
expect_row checker-crash-not-clean "$tmp/definitely-not-a-file.sh" '.' \
  "a crashed checker producing at least one row rather than silence"

# 13 - THE PATTERN-PORTABILITY CHECK ITSELF, driven 0 -> 1 before it is trusted
#      on this file. A checker nobody has seen fire is indistinguishable from
#      one that cannot fire, and this one guards a defect that already shipped:
#      six controls above matched a tab with `\t`, which is a tab under BSD grep
#      and nothing at all under GNU grep, so every one of them reported its
#      subject "went unnoticed" on Linux while the row sat in the dump directly
#      underneath. The two fixtures are BUILT rather than written literally, so
#      that the scanner reads them as fixtures and not as two more defects in
#      this file.
python3 - "$tmp/c13-bad.sh" "$tmp/c13-good.sh" <<'C13'
import io, sys

esc = chr(92) + 't'
q = chr(39)
bad = ('expect_row planted "$f" ' + q + '^SHARED' + esc + 'PLANTED' + esc + q
       + ' "a pattern written with a backslash escape"\n')
good = ('expect_row planted "$f" "^SHARED${TAB}PLANTED${TAB}"'
        ' "a pattern written with a tab by value"\n')
io.open(sys.argv[1], "w", encoding="utf-8").write(bad)
io.open(sys.argv[2], "w", encoding="utf-8").write(good)
C13
n13=$(unportable_row_patterns "$tmp/c13-bad.sh" | grep -cE "^UNPORTABLE${TAB}")
if [ "$n13" -ge 1 ]; then
  echo "ok: an expect_row pattern that matches a tab with a backslash escape IS caught"
else
  echo "FAIL: an expect_row pattern written with a backslash escape went unnoticed"
  CFAIL=1
fi
if [ -z "$(unportable_row_patterns "$tmp/c13-good.sh")" ]; then
  echo "ok: an expect_row pattern that matches a tab by value is correctly reported CLEAN"
else
  echo "FAIL: a portable expect_row pattern was reported as unportable"
  unportable_row_patterns "$tmp/c13-good.sh" | sed 's/^/      /'
  CFAIL=1
fi
unportable=$(unportable_row_patterns "${BASH_SOURCE[0]}")
if [ -n "$unportable" ]; then
  echo "FAIL: this guard's own expect_row patterns do not mean the same thing under BSD and GNU grep:"
  printf '%s\n' "$unportable" | sed 's/^/      /'
  echo "      Match a tab with \${TAB} (a tab by value), never with a backslash escape."
  CFAIL=1
else
  echo "ok: every expect_row pattern in this file matches a tab by value, not by escape"
fi

# 9 - the unmutated script must report clean, or none of the above prove
#     anything about this rule.
expect_clean unmutated "$BOOTSTRAP" "the unmutated bootstrap"

if [ "$CFAIL" -ne 0 ]; then
  echo "FAILED: at least one control did not behave as required"
  exit 1
fi
echo "PASS: the fleet bootstrap writes no shared /home/runner path, and its per-slot HOME is inside the runner work root"
