#!/usr/bin/env bash
# lint-trap-handlers-exit.sh - a trap on INT or TERM must EXIT.
#
# Usage: bash scripts/lint-trap-handlers-exit.sh [ROOT]
#        bash scripts/lint-trap-handlers-exit.sh --self-test
#
#   ROOT defaults to the repository root DERIVED FROM THIS SCRIPT'S OWN PATH,
#   for the reason scripts/lint-hitl-queue-choke-point.sh states: a scan rooted
#   at $PWD is silently vacuous whenever CI's working directory differs from the
#   repo root, and a vacuous scan is a green board.
#
# THE INVARIANT
#
#   A `trap` registration whose signal list contains INT or TERM must run a
#   handler that EXITS. A handler that does not exit RETURNS TO THE SCRIPT BODY:
#   on Ctrl-C the cleanup runs, and then the script carries on against the state
#   it has just torn down, and cleanup runs a second time at exit.
#
#   Measured rather than asserted (#3715). Two reduced cases, same body:
#
#     trap cleanup EXIT INT TERM          -> rc=0,   body CONTINUED after SIGINT
#     trap cleanup EXIT                   -> rc=130, body NEVER reached
#     trap 'cleanup; exit 130' INT
#     trap 'cleanup; exit 143' TERM
#
#   The prescribed form runs cleanup TWICE on a signal - once from the signal
#   handler, once from the still-armed EXIT trap. Every handler in this tree is
#   idempotent (`rm -f`, `docker rm -fv ... || true`, `compose down`), and
#   running a teardown twice is a far smaller defect than running the body once
#   against a torn-down stack, so the duplicate is accepted rather than dodged
#   with a `trap - EXIT` inside each handler.
#
#   130 = 128 + SIGINT(2), 143 = 128 + SIGTERM(15).
#
# WHY A GUARD AND NOT FOUR EDITS
#
#   The correct and incorrect forms differ by whether the handler happens to end
#   in `exit`, which no reviewer reads for. Four sites were defective and three
#   were already correct when this was written, and the three correct ones are
#   what makes this guard's positive control real on day one: the self-test
#   asserts the guard PASSES them, so a matcher that flagged every `trap` would
#   fail its own suite rather than being merged and then muted.
#
# WHAT COUNTS AS "EXITS"
#
#   The handler text contains `exit` IN COMMAND POSITION, or it names a shell
#   function DEFINED IN THE SAME FILE whose body does. Command position means
#   `exit` preceded by nothing but whitespace, or by one of `; & | ( ) { }`, or
#   by `then` / `else` / `do`. That deliberately does NOT admit
#   `echo "exit now"`, where `exit` is preceded by a quote - the guard reports
#   it, which is a LOUD false positive a reviewer resolves in one line, rather
#   than a silent acceptance of a handler that only talks about exiting.
#
#   `trap - INT TERM` and `trap '' INT TERM` are a RESET and an IGNORE, not
#   handlers. Both are accepted; flagging them would be flagging `trap` itself,
#   which is the failure this guard's own header condemns.
#
# KNOWN LIMITS, stated rather than papered over
#
#   1. A handler function DEFINED IN A SOURCED FILE is not resolved, because
#      this guard reads one file at a time. It is reported as a violation with a
#      message that says so - the LOUD direction. No such case exists in this
#      tree; if one arrives, inline the `exit` in the trap string.
#   2. A trap registered through a VARIABLE (`$sig`, `"${SIGNALS[@]}"`) or built
#      by string concatenation is not matched. Same class as
#      lint-hitl-queue-choke-point.sh's Vector 4, and closing it honestly needs
#      a shell parser rather than a wider regex. Pinned as a negative fixture
#      below so nobody believes it is covered.
#   3. A trap whose registration is SPLIT ACROSS LINES with a backslash
#      continuation is matched on its first line only, so a handler whose `exit`
#      lives on the continuation reads as missing - LOUD again.
#   4. Only shell files are scanned: `*.sh`, or any file whose first line is a
#      sh/bash/zsh/dash/ksh shebang. A trap inside a `run:` block in a workflow
#      YAML is not seen. Recorded because it is a real gap, not because it is
#      acceptable; the four sites this guard was written for are all files.

set -euo pipefail

# ---------------------------------------------------------------------------
# is_shell_file FILE - true for *.sh or a file whose first line is a shell
# shebang. Deriving membership from the shebang rather than from an extension
# list is the point: the class is "files bash runs", and half this repo's
# executables have no extension at all.
# ---------------------------------------------------------------------------
is_shell_file() {
  case "$1" in
    *.sh) return 0 ;;
  esac
  local first
  # `tr -d '\0'`: the walk reaches binaries (fixtures, images, compiled test
  # helpers), and a command substitution over a NUL byte makes bash print a
  # warning to stderr on every one of them. A guard whose ordinary output is
  # five warnings trains the reader to skip its output.
  # LC_ALL=C, because BSD `tr` refuses a byte that is not valid in the runner's
  # locale with "Illegal byte sequence" - on every binary in the tree, on macOS
  # only. Same class as the perl-not-sed note below: a portability gap that
  # makes the guard noisy on one platform and quiet on the other.
  first=$(head -c 200 "$1" 2>/dev/null | LC_ALL=C tr -d '\0' | head -1 || true)
  case "$first" in
    '#!'*bash*|'#!'*/sh|'#!'*/sh\ *|'#!'*zsh*|'#!'*dash*|'#!'*ksh*|'#!'*env\ sh*) return 0 ;;
  esac
  return 1
}

# ---------------------------------------------------------------------------
# handler_exits FILE HANDLER - 0 when HANDLER exits, 1 when it does not, 2 when
# HANDLER names a function this file does not define.
#
# perl, not grep, because command position needs a lookbehind alternation and
# the GNU BRE form of it silently does nothing under BSD userland - the same
# portability trap that made a sibling guard weaker on macOS and green on
# Linux.
# ---------------------------------------------------------------------------
exits_in_command_position() {
  # /m so `^` anchors at every LINE start, not only at the start of the string.
  # Without it a function BODY - which begins with the newline after `{` - could
  # never satisfy the "preceded by nothing but whitespace" arm, and every
  # multi-line handler function read as non-exiting. Caught by fixture 4, which
  # is why that fixture asserts the ACCEPTING direction.
  printf '%s' "$1" | perl -0ne 'exit(/(?:^|[;&|(){}]|\bthen\b|\belse\b|\bdo\b)[ \t]*exit\b/ms ? 0 : 1)'
}

# function_body FILE NAME - the source of `NAME() { ... }`, both the one-line
# and the block form.
#
# Crude on purpose, and scoped to ONE function: it exists so a handler cannot be
# credited with an `exit` that belongs to a DIFFERENT function in the same file.
# A whole-file substring check is satisfied by the word appearing anywhere,
# which is the specific hole fixture 5 pins.
#
# Exits 1 when the file defines no such function, which the caller turns into a
# LOUD violation rather than a pass (KNOWN LIMIT 1).
function_body() {
  local file="$1" name="$2"
  awk -v want="$name" '
    # LAST DEFINITION WINS, not the first (E9). bash resolves a redefined
    # function to the most recent definition, so a file whose handler is
    # redefined must be judged on the live one. The first version exited on the
    # first match and credited a dead definition that exits.
    function emit() { lastbody = body; found = 1; inside = 0; depth = 0 }

    # THE PENDING RULE COMES FIRST. FP5: a header with the brace on the NEXT
    # line set pending and then `next`-ed out of the !inside rule, so the rule
    # meant to consume that brace never ran - awk evaluates rules in order and
    # the earlier `next` skipped it. Ordering, not logic, was the defect.
    pending {
      probe = $0; sub(/^[ \t]+/, "", probe)
      pending = 0
      if (probe ~ /^\{/) {
        inside = 1; depth = 1; body = ""
        rest = substr(probe, 2)
        n = gsub(/\{/, "{", rest); m = gsub(/\}/, "}", rest)
        depth += n - m
        if (depth <= 0) { body = rest; emit(); next }
        body = rest "\n"
      }
      next
    }

    !inside {
      line = $0
      sub(/^[ \t]+/, "", line)
      isfn = 0
      if (sub(/^function[ \t]+/, "", line)) isfn = 1
      hdr = ""
      if (index(line, want "()") == 1)       hdr = want "()"
      else if (index(line, want " ()") == 1) hdr = want " ()"
      else if (isfn && index(line, want) == 1 && \
               (length(line) == length(want) || substr(line, length(want)+1, 1) ~ /[ \t{]/)) hdr = want
      if (hdr == "") next
      rest = substr(line, length(hdr) + 1)
      ob = index(rest, "{")
      if (ob == 0) { pending = 1; next }
      tail = substr(rest, ob + 1)
      depth = 1
      n = gsub(/\{/, "{", tail); m = gsub(/\}/, "}", tail)
      depth += n - m
      if (depth <= 0) {
        cb = index(tail, "}")
        body = substr(tail, 1, cb - 1)
        emit(); next
      }
      inside = 1; body = tail "\n"; next
    }

    inside {
      # BRACE DEPTH over CODE ONLY (FP4, and R3 round 2 HIGH-1).
      #
      # Counting braces as CHARACTERS broke in both directions on text that is
      # not code, and the diagnostics lied about the cause:
      #   an unbalanced `{` in a comment or string -> depth never returns to 0
      #      -> "names handler X, which this file does not define", about a file
      #         that plainly defines it;
      #   an unbalanced `}` -> depth hits 0 early -> body truncated BEFORE the
      #      exit -> "handler never exits", about a handler that does.
      # Both RED A REQUIRED CHECK on correct code. The realistic input, given
      # this tree, is a `{` inside a COMMENT in a handler body.
      #
      # codeonly() blanks quoted strings and trailing comments before counting.
      # A heredoc body is skipped wholesale, because its payload is data.
      line = codeonly($0)
      n = gsub(/\{/, "{", line); m = gsub(/\}/, "}", line)
      depth += n - m
      body = body $0 "\n"
      if (depth <= 0) emit()
    }

    # codeonly - the line with quoted strings and a trailing # comment removed.
    #
    # Deliberately crude and deliberately BIASED: when it cannot tell, it keeps
    # the text, so the failure direction is "count a brace that is not code"
    # (which this guard already survives, because the body simply runs longer)
    # rather than "miss a brace that is". Heredoc payloads are skipped by the
    # hd state below, since `cat <<EOF ... EOF` can contain anything at all.
    function codeonly(t,   out, i, c, q, esc) {
      if (hd != "") { if (t ~ ("^[ \t]*" hd "[ \t]*$")) hd = ""; return "" }
      if (match(t, /<<-?[\"\x27]?[A-Za-z_][A-Za-z0-9_]*/)) {
        hd = substr(t, RSTART, RLENGTH)
        gsub(/^<<-?[\"\x27]?/, "", hd)
        gsub(/[\"\x27]/, "", hd)
      }
      out = ""; q = ""
      for (i = 1; i <= length(t); i++) {
        c = substr(t, i, 1)
        if (q != "") { if (c == q) q = ""; continue }
        if (c == "\"" || c == "\x27") { q = c; continue }
        if (c == "#" && (i == 1 || substr(t, i-1, 1) ~ /[ \t;]/)) break
        out = out c
      }
      return out
    }

    END { if (!found) exit 1; printf "%s", lastbody }
  ' "$file" 2>/dev/null || return 1
  return 0
}

handler_exits() {
  local file="$1" handler="$2"

  # A reset (`-`) or an ignore (`''`) is not a handler.
  case "$handler" in
    -|''|'""'|"''") return 0 ;;
  esac

  if exits_in_command_position "$handler"; then
    return 0
  fi

  # A bare word is a function name. Anything else is inline shell that we have
  # already searched, so it does not exit.
  case "$handler" in
    *[^A-Za-z0-9_:.-]*) return 1 ;;
  esac

  local body
  if ! body=$(function_body "$file" "$handler"); then
    return 2
  fi
  if exits_in_command_position "$body"; then
    return 0
  fi

  # ONE LEVEL OF DELEGATION. FP2: `cleanup() { rm -f x; die; }` with
  # `die() { exit 130; }` in the same file is a handler that exits, and the
  # first version called it a violation. Bounded to one hop deliberately - a
  # transitive walk needs a call graph, and the depth that matters in practice
  # is a `die`/`fail` helper one call away. A deeper chain is reported, which is
  # the LOUD direction and is stated in KNOWN LIMITS.
  local callee
  while IFS= read -r callee; do
    [ -z "$callee" ] && continue
    [ "$callee" = "$handler" ] && continue
    local sub
    if sub=$(function_body "$file" "$callee") && exits_in_command_position "$sub"; then
      return 0
    fi
  done < <(printf '%s' "$body" | LC_ALL=C grep -oE '(^|[;&|(){}[:space:]])[a-z_][a-z0-9_]*([[:space:]]*$|[[:space:]]*;)' | tr -d ' ;&|(){}')
  return 1
}


# split_traps FILE - prints `<lineno>:<one trap registration>` for EVERY trap on
# every line, not just a trap that begins the line.
#
# E1/E2/E3, all measured: the first version anchored on
# `^[[:space:]]*trap[[:space:]]`, so `[ -n "$X" ] && trap cleanup INT TERM`,
# `if true; then trap cleanup INT TERM; fi` and a SECOND trap after a first one
# on the same line were all invisible. E3 was the worst of the three: the line
# WAS matched, the parser returned the FIRST trap's handler (which exits), the
# guard passed, and the second registration was never looked at - a green result
# produced by examining the wrong half of a matched line.
#
# Splitting on `;`, `&&`, `||` and `then`/`do`/`else` gives one command per
# record, which is what the per-registration parser below already assumes.
# THE PERL PROGRAM LIVES IN A QUOTED HEREDOC, NOT IN A SINGLE-QUOTED ARGUMENT.
#
# Three times while writing this guard an APOSTROPHE inside a comment closed the
# enclosing `perl -ne '...'` string and turned the whole script into a bash
# syntax error - including once in a note that said "no apostrophes in this
# block". Discipline did not fix it three times, so the structure changes: a
# `<<'"'"'PERL'"'"'` heredoc quotes nothing and expands nothing, so any character may
# appear in the program or its comments.
# `|| true` is REQUIRED, not defensive: `read -d ''` returns NON-ZERO when it
# reaches EOF without finding the delimiter, which is ALWAYS the case for a
# heredoc. Under `set -e` the script then exits 1 at this line, printing
# nothing - a guard that reports failure by dying silently, which is
# indistinguishable from a violation it found and could not describe.
IFS= read -r -d '' SPLIT_TRAPS_PL <<'PERL' || true
next unless /^(\d+):(.*)$/s;
my ($n, $rest) = ($1, $2);
# A COMMENT LINE IS NOT A REGISTRATION. The old anchor (^\s*trap\s) excluded
# comments for free; splitting mid-line does not, and the first version of this
# splitter flagged this guard's own prose describing the evasions it closes.
next if $rest =~ /^\s*#/;
# ONE QUOTE-AWARE PASS splits on `;`, `&&` and `||`.
#
# R3 round 2: the `;` split was quote-aware and the very next line ran
# split(/&&|\|\|/) on RAW TEXT, so a handler carrying this repo's dominant
# cleanup idiom - trap 'docker rm -fv c || true' INT TERM - was cut INSIDE the
# quoted handler. The emitted record kept the opening `trap '...` and LOST THE
# SIGNAL LIST, so the INT/TERM test matched nothing and the registration was
# never examined at all. rc=0 on a handler that does not exit: a regression
# introduced by the fix for E1-E3, because the anchored form it replaced had
# captured the whole line.
my @cmds; my $cur = ""; my $q = "";
my @ch = split //, $rest;
for (my $i = 0; $i <= $#ch; $i++) {
  my $c = $ch[$i];
  if ($q ne "") { $cur .= $c; $q = "" if $c eq $q; next; }
  if ($c eq '"' or $c eq "'") { $q = $c; $cur .= $c; next; }
  if ($c eq ";") { push @cmds, $cur; $cur = ""; next; }
  if (($c eq "&" or $c eq "|") and $i < $#ch and $ch[$i+1] eq $c) {
    push @cmds, $cur; $cur = ""; $i++; next;
  }
  $cur .= $c;
}
push @cmds, $cur;
for my $c (@cmds) {
  $c =~ s/^\s*//;
  $c =~ s/^(then|do|else|elif)\s+//;
  # a `case` arm: `start) trap cleanup INT TERM ;;`
  $c =~ s/^[^()\s]*\)\s*//;
  $c =~ s/\s+(fi|done|esac)\s*$//;
  next unless $c =~ /^trap\s/;
  print "$n:$c\n";
}
PERL

# split_traps FILE - prints `<lineno>:<one trap registration>` for EVERY trap on
# every line, not just a trap that begins the line.
#
# E1/E2/E3, all measured: the first version anchored on
# `^[[:space:]]*trap[[:space:]]`, so a trap after `&&`, a trap inside
# `if ...; then ...; fi` and a SECOND trap after a first one on the same line
# were all invisible. E3 was the worst: the line WAS matched, the parser
# returned the FIRST trap (which exits), the guard passed, and the second
# registration was never looked at.
split_traps() {
  LC_ALL=C grep -n 'trap[[:space:]]' "$1" 2>/dev/null | perl -ne "$SPLIT_TRAPS_PL" || true
}

# ---------------------------------------------------------------------------
# scan ROOT - prints one `<relpath>:<lineno>: <reason>` line per violation.
# Nothing else reaches stdout, so the caller can count lines.
# ---------------------------------------------------------------------------
scan() {
  local root="$1"
  local f rel
  while IFS= read -r f; do
    is_shell_file "$f" || continue
    rel="${f#"$root"/}"
    # A trap registration, first token on the line. `grep -n` keeps the line
    # number so the violation is clickable.
    while IFS= read -r hit; do
      local lineno line
      lineno="${hit%%:*}"
      line="${hit#*:}"
      # `line` is now ONE registration, already isolated by split_traps.

      # Split into the handler argument and the signal list. The handler is
      # either a quoted string or a single bare word.
      local handler rest
      case "$line" in
        *[\'\"]*)
          handler=$(printf '%s' "$line" | perl -ne '
            if (/^\s*trap\s+'"'"'(.*)'"'"'\s+\S/) { print $1 }
            elsif (/^\s*trap\s+'"'"'([^'"'"']*)'"'"'\s*(.*)$/) { print $1 }
            elsif (/^\s*trap\s+"([^"]*)"\s*(.*)$/)          { print $1 }
            else { if (/^\s*trap\s+(\S+)\s*(.*)$/) { print $1 } }')
          rest=$(printf '%s' "$line" | perl -ne '
            if (/^\s*trap\s+'"'"'.*'"'"'\s+(\S.*)$/) { print $1 }
            elsif (/^\s*trap\s+'"'"'[^'"'"']*'"'"'\s*(.*)$/) { print $1 }
            elsif (/^\s*trap\s+"[^"]*"\s*(.*)$/)          { print $1 }
            else { if (/^\s*trap\s+\S+\s*(.*)$/) { print $1 } }')
          ;;
        *)
          handler=$(printf '%s' "$line" | perl -ne 'if (/^\s*trap\s+(\S+)\s*(.*)$/) { print $1 }')
          rest=$(printf '%s' "$line" | perl -ne 'if (/^\s*trap\s+\S+\s*(.*)$/) { print $1 }')
          ;;
      esac

      # Strip a trailing comment from the signal list so `trap x INT # note`
      # does not read INT out of the prose.
      rest="${rest%%#*}"
      # ...and NORMALISE the signal list before matching it. E4/E5/E6, measured:
      # `trap cleanup 'INT'`, `trap cleanup \"INT\" \"TERM\"` and a trailing
      # `trap cleanup TERM;` all went unseen, because the matcher tested for a
      # signal name surrounded by WHITESPACE and a quote or a semicolon breaks
      # that boundary. These are ordinary bash, not exotic - and the header
      # claims spelling coverage ("a census bounded by one spelling"), so a
      # fourth spelling walking past was the header being wrong rather than a
      # limit being accepted.
      rest=$(printf '%s' "$rest" | tr -d '"'\''' | tr ';' ' ')

      # Does the signal list name INT or TERM? SIGINT/SIGTERM and the numeric
      # forms 2/15 are the same signals under different spellings; a guard that
      # only knew the bare names would be a census bounded by one spelling.
      printf '%s' " $rest " | LC_ALL=C grep -qiE '[[:space:]](SIG)?(INT|TERM)[[:space:]]|[[:space:]](2|15)[[:space:]]' || continue

      local rc=0
      handler_exits "$f" "$handler" || rc=$?
      case "$rc" in
        0) ;;
        1) printf '%s:%s: trap on INT/TERM whose handler never exits: %s\n' \
             "$rel" "$lineno" "$(printf '%s' "$line" | sed 's/^[[:space:]]*//')" ;;
        2) printf '%s:%s: trap on INT/TERM names handler %q, which this file does not define (a sourced handler cannot be checked - inline the exit): %s\n' \
             "$rel" "$lineno" "$handler" "$(printf '%s' "$line" | sed 's/^[[:space:]]*//')" ;;
      esac
    done < <(split_traps "$f")
  done < <(find "$root" \
             \( -name .git -o -name node_modules -o -name vendor -o -name .next \
                -o -name dist -o -name coverage -o -name .venv -o -name __pycache__ \) -prune -o \
             -type f -print 2>/dev/null | LC_ALL=C sort)
  return 0
}

run_lint() {
  local root="$1" found n
  found=$(scan "$root")
  n=$(printf '%s' "$found" | grep -c . || true)

  if [ "$n" -eq 0 ]; then
    echo "✅ Every trap on INT/TERM exits - no handler returns to the body of the script it just cleaned up after."
    return 0
  fi

  echo "❌ trap-handler lint FAILED: $n registration(s) trap INT or TERM without exiting."
  echo ""
  printf '%s\n' "$found" | sed 's/^/   /'
  echo ""
  echo "A trap handler that does not exit RETURNS TO THE SCRIPT BODY. On Ctrl-C"
  echo "the cleanup runs and then the script carries on against the state it just"
  echo "tore down, and cleanup runs a second time at exit."
  echo ""
  echo "Use the form measured to exit 130 on SIGINT and never reach the body:"
  echo ""
  echo "    trap cleanup EXIT"
  echo "    trap 'cleanup; exit 130' INT"
  echo "    trap 'cleanup; exit 143' TERM"
  return 1
}

# ---------------------------------------------------------------------------
# --self-test: the guard must be shown to FAIL, not only to pass, and to pass
# for the right reason.
#
# Every fixture's trap line is built from $TRAP_KW rather than written
# literally, so this file contains no line that starts with `trap `. That is
# what lets the guard scan its own source instead of carrying a self-exclusion
# - an exclusion is a hole, and the one guard in this tree that has one says so
# in its own header.
# ---------------------------------------------------------------------------
TRAP_KW='trap'

self_test() {
  local fails=0 ran=0 tmp
  tmp=$(mktemp -d)
  # RETURN, not EXIT/INT/TERM: this is a function-scoped cleanup and it must
  # not disturb the traps the shell running the self-test already holds.
  trap 'rm -rf "$tmp"' RETURN

  check() { # check <label> <expected-rc> <root>
    ran=$((ran + 1))
    local label="$1" want_rc="$2" root="$3" rc=0
    run_lint "$root" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq "$want_rc" ]; then
      echo "  ok   $label (rc=$rc)"
    else
      echo "  FAIL $label (rc=$rc, wanted $want_rc)"
      fails=$((fails + 1))
    fi
  }

  mk() { mkdir -p "$(dirname "$1")" && printf '%s\n' "$2" > "$1"; }

  # 1. THE DEFECT. The exact line all four fixed sites carried.
  local bad="$tmp/bad"
  mk "$bad/s.sh" "cleanup() {
  rm -f /tmp/x
}
$TRAP_KW cleanup EXIT INT TERM"
  check "a non-exiting handler on EXIT INT TERM is caught" 1 "$bad"

  # 2. THE FIX. Same handler, the prescribed three-trap form.
  local good="$tmp/good"
  mk "$good/s.sh" "cleanup() {
  rm -f /tmp/x
}
$TRAP_KW cleanup EXIT
$TRAP_KW 'cleanup; exit 130' INT
$TRAP_KW 'cleanup; exit 143' TERM"
  check "the prescribed three-trap form passes" 0 "$good"

  # 3. EXIT ALONE is not this guard's business. Without this fixture the
  #    matcher could have been "any trap with a non-exiting handler", which
  #    would flag every ordinary cleanup trap in the repo.
  local exitonly="$tmp/exitonly"
  mk "$exitonly/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup EXIT"
  check "a non-exiting handler on EXIT ALONE is not flagged" 0 "$exitonly"

  # 4. A BARE FUNCTION NAME whose BODY exits is accepted. The rule is about the
  #    handler exiting, not about where the word sits.
  local fnexit="$tmp/fnexit"
  mk "$fnexit/s.sh" "onsig() {
  rm -f /tmp/x
  exit 130
}
$TRAP_KW onsig INT TERM"
  check "a handler FUNCTION that exits is accepted" 0 "$fnexit"

  # 5. ...and the credit must come from THAT function. A sibling function that
  #    exits must not cover for a handler that does not - the exact hole a
  #    whole-file substring check leaves.
  local sibling="$tmp/sibling"
  mk "$sibling/s.sh" "die() {
  exit 1
}
cleanup() {
  rm -f /tmp/x
}
$TRAP_KW cleanup INT TERM"
  check "a SIBLING function's exit does not cover a non-exiting handler" 1 "$sibling"

  # 6. RESET and IGNORE are not handlers. seed-portal-playwright.sh really
  #    disarms its traps with \`trap -\`, so flagging this would red main.
  local reset="$tmp/reset"
  mk "$reset/s.sh" "$TRAP_KW - EXIT INT TERM"
  check "a trap RESET (trap -) is not flagged" 0 "$reset"

  local ignore="$tmp/ignore"
  mk "$ignore/s.sh" "$TRAP_KW '' INT TERM"
  check "a trap IGNORE (trap '') is not flagged" 0 "$ignore"

  # 7. SIGNAL SPELLINGS. A guard that knew only the bare names would be a
  #    census bounded by one spelling; all three forms are legal in bash.
  local sigprefix="$tmp/sigprefix"
  mk "$sigprefix/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup SIGINT SIGTERM"
  check "SIGINT/SIGTERM spelling is caught" 1 "$sigprefix"

  local numeric="$tmp/numeric"
  mk "$numeric/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup 2 15"
  check "numeric signal spelling (2/15) is caught" 1 "$numeric"

  # 8. A DIFFERENT SIGNAL must not trip it. Without this the numeric arm above
  #    could have been a substring match on any digit.
  local other="$tmp/other"
  mk "$other/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup HUP USR1"
  check "a trap on HUP/USR1 only is not flagged" 0 "$other"

  local twenty="$tmp/twenty"
  mk "$twenty/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup 20"
  check "signal 20 (TSTP) is not mistaken for 2" 0 "$twenty"

  # 9. `exit` MUST BE IN COMMAND POSITION. A handler that only TALKS about
  #    exiting has not exited, and this is the fixture that stops the matcher
  #    degrading into a substring search.
  local talks="$tmp/talks"
  mk "$talks/s.sh" "$TRAP_KW 'echo \"exit now\"' INT TERM"
  check "a handler that merely PRINTS the word exit is caught" 1 "$talks"

  local exiting="$tmp/exiting"
  mk "$exiting/s.sh" "$TRAP_KW 'echo exiting; exit 130' INT"
  check "the word 'exiting' does not satisfy it, but a real exit beside it does" 0 "$exiting"

  # 10. The three REAL correct sites, verbatim in shape. This is the positive
  #     control the issue asked for: the guard is only credible if the forms
  #     already in the tree pass it.
  local real="$tmp/real"
  mk "$real/ssm.sh" "$TRAP_KW \"echo ''; echo 'Closing tunnel...'; kill \$PID 2>/dev/null; exit 0\" INT TERM"
  check "positive control: ssm-tunnel's inline exit-0 handler passes" 0 "$real"

  local seed="$tmp/seed"
  mk "$seed/seed.sh" "    $TRAP_KW 'rc=\$?; if [ \"\${KEEP_UP}\" -eq 0 ]; then teardown_stack; fi; exit \$rc' EXIT INT TERM
        $TRAP_KW - EXIT INT TERM"
  check "positive control: seed-portal-playwright's rc-preserving handler passes" 0 "$seed"

  # 11. A NON-SHELL file with a trap-shaped line is not scanned.
  local goish="$tmp/goish"
  mk "$goish/x.go" "// $TRAP_KW cleanup EXIT INT TERM"
  check "a .go file is not scanned" 0 "$goish"

  # 12. ...but a shell script with NO .sh extension IS, via its shebang. The
  #     class is "files bash runs", not "files named *.sh".
  local shebang="$tmp/shebang"
  mkdir -p "$shebang"
  printf '#!/usr/bin/env bash\ncleanup() { rm -f /tmp/x; }\n%s cleanup EXIT INT TERM\n' "$TRAP_KW" > "$shebang/deploy"
  check "an extensionless script is scanned via its shebang" 1 "$shebang"

  # 13. A handler function this file does not define is reported, not waved
  #     through. The LOUD direction for KNOWN LIMIT 1.
  local sourced="$tmp/sourced"
  mk "$sourced/s.sh" "source ./lib.sh
$TRAP_KW remote_cleanup INT TERM"
  check "a handler defined in a SOURCED file is reported, not assumed safe" 1 "$sourced"

  # 14. NEGATIVE FIXTURE for KNOWN LIMIT 2. Asserts rc=0 - the guard does NOT
  #     catch it - which is a pin on a stated limit, not an oversight. If
  #     someone later closes this class, this assertion fails, which is the
  #     correct prompt to delete it and the KNOWN LIMITS entry together.
  local vartrap="$tmp/vartrap"
  mk "$vartrap/s.sh" "SIGNALS='INT TERM'
cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup \$SIGNALS"
  check "KNOWN LIMIT: a signal list behind a VARIABLE is NOT caught" 0 "$vartrap"

  # 14b. R3 ROUND 1 probed this guard with fourteen shapes and DEFEATED IT WITH
  #      NINE. Five were FALSE POSITIVES - correct scripts reported as
  #      violations, which is the worse direction, because a miss is silent
  #      while a false positive reds a required check on a correct fix. Every
  #      one is pinned below, in the direction it failed.

  #      FALSE POSITIVES: the handler DOES exit and must not be flagged.
  local fp1="$tmp/fp1"
  mk "$fp1/s.sh" "function cleanup {
  rm -f /tmp/x
  exit 130
}
$TRAP_KW cleanup INT TERM"
  check "FP: 'function name {' (no parens) is resolved" 0 "$fp1"

  local fp2="$tmp/fp2"
  mk "$fp2/s.sh" "die() { exit 130; }
cleanup() { rm -f /tmp/x; die; }
$TRAP_KW cleanup INT TERM"
  check "FP: a handler delegating to a local die() exits" 0 "$fp2"

  local fp3="$tmp/fp3"
  mk "$fp3/s.sh" "$TRAP_KW 'echo \"it'\\''s done\"; exit 130' INT TERM"
  check "FP: an escaped quote inside the handler string" 0 "$fp3"

  local fp4="$tmp/fp4"
  mk "$fp4/s.sh" "cleanup() {
  if true; then
    { rm -f /tmp/x; }
  fi
  exit 130
}
$TRAP_KW cleanup INT TERM"
  check "FP: an inner { } block does not truncate the body" 0 "$fp4"

  local fp5="$tmp/fp5"
  mk "$fp5/s.sh" "cleanup ()
{
  rm -f /tmp/x
  exit 130
}
$TRAP_KW cleanup INT TERM"
  check "FP: the opening brace on the NEXT line" 0 "$fp5"

  #      EVASIONS: the handler does NOT exit and must be flagged. E1-E3 are one
  #      class - the registration is not the first thing on its line - and E3 is
  #      the sharpest: the line WAS matched, the parser returned the FIRST trap
  #      (which exits), and the second registration was never examined. A green
  #      result produced by reading the wrong half of a matched line.
  local e1="$tmp/e1"
  mk "$e1/s.sh" "cleanup() { rm -f /tmp/x; }
[ -n \"\$X\" ] && $TRAP_KW cleanup INT TERM"
  check "trap after && is seen" 1 "$e1"

  local e2="$tmp/e2"
  mk "$e2/s.sh" "cleanup() { rm -f /tmp/x; }
if true; then $TRAP_KW cleanup INT TERM; fi"
  check "trap inside if/then is seen" 1 "$e2"

  local e3="$tmp/e3"
  mk "$e3/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW \"echo bye; exit 0\" EXIT; $TRAP_KW cleanup INT TERM"
  check "a SECOND trap on the same line is examined too" 1 "$e3"

  #      E4-E6: the signal list was matched by whitespace boundary, so a quote
  #      or a semicolon adjacent to the name hid it. All three are ordinary
  #      bash, and the header claims spelling coverage.
  local e4="$tmp/e4"
  mk "$e4/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup 'INT'"
  check "a SINGLE-QUOTED signal name is seen" 1 "$e4"

  local e5="$tmp/e5"
  mk "$e5/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup \"INT\" \"TERM\""
  check "DOUBLE-QUOTED signal names are seen" 1 "$e5"

  local e6="$tmp/e6"
  mk "$e6/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup TERM;"
  check "a trailing semicolon after the signal is seen" 1 "$e6"

  #      E9: bash resolves a redefined function to the LAST definition. The
  #      extractor took the first and credited a dead one that exits.
  local e9="$tmp/e9"
  mk "$e9/s.sh" "cleanup() { exit 130; }
cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup INT TERM"
  check "a REDEFINED handler is judged on the LAST definition" 1 "$e9"

  #      ...and a trap in a COMMENT is not a registration. Splitting mid-line
  #      lost the free comment exclusion the old line anchor had, and the first
  #      version of the splitter flagged this guard's own documentation.
  local cmt2="$tmp/cmt2"
  mk "$cmt2/s.sh" "# $TRAP_KW cleanup INT TERM   <- prose, not a registration
cleanup() { rm -f /tmp/x; }
$TRAP_KW cleanup EXIT"
  check "a trap in a COMMENT is not a registration" 0 "$cmt2"

  # 14c. R3 ROUND 2 ATTACKED THE ROUND-1 FIXES and found two more, both
  #      REGRESSIONS INTRODUCED BY THOSE FIXES. A fix is new code written under
  #      time pressure and is the least-reviewed part of a change.

  #      HIGH-1: brace depth was counted over CHARACTERS, so an unbalanced brace
  #      in a STRING or a COMMENT broke it in both directions - and the
  #      diagnostics lied about the cause ("does not define" for a file that
  #      plainly does). Every fixture here is a handler that DOES exit.
  local bc1="$tmp/bc1"
  mk "$bc1/s.sh" "cleanup() {
  # the compose project uses a { in its label filter
  docker compose down -v || true
  exit 130
}
$TRAP_KW cleanup INT TERM"
  check "FP: an unbalanced { in a COMMENT in the body" 0 "$bc1"

  local bc2="$tmp/bc2"
  mk "$bc2/s.sh" "cleanup() {
  echo \"tearing down {\"
  exit 130
}
$TRAP_KW cleanup INT TERM"
  check "FP: an unbalanced { in a STRING in the body" 0 "$bc2"

  local bc3="$tmp/bc3"
  mk "$bc3/s.sh" "cleanup() {
  echo \"}\"
  exit 130
}
$TRAP_KW cleanup INT TERM"
  check "FP: an unbalanced } in a STRING truncated the body" 0 "$bc3"

  local bc4="$tmp/bc4"
  mk "$bc4/s.sh" "cleanup() {
  cat <<EOF
}
EOF
  exit 130
}
$TRAP_KW cleanup INT TERM"
  check "FP: a HEREDOC payload containing a lone }" 0 "$bc4"

  #      HIGH-2: the ;-split was quote-aware and the &&/||-split was not, so a
  #      handler carrying this repo's dominant cleanup idiom was cut INSIDE the
  #      quoted string. The record lost its SIGNAL LIST, so the INT/TERM test
  #      matched nothing and the registration was never examined - rc=0 on a
  #      handler that does not exit.
  local oror="$tmp/oror"
  mk "$oror/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW 'docker rm -fv c || true' INT TERM"
  check "a handler containing || is still examined" 1 "$oror"

  local andand="$tmp/andand"
  mk "$andand/s.sh" "cleanup() { rm -f /tmp/x; }
$TRAP_KW 'rm -f /tmp/x && echo done' INT TERM"
  check "a handler containing && is still examined" 1 "$andand"

  local okoror="$tmp/okoror"
  mk "$okoror/s.sh" "$TRAP_KW 'docker rm -fv c || true; exit 130' INT TERM"
  check "...and one that DOES exit through || is not flagged" 0 "$okoror"

  #      A trap in a `case` arm - reported as residual by round 2 and closed in
  #      the same pass.
  local casearm="$tmp/casearm"
  mk "$casearm/s.sh" "cleanup() { rm -f /tmp/x; }
case \"\$1\" in
  start) $TRAP_KW cleanup INT TERM ;;
esac"
  check "a trap inside a case arm is seen" 1 "$casearm"

  # 15. THE REAL REPOSITORY passes. Fixtures prove the matcher; only this
  #     proves the matcher is pointed at the tree it is supposed to guard.
  check "the real repository passes" 0 "$REPO_ROOT"

  # 15b. The edition marker reads what is present and nothing else: a tree
  #      with the mirrored lint.yml and no sync workflow is the community tree;
  #      with the sync workflow present it is the enterprise tree; a fixture
  #      with neither is neither (axonflow#483).
  ran=$((ran + 1))
  local mfix="$tmp/marker"
  mk "$mfix/.github/workflows/lint.yml" "name: Lint"
  local efix="$tmp/marker-ent"
  mk "$efix/.github/workflows/lint.yml" "name: Lint"
  mk "$efix/.github/workflows/sync-community-repo.yml" "name: Sync"
  if is_community_tree "$mfix" && ! is_community_tree "$efix" && ! is_community_tree "$tmp/bad"; then
    echo "  ok   the edition marker separates community, enterprise and fixture trees"
  else
    echo "  FAIL the edition marker misreads a tree shape"
    fails=$((fails + 1))
  fi

  # 16. ...and it passes for the RIGHT REASON. A scan that matched no trap at
  #     all would satisfy 15 while guarding nothing. Assert the walk really
  #     reaches known-correct sites and really classifies them.
  #
  #     EDITION-AWARE (the guard portability rule, v10.4.0 community sync,
  #     axonflow#483): this file syncs to the community mirror, so it must
  #     prove itself on the MIRROR'S OWN INPUTS. The first three probes live
  #     under scripts/, which the sync strips except for the lints it re-includes
  #     by name, so on the mirror they were "seen=0/3" and the self-test
  #     reddened the mirror's required Lint Summary. The probe set is now
  #     derived from what the checked-out tree contains: on the enterprise
  #     tree (the sync workflow is present) EVERY probe must be present and
  #     seen - nothing is lowered there; on the community tree (lint.yml
  #     present, the sync workflow absent: the sync does not ship itself, and
  #     no self-test fixture carries either) the scripts/ probes are reported
  #     absent with the reason and the mirrored probes carry the check.
  ran=$((ran + 1))
  local edition
  if is_community_tree "$REPO_ROOT"; then edition=community; else edition=enterprise; fi
  local seen=0 present=0 absent=""
  for probe in scripts/ssm-tunnel-rds.sh scripts/ssm-tunnel-invpc.sh scripts/seed-portal-playwright.sh \
               migrations/core/v9_tests/run_tests.sh \
               tests/regression-test-required/e2e_setup_cleanup_scope_test.sh \
               tests/regression-test-required/main_guard_visibility_test.sh; do
    if [ ! -f "$REPO_ROOT/$probe" ]; then
      absent="$absent $probe"
      continue
    fi
    present=$((present + 1))
    if LC_ALL=C grep -qE '^[[:space:]]*trap[[:space:]]' "$REPO_ROOT/$probe" 2>/dev/null; then
      seen=$((seen + 1))
    fi
  done
  # And that the walk itself finds shell files at all - counted over the same
  # walk run_lint takes, so the floor is the tree's, not one directory's.
  local nfiles
  nfiles=$(find "$REPO_ROOT" \
             \( -name .git -o -name node_modules -o -name vendor -o -name .next \
                -o -name dist -o -name coverage -o -name .venv -o -name __pycache__ \) -prune -o \
             -type f -name '*.sh' -print 2>/dev/null | wc -l | tr -d ' ')
  local want_present=6
  if [ "$edition" = community ]; then
    want_present=3
    echo "  ..   community tree: probes absent by the sync's own exclusions, not counted:$absent"
  fi
  if [ "$present" -eq "$want_present" ] && [ "$seen" -eq "$present" ] && [ "$nfiles" -gt 20 ]; then
    echo "  ok   the real scan reaches the $present known-correct sites present on this $edition tree ($nfiles shell files in the walk)"
  else
    echo "  FAIL anti-vacuity ($edition tree): present=$present/$want_present known-correct sites, seen=$seen of them, $nfiles shell files in the walk${absent:+; absent:$absent}"
    fails=$((fails + 1))
  fi

  echo ""
  echo "=== SELF-TEST: ${ran} assertions, ${fails} failures ==="
  [ "$fails" -eq 0 ]
}

# is_community_tree ROOT - true for the tree the community sync produces:
# it carries the mirrored lint.yml but not the sync workflow (the sync does
# not ship itself). The enterprise tree carries both; a self-test fixture
# carries neither. Derived from what is present, never from a flag.
is_community_tree() {
  [ -f "$1/.github/workflows/lint.yml" ] && [ ! -f "$1/.github/workflows/sync-community-repo.yml" ]
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

run_lint "${1:-$REPO_ROOT}"
