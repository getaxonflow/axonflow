#!/usr/bin/env bash
# lint-hitl-queue-choke-point.sh - the HITL approval-queue single-writer invariant.
#
# Usage: bash scripts/lint-hitl-queue-choke-point.sh [ROOT]
#        bash scripts/lint-hitl-queue-choke-point.sh --self-test
#
#   ROOT defaults to the repository root DERIVED FROM THIS SCRIPT'S OWN PATH.
#   That is scripts/lint-deployment-mode.sh's #3170 lesson applied up front: a
#   scan rooted at $PWD is silently vacuous whenever CI's working directory
#   differs from the repo root, and a vacuous scan is a green board.
#
# THE INVARIANT
#
#   Exactly ONE non-test file in the tree may contain the literal
#   `INSERT INTO`, `MERGE INTO` or `COPY` against hitl_approval_queue, and it is
#   platform/agent/hitl/queue/writer.go - the shared writer that
#   platform/agent/hitl/queue.Enqueuer fronts with the licence-tier gate, the
#   MaxPendingApprovals cap and the hitl_approval_history trail.
#
# WHY THIS GUARD EXISTS AT ALL
#
#   This is the SECOND time this bypass has been closed. #1998 (v7.8.0) found
#   the MCP tool `axonflow_request_approval` writing the table directly, routed
#   it through the service, and shipped with no ratchet. It also passed over
#   two writers that were already there: platform/orchestrator/hitl_wcp_
#   {community,enterprise}.go were added 2026-01-25 (#1082), three months
#   BEFORE that fix, and kept theirs for seven months in total - skipping the
#   tier gate, the pending cap and the Article 14 history on every workflow
#   approval, on both editions. A one-off fix with no ratchet is a fix with a
#   half-life, and it does not even cover the writers standing next to it.
#
#   [[feedback_a_guard_that_never_runs_in_ci_is_a_guard_in_name_only]]: this
#   runs as its OWN job in .github/workflows/lint.yml with no `if:` condition,
#   and `Lint Summary` - the required status check - holds it to 'success'
#   with no 'skipped' tolerance. Wiring it as a step inside golangci-lint
#   would have been worse than not wiring it: that job is
#   `if: needs.detect-changes.outputs.go-code == 'true'`, and a PR that adds a
#   direct writer in a .sql seed or a shell fixture is exactly the PR that
#   skips it.
#
# WHY A COUNT PER FILE, NOT A BARE PATH ALLOW-LIST
#
#   Same reasoning as scripts/lint-policy-table-choke-point.sh: a bare "this
#   file is fine" entry also permits a SECOND statement added to that same
#   file later. Keying the entry to the file's current occurrence count means
#   both adding and deleting one fails the lint until a human bumps the number
#   in a reviewed diff.
#
# WHY TEST FILES ARE EXCLUDED
#
#   Tests legitimately seed rows and legitimately assert on the statement text
#   (sqlmock's ExpectQuery takes the SQL as a regex). Excluding them is not a
#   loophole: a bypass that only exists in _test.go writes to no customer's
#   database. The exclusion is by FILENAME SUFFIX, checked below, not by
#   directory - a non-test helper parked in a test directory is still a writer.

set -euo pipefail

# ---------------------------------------------------------------------------
# The allow-list: path -> exact expected occurrence count of the needle.
# One line per file, `<count> <path>`. An entry that cannot be justified in one
# sentence is not a line to add here.
# ---------------------------------------------------------------------------
#
#   platform/agent/hitl/queue/writer.go - THE choke point. Its count is a
#   ratchet on the one file that is allowed to grow, not an argument that it
#   belongs here; adding a second INSERT to it must still be a reviewed act.
#
ALLOW_LIST=$(cat <<'EOF'
1 platform/agent/hitl/queue/writer.go
EOF
)

NEEDLE='INSERT INTO hitl_approval_queue'

# ---------------------------------------------------------------------------
# scan ROOT - prints one `<count> <relpath>` line per non-test file that
# contains the needle, sorted. Nothing else goes to stdout, so the caller can
# diff it against the allow-list.
#
# The extension list is deliberately WIDER than Go: the pre-existing writers
# were Go, but a migration, a seed or an e2e fixture that inserts into this
# table bypasses the gate just as completely. `--include` on the shell/SQL
# extensions costs nothing and closes the class.
#
# LC_ALL=C so the sort order is byte order and cannot depend on the runner's
# locale - a lesson from #3334's guard, where LC_ALL=C sort order turned out
# to be load-bearing for a memory-carrying scan.
# ---------------------------------------------------------------------------
scan() {
  local root="$1"
  # EXCLUSION, not inclusion. The first version listed extensions to scan
  # (.go/.sql/.sh/.ts/.tsx/.py/.java) and R3 walked past it with the same
  # statement in a .yaml - and .js, .rb, .tmpl and .jsx would have done as
  # well. A guard whose coverage is an allow-list of file types is only as
  # good as somebody's imagination; this one looks at every text file and
  # names what it deliberately skips.
  LC_ALL=C grep -rIl --binary-files=without-match \
      --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor \
      --exclude-dir=.next --exclude-dir=dist --exclude-dir=coverage \
      -i -e 'hitl_approval_queue' "$root" 2>/dev/null \
      --exclude-dir=.venv --exclude-dir=__pycache__ \
    | while IFS= read -r f; do
        local rel="${f#"$root"/}"
        case "$rel" in
          # Test files, by FILENAME SUFFIX. A bypass that exists only in a
          # _test.go writes to no customer's database, and sqlmock's
          # ExpectQuery legitimately takes the statement text as its regex.
          *_test.go|*_test.sh|*.test.ts|*.test.tsx|*_test.py) continue ;;
          # pytest's OTHER standard shape. `*_test.py` alone missed it.
          test_*.py|*/test_*.py) continue ;;
          # runtime-e2e suites seed fixtures into a throwaway compose stack
          # they boot and tear down themselves. This is the one DIRECTORY
          # exclusion, and it is justified by a structural fact rather than by
          # convenience: scripts/e2e/lint-runtime-e2e-executors.sh enforces a
          # bijection between the directories under runtime-e2e/ and the rows
          # of runtime_e2e_suites.tsv, so nothing can live here that is not a
          # declared suite. The suffix rule alone would not cover it - the
          # suites' entry points are named `test.sh`, not `*_test.sh`.
          #
          # ...but runtime-e2e/lib IS scanned. The bijection above is between
          # SUITE directories and TSV rows; `lib/` is neither a suite nor a
          # TSV row, it is sourced helper code shared by all of them, and it
          # matched `runtime-e2e/*` purely by glob accident. A writer parked
          # there would have been invisible to this guard while running inside
          # every suite that sources it. This arm is empty on purpose: it
          # matches before the exclusion below and falls through to be scanned.
          runtime-e2e/lib/*) ;;
          runtime-e2e/*) continue ;;
          # This guard names the statement it looks for.
          scripts/lint-hitl-queue-choke-point.sh) continue ;;
          # DOCUMENTATION, as a CLASS. Round 1 excluded CHANGELOG.md alone,
          # which R3 round 2 correctly called the tell rather than the fix: a
          # one-file patch for a class that covers every ADR, README and API
          # doc. Markdown is prose, not an execution surface - a statement in
          # a .md writes to no database - and the files that describe this
          # invariant are exactly the ones that quote it. Excluding the class
          # is what stops the allow-list being bumped reflexively, which this
          # script's own header condemns.
          *.md|*.mdx) continue ;;
        esac
        local n
        n=$(count_statements "$f")
        [ "$n" -gt 0 ] && printf '%s %s\n' "$n" "$rel"
      done \
    | LC_ALL=C sort -k2
  return 0
}

# count_statements FILE - occurrences of an INSERT into hitl_approval_queue
# that are not inside a comment.
#
# STATEMENT-ORIENTED, NOT LINE-ORIENTED, and that is #3334's lesson applied
# rather than re-learned. That session's guard found the real DDL splitting
# `ALTER TABLE` from `ADD COLUMN` across two lines, so a line grep matched
# NOTHING and reported clean while sitting on the statement it was written to
# find. R3 defeated the first version of THIS guard the same way, plus with a
# lowercase `insert into` (SQL is case-insensitive) and with a file extension
# the inclusion list did not name.
#
# So: strip comments, fold case, collapse all whitespace to single spaces, and
# then count the needle. A split across lines, an odd indent, and `Insert
# Into` all normalise to the same thing.
#
# COMMENTS ARE STRIPPED, AND THAT IS NOT COSMETIC. Without it this guard's own
# count moved every time somebody edited the prose above the statement, and
# every doc comment that CITES the choke point (there are several, all there
# to stop the next person adding a second writer) registered as a writer. A
# guard whose number drifts on prose edits gets its allow-list bumped
# reflexively, and a reflexively-bumped ratchet is not a ratchet.
#
# The comment rule is per-line and leading-token only: a line whose first
# non-space characters are `//`, `#`, `--` or `*` is prose. No INSERT can
# begin with any of those tokens, so a real statement cannot hide behind it.
#
# SCHEMA-QUALIFIED AND DOUBLE-QUOTED forms are matched too
# (`public.hitl_approval_queue`, `"hitl_approval_queue"`,
# `"public"."hitl_approval_queue"`). Both are in-tree conventions - the repo
# already carries five of each - and platform/agent/rls_write_audit_test.go
# enumerates exactly those three shapes as forms IT handles. A guard that a
# sibling matcher one directory over already out-classes is not a ratchet.
#
# KNOWN LIMITS, stated rather than papered over. All three would need machinery
# that buys nothing against the failure mode actually observed twice now - an
# ordinary copy-pasted statement in a new file:
#
#   1. A writer whose TABLE NAME IS NOT A LITERAL next to the verb. Two
#      shapes, one class: string concatenation (`"INSERT INTO " + tableVar`)
#      and a name passed as a parameter to dynamic SQL
#      (`EXECUTE format('INSERT INTO %I ...', 'hitl_approval_queue')`). Both
#      were probed against the finished guard and both evade it. This is
#      #3334's Vector 4 exactly, and that session's conclusion applies here:
#      the fix - matching any statement that contains an INSERT and the table
#      name anywhere - trades a silent false negative for a LOUD false
#      positive on `INSERT INTO other_table SELECT ... FROM
#      hitl_approval_queue`, which is a legitimate shape this repo is free to
#      write. Closing it honestly needs a per-language AST pass, not a wider
#      regex. Left open, named, and pinned as a negative fixture so nobody
#      believes it is covered.
#   2. A writer inside a SYMLINKED DIRECTORY is not scanned - `grep -r` does
#      not follow symlinked directories (`-R` would, and would also open the
#      door to traversal loops). No such directory exists in this repo.
#   3. A writer built by a TEMPLATE or a code generator whose output is not
#      committed.
#   4. The COPY verb is matched DIRECTION-BLIND: `COPY hitl_approval_queue TO
#      STDOUT` is an export - a read - and is flagged anyway. Deliberate:
#      distinguishing FROM from TO needs statement parsing, the false positive
#      is LOUD (a reviewer sees exactly what tripped it and allow-lists or
#      rewrites), and an export of this table in non-test code would deserve a
#      look regardless. The parenthesised form `COPY (SELECT ...) TO` is not
#      flagged - the table name there is not adjacent to the verb.
count_statements() {
  # ORDER MATTERS, and getting it wrong is a documented incident. #3334's
  # guard stripped BLOCK comments in a pass BEFORE line comments, so a `/*`
  # inside a `--` comment opened a block state that never closed and hid 303
  # lines of real migration. So: line comments FIRST (they are per-line and
  # cannot be affected by what follows), then block comments on the joined
  # text.
  #
  # perl, not sed: the block-stripping expression needs non-greedy matching,
  # and the GNU BRE form (`\+`, `\(...\)`) that expresses it silently does
  # nothing under BSD sed - so on macOS the strip was a no-op and the inline
  # `/* */` evasion sailed through while the self-test on a GNU box would have
  # passed. Same class as the bash 3.2 lesson: a portability gap that makes
  # the guard weaker on one platform and green on the other. perl is already a
  # hard dependency of this repo's markdown tooling.
  #
  # Block comments are stripped rather than skipped-by-leading-token because
  # an idiomatic Go package doc is a `/* ... */` whose body lines start with
  # no marker at all - round 1's leading-token rule counted those as writers,
  # a false positive R3 round 2 measured. Stripping `/* ... */` after joining
  # handles both that and `INSERT INTO /*x*/ hitl_approval_queue`, which is
  # the inline form the same #3334 session was bitten by.
  #
  # ESCAPED newlines and tabs are whitespace too. A statement split across
  # lines inside a Go DOUBLE-quoted string carries the two characters
  # backslash-n, not a real newline, so `tr` never sees it and
  # `INSERT\n  INTO\n  hitl_approval_queue` matched nothing. That is the same
  # split-statement vector this guard already claims to handle - the self-test
  # pins the BACKTICK form, which uses real newlines, and the double-quoted
  # twin walked straight past it. Measured, not theorised: it was one of three
  # evasions probed against the finished guard, and the only one that is a
  # plausible ACCIDENT rather than a deliberate dodge.
  #
  # Safe to blank: turning a literal backslash-n into a space cannot create a
  # match that was not already there, because the table name still has to be
  # present verbatim.
  #
  # THE BLOCK STRIP REFUSES TO OPEN ON A /* TOUCHING A QUOTE ON EITHER SIDE.
  # The lookbehind (round 2) guards a literal that BEGINS "/*"; R3 round 3
  # measured that a literal ENDING in /* - a path glob like "migrations/*" -
  # still opened a strip window that swallowed a real INSERT further down,
  # which is verbatim the class the round-2 commit claimed closed. Hence the
  # lookahead too: in `"migrations/*"` the character AFTER /* is a quote, and
  # no genuine comment opener is immediately followed by one in this tree
  # (a comment like /*"x"*/ would now go unstripped, which errs LOUD - the
  # text may then be counted as a writer - rather than silent). Both
  # directions are pinned as fixtures below.
  LC_ALL=C grep -v -E '^[[:space:]]*(//|#|--)' "$1" 2>/dev/null \
    | tr '\n' ' ' \
    | perl -0pe 's{(?<!["\x27\x60])/\*(?!["\x27\x60]).*?\*/}{ }gs' \
    | perl -0pe 's{\\[nrt]}{ }gs' \
    | tr -s '[:space:]' ' ' \
    | LC_ALL=C grep -o -i -E '(insert[[:space:]]+into|merge[[:space:]]+into|copy)[[:space:]]*("?[a-z_][a-z0-9_]*"?[[:space:]]*\.[[:space:]]*)?"?hitl_approval_queue"?([^a-z0-9_"]|$)' \
    | wc -l \
    | tr -d ' '
  # `|| true` is NOT enough here and its absence is a latent trap: the pipeline
  # ends in wc, which always succeeds, but an EARLIER stage (grep -v on a
  # comment-only file) exits 1 and `pipefail` propagates it. Today that is
  # masked only because run_lint calls scan inside $( ), where bash suppresses
  # errexit. Calling scan directly under `set -euo pipefail` would abort at the
  # first zero-count file and print nothing - a scan that reports clean by
  # stopping. Made explicit rather than left to the call site.
  return 0
}

run_lint() {
  local root="$1"
  local want got
  want=$(printf '%s\n' "$ALLOW_LIST" | grep -v '^[[:space:]]*$' | LC_ALL=C sort -k2)
  got=$(scan "$root")

  if [ "$want" = "$got" ]; then
    echo "✅ HITL queue choke point intact - the only non-test write statement (INSERT/MERGE/COPY into hitl_approval_queue) is in the shared writer."
    printf '%s\n' "$got" | sed 's/^/   /'
    return 0
  fi

  echo "❌ HITL queue choke-point lint FAILED."
  echo ""
  echo "Expected (allow-list in $(basename "$0")):"
  printf '%s\n' "$want" | sed 's/^/   /'
  echo ""
  echo "Found:"
  printf '%s\n' "$got" | sed 's/^/   /'
  echo ""
  echo "Every write to hitl_approval_queue must go through"
  echo "platform/agent/hitl/queue - the chokepoint that applies the licence-tier"
  echo "gate (#1998), the MaxPendingApprovals cap and the hitl_approval_history"
  echo "trail. A direct INSERT skips all three, silently, on every edition."
  echo ""
  echo "If a new writer is genuinely required, extend queue.Enqueuer instead."
  echo "If you are moving the statement, update the allow-list above IN THE"
  echo "SAME DIFF so the change is a reviewed act."
  return 1
}

# ---------------------------------------------------------------------------
# --self-test: the guard must be shown to fail, not only to pass.
#
# [[feedback_an_assertion_that_cannot_pass_is_the_same_defect_as_one_that_cannot_fail]]
# - both directions are exercised here. Round after round on #3334's sibling
# guard, the fix for a false negative introduced a false POSITIVE and back
# again, so every fixture below is a pin, not a demonstration.
# ---------------------------------------------------------------------------
self_test() {
  local fails=0 ran=0
  local tmp
  tmp=$(mktemp -d)
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

  # 1. The sanctioned layout passes.
  local ok="$tmp/ok"
  mk "$ok/platform/agent/hitl/queue/writer.go" "const q = \`$NEEDLE (a) VALUES (\$1)\`"
  check "sanctioned single writer passes" 0 "$ok"

  # 2. A SECOND writer fails. This is the regression the guard exists for -
  #    it is the exact shape hitl_wcp_enterprise.go had.
  local two="$tmp/two"
  cp -R "$ok" "$two"
  mk "$two/platform/orchestrator/hitl_wcp_enterprise.go" "query := \`$NEEDLE (a) VALUES (\$1)\`"
  check "a second non-test writer fails" 1 "$two"

  # 3. A second occurrence inside the ALLOW-LISTED file fails too. A bare path
  #    allow-list would pass this, which is why the entries carry counts.
  local grow="$tmp/grow"
  mk "$grow/platform/agent/hitl/queue/writer.go" "$NEEDLE (a)
$NEEDLE (b)"
  check "a second statement in the allow-listed file fails" 1 "$grow"

  # 4. DELETING the sanctioned writer fails. A count-keyed list must not drift
  #    silently stale in either direction, and 'the choke point vanished' is
  #    not a passing state.
  local gone="$tmp/gone"
  mkdir -p "$gone/platform"
  check "the choke point disappearing fails" 1 "$gone"

  # 5. A _test.go writer is ignored.
  local tst="$tmp/tst"
  cp -R "$ok" "$tst"
  mk "$tst/platform/orchestrator/hitl_wcp_enterprise_test.go" "mock.ExpectQuery(\"$NEEDLE\")"
  check "a _test.go writer is ignored" 0 "$tst"

  # 6. A NON-Go writer is caught. The pre-existing bypasses were Go, so a
  #    Go-only scan would have looked correct while a .sql seed walked past it.
  local sql="$tmp/sql"
  cp -R "$ok" "$sql"
  mk "$sql/migrations/core/999_seed.sql" "$NEEDLE (a) VALUES ('x');"
  check "a .sql writer is caught" 1 "$sql"

  # 7. A non-test helper living in a test DIRECTORY is caught. The exclusion
  #    is by filename suffix; scoping it by directory would have let a
  #    fixtures/ helper hold a real writer.
  local dir="$tmp/dir"
  cp -R "$ok" "$dir"
  mk "$dir/platform/orchestrator/testdata/seed_helper.go" "$NEEDLE (a)"
  check "a non-test file under a test directory is caught" 1 "$dir"

  # 8. A near-miss on ANOTHER table does not trip the guard. Without this the
  #    guard could be passing for the wrong reason - matching a substring that
  #    is not the statement it names.
  local near="$tmp/near"
  cp -R "$ok" "$near"
  mk "$near/platform/agent/hitl/other.go" "INSERT INTO hitl_approval_history (a) VALUES (\$1)"
  check "INSERT INTO hitl_approval_history does not trip it" 0 "$near"

  # 9. A COMMENT citing the statement does not count. Regression pin: the
  #    first version of this guard counted them, so its own file scored 4 and
  #    the two hitl repositories scored 1 each - purely from doc comments that
  #    exist to STOP a second writer being added.
  local cmt="$tmp/cmt"
  cp -R "$ok" "$cmt"
  #     Every form that really occurs in source: line comments in three
  #     syntaxes, a Go BLOCK comment whose body lines carry a `*` marker, and
  #     one whose body lines carry NO marker at all - the idiomatic package-doc
  #     shape, and the false positive R3 round 2 measured against round 1's
  #     leading-token-only rule.
  mk "$cmt/platform/agent/hitl/repository.go" "// the ONE authored \`$NEEDLE\` lives in queue/
	// $NEEDLE is not written here
	# $NEEDLE
	-- $NEEDLE
/*
 * $NEEDLE is not written here either
 */
/*
$NEEDLE must never appear in this package
*/"
  check "comments citing the statement do not count, in every real form" 0 "$cmt"

  # 10. A statement is still caught in a file that ALSO comments about it -
  #     the other direction of fixture 9. Without this, stripping comments
  #     could have been implemented as "skip any file that mentions it in a
  #     comment", which would be a false negative wearing a fix's clothes.
  local both="$tmp/both"
  cp -R "$ok" "$both"
  mk "$both/platform/orchestrator/hitl_wcp_enterprise.go" "// we must never write $NEEDLE here
	query := \`$NEEDLE (a) VALUES (\$1)\`"
  check "a real statement beside a comment is still caught" 1 "$both"

  # 11. A runtime-e2e suite seed is ignored. Its entry point is `test.sh`,
  #     which the *_test.sh suffix rule does NOT match - the exclusion is the
  #     directory, and this pins that it is actually in force.
  local rte="$tmp/rte"
  cp -R "$ok" "$rte"
  mk "$rte/runtime-e2e/2654_hitl_expiry_metric/test.sh" "psql -c \"$NEEDLE (a) VALUES ('x')\""
  check "a runtime-e2e suite seed is ignored" 0 "$rte"

  # 12. REGRESSION PINS for the three ways R3 defeated the first version of
  #     this guard. Each of these returned rc=0 (clean) against a
  #     line-oriented, case-sensitive, extension-allow-listed scan.
  local lower="$tmp/lower"
  cp -R "$ok" "$lower"
  mk "$lower/platform/orchestrator/sneak.go" "query := \`insert into hitl_approval_queue (a) VALUES (\$1)\`"
  check "a LOWERCASE insert is caught (SQL is case-insensitive)" 1 "$lower"

  local split="$tmp/split"
  cp -R "$ok" "$split"
  mk "$split/platform/orchestrator/sneak.go" "query := \`INSERT INTO
	hitl_approval_queue (a) VALUES (\$1)\`"
  check "a statement SPLIT ACROSS LINES is caught (#3334's lesson)" 1 "$split"

  # 12b. R3 ROUND 2 probed the FINISHED guard with six evasions. Three got
  #      through. This is the one that is closed, and it matters because the
  #      pin directly above claims this exact capability: a statement split
  #      across lines. That one uses a BACKTICK string, so the newlines are
  #      real and `tr` flattens them. Inside a DOUBLE-quoted Go string the
  #      same split is the two characters backslash-n, which `tr` never sees -
  #      so the guard passed a statement of a shape it advertised catching.
  local esc="$tmp/esc"
  cp -R "$ok" "$esc"
  mk "$esc/platform/orchestrator/sneak.go" "query := \"INSERT\\n  INTO\\n  hitl_approval_queue (a) VALUES (\$1)\""
  check "a statement split by ESCAPED newlines is caught" 1 "$esc"

  # 12d. R3 ROUND 2, SECOND REVIEWER. Three more evasions, all reproduced
  #      against the finished guard and all now closed.
  #
  #      MERGE and COPY are ordinary Postgres write verbs. The header claims
  #      the invariant is "every WRITE goes through the chokepoint" while the
  #      needle only ever said INSERT INTO - so a seed, a backfill or a
  #      migration using either wrote rows and passed. The claim was wider
  #      than the matcher, which is the same defect shape as an absence claim
  #      backed by a truncated grep.
  local merge="$tmp/merge"
  cp -R "$ok" "$merge"
  mk "$merge/platform/orchestrator/sneak.go" "q := \`MERGE INTO hitl_approval_queue t USING s ON t.id=s.id WHEN NOT MATCHED THEN INSERT (a) VALUES (1)\`"
  check "MERGE INTO ... THEN INSERT is caught" 1 "$merge"

  local copyv="$tmp/copyv"
  cp -R "$ok" "$copyv"
  mk "$copyv/migrations/core/999_seed.sql" "COPY hitl_approval_queue (org_id, tenant_id) FROM STDIN;"
  check "COPY ... FROM STDIN is caught" 1 "$copyv"

  #      And the one that is my own fix biting back. The block-comment strip
  #      was added to stop a Go package doc reading as a writer. It runs over
  #      the JOINED file, so a `/*` appearing inside a STRING LITERAL - a
  #      regex, a glob, an eslint pragma - opened a strip window that swallowed
  #      a real statement further down. A false positive closed, a false
  #      negative opened: #3334's alternation exactly, in the same guard, one
  #      round later. The strip now refuses to open on a `/*` preceded by a
  #      quote character.
  #
  #      NOT a full lexer, and deliberately not: blanking string literals
  #      outright is what #3334 measured and REJECTED, because on that guard
  #      the DDL lived inside a literal. On this one the statements we hunt
  #      live inside Go backtick literals, so blanking would delete the
  #      evidence rather than the noise.
  local strlit="$tmp/strlit"
  cp -R "$ok" "$strlit"
  mk "$strlit/platform/orchestrator/sneak.go" "const open = \"/*\"
q := \`INSERT INTO hitl_approval_queue (a) VALUES (\$1)\`
const shut = \"*/\""
  check "an INSERT between /* and */ STRING LITERALS is caught" 1 "$strlit"

  #      R3 round 3: the round-2 lookbehind only guarded a literal BEGINNING
  #      "/*". A literal ENDING in /* - a path glob - reopened the window and
  #      swallowed a real INSERT between the glob and a later package-doc
  #      trailer. Same class, opposite edge. Pinned in BOTH directions: the
  #      glob must not hide a writer, and an ordinary trailing package doc
  #      must still be stripped rather than counted as one.
  local glob="$tmp/glob"
  cp -R "$ok" "$glob"
  mk "$glob/platform/orchestrator/sneak.go" "var scanPaths = []string{\"migrations/*\", \"platform/*\"}
q := \`INSERT INTO hitl_approval_queue (a) VALUES (\$1)\`
/*
Package doc trailer.
*/"
  check "a PATH GLOB literal does not hide a writer before a package doc" 1 "$glob"

  local trailer="$tmp/trailer"
  cp -R "$ok" "$trailer"
  mk "$trailer/platform/orchestrator/ok2.go" "var x = 1
/*
An ordinary trailing package doc that mentions INSERT INTO hitl_approval_queue.
*/"
  check "an ordinary package-doc trailer is still stripped, not counted" 0 "$trailer"

  #      The runtime-e2e/lib widening (round 2) shipped UNPINNED: no fixture
  #      exercised the empty case arm, so reordering the two arms - or
  #      deleting the lib arm - reverted it with a green board. A behaviour
  #      change without a fixture is a demonstration, not a pin, in a script
  #      whose own header says every fixture below is a pin.
  local libw="$tmp/libw"
  cp -R "$ok" "$libw"
  mk "$libw/runtime-e2e/lib/seed_helper.sh" "psql -c \"$NEEDLE (a) VALUES ('x')\""
  check "a writer in runtime-e2e/lib IS scanned (lib is helper code, not a suite)" 1 "$libw"

  # 12c. NEGATIVE FIXTURES for the two evasions that remain open. These assert
  #      rc=0 - the guard does NOT catch them - which looks backwards until you
  #      read it as what it is: a pin on a STATED LIMIT. Both put the table
  #      name somewhere other than as a literal beside the verb, which is
  #      #3334's Vector 4. Widening the regex to reach them would flag
  #      `INSERT INTO other SELECT ... FROM hitl_approval_queue`, a legitimate
  #      shape, so the honest fix is an AST pass and the honest interim is to
  #      say so out loud. If someone later closes this class properly, these
  #      two assertions FAIL, which is the correct prompt to delete them and
  #      the KNOWN LIMITS paragraph together.
  local dyn="$tmp/dyn"
  cp -R "$ok" "$dyn"
  mk "$dyn/platform/orchestrator/sneak.go" "q := \`EXECUTE format('INSERT INTO %I (a) VALUES (1)', 'hitl_approval_queue')\`"
  check "KNOWN LIMIT: a dynamic-SQL name parameter is NOT caught" 0 "$dyn"

  local concat="$tmp/concat"
  cp -R "$ok" "$concat"
  mk "$concat/platform/orchestrator/sneak.go" "t := \"hitl_approval_queue\"; q := \"INSERT INTO \" + t"
  check "KNOWN LIMIT: a concatenated table name is NOT caught" 0 "$concat"

  local yaml="$tmp/yaml"
  cp -R "$ok" "$yaml"
  mk "$yaml/deploy/seed.yaml" "  sql: \"$NEEDLE (a) VALUES ('x')\""
  check "an UNLISTED file extension is caught (.yaml)" 1 "$yaml"

  # 13. ...and the same three do NOT create false positives in prose. The
  #     matcher folds case, so a comment mentioning it in lower case must
  #     still be skipped.
  local prose="$tmp/prose"
  cp -R "$ok" "$prose"
  mk "$prose/platform/orchestrator/notes.go" "// never insert into hitl_approval_queue directly
# nor INSERT INTO hitl_approval_queue from a script"
  check "prose mentioning it in any case does not trip it" 0 "$prose"

  # 14. SCHEMA-QUALIFIED and DOUBLE-QUOTED writers, the two evasions R3
  #     round 1's second lens found. Both are conventions this repo already
  #     uses, so neither is exotic.
  local qual="$tmp/qual"
  cp -R "$ok" "$qual"
  mk "$qual/platform/orchestrator/sneak.go" "q := \`INSERT INTO public.hitl_approval_queue (a) VALUES (\$1)\`"
  check "a SCHEMA-QUALIFIED writer is caught" 1 "$qual"

  local quoted="$tmp/quoted"
  cp -R "$ok" "$quoted"
  mk "$quoted/platform/orchestrator/sneak.go" "q := \`INSERT INTO \"hitl_approval_queue\" (a) VALUES (\$1)\`"
  check "a DOUBLE-QUOTED writer is caught" 1 "$quoted"

  local both2="$tmp/both2"
  cp -R "$ok" "$both2"
  mk "$both2/platform/orchestrator/sneak.go" "q := \`INSERT INTO \"public\".\"hitl_approval_queue\" (a) VALUES (\$1)\`"
  check "a SCHEMA-QUALIFIED + QUOTED writer is caught" 1 "$both2"

  # 15. A DIFFERENT table in the same schema must NOT trip it - the widened
  #     matcher must not have become a substring match on the schema.
  local other="$tmp/other"
  cp -R "$ok" "$other"
  mk "$other/platform/orchestrator/ok.go" "q := \`INSERT INTO public.hitl_approval_history (a) VALUES (\$1)\`"
  check "public.hitl_approval_history does not trip it" 0 "$other"

  # 16. An INLINE block comment between INTO and the table must not hide a
  #     real writer. This is #3334's own trap, in the form R3 round 2 used to
  #     walk past round 1's matcher.
  local inline="$tmp/inline"
  cp -R "$ok" "$inline"
  mk "$inline/platform/orchestrator/sneak.go" "q := \`INSERT INTO /* sneaky */ hitl_approval_queue (a) VALUES (\$1)\`"
  check "an INLINE /* */ between INTO and the table is caught" 1 "$inline"

  # 17. Spacing variants that PostgreSQL accepts.
  local spacing="$tmp/spacing"
  cp -R "$ok" "$spacing"
  mk "$spacing/platform/orchestrator/sneak.go" "q := \`INSERT   INTO public . hitl_approval_queue (a) VALUES (\$1)\`"
  check "extra spaces and a spaced schema dot are caught" 1 "$spacing"

  local nospace="$tmp/nospace"
  cp -R "$ok" "$nospace"
  mk "$nospace/platform/orchestrator/sneak.go" "q := \`INSERT INTO\"hitl_approval_queue\" (a) VALUES (\$1)\`"
  check "no space before a QUOTED identifier is caught" 1 "$nospace"

  # 18. A DIFFERENT table whose name merely starts with ours must not trip it.
  #     Without a right-hand word boundary, hitl_approval_queue_archive would
  #     be a false positive.
  local prefix="$tmp/prefix"
  cp -R "$ok" "$prefix"
  mk "$prefix/platform/orchestrator/ok.go" "q := \`INSERT INTO hitl_approval_queue_archive (a) VALUES (\$1)\`"
  check "hitl_approval_queue_archive does not trip it" 0 "$prefix"

  # 19. A .md file is documentation, not an execution surface. Round 1
  #     excluded CHANGELOG.md alone; the class is what matters.
  local doc="$tmp/doc"
  cp -R "$ok" "$doc"
  mk "$doc/docs/some-adr.md" "The invariant: exactly one \`$NEEDLE\` exists.

\`\`\`sql
$NEEDLE (a) VALUES ('x');
\`\`\`"
  check "a .md documenting the statement does not trip it" 0 "$doc"

  # 20. The REAL repository passes. Fixtures prove the matcher; only this
  #     proves the matcher is pointed at the tree it is supposed to guard.
  #     [[feedback_a_verification_command_that_did_nothing_still_exits_zero]]
  check "the real repository passes" 0 "$REPO_ROOT"

  # 21. ...and it passes for the RIGHT REASON. A scan that matched nothing at
  #     all would satisfy 12 while guarding nothing - the exact way #3334's
  #     first guard went green. Assert the choke point is actually seen.
  ran=$((ran + 1))
  if scan "$REPO_ROOT" | grep -qx '1 platform/agent/hitl/queue/writer.go'; then
    echo "  ok   the real scan actually FINDS the choke point"
  else
    echo "  FAIL the real scan found no choke point - it is passing vacuously"
    echo "       scan output was: [$(scan "$REPO_ROOT" | tr '\n' '|')]"
    fails=$((fails + 1))
  fi

  echo ""
  echo "=== SELF-TEST: ${ran} assertions, ${fails} failures ==="
  [ "$fails" -eq 0 ]
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

run_lint "${1:-$REPO_ROOT}"
