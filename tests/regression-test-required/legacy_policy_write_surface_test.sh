#!/usr/bin/env bash
# The WRITE SURFACE of static_policies and dynamic_policies, pinned two ways.
#
# WHY THIS RATCHET EXISTS. v11 decision D1 retires static/dynamic as an
# authoring, storage and UI model: after migrations/core/172 the typed
# authoring model is the only write path, and both tables are SELECT-only to
# the application roles. The revoke is the enforcement; this is the ledger that
# stops the tree drifting out from under it.
#
# "SELECT-only to the application roles" IS A CLAIM ABOUT MORE THAN THE TWO
# TABLES, and the rest of it is not enforced here. An auto-updatable VIEW over
# static_policies is a write path that a revoke on the table does not close,
# and there are eight of them - one in core/014, seven in the industry
# verticals. That door is held by enforce_legacy_policy_read_only(), installed
# by core/172 and called by the agent after every migration has run, because
# industry migrations are numbered 200+ so as to run last and a migration
# cannot bind a relation that does not exist yet. It is asserted behaviourally
# in platform/agent/legacy_policy_read_only_realpg_test.go, not here: this
# script reads source text, and the statement that walks through a view names
# no table for it to match.
#
# WHAT IT CATCHES THAT THE MIGRATION CANNOT. A grant refuses a write at
# runtime, on a deployment connecting as an application role, in an error an
# operator eventually sees. It cannot stop a TWELFTH write site being added to
# the source, and a twelfth write site is how "one write path" quietly stops
# being true: it compiles, every unit test passes because unit tests use the
# owner connection or sqlmock, and the failure surfaces on a customer's stack.
#
# ───────────────────────────────────────────────────────────────────────────
# CHECK 1 - THE WRITE SITES, PINNED AS A SET AND NOT AS A COUNT
# ───────────────────────────────────────────────────────────────────────────
#
# A COUNT CANNOT SEE A SWAP. Eleven write sites that become a different eleven
# - one removed from Create, one added to a new method in the same file - leave
# every per-file number intact and the pin meaningless. So the authoritative
# pin is a DIGEST over the sorted (file, enclosing function, verb+table) set.
#
# The per-file counts are kept as well, and not as redundancy: they produce the
# error message that names WHICH file moved. A digest alone reports only that
# something did.
#
# The set is keyed on the enclosing FUNCTION, never on a line number. A census
# keyed on a source position is invalidated by anything above it - a
# comment-only sweep across the tree moves every line and reddens a ratchet on
# a PR that changed no code.
#
# ───────────────────────────────────────────────────────────────────────────
# WHAT THIS CENSUS CANNOT SEE, STATED RATHER THAN LEFT TO BE DISCOVERED
# ───────────────────────────────────────────────────────────────────────────
#
# It matches SQL VERBS AGAINST TABLE NAMES IN SOURCE TEXT. A write assembled at
# run time is therefore invisible to it: a query builder, a shared helper that
# takes the verb or the table as a parameter, or any statement whose table name
# arrives from configuration or from the database itself.
#
# That is not hypothetical. cascadeDeleteCommunitySaasTenantData in
# platform/agent/community_saas_sweep.go issues
#
#     fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = ANY($1)`, table)
#
# over a table list DISCOVERED FROM information_schema at run time - every
# public BASE TABLE with a varchar/text `tenant_id` column, minus an exclusion
# set. `dynamic_policies` has one, so it was in that set: a twelfth write site
# this script could not find, and one migration 172 would have broken, because
# the cascade returns on the first error inside the sweep's transaction and one
# refused table stops tenant termination entirely.
#
# It was found by RUNNING the discovery function against a migrated database,
# and it is pinned the same way - by the mechanism, not by the text - in
# platform/agent/legacy_policy_read_only_realpg_test.go's
# TestTheCommunitySaasSweepNeverCascadesIntoALegacyPolicyTable_RealPG. A
# source-text assertion over that exclusion map would carry the same blindness
# one layer up: it would pass on a database where a later migration added
# `tenant_id` to some other policy table.
#
# TWO NARROWER BLIND SPOTS, for the same reason: the scan is `platform ee`, a
# LIST OF ROOTS rather than an exclusion rule, so a write under cmd/, tools/ or
# scripts/ is outside it; and WRITE_RE requires the verb and the table on ONE
# line, so a query broken across lines is invisible. Both are stated rather than
# fixed because widening either produces false positives this census has no way
# to triage - the roots are where the services live, and every real query in
# this tree spells the verb and the table together.
#
# So this script is the CHEAP tier and is honest about being it. The sound
# check walks to the thing that executes and needs a database; the two are
# complements, and neither is a substitute for the other. The one thing this
# script CAN do about the class is refuse to let the known indirection's
# exclusion set quietly lose an entry, which CHECK 3 below does.
#
# THE PINNED DIGEST IS THE SAME IN THIS TREE AND IN THE COMMUNITY MIRROR, and
# that is a property rather than a coincidence: every write site is under
# platform/, `ee/` contributes zero, and the mirror excludes `ee/` entirely. So
# one pinned value is correct in both trees, and this script - which IS
# mirrored - proves itself on the mirror's own inputs rather than only on this
# one. If an ee/ write site is ever added, THIS tree reds (the digest moves and
# the file is uncensused) while the mirror stays green on the old digest, which
# is the safe direction for the asymmetry to run.
#
# ───────────────────────────────────────────────────────────────────────────
# CHECK 2 - NO OTHER MIGRATION NARROWS THE GRANTS 172's ROLLBACK RESTORES,
#           AND NO OTHER MIGRATION RESTORES THE ONES 172 REMOVES
# ───────────────────────────────────────────────────────────────────────────
#
# migrations/core/172_..._down.sql restores SELECT, INSERT, UPDATE, DELETE -
# the exact set core/098 granted. That is the correct rollback ONLY while
# nothing between 098 and 172 narrowed it: if some intervening migration had
# revoked part of that set, the rollback would hand back MORE than the tree had
# before 172 ran.
#
# Verified when 172 was written - no migration outside 098's own down and 172
# itself issues a REVOKE naming either table - and this check is what keeps it
# verified, rather than leaving a fact that was true once inside a comment.
#
# ANTI-VACUITY. Four floors, each a state in which this script would report
# success while checking nothing: no write site found anywhere; an allow-listed
# file that does not exist; an allow-list that parses to zero entries; a
# computed digest that is empty.
set -uo pipefail

REPO_ROOT="${1:-.}"
cd "$REPO_ROOT" || exit 1

STATUS=0

# LC_ALL=C PINS THE COLLATION, AND THE DIGEST BELOW IS ONLY MEANINGFUL WITH IT.
#
# `sort` collates by locale. A developer shell on macOS is typically
# en_US.UTF-8, which folds case and orders `Create, createPolicyTx, Delete`; a
# Linux runner is typically C/POSIX, which orders `Create, Delete, Update,
# createPolicyTx`. The SET is identical either way and its digest is NOT, so a
# digest pinned on one platform is a permanent red on the other - measured:
# 537e586d… on macOS, fa18a651… on debian, same twelve sites, same script.
#
# This is a nastier shape than the two spellings of sha256 the helper below
# handles, because nothing about the failure points at collation: the script
# prints two different hashes over two listings that are set-equal and, in the
# common case, look identical at a glance.
export LC_ALL=C

# sha256 of stdin, portable across the GNU and BSD spellings. CI is Linux and
# developers run macOS; a script that only worked on one would be discovered by
# whoever was on the other, at the worst moment.
sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

# EVERY migration file, at BOTH depths.
#
# `migrations/*/*.sql` is 398 files and misses 27, which are NOT all one thing:
# 17 are the industry verticals nesting one level deeper (14 under
# migrations/industry/banking/, 3 under migrations/industry/travel/) and 10 are
# the migrations/core/v9_tests/ psql harness. Both are wanted HERE - this is a
# census over every file that could carry a write statement, and a fixture that
# grants or revokes is as interesting as a migration that does. (The resolver in
# runtime-e2e/3636_forcerls_grants/test.sh excludes v9_tests for the opposite
# reason: there it would resolve a MISSING migration's stem onto a harness
# fixture and report it present.)
# The 17 industry files are not an obscure corner - they are where SEVEN OF THE EIGHT views
# over static_policies are created, which is to say the files that motivate the
# view enforcer this script's header describes. A GRANT or a REVOKE in any of
# them was invisible to both checks below, measured with probe migrations:
# identical statements were caught in migrations/core/ and passed silently in
# migrations/industry/travel/.
#
# Written as a function over an explicit two-depth glob rather than `find`,
# because `find` orders by directory walk and the checks below compare sorted
# output; and because the two depths are the whole story - migrations/ has no
# third level, and if it ever gains one this returns fewer files than exist,
# which CHECK 2's anti-vacuity floors are there to catch.
migration_files() {
  for f in migrations/*/*.sql migrations/*/*/*.sql; do
    [ -f "$f" ] && echo "$f"
  done
}

# ---------------------------------------------------------------------------
# CHECK 1
# ---------------------------------------------------------------------------

# The SQL verbs, matched case-sensitively and upper-case. Every real query in
# this tree spells them that way and comment prose does not - the same
# reasoning scripts/lint-policy-table-choke-point.sh gives for `FROM`.
WRITE_RE='(INSERT INTO|UPDATE|DELETE FROM) (static_policies|dynamic_policies)'

# file|count|justification. An entry that cannot be justified in one sentence
# is not a line to add here; it is a finding for #3786's accounting. The
# correct direction of travel for every runtime line below is DOWN TO ZERO,
# which is #3565's legacy-authoring-freeze scope rather than this file's.
# `read -d ''`, NOT `$(cat <<EOF)`. bash 3.2 cannot parse a heredoc inside a
# command substitution at all - it reports "unexpected EOF while looking for
# matching )" at the assignment and dies. `read` returns non-zero at EOF, hence
# the `|| true`.
read -r -d '' ALLOW_LIST <<'EOF' || true
platform/agent/static_policy_repository.go|4|Agent-side static policy CRUD: Create (INSERT), Update, Delete (soft delete) and ToggleEnabled (UPDATE). Retires with the legacy authoring surface, #3565.
platform/orchestrator/policy_api_repository.go|5|Orchestrator-side dynamic policy CRUD: Create and createPolicyTx (INSERT), Update and updatePolicyTx (UPDATE), Delete (DELETE). Retires with the legacy authoring surface, #3565.
platform/orchestrator/db_dynamic_policies.go|1|insertSamplePolicies alone, the database-backed dynamic engine's dev sample seed. Was 2 until #4026: seedSystemMediaPolicies INSERTed the five sys_media_* controls here at every boot, which core/172 had already made impossible for the application roles (core/173 seeds them as the migration owner), so the write was refused with SQLSTATE 42501 and logged as a warning while the production-posture clean-boot guard failed the stack. It is now verifySystemMediaPolicies, a read. insertSamplePolicies remains a write site and now asks has_table_privilege before attempting it. Retires with the legacy authoring surface, #3565.
EOF

# The pinned SET. Regenerate deliberately, in a reviewed diff, by running this
# script and copying the digest it prints on failure.
# Moved by #4026, in the shrinking direction: seedSystemMediaPolicies' INSERT
# INTO dynamic_policies left the surface and nothing joined it. The printed
# surface was checked row by row when this was rebased - all ten remaining
# sites are the same ten, which is the check a digest alone cannot give you and
# the reason the failure message prints the whole set.
# Moved by #4084, in the shrinking direction again: testutil.SingaporePIISeedData
# left the surface. It was listed here as "the shared fixture seeder", but
# nothing in the tree called it, test or otherwise - the legacy-freeze writer
# census found it as an entry nothing reaches, and its exemption reason could
# not be written truthfully, so the dead function was deleted rather than
# exempted. The ten remaining sites are the ten above, row for row.
EXPECTED_SET_DIGEST="bc3591fc7741522ee36f279587c4e74848d35e0778ecf59d0aa61bd1a5de3457"

# THE AWK PROGRAM IS WRITTEN TO A FILE AT TOP LEVEL AND RUN WITH `awk -f`.
#
# It is not inline inside a $( ), because bash 3.2 - stock on macOS - counts
# parentheses NAIVELY inside command substitution, even inside single quotes
# where the shell has no business looking. An awk regex such as /[ (].*$/ is
# then a syntax error at startup, on a script whose header reasons about the
# GNU/BSD split for sha256 a few checks earlier. A quoted heredoc assigned
# through a variable does not help; a heredoc at top level does, because
# nothing is substituting.
# The template carries SIX X's because GNU coreutils `mktemp` REQUIRES at least
# three and BSD `mktemp` does not. `mktemp -t w1c-extract` is accepted on macOS
# and fails on every Linux runner with `too few X's in template` - which is what
# shipped here first, in the fix for a macOS-only parse failure, three lines
# under a comment reasoning about exactly this split. A portability defect is
# not fixed by knowing the platforms differ; it is fixed by running it on both.
AWK_EXTRACT=$(mktemp -t w1c-extract.XXXXXX)
trap 'rm -f "$AWK_EXTRACT"' EXIT
cat > "$AWK_EXTRACT" <<'AWK'
/^func / {
  fn = $0
  sub(/^func +/, "", fn)
  sub(/^\([^)]*\) *(\*)?/, "", fn)
  sub(/[ (].*$/, "", fn)
  if (fn == "") fn = "(unnamed)"
}
match($0, /(INSERT INTO|UPDATE|DELETE FROM) (static_policies|dynamic_policies)/) {
  printf "%s|%s|%s\n", file, (fn == "" ? "(package scope)" : fn), substr($0, RSTART, RLENGTH)
}
AWK

write_surface() {
  local f
  for f in $(grep -rlE "$WRITE_RE" --include='*.go' platform ee 2>/dev/null | grep -v '_test\.go$' | sort); do
    awk -v file="$f" -f "$AWK_EXTRACT" "$f"
  done | sort
}

SURFACE=$(write_surface)
if [ -z "$SURFACE" ]; then
  echo "FAIL: no legacy-policy write site was found anywhere. Either the search is broken or the tree moved; a census that finds nothing reports success while checking nothing."
  exit 1
fi

ACTUAL_DIGEST=$(printf '%s\n' "$SURFACE" | sha256_stdin)
if [ -z "$ACTUAL_DIGEST" ]; then
  echo "FAIL: the write-surface digest came out empty, so nothing was pinned."
  exit 1
fi
if [ "$ACTUAL_DIGEST" != "$EXPECTED_SET_DIGEST" ]; then
  echo "FAIL: the legacy-policy write surface has changed."
  echo "      expected digest $EXPECTED_SET_DIGEST"
  echo "      actual digest   $ACTUAL_DIGEST"
  echo "      A digest rather than a count, because a count cannot see a SWAP: one site removed and another added leaves every number intact."
  echo "      The surface now is:"
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "        $line"
  done <<< "$SURFACE"
  STATUS=1
fi

# COUNTS WITHOUT AN ASSOCIATIVE ARRAY. `declare -A` is bash 4+, and stock
# macOS ships bash 3.2 - on which this script died with a syntax error at
# startup. It failed LOUDLY rather than vacuously, so nothing was ever wrong;
# but this file reasons explicitly about the GNU/BSD split for sha256 four
# checks earlier, and using a bash-4 builtin two checks later was the same
# oversight in the other direction. A sorted count is portable and is the
# shape the rest of this script already uses.
COUNTS=$(printf '%s\n' "$SURFACE" | cut -d'|' -f1 | sort | uniq -c | awk '{print $2 "|" $1}')

count_for() {
  local f="$1" line
  while IFS='|' read -r path n; do
    [ "$path" = "$f" ] && { echo "$n"; return; }
  done <<< "$COUNTS"
  echo 0
}

CHECKED=0
while IFS='|' read -r file count _justification; do
  [ -z "$file" ] && continue
  if [ ! -f "$file" ]; then
    echo "FAIL: $file is allow-listed and does not exist. Remove the entry, or the census is describing a tree that is gone."
    STATUS=1
    continue
  fi
  have=$(count_for "$file")
  if [ "$have" -ne "$count" ]; then
    echo "FAIL: $file carries $have legacy-policy write statement(s), the census says $count."
    echo "      Adding one: after migrations/core/172 the typed authoring model is the only write path (v11 D1)."
    echo "      Removing one: bump the number DOWN, which is the direction this census is meant to travel."
    STATUS=1
  fi
  CHECKED=$(( CHECKED + 1 ))
done <<< "$ALLOW_LIST"

if [ "$CHECKED" -eq 0 ]; then
  echo "FAIL: the allow-list parsed to zero entries, so nothing was compared."
  exit 1
fi

# Every file that HAS a write site must be on the list. Without this the census
# only constrains files it already knows about, and a brand-new file carrying a
# brand-new write path would pass unmentioned.
while IFS='|' read -r f _n; do
  [ -z "$f" ] && continue
  if ! grep -qF "$f|" <<< "$ALLOW_LIST"; then
    echo "FAIL: $f writes a legacy policy table and is not in the census."
    echo "      After migrations/core/172 these tables are SELECT-only to both application roles, so this write is refused at runtime on any deployment using them."
    STATUS=1
  fi
done <<< "$COUNTS"

# ---------------------------------------------------------------------------
# CHECK 2
# ---------------------------------------------------------------------------

# The only two files permitted to REVOKE on either legacy table. 098's own down
# is the wholesale role teardown; 172 is this program.
ALLOWED_REVOKERS="migrations/core/098_v9_rls_roles_down.sql
migrations/core/172_legacy_policy_tables_read_only.sql"

# A RE-GRANT UNDOES 172 AS COMPLETELY AS A REVOKE UNDOES 098, and only the
# revoke side was checked. A later migration adding a legacy table to a
# core/170- or enterprise/151-style `GRANT ... ON ALL TABLES` backfill, or
# naming one directly, silently restores the write path this program removed -
# and the real-Postgres suite would not see an ENTERPRISE-chain instance at
# all, because approletest applies migrations/core only.
#
# Only 098 (which creates the roles and grants them everything) and 172's own
# down migration may grant write on these tables.
ALLOWED_GRANTERS="migrations/core/098_v9_rls_roles.sql
migrations/core/172_legacy_policy_tables_read_only_down.sql"

# COMMENTS ARE STRIPPED BEFORE MATCHING, and the match is narrowed to the two
# APPLICATION roles.
#
# Both refinements were forced by the tree rather than chosen. Without the
# strip, core/170_down and enterprise/151_down are flagged: each says
# "IT REVOKES NOTHING, AND THAT IS THE WHOLE POINT" in a comment and repeats
# the word inside a RAISE NOTICE, and neither executes one. Without the role
# narrowing, community-saas/085 is flagged: it revokes writes on ALL TABLES
# from `community_saas_bridge_ro`, a read-only bridge role that is not one of
# the two 172 restores for and whose privileges 172's rollback never touches.
# MATCHED PER STATEMENT, NOT PER LINE.
#
# The first version was a pipeline of greps, each filtering the LINES the last
# one emitted - so all four conditions had to appear on one line and a GRANT
# split across lines satisfied none of them. That shape is already idiomatic in
# this tree: migrations/community-saas/087 carries a multi-line
# `GRANT SELECT (...)`. Comments are stripped, newlines are folded, and the
# result is split on `;` so each statement is tested whole.
#
# A flagged statement must satisfy THREE conditions at once, because each one
# alone over-matches on this tree:
#
#   1. it is executable, not commentary. core/170_down and
#      enterprise/151_down each say "IT REVOKES NOTHING, AND THAT IS THE WHOLE
#      POINT" in a comment and repeat the word inside a RAISE NOTICE, and
#      neither executes one;
#   2. its target is one of the two APPLICATION roles. community-saas/085
#      revokes writes on ALL TABLES from `community_saas_bridge_ro`, a
#      read-only bridge role 172's rollback never touches;
#   3. its object could BE a legacy policy table - either named, or reached
#      through ALL TABLES. core/171 and enterprise/155 both revoke from the
#      application roles, on their own new tables, and neither narrows
#      anything 172's rollback restores.
# statements_of prints one SQL statement per line, comments stripped.
statements_of() {
  sed 's/--.*//' "$1" | tr '\n' ' ' | tr ';' '\n'
}

REVOKERS=$(for f in $(migration_files); do
    [ -f "$f" ] || continue
    if statements_of "$f" \
         | grep -E "REVOKE" \
         | grep -E "axonflow_app_role|axonflow_platform_admin" \
         | grep -qE "static_policies|dynamic_policies|ALL TABLES"; then
      echo "$f"
    fi
  done | sort -u)

REVOKER_COUNT=0
while read -r f; do
  [ -z "$f" ] && continue
  REVOKER_COUNT=$(( REVOKER_COUNT + 1 ))
  if ! grep -qxF "$f" <<< "$ALLOWED_REVOKERS"; then
    echo "FAIL: $f revokes privileges covering a legacy policy table."
    echo "      migrations/core/172_..._down.sql restores the SELECT/INSERT/UPDATE/DELETE set core/098 granted, which is the correct rollback ONLY while nothing between them narrowed it."
    echo "      Either this migration is a mistake, or 172's down migration must be reworked to restore the narrowed set instead."
    STATUS=1
  fi
done <<< "$REVOKERS"

if [ "$REVOKER_COUNT" -eq 0 ]; then
  echo "FAIL: no migration was found revoking anything, not even core/098's own down. The search is broken and this check is vacuous."
  STATUS=1
fi

# The GRANT direction, same three conditions: executable, an application role,
# and an object that could BE a legacy policy table.
#
# TWO SPELLINGS THAT USED TO WALK STRAIGHT PAST THIS, both measured against the
# guard with probe migrations before they were closed:
#
#   GRANT ALL ON static_policies TO axonflow_app_role;
#
# `ALL` without `PRIVILEGES` is the SQL-standard shorthand and PostgreSQL takes
# it. It restores INSERT, UPDATE, DELETE and TRUNCATE in one statement - the
# whole of what 172 removed - and the verb filter listed only `ALL PRIVILEGES`,
# so the guard was green on it. Now `GRANT ALL` matches in either spelling, and
# the character class after it admits `(` as well as a space: `GRANT ALL(enabled)
# ON static_policies` is valid SQL that restores exactly the column the legacy
# surfaces toggle, and a trailing-space-only pattern was the one spelling still
# open - which is the "next spelling nobody thought of" that core/172's own
# comment warns about, arriving in the guard rather than in the function.
#
#   ALTER DEFAULT PRIVILEGES IN SCHEMA public
#     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO axonflow_app_role;
#
# The object filter required the literal `ALL TABLES`, and this says `TABLES`.
# That is not an academic gap: it is the EXACT mechanism core/172's own header
# identifies as the root cause of the view write path - core/098 arms default
# privileges, and every view created afterwards is granted write as it appears.
# A guard whose job is to stop a later migration re-opening the door could not
# see a later migration re-arming it.
GRANTERS=$(for f in $(migration_files); do
    [ -f "$f" ] || continue
    if statements_of "$f" \
         | grep -E "GRANT" \
         | grep -E "axonflow_app_role|axonflow_platform_admin" \
         | grep -E "INSERT|UPDATE|DELETE|TRUNCATE|ALL PRIVILEGES|GRANT[[:space:]]+ALL[[:space:](]" \
         | grep -qE "static_policies|dynamic_policies|ALL TABLES|DEFAULT PRIVILEGES"; then
      echo "$f"
    fi
  done | sort -u)

GRANTER_COUNT=0
while read -r f; do
  [ -z "$f" ] && continue
  GRANTER_COUNT=$(( GRANTER_COUNT + 1 ))
  if ! grep -qxF "$f" <<< "$ALLOWED_GRANTERS"; then
    echo "FAIL: $f grants write privileges reaching a legacy policy table to an application role."
    echo "      migrations/core/172 removed exactly those, and a re-grant undoes it as completely as a revoke would."
    echo "      If the grant is intended, 172 is no longer true and v11 decision D1 needs revisiting; if it is not, narrow the grant."
    STATUS=1
  fi
done <<< "$GRANTERS"

if [ "$GRANTER_COUNT" -eq 0 ]; then
  echo "FAIL: no migration was found granting write on these tables, not even core/098. The search is broken and this check is vacuous."
  STATUS=1
fi

# ---------------------------------------------------------------------------
# CHECK 3 - THE ONE RUN-TIME-ASSEMBLED WRITE PATH THIS SCRIPT KNOWS ABOUT
# ---------------------------------------------------------------------------
#
# See "WHAT THIS CENSUS CANNOT SEE" above. This is not a substitute for the
# real-Postgres pin on the discovery function; it is the cheap tier refusing to
# let the exclusion set lose an entry silently, on a lane where the shell suite
# runs and the Go suite does not.
SWEEP=platform/agent/community_saas_sweep.go
if [ ! -f "$SWEEP" ]; then
  echo "FAIL: $SWEEP does not exist; the run-time cascade check is vacuous."
  STATUS=1
else
  for table in static_policies dynamic_policies; do
    if ! grep -qE "^[[:space:]]*\"$table\":[[:space:]]*\{\}," "$SWEEP"; then
      echo "FAIL: $table is not in communitySaasSweepNonCascadeTables in $SWEEP."
      echo "      That sweep DELETEs from every table with a varchar tenant_id discovered from information_schema, and both legacy policy tables have one."
      echo "      After migrations/core/172 the DELETE is refused, and the cascade returns on the first error inside the sweep's transaction - so one refused table stops tenant termination ENTIRELY."
      STATUS=1
    fi
  done
fi

if [ "$STATUS" -eq 0 ]; then
  echo "PASS: legacy-policy write surface pinned by digest ($CHECKED file(s), $(printf '%s\n' "$SURFACE" | wc -l | tr -d ' ') site(s)); $REVOKER_COUNT migration(s) revoke and $GRANTER_COUNT grant write on these tables, all expected (#3786, v11 D1)."
fi
exit "$STATUS"
