#!/usr/bin/env bash
# lint-no-second-org-column.sh - the organization_id reintroduction guard (#3334).
#
# Usage:
#   bash scripts/lint-no-second-org-column.sh [ROOT]
#   bash scripts/lint-no-second-org-column.sh --self-test
#
#   ROOT defaults to the repository root DERIVED FROM THIS SCRIPT'S OWN PATH,
#   for the reason scripts/lint-deployment-mode.sh records (#3170): a scan
#   rooted at $PWD is silently vacuous the moment CI's working directory
#   differs from the repo root. Fixtures pass a directory explicitly.
#
# ════════════════════════════════════════════════════════════════════════════
# THE INVARIANT
# ════════════════════════════════════════════════════════════════════════════
#
#   The policy tables carry exactly ONE organization-scope column: org_id.
#   No forward migration may introduce a SECOND one - under any spelling -
#   onto static_policies, dynamic_policies or policy_overrides.
#
# WHY THIS EXISTS (#3334). These tables carried `organization_id` AND `org_id`
# side by side, with different types, different populations and different
# meanings. The census #3334 demanded, run against a real database, found
# static_policies at 101 rows with organization_id 0% populated and org_id
# 100% populated, and dynamic_policies split the same way. The two columns
# were not redundant-but-harmless: policy_overrides' valid_override_scope
# CHECK rejected the org-scoped shape (organization_id NULL, tenant_id NULL,
# org_id set) that the org-keyed selection model produces, so the schema
# actively contradicted the code. migrations/core/166 drops the legacy column
# and the CHECK that referenced it.
#
# The drop is a one-time event. THIS script is what stops the next feature
# from adding the column back - because a second org-scope column is not an
# obviously-wrong thing to write. It reads as ordinary schema work, and the
# first time anyone notices is when two columns disagree about who owns a
# policy.
#
# ════════════════════════════════════════════════════════════════════════════
# WHY NOTHING THAT ALREADY EXISTS COVERS THIS
# ════════════════════════════════════════════════════════════════════════════
#
# Four things look like they guard this. None do - each verified, not assumed:
#
#   * scripts/lint-policy-table-choke-point.sh matches `FROM static_policies` /
#     `FROM dynamic_policies` in Go source and compares per-file call-site
#     counts to an allow-list. It never opens migrations/ at all, and its
#     pattern is anchored on the SQL keyword FROM, so `ALTER TABLE
#     static_policies ADD COLUMN organization_id` is invisible to it.
#   * .github/workflows/migrations-gate.yml proves the chain APPLIES cleanly
#     from a fresh database. A migration that adds a column applies perfectly
#     - an apply-success gate cannot express a claim about schema SHAPE.
#   * scripts/validate-schema-completeness.sh checks that 12 named tables
#     exist. It is referenced by no workflow (grep over .github/workflows/
#     returns zero hits), so it does not run in CI at all.
#   * runtime-e2e/3490_org_keyed_policy_selection/test.sh, named in
#     migrations/core/166 as a backstop, contains ZERO occurrences of either
#     `organization_id` or `information_schema` (measured: `grep -c` returns
#     0 for both over its 764 lines). It asserts selection behaviour, never
#     column absence.
#
# migrations/core/166's own self-test is real but structurally cannot cover
# this: it runs INSIDE migration 166, so it observes the schema as of 166 and
# is blind to migration 167 adding the column straight back.
#
# ════════════════════════════════════════════════════════════════════════════
# WHY THIS IS STATEMENT-ORIENTED AND NOT A LINE GREP
# ════════════════════════════════════════════════════════════════════════════
#
# THIS IS THE WHOLE DESIGN. The real DDL in this repository splits `ALTER
# TABLE` from `ADD COLUMN` across two lines:
#
#     migrations/core/030_policy_tier_columns.sql:18-19
#         ALTER TABLE static_policies
#             ADD COLUMN IF NOT EXISTS organization_id UUID;
#
# A line-oriented guard - `grep -E 'ALTER TABLE (static|dynamic)_policies.*ADD
# COLUMN.*organization_id'` - matches NOTHING against that file. It would go
# green on a tree that contains the very statement it was written to find,
# and it would go green on a new migration written in the same house style.
# That is the "guard that passes because it matched nothing" failure mode, and
# it is why this script strips comments, normalises whitespace, splits on `;`
# and matches whole STATEMENTS.
#
# ════════════════════════════════════════════════════════════════════════════
# THE SIX REINTRODUCTION VECTORS THIS COVERS
# ════════════════════════════════════════════════════════════════════════════
#
#   1. ADD [COLUMN]       ALTER TABLE static_policies ADD COLUMN organization_id ...
#   2. CREATE TABLE       CREATE TABLE policy_overrides ( ... organization_id ... )
#   3. RENAME COLUMN      ALTER TABLE dynamic_policies RENAME COLUMN org_id TO organization_id
#   4. Dynamic SQL        EXECUTE format('ALTER TABLE %I ADD COLUMN organization_id ...', tbl)
#   5. Rebuild-and-swap   CREATE TABLE x ...; ALTER TABLE x RENAME TO static_policies
#   6. Copied column set  CREATE TABLE x (LIKE donor INCLUDING ALL) / INHERITS (donor)
#                         / AS TABLE donor / AS SELECT * FROM donor
#
# In vector 1 the `COLUMN` keyword is OPTIONAL, because it is optional in the
# Postgres grammar: `ALTER TABLE ... ADD [ COLUMN ] [ IF NOT EXISTS ] name type`.
# Requiring it left `ALTER TABLE static_policies ADD organization_id text` -
# valid, applying DDL that reintroduces the column - entirely undetected.
#
# Vector 5 is two statements that are individually innocent: a shadow table is
# built under a scratch name and then renamed over the real one. The table
# created with a banned column is remembered for the WHOLE scan, not per file,
# because the CREATE and the RENAME are usually in different migrations. That
# memory is ORDER-DEPENDENT: files are scanned in `LC_ALL=C sort` order, so a
# CREATE that sorts AFTER its own RENAME (across directories, say
# migrations/internal/ against migrations/core/) is not seen. Sort order is
# not apply order, so this is a real if narrow gap rather than a theoretical
# one; closing it properly needs a second pass.
#
# A shadow table does NOT have to be BORN with the banned column, and assuming
# it did was a live false negative that this header itself asserted was covered.
# It can be created bare and then ALTERed:
#     CREATE TABLE static_policies_new (id uuid);
#     ALTER TABLE static_policies_new ADD COLUMN organization_id uuid;
#     ALTER TABLE static_policies_new RENAME TO static_policies;
# exited 0, on all three tables, because the flag was only ever set inside the
# two CREATE TABLE arms - the ADD resolved to a NON-target name and returned at
# the target-table filter before recording anything. The ADD COLUMN and RENAME
# COLUMN arms therefore record the table BEFORE that filter runs; see check().
#
# Vector 6 is the shape where the banned name is in the statement NOWHERE at
# all, because the column set is copied from another relation:
#     CREATE TABLE static_policies_new (LIKE legacy_policies INCLUDING ALL);
#     ALTER TABLE static_policies_new RENAME TO static_policies;
# `(LIKE donor)` is the canonical Postgres table-rebuild idiom, so this is the
# form a competent author would reach for first. `INHERITS (parent)`,
# `AS TABLE donor` and `AS SELECT * FROM donor` are the same problem wearing
# three other keywords. None can be resolved by matching a column name, so the
# derived table is treated as POSSIBLY carrying one: reported when it is itself
# a policy table, and remembered for vector 5 when it is not. The donor's real
# shape is deliberately not chased - see WHAT THIS DOES NOT CATCH.
#
# Vector 2 is not hypothetical and is the reason this script does not stop at
# ADD COLUMN, which is the narrower shape. TWO of the four affected tables
# never received the column by ALTER at all - policy_overrides got it in its
# CREATE TABLE column list (core/030:80) and policy_evaluations in its own
# (core/039:182). A guard that only understood ADD COLUMN would have been
# blind to the exact shape in which the column originally arrived, and could
# be bypassed by a `CREATE TABLE IF NOT EXISTS policy_overrides (...)` that
# re-states the table with the column present.
#
# Vector 4 is likewise real: migrations/core/166's own DOWN migration re-adds
# the column with
#     EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS organization_id text', tbl)
# over an ARRAY of the three policy tables. When the table name is a `%I` /
# `%s` placeholder it cannot be resolved statically, so any banned column
# introduced through an indirected table name is reported and must be
# allow-listed. This converts a silent blind spot into a reviewed decision -
# the same reasoning lint-policy-table-choke-point.sh applies to its own
# `fmt.Sprintf` gap, except that gap is documented-and-open where this one is
# closed.
#
# ════════════════════════════════════════════════════════════════════════════
# WHAT IS DELIBERATELY NOT A VIOLATION
# ════════════════════════════════════════════════════════════════════════════
#
#   * `*_down.sql` files are not scanned. A down migration exists precisely to
#     restore the prior shape, so re-adding the column there is its correct
#     behaviour - core/166's down migration does exactly that. This is not a
#     bypass: the real runner never applies them forward
#     (platform/agent/migration_helpers.go:312 skips any `_down.sql`), so a
#     column that only appears in a down file is not in the forward schema.
#   * `policy_evaluations` is NOT a target table. Its `organization_id uuid`
#     was a deliberate keep: core/090's header records "leave organization_id
#     UUID for backwards compatibility with existing readers" and adds a
#     separate VARCHAR `org_id` beside it. #3334 did not ask for it and
#     core/166 does not drop it.
#   * `customers.organization_id` is NOT a target table either. It is a
#     NOT NULL UNIQUE organisation-name slug (a different thing wearing the
#     same name) read at platform/agent/db_auth.go and seeded across
#     scripts/, migrations/internal/125 and platform/connectors/config/.
#   * `ALTER COLUMN ... TYPE` is not an introduction. core/133 retypes
#     organization_id from uuid to text; changing a column's type is not
#     adding a second column.
#   * `DROP COLUMN` is not an introduction, for the obvious reason.
#   * `org_id` - the canonical column - is not a banned spelling.
#   * Any mention inside a `--` line comment, a `/* ... */` block comment, or a
#     column name that merely CONTAINS a banned name as a substring
#     (`sub_organization_id`, `organization_identifier`). Identifier matches
#     are boundary-anchored on both sides.
#
# ════════════════════════════════════════════════════════════════════════════
# WHAT THIS DOES NOT CATCH - written down rather than left to be discovered
# ════════════════════════════════════════════════════════════════════════════
#
#   * A column introduced under a name that is not in BANNED_COLUMNS. This
#     guard enforces "no second column under THESE spellings", not "no second
#     org-scope column under any name a future author invents".
#   * DDL assembled by concatenating fragments across separate statements, so
#     that no single statement contains both the table and the column.
#   * A `--` sequence inside a SQL string literal truncates that statement at
#     that point (the line-comment strip is not string-literal aware). No
#     migration in the tree does this; a statement so written could hide a
#     violation that occurs AFTER the `--` within the same statement. The
#     converse case - a `/*` inside a `--` comment - USED to be far worse,
#     silently discarding the remainder of the file, and is now handled: the
#     two comment forms compete left-to-right, whichever opens first.
#   * A file containing an unterminated `/*` cannot be fully scanned. Rather
#     than certify it, the scanner REPORTS it as a violation, so the failure
#     mode is a loud red build rather than a silent blind spot.
#   * Schema changes made anywhere other than migrations/**/*.sql - e.g. DDL
#     hand-built in Go test helpers such as platform/testutil/postgres.go.
#   * `SELECT ... AS organization_id INTO policy_overrides FROM ...`. SELECT
#     INTO creates a table without the words CREATE TABLE appearing anywhere,
#     so no branch below sees it. It is left OPEN rather than guessed at,
#     because the same keyword pair is how PL/pgSQL assigns a query result to a
#     VARIABLE - and that is what migrations/ actually contains. Measured:
#     `SELECT ... INTO <name>` occurs on 118 lines across migrations/**/*.sql
#     (excluding INSERT INTO), and the targets are declared block variables
#     (`INTO v_bad`, `INTO result`, `INTO drifted`, `INTO table_exists`), not
#     tables. A naive `select .* into` branch would therefore fail 118 innocent
#     lines to close a shape the tree does not use. Closing it properly needs
#     the target of INTO resolved against the enclosing block's DECLARE list.
#   * The DONOR of a vector-6 copy is never resolved. `CREATE TABLE x (LIKE
#     donor)` is treated as possibly carrying a banned column WITHOUT reading
#     donor's shape, so a legitimate rebuild from a donor that provably has no
#     banned column is still reported and needs a reviewed allow-list entry.
#     That is the fail-CLOSED direction and it is the deliberate choice: the
#     donor may be created outside migrations/, in a file that sorts later, or
#     have been altered by any migration in between, so "resolve the donor"
#     means modelling every table's full column history - which is a different
#     and much larger program than this one. Measured cost of the conservative
#     rule on the tree as it stands: zero. Across 207 forward migrations the
#     table-element `LIKE` occurs 5 times, `INHERITS` 4 and `AS TABLE` once,
#     and all ten are prose inside `--` comments; there is no real occurrence
#     of any vector-6 shape to false-positive on.
#   * A CTAS whose star is not at the HEAD of the select list -
#     `CREATE TABLE x AS SELECT id, t.* FROM donor` - is not matched. The star
#     pattern is anchored right after `SELECT` (allowing DISTINCT/ALL and a
#     table qualifier) so that `count(*)` cannot match it, and that anchoring
#     is what a mid-list star slips past. Closing it needs the select list
#     parsed to the matching FROM rather than pattern-matched.
#   * `CREATE TABLE x PARTITION OF parent` - a partition takes its columns from
#     the parent exactly as INHERITS does. Not matched, and not closed here
#     because a partition cannot then be RENAMEd over its own parent, so the
#     reachable end state is narrower than vector 6's. Measured: `PARTITION OF`
#     occurs once in migrations/**/*.sql, at
#     migrations/enterprise/100_billing_and_metering.sql:204, and that one is
#     inside a `--` comment (an illustration of how to add a monthly partition),
#     so the tree contains no live partitioned CREATE either.
#
# Model: scripts/lint-policy-table-choke-point.sh and
# scripts/lint-deployment-mode.sh (ROOT-from-BASH_SOURCE, set -euo pipefail,
# ❌/✅ output, pipe-delimited heredoc allow-list, non-zero exit on violation).
# Associative arrays (`declare -A`) are deliberately NOT used: macOS ships
# bash 3.2 as /bin/bash and 3.2 has no `declare -A` at all - a hard parse
# error, not a degraded fallback. `"${arr[@]}"` over a possibly-empty array is
# likewise avoided under `set -u`, which aborts on bash 3.2 while bash 5
# accepts it. No `... | grep -q` pipeline appears anywhere below: under
# `set -o pipefail` grep's early exit closes the pipe and the writer dies of
# SIGPIPE, making the whole pipeline return 141 - a guard that fails OPEN.
# Detection is done in a single awk pass whose output is captured, never piped
# into a short-circuiting reader.

set -euo pipefail

SELF_TEST=0
ROOT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --self-test)
      SELF_TEST=1; shift ;;
    -h|--help)
      echo "Usage: $0 [ROOT] | $0 --self-test"; exit 0 ;;
    *)
      ROOT="$1"; shift ;;
  esac
done

SCRIPT_PATH="${BASH_SOURCE[0]}"

# ════════════════════════════════════════════════════════════════════════════
# Configuration
# ════════════════════════════════════════════════════════════════════════════

# Tables whose org-scope column #3334 consolidated onto org_id.
# policy_evaluations is deliberately absent - see the header.
TARGET_TABLES='static_policies|dynamic_policies|policy_overrides'

# Spellings that would constitute a SECOND org-scope column.
BANNED_COLUMNS='organization_id|organisation_id|org_uuid'

# Allow-list: file | exact expected violation count | one-line justification.
#
# Same shape and same discipline as lint-policy-table-choke-point.sh's
# ALLOW_LIST_TABLE. The count is the point: a bare path allowance would also
# silently permit a NEW banned column added to an already-listed file later.
# Keying each entry to its CURRENT count means both ADDING and REMOVING an
# occurrence fails this lint until a human changes the number in a reviewed
# diff, so the number can never drift silently stale in either direction.
ALLOW_LIST_TABLE='
migrations/core/030_policy_tier_columns.sql|3|The historical INTRODUCTION of organization_id, and immutable history - migrations are never edited after they ship. Three statements: ADD COLUMN on static_policies (:18-19), ADD COLUMN on dynamic_policies (:50-51), and the policy_overrides CREATE TABLE column list (:80). migrations/core/166 drops all three columns; this file stays as the record of where they came from.
'

# ════════════════════════════════════════════════════════════════════════════
# Detection
# ════════════════════════════════════════════════════════════════════════════
#
# scan_tree ROOT_DIR: prints one `file|line|kind|statement-excerpt` record per
# violating STATEMENT, in file order. Prints nothing when the tree is clean.
# Exits non-zero only on a genuine error, never on a violation - the caller
# decides what a violation means.
scan_tree() {
  local root_dir="$1"

  # `find` rather than a glob: migrations/ is nested (core/, enterprise/,
  # industry/banking/, internal/, community-saas/) and a bash 3.2 glob has no
  # `**`. -print0/-0 keeps paths with spaces intact.
  find "$root_dir/migrations" -type f -name '*.sql' ! -name '*_down.sql' -print0 2>/dev/null |
    LC_ALL=C sort -z |
    xargs -0 -r awk \
      -v targets="$TARGET_TABLES" \
      -v banned="$BANNED_COLUMNS" \
      -v root="$root_dir" '
    # ────────────────────────────────────────────────────────────────────
    # Per-file state. FNR==1 fires on the first line of each file, which is
    # also the only place a PREVIOUS file can be finalised: awk has no
    # end-of-file rule. finish_file() therefore runs here for the file just
    # closed, and again in END for the last one. Skipping that was a real
    # defect: a trailing statement with no terminating `;` in any file but
    # the last was silently discarded by the reset below.
    # ────────────────────────────────────────────────────────────────────
    FNR == 1 {
      finish_file()
      buf = ""; startline = 0; inblock = 0; blockstart = 0; curfile = FILENAME
    }

    {
      line = $0

      # ── Strip comments in ONE left-to-right pass ────────────────────────
      # `--` and `/*` COMPETE: whichever opens first wins. Stripping block
      # comments in a separate earlier pass was a live false negative - a
      # `/*` occurring INSIDE a `--` comment (e.g. the path globs
      # "customer-portal/*" in core/099:14 and "industry/banking/*" in
      # core/127:89, both on main) opened a block-comment state that never
      # closed, so the scanner discarded the entire rest of the file and
      # certified it clean. Measured before this fix: 135 of 148 lines of
      # core/099 and 168 of 256 lines of core/127 were invisible, and a
      # column appended to core/127 passed the guard.
      clean = ""
      i = 1
      n = length(line)
      while (i <= n) {
        if (inblock) {
          p = index(substr(line, i), "*/")
          if (p == 0) { i = n + 1 }
          else { i = i + p + 1; inblock = 0 }
        } else {
          p = index(substr(line, i), "/*")
          d = index(substr(line, i), "--")
          if (d > 0 && (p == 0 || d < p)) {
            # A line comment opens first: the rest of the LINE is comment.
            clean = clean substr(line, i, d - 1)
            i = n + 1
          } else if (p == 0) {
            clean = clean substr(line, i)
            i = n + 1
          } else {
            clean = clean substr(line, i, p - 1)
            i = i + p + 1
            inblock = 1
            blockstart = FNR
          }
        }
      }

      # ── Accumulate into the pending statement ───────────────────────────
      # startline is stamped on the first line carrying real content after the
      # previous statement closed, so the reported line is where the statement
      # actually begins rather than where its terminating `;` landed.
      if (buf !~ /[^ \t]/ && clean ~ /[^ \t]/) startline = FNR
      buf = buf " " clean

      # ── Emit each complete `;`-terminated statement ─────────────────────
      while ((sp = index(buf, ";")) > 0) {
        stmt = substr(buf, 1, sp - 1)
        buf  = substr(buf, sp + 1)
        check(stmt, startline, curfile)
        if (buf !~ /[^ \t]/) startline = FNR
      }
    }

    END { finish_file() }

    # finish_file: flush the trailing statement of the file just closed and
    # refuse to certify a file the scanner could not fully parse.
    function finish_file(   rel) {
      if (curfile == "") return
      if (buf ~ /[^ \t]/) check(buf, startline, curfile)
      if (inblock) {
        # An unterminated /* means everything after it was discarded. That is
        # exactly the state in which a violation would be invisible, so it is
        # reported rather than passed over in silence.
        rel = curfile
        sub("^" root "/", "", rel)
        printf "%s|%d|UNTERMINATED BLOCK COMMENT|a /* opened here was never closed, so the rest of this file was not scanned\n", rel, blockstart
      }
    }

    # ────────────────────────────────────────────────────────────────────
    # norm: lowercase, drop double-quote identifier quoting, and collapse all
    # whitespace to single spaces. This is the step that makes a two-line
    # `ALTER TABLE x \n ADD COLUMN y` a single matchable statement. Postgres
    # folds unquoted identifiers to lowercase, so lowercasing is faithful to
    # how the server reads it; stripping `"` means a quoted "organization_id"
    # is matched like the bare spelling.
    #
    # Stripping `"` is NOT literal-aware, and that is a deliberate trade, not
    # an oversight. A single-quoted SQL literal routinely contains double
    # quotes - every jsonb default does - so this DOES reach inside literals.
    # Blanking literals first would be the obvious answer and is WRONG here:
    # vector 4 exists precisely because the DDL lives INSIDE a single-quoted
    # literal - the EXECUTE format(...) shape in the file header - so blanking
    # them would silently delete that detector. The column-definition matcher
    # is made precise instead; see check().
    # ────────────────────────────────────────────────────────────────────
    function norm(s) {
      s = tolower(s)
      gsub(/"/, "", s)
      gsub(/[ \t\r\n]+/, " ", s)
      sub(/^ /, "", s)
      sub(/ $/, "", s)
      return s
    }

    # bare: strip a schema qualifier from a table token, so
    # `public.static_policies` compares equal to `static_policies`. Quoting is
    # already gone by way of norm().
    function bare(tok) {
      sub(/^.*\./, "", tok)
      return tok
    }

    # token_after: the first identifier-ish token following the first match of
    # `pat` in `s`, or "" if `pat` does not match. Used to pull the table name
    # out of ALTER TABLE / CREATE TABLE. awk has no capture groups, so this is
    # match() + substr() by hand.
    #
    # `pat` MUST be passed as a STRING, never as a /.../ literal. In awk a bare
    # regex literal used as an expression evaluates to `$0 ~ /.../`, i.e. the
    # number 0 or 1 - so passing one here silently matches against the digit
    # "0"/"1" instead of the intended pattern, token_after returns "", and
    # every violation is dropped. That reads as a clean tree: the guard goes
    # green having matched nothing.
    function token_after(s, pat,   rest, tok) {
      if (!match(s, pat)) return ""
      rest = substr(s, RSTART + RLENGTH)
      if (!match(rest, /^[^ (,;]+/)) return ""
      tok = substr(rest, RSTART, RLENGTH)
      return bare(tok)
    }

    # indirected: the table name is a runtime placeholder (format() %I/%s or a
    # $-parameter), so it cannot be resolved statically and may well be one of
    # the target tables.
    function indirected(tok) {
      return (tok ~ /%/ || tok ~ /^\$/)
    }

    # ────────────────────────────────────────────────────────────────────
    # check: does this statement introduce a banned column on a target table?
    #
    # Both halves must hold. The column half is POSITIONAL - the banned name
    # must sit where a column being defined sits, not merely appear somewhere
    # in the statement. That is what keeps a message like
    #   RAISE EXCEPTION Migration 166 failed: %.organization_id still exists
    # from counting as a reintroduction: the name is preceded by a `.`, not by
    # `ADD [COLUMN]`, `TO`, or a column-list `(`/`,`.
    #
    # The positional rule is deliberately fail-CLOSED and is not exact. A
    # CREATE TABLE on a target table whose CHECK names the column bare
    # immediately after a `(` - `CHECK ((organization_id IS NOT NULL AND ...` -
    # does satisfy it, because `is` is indistinguishable from a type name at
    # this resolution. That shape is exactly the one core/030 carries, and it is
    # allow-listed; anywhere else, a target table constraining a column it
    # does not declare is worth a human look.
    # ────────────────────────────────────────────────────────────────────
    function check(raw, ln, file,   s, tbl, kind, b, t, src, rel) {
      s = norm(raw)
      if (s == "") return

      b = "(" banned ")"
      t = "(" targets ")"
      kind = ""

      # Vector 1 - ADD [COLUMN] [IF NOT EXISTS] <banned>.
      # `COLUMN` is OPTIONAL in the Postgres grammar
      # (ALTER TABLE ... ADD [ COLUMN ] [ IF NOT EXISTS ] name type), so
      # requiring it left `ALTER TABLE static_policies ADD organization_id
      # text` - valid, applying DDL - completely undetected.
      if (s ~ ("(^|[^a-z0-9_])add +(column +)?(if +not +exists +)?" b "([^a-z0-9_]|$)")) {
        tbl = token_after(s, "(^|[^a-z0-9_])alter +table +(if +exists +)?(only +)?")
        # Recorded BEFORE the target-table filter below, and this placement is
        # the whole point. A shadow table need not be born with the column: it
        # can be created bare and then ALTERed. If the flag were only set in
        # the CREATE TABLE arms, `CREATE TABLE static_policies_new (id uuid);
        # ALTER TABLE static_policies_new ADD COLUMN organization_id uuid;
        # ALTER TABLE static_policies_new RENAME TO static_policies;` would exit
        # 0 - the ADD is on a non-target name so it returns at the filter, and
        # the RENAME then finds nothing remembered. Measured as a live false
        # negative on all three tables before this line existed.
        created_with_banned[tbl] = 1
        kind = "ADD COLUMN"
      }
      # Vector 3 - RENAME COLUMN <anything> TO <banned>
      else if (s ~ ("(^|[^a-z0-9_])rename +column +[a-z0-9_]+ +to +" b "([^a-z0-9_]|$)")) {
        tbl = token_after(s, "(^|[^a-z0-9_])alter +table +(if +exists +)?(only +)?")
        # Same reasoning as the ADD arm: renaming an innocent column to a banned
        # name on a shadow table leaves that table carrying the column, so it
        # must be remembered before the target filter can return.
        created_with_banned[tbl] = 1
        kind = "RENAME COLUMN"
      }
      # Vector 2 - CREATE TABLE whose column list defines <banned>. The banned
      # name must open a column definition: preceded by `(` or `,` and
      # followed by whitespace (a type). `organization_id` appearing as
      # `foo.organization_id` inside a CHECK never matches.
      #
      # Every such table is remembered in created_with_banned[], target or
      # not, because vector 5 below needs to know about the non-target ones.
      else if (s ~ ("(^|[^a-z0-9_])create +table +")) {
        # The banned name must open a column DEFINITION: preceded by `(` or
        # `,`, and followed by a TYPE - which is why the trailing ` +[a-z]` is
        # load-bearing rather than cosmetic. Without it a JSON key inside a
        # jsonb DEFAULT matched: norm() strips the double quotes, so a default
        # of {"tenant": 1, "organization_id" : 2} collapses to
        # ..., organization_id : 2..., whose comma then reads as a column-list
        # separator. A type always starts with a letter; a JSON key is
        # followed by a colon, so requiring a type character separates them.
        # The class includes _ because Postgres array shorthand types are spelled
        # _text, _int4 and so on; a colon is still excluded, which is what
        # matters. This
        # also stops a bare name inside a column-list constraint - UNIQUE
        # (org_id, organization_id) - from counting, since there the next
        # character is a bracket or comma.
        if (s ~ ("[(,] *" b " +[a-z_]")) {
          tbl = token_after(s, "(^|[^a-z0-9_])create +table +(if +not +exists +)?")
          created_with_banned[tbl] = 1
          kind = "CREATE TABLE"
        }
        # CREATE TABLE ... AS SELECT takes its column names from the QUERY, so
        # a banned column arrives with no type token after it at all. Two valid
        # shapes, both of which create the column and neither of which can
        # satisfy the ` +[a-z_]` type requirement above:
        #   CREATE TABLE policy_overrides (id, organization_id) AS SELECT ...
        #   CREATE TABLE policy_overrides AS SELECT org_id AS organization_id ...
        # In the first the name is followed by `)` or `,`; in the second it is
        # preceded by `as`, not by `(`/`,`. R3 round 4 found both.
        #
        # The looser patterns are gated on the statement actually BEING a CTAS,
        # and the gate anchors `as` to the position right after the table name
        # and its optional parenthesised column list - `\([^()]*\)` cannot span
        # a nested paren, so an ordinary CREATE TABLE carrying `GENERATED
        # ALWAYS AS (...)` or any other inner `as (` does not enter this arm.
        # That is what stops `UNIQUE (org_id, organization_id)` on such a table
        # from matching `[(,] *b *[,)]` and reopening a false positive.
        else if (s ~ ("(^|[^a-z0-9_])create +table +(if +not +exists +)?[^ (,;]+ *(\\([^()]*\\))? *as +")) {
          if (s ~ ("[(,] *" b " *[,)]") || s ~ ("(^|[^a-z0-9_])as +" b "([^a-z0-9_]|$)")) {
            tbl = token_after(s, "(^|[^a-z0-9_])create +table +(if +not +exists +)?")
            created_with_banned[tbl] = 1
            kind = "CREATE TABLE AS SELECT"
          }
          # `AS SELECT *` and `AS TABLE donor` take their columns from the donor
          # relation, so no banned name appears in the statement at all. They are
          # members of the copied-column-set family described below, but they
          # MUST be handled here rather than in that arm: both satisfy the CTAS
          # gate above (`... x as ...`), so an else-if hung off that gate would
          # be unreachable. Caught while writing it, not after.
          else if (s ~ ("(^|[^a-z0-9_])as +select +(distinct +)?(all +)?([a-z0-9_]+\\.)?\\*") \
                || s ~ ("(^|[^a-z0-9_])as +table +[a-z_]")) {
            tbl = token_after(s, "(^|[^a-z0-9_])create +table +(if +not +exists +)?")
            created_with_banned[tbl] = 1
            kind = "CREATE TABLE with a COPIED column set (AS SELECT * / AS TABLE)"
          }
        }
        # Vector 6 - a CREATE TABLE that COPIES its column set from another
        # relation. `(LIKE donor)` is the canonical Postgres rebuild idiom and
        # `INHERITS (parent)` is its inheritance cousin; `AS TABLE donor` and the
        # starred CTAS handled just above are the query-shaped members. In
        # every one of them the banned name appears NOWHERE in the statement -
        # the columns arrive from a relation this scanner does not model - so no
        # name-matching branch can ever see them.
        #
        # Resolved fail-CLOSED rather than left open, and the trade was measured
        # rather than assumed: across the 207 forward migrations in this tree the
        # table-element `LIKE` form occurs on 5 lines, `INHERITS` on 4 and
        # `AS TABLE` on 1, and ALL TEN are prose inside `--` comments ("(like
        # Serko)", "inherits owner", "as table owner"), which the comment strip
        # removes before check() ever runs. There is not one real occurrence of
        # any of these shapes, so closing them costs zero false positives today
        # and turns a future one into a reviewed allow-list entry - the same
        # reasoning vector 4 applies to an indirected table name.
        #
        # `LIKE` is anchored to a table-element position (preceded by `(` or `,`,
        # followed by an identifier character) so that the LIKE *operator* cannot
        # match. Measured: 123 lines in this tree carry the operator shape
        # <ident> LIKE <literal>, 120 of them outside any comment, and in every
        # one the operand name sits between the bracket and the keyword and the
        # literal after it opens with a quote - so neither anchor is satisfied.
        else if (s ~ ("[(,] *like +[a-z_]") \
              || s ~ ("(^|[^a-z0-9_])inherits +\\(") \
              || s ~ ("(^|[^a-z0-9_])as +table +[a-z_]")) {
          tbl = token_after(s, "(^|[^a-z0-9_])create +table +(if +not +exists +)?")
          created_with_banned[tbl] = 1
          kind = "CREATE TABLE with a COPIED column set (LIKE / INHERITS / AS TABLE)"
        }
      }
      # Vector 5 - the rebuild-and-swap. A shadow table carrying the banned
      # column is created under a scratch name and then renamed over a policy
      # table; neither statement alone reintroduces anything, but the end
      # state is a policy table with the column back. created_with_banned[] is
      # deliberately NOT reset per file, because the CREATE and the RENAME are
      # usually in different migrations.
      else if (s ~ ("(^|[^a-z0-9_])alter +table +.* rename +to +")) {
        src = token_after(s, "(^|[^a-z0-9_])alter +table +(if +exists +)?(only +)?")
        tbl = token_after(s, "(^|[^a-z0-9_])rename +to +")
        if (src != "" && created_with_banned[src]) {
          kind = "RENAME TO (a table created with a banned column is renamed over a policy table)"
        } else {
          return
        }
      }

      if (kind == "") return
      if (tbl == "") return

      # Vector 4 is not a separate branch: it is any of the above where the
      # table name could not be resolved statically.
      if (indirected(tbl)) {
        kind = kind " (indirected table name \"" tbl "\")"
      } else if (tbl !~ ("^" t "$")) {
        return
      }

      # Trim the reported statement so a 40-line CREATE TABLE does not flood
      # the failure output.
      if (length(s) > 160) s = substr(s, 1, 157) "..."

      rel = file
      sub("^" root "/", "", rel)
      printf "%s|%d|%s|%s\n", rel, ln, kind, s
    }
  '
}

# ════════════════════════════════════════════════════════════════════════════
# allow_list_count FILE: prints the expected violation count for FILE, or
# returns non-zero if FILE has no entry. Linear scan - a handful of rows.
# ════════════════════════════════════════════════════════════════════════════
allow_list_count() {
  local target="$1" p c _just
  # shellcheck disable=SC2034  # justification column intentionally unread
  while IFS='|' read -r p c _just; do
    [ -n "$p" ] || continue
    if [ "$p" = "$target" ]; then
      printf '%s' "$c"
      return 0
    fi
  done <<EOF
$ALLOW_LIST_TABLE
EOF
  return 1
}

# ════════════════════════════════════════════════════════════════════════════
# run_lint ROOT_DIR: the whole check. Returns 0 clean, 1 on violation.
# ════════════════════════════════════════════════════════════════════════════
run_lint() {
  local root_dir="$1"
  local matches seen_files fail=0 unlisted="" miscount="" file actual expected
  local alfile alcount _just

  if [ ! -d "$root_dir/migrations" ]; then
    echo "❌ no migrations/ directory under ${root_dir} - nothing was scanned"
    echo "   A lint that scans an empty tree reports success while proving nothing."
    return 1
  fi

  # Checked explicitly rather than left to `set -e`: errexit is DISABLED
  # inside a function invoked in a `||` or `if` context (which is exactly
  # how the self-test calls this one), so a failing scan would otherwise
  # leave matches empty and be indistinguishable from a clean tree.
  if ! matches="$(scan_tree "$root_dir")"; then
    echo "❌ second-org-column lint: the migration scan itself failed under ${root_dir}"
    echo "   Treating a failed scan as a violation; a scan that did not run proves nothing."
    return 1
  fi

  seen_files=""
  if [ -n "$matches" ]; then
    seen_files="$(printf '%s\n' "$matches" | awk -F'|' 'NF{print $1}' | awk '!seen[$0]++')"
  fi

  if [ -n "$seen_files" ]; then
    while IFS= read -r file; do
      [ -n "$file" ] || continue
      actual="$(printf '%s\n' "$matches" | awk -F'|' -v f="$file" '$1==f' | wc -l | tr -d ' ')"
      if ! expected="$(allow_list_count "$file")"; then
        unlisted="${unlisted}${file}"$'\n'
        fail=1
        continue
      fi
      if [ "$actual" -ne "$expected" ]; then
        miscount="${miscount}  ${file}: expected ${expected}, found ${actual}"$'\n'
        fail=1
      fi
    done <<EOF
$seen_files
EOF
  fi

  # An allow-listed file that no longer matches at all is a STALE entry - the
  # same "the number must never drift silently" discipline, in the other
  # direction. Gated on the file existing under this scan root, because a
  # fixture tree legitimately does not contain it and that is not "the column
  # vanished", it is "this root never had it".
  # shellcheck disable=SC2034  # justification column intentionally unread
  while IFS='|' read -r alfile alcount _just; do
    [ -n "$alfile" ] || continue
    [ -f "$root_dir/$alfile" ] || continue
    if [ -z "$(printf '%s\n' "$seen_files" | awk -v f="$alfile" '$0==f')" ]; then
      miscount="${miscount}  ${alfile}: expected ${alcount}, found 0 (entry is stale - the statements moved or were removed)"$'\n'
      fail=1
    fi
  done <<EOF
$ALLOW_LIST_TABLE
EOF

  if [ "$fail" -eq 1 ]; then
    echo "❌ second-org-column lint failed (#3334)"
    echo ""
    if [ -n "$unlisted" ]; then
      echo "These forward migrations introduce a second organization-scope column on"
      echo "a policy table and are NOT on the allow-list in"
      echo "scripts/lint-no-second-org-column.sh:"
      echo ""
      while IFS= read -r file; do
        [ -n "$file" ] || continue
        echo "  $file"
        printf '%s\n' "$matches" | awk -F'|' -v f="$file" '$1==f {printf "    :%s  %s\n      %s\n", $2, $3, $4}'
      done <<EOF
$unlisted
EOF
      echo ""
    fi
    if [ -n "$miscount" ]; then
      echo "These allow-listed files no longer match their expected violation count"
      echo "(a statement was added or removed without updating the allow-list):"
      echo ""
      printf '%s' "$miscount"
      echo ""
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "HOW TO FIX:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "The invariant (#3334): the policy tables carry exactly ONE"
    echo "organization-scope column, and it is org_id."
    echo ""
    echo "  // ✅ Correct - scope a policy row by the canonical column"
    echo "  ALTER TABLE static_policies ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);"
    echo ""
    echo "  // ❌ Wrong - a second org-scope column is exactly the state #3334"
    echo "  //            retired: two columns, different types, different"
    echo "  //            populations, disagreeing about who owns a policy"
    echo "  ALTER TABLE static_policies ADD COLUMN organization_id UUID;"
    echo ""
    echo "If the table name is a format() placeholder, the scan cannot tell"
    echo "which table it resolves to and reports it on purpose. Name the table"
    echo "literally, or add a reviewed allow-list entry."
    echo ""
    echo "If this really is a legitimate, reviewed exception, add or update the"
    echo "entry in ALLOW_LIST_TABLE in scripts/lint-no-second-org-column.sh"
    echo "with a one-line justification, and say why on issue #3334."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    return 1
  fi

  local scanned allowed_total allowed_files
  scanned="$(find "$root_dir/migrations" -type f -name '*.sql' ! -name '*_down.sql' | wc -l | tr -d ' ')"

  # A NON-ZERO scanned count is the floor, not the proof - but a ZERO count is
  # positive proof the run was vacuous, and a lint that scanned nothing must
  # never print a tick.
  if [ "$scanned" -eq 0 ]; then
    echo "❌ second-org-column lint scanned 0 forward migrations under ${root_dir}/migrations"
    echo "   Reporting success here would certify a check that never ran."
    return 1
  fi

  allowed_total=0
  allowed_files=0
  # shellcheck disable=SC2034  # justification column intentionally unread
  while IFS='|' read -r alfile alcount _just; do
    [ -n "$alfile" ] || continue
    allowed_total=$(( allowed_total + alcount ))
    allowed_files=$(( allowed_files + 1 ))
  done <<EOF
$ALLOW_LIST_TABLE
EOF

  echo "✅ second-org-column lint passed (#3334)"
  echo "   ${scanned} forward migration(s) scanned (*_down.sql excluded - the runner never applies them)"
  echo "   tables guarded: static_policies, dynamic_policies, policy_overrides"
  echo "   spellings guarded: organization_id, organisation_id, org_uuid"
  echo "   ${allowed_total} allow-listed historical occurrence(s) across ${allowed_files} file(s), all count-matched"
  echo "   0 unlisted reintroduction(s)"
  return 0
}

# ════════════════════════════════════════════════════════════════════════════
# --self-test
# ════════════════════════════════════════════════════════════════════════════
#
# Drives this script over fixtures it builds itself and asserts BOTH
# directions: that every reintroduction vector FAILS the lint, and that every
# legitimate survivor PASSES it. Both halves matter equally - an assertion
# that cannot pass is the same defect as one that cannot fail, and a guard
# proven only to go green has not been proven to do anything at all.
#
# Modelled on scripts/check-partner-operator-parity.sh --self-test, and wired
# into CI beside the real run so the fixtures are exercised on every PR.
# ════════════════════════════════════════════════════════════════════════════

SELF_TEST_FAILURES=0

# fixture_tree FILENAME BODY: builds a temp tree holding BODY at
# migrations/core/FILENAME, plus a benign forward migration.
#
# The baseline file is load-bearing, not decoration. run_lint refuses to
# report success on a tree with zero forward migrations, so a fixture
# consisting only of a `*_down.sql` file would be rejected for being VACUOUS
# rather than for anything to do with down-file handling - the assertion
# would be incapable of passing no matter how the down-exclusion behaved, and
# would therefore be measuring nothing. The self-test caught exactly that
# before this baseline existed. The baseline keeps every fixture tree
# non-vacuous so each assertion tests only the property it names.
fixture_tree() {
  local dir="$1" fname="$2" body="$3"
  mkdir -p "$dir/migrations/core"
  printf 'ALTER TABLE static_policies ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);\n' \
    > "$dir/migrations/core/001_baseline.sql"
  printf '%s\n' "$body" > "$dir/migrations/core/$fname"
}

# expect_fail NAME SQL_BODY [FILENAME]: the fixture MUST be rejected.
expect_fail() {
  local name="$1" body="$2" fname="${3:-900_fixture.sql}"
  local dir rc out
  dir="$(mktemp -d)"
  fixture_tree "$dir" "$fname" "$body"
  rc=0
  out="$(run_lint "$dir" 2>&1)" || rc=$?
  rm -rf "$dir"
  if [ "$rc" -eq 0 ]; then
    printf 'not ok - %s: expected a violation, lint passed\n' "$name"
    printf '%s\n' "$out" | sed 's/^/      /'
    SELF_TEST_FAILURES=$(( SELF_TEST_FAILURES + 1 ))
  else
    printf 'ok - %s (rejected)\n' "$name"
  fi
}

# expect_pass NAME SQL_BODY [FILENAME]: the fixture MUST be accepted.
expect_pass() {
  local name="$1" body="$2" fname="${3:-900_fixture.sql}"
  local dir rc out
  dir="$(mktemp -d)"
  fixture_tree "$dir" "$fname" "$body"
  rc=0
  out="$(run_lint "$dir" 2>&1)" || rc=$?
  rm -rf "$dir"
  if [ "$rc" -ne 0 ]; then
    printf 'not ok - %s: expected clean, lint rejected it\n' "$name"
    printf '%s\n' "$out" | sed 's/^/      /'
    SELF_TEST_FAILURES=$(( SELF_TEST_FAILURES + 1 ))
  else
    printf 'ok - %s (accepted)\n' "$name"
  fi
}

self_test() {
  printf 'lint-no-second-org-column --self-test\n\n'
  printf -- '--- vectors that MUST be rejected ---\n'

  # THE central case: the two-line house style. A line-oriented guard passes
  # this fixture, which is why it is first.
  expect_fail 'ADD COLUMN split across two lines (the core/030 house style)' \
'ALTER TABLE static_policies
    ADD COLUMN IF NOT EXISTS organization_id UUID;'

  expect_fail 'ADD COLUMN on one line' \
'ALTER TABLE dynamic_policies ADD COLUMN organization_id text;'

  expect_fail 'lower-case DDL' \
'alter table policy_overrides add column if not exists organization_id text;'

  expect_fail 'CREATE TABLE column list (the shape policy_overrides arrived in)' \
'CREATE TABLE IF NOT EXISTS policy_overrides (
    id UUID PRIMARY KEY,
    organization_id UUID,
    tenant_id VARCHAR(100)
);'

  expect_fail 'RENAME COLUMN org_id TO organization_id' \
'ALTER TABLE static_policies RENAME COLUMN org_id TO organization_id;'

  expect_fail 'dynamic SQL with an indirected %I table name' \
"DO \$\$
BEGIN
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS organization_id text', tbl);
END \$\$;"

  expect_fail 'British spelling organisation_id' \
'ALTER TABLE static_policies ADD COLUMN organisation_id text;'

  expect_fail 'org_uuid spelling' \
'ALTER TABLE dynamic_policies ADD COLUMN IF NOT EXISTS org_uuid uuid;'

  expect_fail 'schema-qualified and quoted table name' \
'ALTER TABLE public."static_policies" ADD COLUMN organization_id text;'

  expect_fail 'ALTER TABLE IF EXISTS ONLY' \
'ALTER TABLE IF EXISTS ONLY dynamic_policies ADD COLUMN organization_id text;'

  # ── R3 round 1 regression fixtures ──────────────────────────────────────
  # Each of these was a REAL false negative found by hostile review, not a
  # hypothetical. They are pinned here so a future refactor that reopens one
  # fails CI instead of quietly restoring the hole.

  expect_fail 'a /* inside a -- comment must not blind the rest of the file' \
'-- see ee/platform/customer-portal/* for the callers
ALTER TABLE static_policies
    ADD COLUMN IF NOT EXISTS organization_id UUID;'

  expect_fail 'ADD without the optional COLUMN keyword' \
'ALTER TABLE static_policies ADD organization_id text;'

  expect_fail 'ADD IF NOT EXISTS without the optional COLUMN keyword' \
'ALTER TABLE dynamic_policies ADD IF NOT EXISTS organization_id text;'

  expect_fail 'a double-quoted column identifier' \
'ALTER TABLE static_policies ADD COLUMN "organization_id" text;'

  expect_fail 'a double-quoted column identifier in a CREATE TABLE list' \
'CREATE TABLE policy_overrides (
    id uuid PRIMARY KEY,
    "organization_id" uuid
);'

  expect_fail 'an unterminated /* leaves the file unscanned and must be reported' \
'/* note: this comment is never closed
ALTER TABLE static_policies ADD COLUMN organization_id text;'

  # R3 round 3: the type-token requirement added in round 2 must not start
  # missing real column definitions. Postgres array shorthand types are spelled
  # _text / _int4, so the class has to admit a leading underscore.
  expect_fail 'a column whose type is the _text array shorthand' \
'CREATE TABLE policy_overrides (
    id uuid PRIMARY KEY,
    organization_id _text
);'

  expect_fail 'a column whose type sits on the following line' \
'CREATE TABLE static_policies (
    id uuid PRIMARY KEY,
    organization_id
        uuid
);'

  # R3 round 4: CREATE TABLE ... AS SELECT names its columns from the query,
  # so the banned name carries NO type token and the round-2 ` +[a-z_]`
  # requirement cannot see it. Both shapes were live false negatives.
  expect_fail 'CTAS with an explicit column-name list (no types anywhere)' \
'CREATE TABLE policy_overrides (id, organization_id) AS SELECT id, org_id FROM legacy_overrides;'

  expect_fail 'CTAS whose SELECT aliases a column to the banned name' \
'CREATE TABLE policy_overrides AS SELECT id, org_id AS organization_id FROM legacy_overrides;'

  expect_fail 'rebuild-and-swap via CTAS: a shadow table renamed over a policy table' \
'CREATE TABLE static_policies_new (id, organization_id) AS SELECT id, org_id FROM static_policies;
ALTER TABLE static_policies_new RENAME TO static_policies;'

  expect_fail 'rebuild-and-swap: a shadow table renamed over a policy table' \
'CREATE TABLE static_policies_new (
    id uuid PRIMARY KEY,
    organization_id uuid
);
ALTER TABLE static_policies RENAME TO static_policies_old;
ALTER TABLE static_policies_new RENAME TO static_policies;'

  # ── R3 round 5 regression fixtures ──────────────────────────────────────
  # An independent mutation matrix scored 67/82 against the round-4 script and
  # every one of the 15 failures was a FALSE NEGATIVE in one of three vectors.
  # All three are pinned here on ALL THREE target tables, because the vectors
  # are table-independent and a single-table fixture would not have proven
  # that. Each was confirmed to exit 0 before the fix and to exit non-zero
  # naming the right kind after it.

  # 5a. Rebuild-and-swap where the shadow table is created BARE and gains the
  # column by ALTER. The file header claimed vector 5 was covered; it was
  # covered only for a shadow table born with the column in its CREATE list.
  expect_fail 'swap: bare shadow table + ADD COLUMN, over static_policies' \
'CREATE TABLE static_policies_new (id uuid);
ALTER TABLE static_policies_new ADD COLUMN organization_id uuid;
ALTER TABLE static_policies_new RENAME TO static_policies;'

  expect_fail 'swap: bare shadow table + ADD COLUMN, over dynamic_policies' \
'CREATE TABLE dynamic_policies_new (id uuid);
ALTER TABLE dynamic_policies_new ADD COLUMN IF NOT EXISTS organisation_id text;
ALTER TABLE dynamic_policies_new RENAME TO dynamic_policies;'

  expect_fail 'swap: bare shadow table + ADD COLUMN, over policy_overrides' \
'CREATE TABLE policy_overrides_new (id uuid);
ALTER TABLE policy_overrides_new ADD org_uuid uuid;
ALTER TABLE policy_overrides_new RENAME TO policy_overrides;'

  expect_fail 'swap: bare shadow table + RENAME COLUMN, over static_policies' \
'CREATE TABLE static_policies_new (id uuid, org_id text);
ALTER TABLE static_policies_new RENAME COLUMN org_id TO organization_id;
ALTER TABLE static_policies_new RENAME TO static_policies;'

  expect_fail 'swap: bare shadow table + RENAME COLUMN, over dynamic_policies' \
'CREATE TABLE dynamic_policies_new (id uuid, org_id text);
ALTER TABLE dynamic_policies_new RENAME COLUMN org_id TO organization_id;
ALTER TABLE dynamic_policies_new RENAME TO dynamic_policies;'

  expect_fail 'swap: bare shadow table + RENAME COLUMN, over policy_overrides' \
'CREATE TABLE policy_overrides_new (id uuid, org_id text);
ALTER TABLE policy_overrides_new RENAME COLUMN org_id TO organization_id;
ALTER TABLE policy_overrides_new RENAME TO policy_overrides;'

  # 5b. CREATE TABLE ... (LIKE donor) - the canonical Postgres rebuild idiom.
  # The column set is copied, so the banned name is nowhere in the statement.
  # Both the swap form and the direct re-statement of the table are covered.
  expect_fail 'LIKE donor: swap over static_policies' \
'CREATE TABLE static_policies_new (LIKE legacy_static_policies INCLUDING ALL);
ALTER TABLE static_policies_new RENAME TO static_policies;'

  expect_fail 'LIKE donor: swap over dynamic_policies' \
'CREATE TABLE dynamic_policies_new (LIKE legacy_dynamic_policies INCLUDING DEFAULTS);
ALTER TABLE dynamic_policies_new RENAME TO dynamic_policies;'

  expect_fail 'LIKE donor: direct CREATE TABLE IF NOT EXISTS policy_overrides' \
'CREATE TABLE IF NOT EXISTS policy_overrides (LIKE legacy_overrides INCLUDING ALL);'

  expect_fail 'LIKE donor: direct CREATE TABLE static_policies' \
'CREATE TABLE static_policies (LIKE legacy_static_policies INCLUDING ALL);'

  expect_fail 'LIKE donor: direct CREATE TABLE dynamic_policies, second table element' \
'CREATE TABLE dynamic_policies (
    id uuid PRIMARY KEY,
    LIKE legacy_dynamic_policies INCLUDING ALL
);'

  # 5c. CREATE TABLE ... INHERITS (parent) - the child inherits the parent's
  # columns, again without naming any of them.
  expect_fail 'INHERITS parent: direct CREATE TABLE static_policies' \
'CREATE TABLE static_policies (
    id uuid PRIMARY KEY
) INHERITS (legacy_static_policies);'

  expect_fail 'INHERITS parent: direct CREATE TABLE dynamic_policies' \
'CREATE TABLE dynamic_policies (id uuid) INHERITS (legacy_dynamic_policies);'

  expect_fail 'INHERITS parent: swap over policy_overrides' \
'CREATE TABLE policy_overrides_new (id uuid) INHERITS (legacy_overrides);
ALTER TABLE policy_overrides_new RENAME TO policy_overrides;'

  # The two remaining members of the copied-column-set family, closed with it
  # rather than left as a fresh undocumented bypass one keyword away from 5b.
  expect_fail 'AS SELECT * copies the donor column set, over policy_overrides' \
'CREATE TABLE policy_overrides_new AS SELECT * FROM legacy_overrides;
ALTER TABLE policy_overrides_new RENAME TO policy_overrides;'

  expect_fail 'AS TABLE donor copies the donor column set, over static_policies' \
'CREATE TABLE static_policies AS TABLE legacy_static_policies;'

  printf -- '\n--- survivors and near-misses that MUST be accepted ---\n'

  expect_pass 'line comment mentioning the exact DDL' \
'-- ALTER TABLE static_policies ADD COLUMN organization_id UUID;
-- organization_id was dropped from static_policies by core/166.
ALTER TABLE static_policies ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);'

  expect_pass 'block comment mentioning the exact DDL' \
'/* ALTER TABLE policy_overrides
     ADD COLUMN organization_id UUID; */
ALTER TABLE policy_overrides ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);'

  expect_pass 'customers.organization_id - the org-name slug, a different thing' \
'ALTER TABLE customers ADD COLUMN IF NOT EXISTS organization_id TEXT;'

  expect_pass 'policy_evaluations.organization_id - deliberately kept (core/090)' \
'CREATE TABLE IF NOT EXISTS policy_evaluations (
    id UUID PRIMARY KEY,
    organization_id UUID,
    tenant_id VARCHAR(100) NOT NULL
);'

  expect_pass 'ALTER COLUMN ... TYPE is a retype, not an introduction (core/133)' \
'ALTER TABLE static_policies ALTER COLUMN organization_id TYPE text USING organization_id::text;'

  expect_pass 'DROP COLUMN (core/030 down, core/166 forward)' \
'ALTER TABLE static_policies DROP COLUMN IF EXISTS organization_id;'

  expect_pass 'org_id - the canonical column - is not banned' \
'ALTER TABLE static_policies ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);'

  expect_pass 'identifier containing a banned name as a substring' \
'ALTER TABLE static_policies ADD COLUMN sub_organization_id text;
ALTER TABLE dynamic_policies ADD COLUMN organization_identifier text;'

  expect_pass 'banned name inside a RAISE EXCEPTION string in a CREATE TABLE statement' \
"DO \$\$
BEGIN
    RAISE EXCEPTION 'Migration 166 failed: %.organization_id still exists', tbl;
END \$\$;"

  expect_pass 'a *_down.sql re-adding the column (core/166 down migration)' \
"DO \$\$
BEGIN
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS organization_id text', tbl);
END \$\$;" '900_fixture_down.sql'

  expect_pass 'unrelated table with an indirected name' \
"DO \$\$
BEGIN
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS client_id text', tbl);
END \$\$;"

  # ── R3 round 2 regression fixture ───────────────────────────────────────
  # Round 1's quote-stripping fix introduced this false positive: norm() is
  # not literal-aware, so the double quotes around a jsonb DEFAULT key were
  # stripped and the JSON comma read as a column-list separator. It failed an
  # innocent migration. The column matcher now requires a TYPE after the name.
  # The single quotes below are real: inside a single-quoted shell string,
  # the '"'"' sequence yields a literal quote, so this fixture carries the
  # exact markup a jsonb DEFAULT has rather than a dollar-quoted stand-in
  # that would exercise a different lexical path from the reported defect.
  expect_pass 'a jsonb DEFAULT whose JSON keys include the banned name' \
'CREATE TABLE IF NOT EXISTS policy_overrides (
    id serial PRIMARY KEY,
    org_id VARCHAR(255) NOT NULL,
    meta jsonb NOT NULL DEFAULT '"'"'{"tenant": 1, "organization_id" : 2}'"'"'::jsonb
);'

  expect_pass 'the banned name inside a column-list constraint, not a definition' \
'CREATE TABLE IF NOT EXISTS policy_overrides (
    id uuid PRIMARY KEY,
    org_id text,
    UNIQUE (org_id, organization_id)
);'

  # R3 round 4: the CTAS arm's looser patterns must not leak into an ordinary
  # CREATE TABLE. This table carries an inner `AS (` (a generated column) AND a
  # bare banned name in a column-list constraint - the exact pair that would
  # false-positive if the CTAS gate were a naive search for `as`.
  expect_pass 'a generated column plus a column-list constraint is not a CTAS' \
'CREATE TABLE IF NOT EXISTS policy_overrides (
    id uuid PRIMARY KEY,
    org_id text,
    span int GENERATED ALWAYS AS (1 + 1) STORED,
    UNIQUE (org_id, organization_id)
);'

  expect_pass 'a CTAS that does not carry a banned column' \
'CREATE TABLE policy_overrides AS SELECT id, org_id FROM legacy_overrides;'

  expect_pass 'ADD CONSTRAINT / ADD PRIMARY KEY naming the column is not an introduction' \
'ALTER TABLE static_policies ADD CONSTRAINT organization_id_fk FOREIGN KEY (org_id) REFERENCES customers(org_id);
ALTER TABLE dynamic_policies ADD PRIMARY KEY (organization_id);'

  expect_pass 'a plain RENAME TO with no banned-column shadow table' \
'ALTER TABLE static_policies_archive RENAME TO static_policies_old;'

  # ── R3 round 5: the new arms must not fire on innocent SQL ──────────────
  # The LIKE *operator* is 147 lines of this tree and the table-element LIKE is
  # 0, so a pattern that confused them would be a far worse trade than the hole
  # it closed. These pin the discrimination in both of the places the operator
  # actually appears inside a CREATE TABLE.
  expect_pass 'the LIKE operator inside a CHECK constraint is not a table element' \
'CREATE TABLE IF NOT EXISTS policy_overrides (
    id uuid PRIMARY KEY,
    org_id text,
    CHECK (org_id LIKE '"'"'cs%'"'"')
);'

  expect_pass 'the LIKE operator in a CTAS WHERE clause is not a table element' \
'CREATE TABLE policy_overrides AS SELECT id, org_id FROM legacy_overrides WHERE (tenant_id) LIKE '"'"'cs%'"'"';'

  # `count(*)` is a star, but not a select-list star: it names one column, it
  # does not copy a column set. Requiring the star to sit at the head of the
  # select list (optionally schema-qualified) is what separates them.
  expect_pass 'count(*) in a CTAS select list does not copy a column set' \
'CREATE TABLE policy_overrides AS SELECT org_id, count(*) AS n FROM legacy_overrides GROUP BY org_id;'

  # The word "like" in prose above a target table. This is what all 5 real
  # table-element-shaped LIKE lines in migrations/ actually are, so if the
  # comment strip ever regressed this fixture is where it would show.
  expect_pass 'prose "(like ...)" in a comment above a target-table CREATE' \
'-- Pre-built policies for travel booking platforms (like Serko)
-- created by a later migration inherits NOTHING.
CREATE TABLE IF NOT EXISTS policy_overrides (
    id uuid PRIMARY KEY,
    org_id text
);'

  # The ADD COLUMN arm now records EVERY table it fires on, target or not, so
  # that a bare shadow table can be caught when it is renamed. That memory must
  # not turn an ordinary rename of an ordinary table into a violation: the
  # rename still only reports when its DESTINATION is a policy table.
  expect_pass 'a non-target table gains the column and is renamed to another non-target name' \
'ALTER TABLE customers ADD COLUMN IF NOT EXISTS organization_id TEXT;
ALTER TABLE customers RENAME TO customers_v2;'

  printf -- '\n--- the allow-list mechanism itself ---\n'

  # A file whose count is allow-listed passes; one MORE occurrence in the same
  # file fails. This is what stops an allow-list entry from becoming a blanket
  # exemption for a file.
  local dir rc
  dir="$(mktemp -d)"
  mkdir -p "$dir/migrations/core"
  cat > "$dir/migrations/core/030_policy_tier_columns.sql" <<'FIXTURE'
ALTER TABLE static_policies
    ADD COLUMN IF NOT EXISTS organization_id UUID;
ALTER TABLE dynamic_policies
    ADD COLUMN IF NOT EXISTS organization_id UUID;
CREATE TABLE IF NOT EXISTS policy_overrides (
    id UUID PRIMARY KEY,
    organization_id UUID,
    tenant_id VARCHAR(100)
);
FIXTURE
  rc=0; run_lint "$dir" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    printf 'ok - allow-listed file at its expected count of 3 (accepted)\n'
  else
    printf 'not ok - allow-listed file at its expected count of 3 was rejected\n'
    SELF_TEST_FAILURES=$(( SELF_TEST_FAILURES + 1 ))
  fi

  printf 'ALTER TABLE policy_overrides ADD COLUMN organisation_id text;\n' \
    >> "$dir/migrations/core/030_policy_tier_columns.sql"
  rc=0; run_lint "$dir" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'ok - a 4th occurrence in the allow-listed file (rejected)\n'
  else
    printf 'not ok - a 4th occurrence in the allow-listed file was accepted\n'
    SELF_TEST_FAILURES=$(( SELF_TEST_FAILURES + 1 ))
  fi
  rm -rf "$dir"

  # A tree with no migrations/ at all must FAIL, not pass vacuously.
  dir="$(mktemp -d)"
  rc=0; run_lint "$dir" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'ok - a tree with no migrations/ directory (rejected, not vacuously green)\n'
  else
    printf 'not ok - a tree with no migrations/ directory reported success\n'
    SELF_TEST_FAILURES=$(( SELF_TEST_FAILURES + 1 ))
  fi
  rm -rf "$dir"

  # A migrations/ directory holding ONLY down files scans 0 forward files and
  # must fail rather than certify a run that looked at nothing.
  dir="$(mktemp -d)"
  mkdir -p "$dir/migrations/core"
  printf 'SELECT 1;\n' > "$dir/migrations/core/900_fixture_down.sql"
  rc=0; run_lint "$dir" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'ok - a tree with 0 forward migrations (rejected, not vacuously green)\n'
  else
    printf 'not ok - a tree with 0 forward migrations reported success\n'
    SELF_TEST_FAILURES=$(( SELF_TEST_FAILURES + 1 ))
  fi
  rm -rf "$dir"

  printf '\n'
  if [ "$SELF_TEST_FAILURES" -ne 0 ]; then
    printf '❌ %s self-test assertion(s) FAILED\n' "$SELF_TEST_FAILURES"
    return 1
  fi
  printf '✅ self-test passed\n'
  return 0
}

# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════

if [ "$SELF_TEST" -eq 1 ]; then
  self_test
  exit $?
fi

if [ -z "$ROOT" ]; then
  ROOT="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
fi

run_lint "$ROOT"
exit $?
