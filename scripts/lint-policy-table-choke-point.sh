#!/usr/bin/env bash
# lint-policy-table-choke-point.sh — the "single choke point" invariant.
#
# Usage: bash scripts/lint-policy-table-choke-point.sh [ROOT]
#   ROOT defaults to the repository root DERIVED FROM THIS SCRIPT'S OWN PATH
#   (scripts/lint-deployment-mode.sh's #3170 lesson applied up front: a scan
#   rooted at $PWD is silently vacuous when CI's working directory ever
#   differs from the repo root). Fixtures pass a directory explicitly.
#
# THE INVARIANT (epic #3293, "Target architecture" section, verbatim):
#
#   "no evaluator reads a policy table directly — every verdict path goes
#   through the substrate. Guarded by a lint on `FROM static_policies` /
#   `FROM dynamic_policies` outside the shared loaders. This is the 'single
#   choke point,' at the layer that spans the services."
#
# Root cause this closes (epic #3293): the #3059 choke-point discipline was
# PER-ENGINE, not system-wide, so segment-awareness (and tenancy, override,
# audit) had to be threaded into every evaluator separately and drifted.
# #3266 is the incident this produced: platform/shared/policy/loader.go's
# GetEffective filtered segment_id while the OTHER reader over the same
# static_policies table did not, so segment-scoped policies leaked to
# non-members. Slice 1 fixed that leak; Slice 2 (#3296) converged the
# evaluation-path readers of static_policies onto loader.go. #3319 finished
# the job on the dynamic side: DynamicPolicyEngine (the in-memory engine) is
# deleted outright, and DatabaseDynamicPolicyEngine's dynamic_policies reads
# moved into loader.go, so both policy tables now have exactly one verdict-path
# reader. This script is the guard that keeps them converged: without it, the
# next feature adds a bespoke reader over either table and #3266's drift
# starts over.
#
# WHAT THIS LINT DOES. Flags any `FROM static_policies` / `FROM
# dynamic_policies` (SQL keyword FROM, upper-case — see "why FROM is
# case-sensitive" below) in non-test Go source under platform/ and ee/,
# UNLESS the file is listed in ALLOW_LIST below, WITH the exact occurrence
# count the file is expected to carry.
#
# platform/shared/policy/loader.go — the sanctioned choke point — is ALSO
# listed in ALLOW_LIST, like every other file here, not exempted by identity.
# It used to be identity-exempt (matched by path, uncounted) on the theory
# that "its whole job is to read these two tables". That was true but wrong
# for this lint's purpose: it made the single most-privileged file in the
# tree the only one with no ratchet, so a query could be added to it with no
# CI signal at all — exactly the silent-growth failure mode every other entry
# below is guarded against. loader.go held 5 occurrences when this lint was
# written and holds 8 today (see its own entry below for what changed); that
# drift is legitimate — loader.go growing IS how the choke point is supposed
# to absorb new reads — but it must still be a deliberate, reviewed act, not
# a silent one. The distinct justification (unlike the CRUD/admin/known-gap
# entries) is exactly that: it is not an exception to the invariant, it IS
# the invariant, so its count exists purely as a ratchet on that one file
# growing without review — not to gate whether it belongs on the list at all.
#
# WHY A COUNT, NOT A BARE PATH LIST. A bare "this file is fine" allowance
# (scripts/lint-deployment-mode.sh's ALLOWED_FILES shape) also silently
# permits a NEW evaluation query added to that same file later — the exact
# way #3266's second reader appeared in the first place. Keying each
# allow-list entry to the file's CURRENT occurrence count means adding one
# more `FROM static_policies` to an already-allow-listed file fails the lint
# until a human consciously bumps the number in a reviewed diff — and
# DELETING one fails it too, so the number never drifts silently stale
# either. Every entry below carries a one-line justification; an entry that
# cannot be justified in one sentence is not a line to add here, it is a
# finding for the epic's own accounting (gh issue view 3293) to resolve.
#
# WHAT COUNTS AS "JUSTIFIED" HERE — the epic's own accounting is the source
# of truth, not this script's author's judgment:
#   - CRUD / admin / metadata reads (by-id GET, List, Update, Delete, version
#     history, tenant/org policy-count quotas) are explicitly OUT OF this
#     issue's scope per epic #3293's Accounting section: "#28 portal
#     effective-policy viewer AND #23/#37/#38 CRUD/metadata/override-create
#     loaders → #3055". They read the table, but they never PRODUCE A
#     VERDICT (block/redact/deny) — the invariant this lint guards is about
#     verdict paths.
#   - platform/agent/mcp_richer_context.go is the ADR-044 session
#     break-glass path: it resolves policy metadata (risk_level,
#     allow_override, version) and active-override state for the audit
#     trail and the override-eligibility UI, never a block/allow verdict
#     itself.
#   - platform/orchestrator/ojk/readiness.go is a readiness PROBE (a COUNT
#     for a health-check endpoint), not a request-evaluation path.
#
# THE DYNAMIC-SIDE GAP IS CLOSED (#3319). Through #3296, two engines —
# DynamicPolicyEngine (platform/orchestrator/dynamic_policy_engine.go) and
# DatabaseDynamicPolicyEngine (platform/orchestrator/db_dynamic_policies.go)
# — still loaded dynamic_policies directly to build their own in-memory
# evaluation caches; #3296 Accounting had scoped that slice to "extract the
# one shared ConditionEvaluator" only (condition-MATCHING converged, see
# platform/shared/policy/condition_evaluator.go), not the table LOAD. #3319
# closed that gap: DynamicPolicyEngine is deleted (there is exactly one
# dynamic-policy engine now, DatabaseDynamicPolicyEngine), and its
# dynamic_policies reads moved into platform/shared/policy/loader.go. The
# invariant is therefore fully enforced for BOTH static_policies and
# dynamic_policies — loader.go is the single sanctioned choke point for
# each — and the allow-list below carries no unconverged-engine entry.
#
# WHY `FROM` IS MATCHED CASE-SENSITIVELY (upper-case only). Every real query
# in this codebase spells the SQL keyword `FROM` upper-case; grep confirms
# zero exceptions. Comment prose in this codebase DOES use lower-case
# "static_policies table" / "from static_policies" — matching case
# insensitively would flag platform/shared/policy/doc.go's package comment
# and others as violations. Matching upper-case FROM only, plus a filter
# that drops comment-only lines (see is_comment_line below) is what
# distinguishes real SQL from prose. There is one real comment line that
# would otherwise false-positive even with the case-sensitive match:
# platform/orchestrator/policy_api_repository.go:126 reads
# "// policy_versions INSERT is gated by `policy_id IN (SELECT FROM
# dynamic_policies ...". The comment-line filter drops it explicitly.
#
# WHAT THIS LINT DOES NOT CATCH — written down rather than left to be
# discovered, same discipline as scripts/lint-deployment-mode.sh:
#   - Table names built via string formatting, e.g.
#     `fmt.Sprintf("... FROM %s ...", table)` where `table` is set to
#     "static_policies" / "dynamic_policies" a few lines earlier. This
#     shape exists TODAY at platform/orchestrator/overrides_handler.go's
#     policyRiskAndOverride (an admin override-eligibility lookup, the same
#     justified class as the other overrides_handler.go entries) and this
#     lint cannot see it. A grep-based lint has no general defense against
#     an indirected table name; closing this gap needs either an AST-aware
#     checker or a lint-comment marker convention at each interpolation
#     site.
#   - A query built by concatenating a partial string across two `+`'d
#     literals or two adjacent string constants, where neither half alone
#     contains the full "FROM static_policies" / "FROM dynamic_policies"
#     substring.
#   - Anything in a vendored dependency, a generated file, or outside
#     platform/ and ee/ (this codebase has no root Go module — see
#     scripts/lint-deployment-mode.sh's own note on the same point).
#
# Model: scripts/lint-deployment-mode.sh (ROOT-from-BASH_SOURCE, set -euo
# pipefail, ❌/✅ output, non-zero exit on violation). No dependency beyond
# grep/awk/sort, matching that script's house style. Associative arrays
# (`declare -A`) are deliberately NOT used, for the same portability reason
# lint-deployment-mode.sh sticks to plain indexed arrays: macOS ships bash
# 3.2 as /bin/bash (Apple stopped updating it at the GPLv2/v3 license
# boundary), and 3.2 does not support `declare -A` at all — it is a hard
# parse error, not a degraded fallback. The allow-list below is a
# pipe-delimited heredoc table (the same shape as lint-deployment-mode.sh's
# FLOOR heredoc), parsed with a linear `while read` scan.

set -euo pipefail

ROOT="${1:-}"
if [ -z "$ROOT" ]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$ROOT"

# ════════════════════════════════════════════════════════════════════════════
# The sanctioned choke point — named here only for the success message below;
# it is counted in ALLOW_LIST_TABLE like every other file, not skipped.
# ════════════════════════════════════════════════════════════════════════════
LOADER_FILE="platform/shared/policy/loader.go"

# ════════════════════════════════════════════════════════════════════════════
# Allow-list: file | exact expected occurrence count of the violation
# pattern (FROM static_policies OR FROM dynamic_policies combined, after the
# comment-line filter) | one-line justification.
#
# See the header above for the classification this is built from and epic
# #3293's Accounting section for the disposition of each class.
# ════════════════════════════════════════════════════════════════════════════
ALLOW_LIST_TABLE='
platform/shared/policy/loader.go|8|THE sanctioned choke point (epic #3293/#3296), not an exception to the invariant. Counted like every other entry so a NEW query added here also trips CI until a human bumps this number in a reviewed diff -- and so does DELETING one, which is why this number moved DOWN. Was 5 when this lint was written, grew to 10, and is 8 since #3490 (Decision 5) deleted the two initQueries templates queryRequestPhase and queryResponsePhase: both carried the retired tenant_id predicate and neither was ever executed (set in initQueries, read nowhere), so they were removed rather than re-keyed -- rewriting a query no caller runs would leave a second, untested definition of the selection rule. The 8 that remain: the loadFromDatabase per-scope query, LoadSystemPolicies, effectivePolicyQueryTemplate (GetEffective pass A/B via ScanEffectivePolicyRows), CountActive (dynamic_policies), GetPolicyByID, dynamicPoliciesQueryWithSegment + dynamicPoliciesQueryWithoutSegment (RefreshDynamicPolicies) and CountAllDynamicPolicies.
platform/agent/mcp_richer_context.go|3|ADR-044 session break-glass: lookupPolicyMeta (audit risk_level/allow_override/version), lookupPolicyVersionsByID (audit policy_version stamping), lookupActiveOverride (slug->UUID resolve before reading policy_overrides) — metadata for the audit trail, never a block/allow verdict itself.
platform/agent/static_policy_repository.go|5|Agent static-policy CRUD (epic #3293 Accounting "#23/#37/#38 CRUD/metadata/override-create loaders -> #3055"): GetByID, List (scopedList + scopedListBare), GetVersions (parent-ownership EXISTS subquery), countTenantPolicies (Community tenant-policy quota). No verdict produced.
platform/orchestrator/overrides_handler.go|4|Orchestrator override-create admin lookups (#3293 Accounting, same #23/#37/#38 -> #3055 disposition): resolvePolicyUUID (static then dynamic) + invalidateCachedDeniedDecisions (static then dynamic) — override-CREATE-time admin reads, not verdict paths.
platform/orchestrator/ojk/readiness.go|1|OJK readiness probe: a health-check COUNT (countIndonesiaPIIPolicies), not a request-evaluation path.
platform/orchestrator/policy_api_repository.go|8|Orchestrator dynamic-policy CRUD (#3293 Accounting "#23/#37/#38" -> #3055): Create, GetByID, List, Delete, GetVersions, findByNameTx, findByName, CountByTenant/CountOrgPolicies. Admin policy-management API, not a verdict path.
'

# is_comment_line CONTENT: true if CONTENT, once leading whitespace is
# stripped, starts with a Go line comment (`//`). Matched so a `FROM
# static_policies` / `FROM dynamic_policies` substring mentioned IN PROSE
# (e.g. policy_api_repository.go:126's "// policy_versions INSERT is gated
# by `policy_id IN (SELECT FROM dynamic_policies ...") is not counted as a
# violation. This is a narrow, single-line filter — it does not attempt full
# Go comment parsing (block comments, mid-line trailing comments) — see the
# header's "what this lint does not catch" section for the general limits of
# a grep-based check.
#
# Implemented as an explicit trim + prefix test rather than a `case`
# glob-pattern match: bash `case` patterns are GLOBS, not regexes, and a
# leading `^` in a glob matches a literal caret character, not "start of
# string" — a `case "$x" in '^[[:space:]]*//'*)` bug that silently matches
# nothing and lets the exact comment line above through as a false positive.
is_comment_line() {
  local trimmed="$1"
  while [ "${trimmed#[[:space:]]}" != "$trimmed" ]; do
    trimmed="${trimmed#[[:space:]]}"
  done
  case "$trimmed" in
    "//"*) return 0 ;;
    *) return 1 ;;
  esac
}

# ════════════════════════════════════════════════════════════════════════════
# Scan
# ════════════════════════════════════════════════════════════════════════════
# Word-boundary-safe: `FROM[[:space:]]+(static|dynamic)_policies` followed by
# a non-identifier character or end of line, so a hypothetical
# `dynamic_policies_v2` table (or the unrelated `static_policy_versions`,
# which does not share the prefix at all) is never matched by accident.
PATTERN='FROM[[:space:]]+(static_policies|dynamic_policies)([^A-Za-z0-9_]|$)'

RAW_MATCHES=$(grep -rnE "$PATTERN" \
  --include="*.go" \
  --exclude="*_test.go" \
  --exclude="*_integration_test.go" \
  platform/ ee/ 2>/dev/null || true)

# Drop comment-only lines. The loader file is NOT skipped here — it is
# counted like every other file and checked against its ALLOW_LIST_TABLE
# entry below.
VIOLATION_LINES=""
if [ -n "$RAW_MATCHES" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    file="${line%%:*}"
    rest="${line#*:}"
    lineno="${rest%%:*}"
    content="${rest#*:}"
    is_comment_line "$content" && continue
    VIOLATION_LINES="${VIOLATION_LINES}${file}:${lineno}:${content}"$'\n'
  done <<EOF
$RAW_MATCHES
EOF
fi

# allow_list_count FILE: prints the expected count for FILE, or "" if FILE
# has no entry. Linear scan over ALLOW_LIST_TABLE — a handful of rows, no
# performance concern, and it keeps this script to plain indexed constructs
# (see the portability note above).
allow_list_count() {
  local target="$1" p c
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

# Distinct files seen in VIOLATION_LINES, in first-seen order.
SEEN_FILES=""
if [ -n "$VIOLATION_LINES" ]; then
  SEEN_FILES=$(printf '%s' "$VIOLATION_LINES" | awk -F: '{print $1}' | awk '!seen[$0]++')
fi

FAIL=0
UNLISTED=""
MISCOUNT=""

if [ -n "$SEEN_FILES" ]; then
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    actual=$(printf '%s' "$VIOLATION_LINES" | awk -F: -v f="$file" '$1==f' | wc -l | tr -d ' ')
    if ! expected=$(allow_list_count "$file"); then
      UNLISTED="${UNLISTED}${file}"$'\n'
      FAIL=1
      continue
    fi
    if [ "$actual" -ne "$expected" ]; then
      MISCOUNT="${MISCOUNT}  ${file}: expected ${expected}, found ${actual}"$'\n'
      FAIL=1
    fi
  done <<EOF
$SEEN_FILES
EOF
fi

# An allow-listed file that no longer matches at all (count dropped to zero)
# is also a stale entry — same "the number must never drift silently"
# discipline. Checked separately since the loop above only walks files that
# DID match at least once. Gated on the file actually EXISTING under this
# scan root: a fixture tree built to exercise one allow-listed file in
# isolation legitimately does not contain the other six, and that is not
# "the reads vanished" — it is "this scan root never had them to begin
# with". Only a file that is PRESENT but has zero matches is genuinely
# stale. (On a real production scan, every allow-listed file exists, so this
# reduces to exactly the original unconditional check.)
# shellcheck disable=SC2034  # justification column intentionally unread
while IFS='|' read -r alfile alcount _just; do
  [ -n "$alfile" ] || continue
  [ -f "$alfile" ] || continue
  if ! printf '%s\n' "$SEEN_FILES" | grep -qx "$alfile"; then
    MISCOUNT="${MISCOUNT}  ${alfile}: expected ${alcount}, found 0 (entry is stale — lower it or the reads moved)"$'\n'
    FAIL=1
  fi
done <<EOF
$ALLOW_LIST_TABLE
EOF

if [ "$FAIL" -eq 1 ]; then
  echo "❌ policy-table choke-point lint failed (epic #3293 / #3296)"
  echo ""
  if [ -n "$UNLISTED" ]; then
    echo "These files read static_policies or dynamic_policies directly and are"
    echo "NOT on the allow-list in scripts/lint-policy-table-choke-point.sh:"
    echo ""
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      echo "  $f"
      printf '%s\n' "$VIOLATION_LINES" | grep "^${f}:" | sed 's/^/    /'
    done <<EOF
$UNLISTED
EOF
    echo ""
  fi
  if [ -n "$MISCOUNT" ]; then
    echo "These allow-listed files no longer match their expected occurrence count"
    echo "(a query was added or removed without updating the allow-list):"
    echo ""
    printf '%s' "$MISCOUNT"
    echo ""
  fi
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "HOW TO FIX:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "The invariant (epic #3293): no evaluator reads static_policies or"
  echo "dynamic_policies directly — every verdict path goes through the shared"
  echo "substrate, platform/shared/policy/loader.go."
  echo ""
  echo "If this is a NEW verdict-path read (a block/redact/deny decision),"
  echo "route it through platform/shared/policy/loader.go instead of adding a"
  echo "bespoke query:"
  echo ""
  echo "  // ✅ Correct"
  echo "  rows, err := sharedpolicy.ScanEffectivePolicyRows(ctx, tx, ...)"
  echo ""
  echo "  // ❌ Wrong — a new bespoke reader is exactly the drift that caused"
  echo "  //             #3266 (a live cross-segment enforcement leak)"
  echo "  rows, err := tx.QueryContext(ctx, \"SELECT ... FROM static_policies ...\")"
  echo ""
  echo "If this is a legitimate CRUD/admin/metadata/probe read (never a"
  echo "verdict), add or update the entry in ALLOW_LIST in"
  echo "scripts/lint-policy-table-choke-point.sh, with a one-line justification"
  echo "comment citing where the epic dispositions that class of read (epic"
  echo "#3293's Accounting section, or a follow-up issue)."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 1
fi

TOTAL_ALLOWED=0
ALLOW_LIST_FILE_COUNT=0
# shellcheck disable=SC2034  # justification column intentionally unread
while IFS='|' read -r alfile alcount _just; do
  [ -n "$alfile" ] || continue
  TOTAL_ALLOWED=$(( TOTAL_ALLOWED + alcount ))
  ALLOW_LIST_FILE_COUNT=$(( ALLOW_LIST_FILE_COUNT + 1 ))
done <<EOF
$ALLOW_LIST_TABLE
EOF

echo "✅ policy-table choke-point lint passed"
echo "   ${LOADER_FILE} is the sanctioned choke point (count-matched like every other entry, not identity-exempt)"
echo "   ${TOTAL_ALLOWED} allow-listed choke-point/CRUD/admin/probe/known-gap occurrence(s) across ${ALLOW_LIST_FILE_COUNT} file(s), all count-matched"
echo "   0 unlisted direct reader(s) of static_policies / dynamic_policies"
