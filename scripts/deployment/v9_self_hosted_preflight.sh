#!/usr/bin/env bash
#
# v9 Self-Hosted Preflight
#
# Purpose: Operators of self-hosted / in-VPC AxonFlow deployments run this BEFORE
#          pulling a new v9 platform image. The script answers, from the RUNNING
#          OLD STACK, every question the upgrade notes would otherwise ask the
#          operator to answer by hand — every check either PASSes, WARNs, or
#          FAILs with concrete remediation.
#
# Refuses to print a final PASS unless every check passes. It never prompts and
# never blocks: WARNINGs are printed with their consequence and exit 0 for the
# operator to acknowledge, FAILs exit 1 and require action before retry.
#
# Check 12 (CORS) deliberately has NO fail branch. It reports a posture change,
# and a posture change is not a reason to refuse an upgrade — so a green run
# says nothing about whether your browser front-end will still work. Read its
# WARNINGs.
#
# Check 22 (the retired plane="memory" metric label) has no fail branch either,
# and for a stronger reason: the thing it describes lives in Prometheus and
# Grafana, which this script cannot see at all. It prints prose. A green run
# says nothing about whether your dashboards will still have data in them.
#
# It never needs the NEW image, never writes to the database, and never restarts
# anything. Every statement it issues is a SELECT, a SHOW, or an EXPLAIN.
#
# ---------------------------------------------------------------------------
# WHY THE NAME STILL SAYS v9 (read before renaming it)
# ---------------------------------------------------------------------------
# The sections below are grouped by the release that introduced them:
#
#   [1/24]-[8/24]   v8.x -> v9.0 baseline (epic #2230 Phase 7)
#   [9/24]-[12/24]  v9.13.0 (the cross-tenant remediation train, epic #3071)
#   [13/24]-[15/24] v9.14.0 governance-gate advisories (#3248, #3057, #3278)
#   [16/24]         v9.17.0 break-glass recovery readiness (ADMIN_API_KEY)
#   [17/24]-[22/24] v10.0.0 (audit_logs backfill sizing, the app-role admin
#                   pool on the orchestrator and portal, a retired env lever, a
#                   retired metric label, and two advisories about what the
#                   segment-enforcement and risk-scoring changes now do)
#   [23/24]-[24/24] v10.0.0 Decision 5 (#3490): per-tenant policy divergence,
#                   and policy rows core/165 cannot resolve an org key for
#
# KEEP THIS MAP IN STEP WITH TOTAL_CHECKS. It exists so a reader can find the
# check that matters to them without scrolling the file, which it stops doing
# the moment the numbering drifts - and drifting silently is exactly what it
# did when checks 23 and 24 were added.
#
# v10 CHECKS LIVE HERE, AND THE FILE IS DELIBERATELY NOT RENAMED THIS TRAIN.
# The name is a PUBLISHED entry point: docs/deployment/v7-to-v8-migration.md,
# v8-enterprise-migration-guide.md and v8-self-hosted-upgrade-guide.md all name
# this file, and `.github/workflows/sync-community-repo.yml` re-includes it BY
# NAME after excluding `/scripts/*` wholesale. Renaming it therefore silently
# stops it reaching the public mirror unless that include is edited in the same
# commit, and breaks every operator runbook that already names it. So a rename
# is a deliberate change with a redirect, taken on its own, and it is not taken
# as a side effect of adding a check. What DID change for v10 is the run banner
# below, which used to read "(v9 line)" and would otherwise have been a small
# lie printed on every run of a v10 preflight.
#
# In the partner install bundle (getaxonflow/axonflow-install) this same file is
# vendored BYTE-IDENTICALLY as `preflight.sh`, so the partner never sees the
# version prefix. `scripts/check-partner-preflight-parity.sh` fails CI if the two
# copies diverge; see that file for the full mechanism.
#
# ---------------------------------------------------------------------------
# ISSUE NUMBERS IN THIS FILE ARE DELIBERATE - DO NOT STRIP THEM PIECEMEAL
# ---------------------------------------------------------------------------
# This file is one of three explicit EXCEPTIONS in
# `.github/workflows/sync-community-repo.yml` (it is named on the
# `scripts/deployment/...` line), so unlike the rest of `scripts/` it DOES ship
# to the public community mirror. It cites internal issue numbers - `#3490`,
# `#3430`, `#3367` and others - and the decision, taken once and recorded here
# so it is not re-litigated one reviewer at a time, is to KEEP them.
#
# The reasoning, in the order it matters:
#   1. A bare `#NNNN` discloses nothing. There is no title, no body and no repo
#      qualifier; on the mirror it resolves to an unrelated community issue or
#      to nothing at all. What would leak is a DESCRIPTION of an unshipped
#      change, and this file carries none.
#   2. CHANGELOG.md is public and cites the SAME numbers for the same changes.
#      They are the only handle an operator has for tying a check here to the
#      entry that explains it. Stripping them from one side of that pair makes
#      both public artifacts worse.
#   3. Consistency is the actual requirement. Removing some while adding others
#      is the defect - it leaves a reader unable to tell whether an absent
#      reference means "no issue" or "redacted". Either all of them go or none
#      of them do, and (1) and (2) say none.
#
# So: cite issues freely here, and do NOT open a PR that deletes existing ones
# without also deleting all of them and the CHANGELOG's. What must never appear
# is prose ABOUT an embargoed change - a customer name, a security finding not
# yet disclosed, or a credential. Those rules are unchanged and are not what an
# issue number is.
#
# Companion docs:
#   technical-docs/v9_phase7_self_hosted_migration.md          (v8 → v9)
#   https://docs.getaxonflow.com/docs/deployment/v9-12-to-v9-13-upgrade/
#   https://docs.getaxonflow.com/docs/deployment/v8-self-hosted-upgrade-guide/
#
# ---------------------------------------------------------------------------
# WHICH DATABASE ROLE TO RUN THIS AS - READ THIS BEFORE THE FIRST RUN
# ---------------------------------------------------------------------------
# THE ANSWER DEPENDS ON YOUR DEPLOYMENT, AND ON ONE DEPLOYMENT SHAPE THE WRONG
# ROLE MAKES THIS SCRIPT REPORT AN ALL-CLEAR IT CANNOT SUPPORT.
#
#   Deployments with AXONFLOW_DB_USE_APP_ROLE unset or true (the platform
#   DEFAULT since v9.0.0, and what check 19 reports on):
#     Run as `axonflow_platform_admin`, the same BYPASSRLS role the migrations
#     use. The application role `axonflow_app_role` does NOT own the policy
#     tables and does NOT carry BYPASSRLS, so row-level security filters its
#     reads: `SELECT count(*) FROM static_policies` returns 0 with psql exit 0
#     and no error message, because the tenant-isolation policy keys on
#     `app.current_org_id` and a bare psql never sets it. Checks 3, 7, 9, 20,
#     21, 23 and 24 read those tables - SEVEN of the twenty-four, not the four
#     an earlier revision of this note listed. The checks below detect this and
#     refuse to print an affirmative pass, but a run under the right role is the
#     answer, not the detection.
#
#     The other seventeen are unaffected for a reason worth stating, so that
#     the next reader does not have to re-derive it: they either read no table
#     at all (they inspect environment variables, container/AWS metadata or a
#     version string), or they read pg_catalog, which row-level security does
#     not filter, or they read tables that carry no RLS policy - `audit_logs`
#     and `schema_migrations`, and core/156's five (`plans`, `workflows`,
#     `workflow_checkpoints`, `execution_summaries`, `webhook_subscriptions`),
#     every one of which measures `relrowsecurity=false relforcerowsecurity
#     =false` on the shipping schema.
#
#   docker-compose install bundles (the bundle sets AXONFLOW_DB_USE_APP_ROLE
#   =false):
#     Run as the bundle's own database user (`axonflow` by default). It OWNS the
#     tables, and the policy tables are ENABLE-only row-level security, which
#     the owner bypasses. `tenants` and `organizations` are FORCE row-level
#     security (core/103) and stay filtered even for the owner; the checks that
#     read them say so rather than treating the empty read as an answer.
#
#   Either way the script is READ-ONLY. It issues SELECTs and container/AWS
#   describe calls only; running it as the migration role grants it no write.
#
# There is no supported "reporting role" shortcut: a role granted plain SELECT
# but neither ownership nor BYPASSRLS is the blind case above.
#
# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
#   DATABASE_URL="postgres://axonflow_platform_admin:...@host:5432/axonflow" \
#     ./v9_self_hosted_preflight.sh
#
#   With explicit env vars (override DATABASE_URL parsing):
#   PGHOST=db.internal PGPORT=5432 PGUSER=axonflow_platform_admin PGPASSWORD=... \
#     PGDATABASE=axonflow ./v9_self_hosted_preflight.sh
#
#   The run prints the role it connected as, plus its rolsuper/rolbypassrls, on
#   the line after "Database connectivity OK" - check it matches the section
#   above before reading any verdict.
#
#   For an ECS-Fargate deployment, also export:
#   ECS_CLUSTER=axonflow-cluster ECS_AGENT_SERVICE=axonflow-agent \
#     ECS_ORCHESTRATOR_SERVICE=axonflow-orchestrator \
#     ./v9_self_hosted_preflight.sh
#
#   For the docker-compose install bundle, run it from the bundle directory —
#   the agent and orchestrator containers are discovered from the Compose
#   project rooted at $PWD:
#   DATABASE_URL="postgres://axonflow:<pw>@localhost:5432/axonflow" ./preflight.sh
#
#   If `psql` is not installed on the host, point the script at the Postgres
#   CONTAINER instead (no host package needed). The DSN is then resolved from
#   INSIDE that container:
#   AXONFLOW_PG_CONTAINER="$(docker compose ps -q postgres)" \
#     DATABASE_URL="postgres://axonflow:<pw>@localhost:5432/axonflow" ./preflight.sh
#
# Optional overrides for the per-component env discovery (checks 10, 12 and 16):
#   ECS_CLUSTER / ECS_AGENT_SERVICE / ECS_ORCHESTRATOR_SERVICE / ECS_PORTAL_SERVICE
#   AXONFLOW_AGENT_CONTAINER / AXONFLOW_ORCHESTRATOR_CONTAINER   (docker id/name)
#     / AXONFLOW_PORTAL_CONTAINER
#   AXONFLOW_AGENT_SERVICE / AXONFLOW_ORCHESTRATOR_SERVICE       (compose service)
#     / AXONFLOW_PORTAL_SERVICE
#   AGENT_ENV_FILE / ORCHESTRATOR_ENV_FILE / PORTAL_ENV_FILE     (.env / EnvironmentFile)
#
# Exit codes:
#   0 - no FAIL. THIS INCLUDES EVERY WARNING, and the distinction matters if
#       anything automated consumes this script. A WARN is a finding that needs
#       a human decision, not a passed check: checks 9, 20, 23 and 24 all report
#       consequences that REMOVE enforcement, and every one of them exits 0. AN
#       UPGRADE PIPELINE GATED ON EXIT STATUS ALONE WILL PROCEED THROUGH ALL OF
#       THEM. Gate on the output, or require a human to acknowledge each warning
#       as the final verdict block asks.
#   1 — at least one FAIL
#   2 — script error (no usable psql transport, DATABASE_URL unset, internal
#       inconsistency). Never a verdict about the deployment.
#
# The WARN-exits-0 contract is deliberate and is NOT changed here. Giving checks
# 23 and 24 an exit code of their own was considered and rejected: it would say
# that the other warnings are safe to automate past, which is false - check 9
# reports policy rows migration core/155 will DISABLE, the same class of silent
# de-enforcement - and this file is vendored byte-identically into the partner
# install bundle, so a third exit code would change the meaning of an existing
# partner pipeline mid-release with no notice. The honest fix is the sentence
# above, not a special case for the two newest checks.

set -euo pipefail

# Colors (degrade gracefully when not a TTY)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

# Per-check result tracking. Each check appends to one of these arrays.
PASS_CHECKS=()
WARN_CHECKS=()
FAIL_CHECKS=()

pass() { PASS_CHECKS+=("$1"); printf "%b✅ PASS%b  %s\n" "$GREEN" "$NC" "$1"; }
warn() { WARN_CHECKS+=("$1|$2"); printf "%b⚠️  WARN%b  %s\n         %s\n" "$YELLOW" "$NC" "$1" "$2"; }
fail() { FAIL_CHECKS+=("$1|$2"); printf "%b❌ FAIL%b  %s\n         %s\n" "$RED" "$NC" "$1" "$2"; }
info() { printf "%bℹ️  INFO%b  %s\n" "$BLUE" "$NC" "$1"; }

# ---------------------------------------------------------------------------
# Section numbering
# ---------------------------------------------------------------------------
# TOTAL_CHECKS is asserted against the number of section() calls at the end. A
# hard-coded "[3/8]" that nobody updated when a ninth check landed is a small
# lie printed on every run, and the kind that makes an operator stop reading.
TOTAL_CHECKS=24
SECTION_NO=0
section() {
    SECTION_NO=$((SECTION_NO + 1))
    printf "%b%b[%d/%d] %s%b\n" "$BOLD" "$BLUE" "$SECTION_NO" "$TOTAL_CHECKS" "$1" "$NC"
}

# ---------------------------------------------------------------------------
# The recognised DEPLOYMENT_MODE values.
# ---------------------------------------------------------------------------
# MUST equal recognisedDeploymentModes() in platform/agent/migration_helpers.go
# — canonicalDeploymentModes plus deploymentModeAliases. Drift between the two
# is caught by TestShellCopiesOfRecognisedModesMatchGo in
# platform/agent/migration_helpers_test.go, which parses this very array. A copy
# that still ACCEPTS a value the platform now refuses is the dangerous
# direction: it lets a preflight say "ready to upgrade" about a stack that will
# not boot.
#
# Keep sorted; the Go test compares sorted lists.
RECOGNISED_MODES=(
  community
  community-saas
  enterprise
  evaluation
  in-vpc-banking
  in-vpc-enterprise
  in-vpc-healthcare
  in-vpc-travel
  invpc
  saas
)

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

# trim_ws VALUE — echo VALUE without leading/trailing whitespace.
# Pure bash 3.2 parameter expansion: no `sed`, no `awk`, no locale surprises.
trim_ws() {
    local v="$1"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    printf '%s' "$v"
}

# lower VALUE — ASCII-lowercase VALUE.
# `tr` is POSIX. Deliberately NOT awk's IGNORECASE, which is a gawk extension
# and silently absent under the BSD awk shipped on macOS.
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# is_uint VALUE — true when VALUE is a non-empty run of ASCII digits. Guards
# every $(( )) below: arithmetic on a non-numeric string aborts the whole script
# under `set -e`, so a malformed scalar must never reach one.
is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# ms_to_us "12.345" — echo the value in whole microseconds, or nothing when it
# is not a number. Postgres reports EXPLAIN's execution time in fractional
# milliseconds; truncating that to integer ms turns every sub-millisecond scan
# into "0 ms" and a five-table total into "~0 ms", which reads like a broken
# measurement rather than a fast one.
ms_to_us() {
    local v="$1" int frac
    int="${v%%.*}"
    case "$v" in
        *.*) frac="${v#*.}" ;;
        *)   frac="0" ;;
    esac
    frac="${frac}000"; frac="${frac:0:3}"
    is_uint "$int" && is_uint "$frac" || return 1
    printf '%s' "$(( int * 1000 + 10#$frac ))"
}

# fmt_us MICROSECONDS — a human duration that never pretends to precision it
# does not have.
fmt_us() {
    local us="$1"
    if [[ "$us" -lt 1000 ]]; then
        printf '%s' "${us} µs"
    elif [[ "$us" -lt 1000000 ]]; then
        printf '%s' "$(( us / 1000 )) ms"
    else
        printf '%s' "$(( us / 1000000 )).$(( (us % 1000000) / 100000 )) s"
    fi
}

# pg_timeout_to_ms VALUE - echo VALUE as whole milliseconds, or echo nothing
# and return 1 when it is not a Postgres timeout literal. Used by check 17.
#
# THE BARE CASE IS MILLISECONDS, AND THAT IS THE WHOLE REASON THIS FUNCTION
# EXISTS. `statement_timeout` is an integer GUC whose implicit unit is
# milliseconds, so `statement_timeout=5000` is five seconds and not five
# thousand. Reading it as seconds inflates every configured timeout by 1000x
# and turns check 17's FAIL into a verdict nobody can ever trip; reading a
# `30s` as 30 does the opposite. Neither is a rounding error, so the units are
# spelled out here rather than defaulted anywhere.
#
# Two shapes arrive: `SHOW statement_timeout` normalises to the largest exact
# unit ("0", "500ms", "30s", "2min"), while a pg_roles.rolconfig or
# pg_db_role_setting entry carries whatever the operator typed, which may be
# bare.
#
# `us` rounds UP, never down. Postgres accepts a sub-millisecond literal on an
# ms-unit GUC, and truncating "500us" to 0 would report the TIGHTEST timeout a
# deployment can have as "no timeout configured" - a fail-open in the one
# direction this check must never fail in. 0 stays 0, because in Postgres a
# statement_timeout of zero genuinely means disabled.
pg_timeout_to_ms() {
    local v num unit
    v="$(lower "$(trim_ws "$1")")"
    [[ -z "$v" ]] && return 1
    # Order matters: `ms` and `us` must be tested before the bare `s` arm, or
    # "500ms" is read as a number ending in "s" and loses two orders of
    # magnitude. `min` is tested before `m` would be, for the same reason.
    case "$v" in
        *us)  num="${v%us}";  unit="us"  ;;
        *ms)  num="${v%ms}";  unit="ms"  ;;
        *min) num="${v%min}"; unit="min" ;;
        *s)   num="${v%s}";   unit="s"   ;;
        *h)   num="${v%h}";   unit="h"   ;;
        *d)   num="${v%d}";   unit="d"   ;;
        *)    num="$v";       unit="ms"  ;;
    esac
    num="$(trim_ws "$num")"
    is_uint "$num" || return 1
    case "$unit" in
        us)  printf '%s' "$(( (10#$num + 999) / 1000 ))" ;;
        ms)  printf '%s' "$(( 10#$num ))" ;;
        s)   printf '%s' "$(( 10#$num * 1000 ))" ;;
        min) printf '%s' "$(( 10#$num * 60000 ))" ;;
        h)   printf '%s' "$(( 10#$num * 3600000 ))" ;;
        d)   printf '%s' "$(( 10#$num * 86400000 ))" ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# Check 17's statement_timeout folding
# ---------------------------------------------------------------------------
# Declared up here with the other pure helpers, and NOT down beside check 17,
# for the reason classify_mode gives above: everything interesting about which
# configured timeout "wins" is string handling, and string handling nobody has
# watched fail is not a check. --self-test drives all of it with no database.
#
# C17_TIGHTEST_MS is the tightest NON-ZERO timeout seen so far, in whole
# milliseconds, or "" for none. C17_SOURCES_UNREADABLE records that at least
# one place a timeout could be set could not be read or could not be parsed, so
# a later "none configured" can be reported as the narrower claim it is.
C17_TIGHTEST_MS=""
C17_TIGHTEST_SRC=""
C17_SOURCES_UNREADABLE=0

# c17_split_entries BLOB KIND - fold every "label=value" entry in a
# semicolon-delimited BLOB into the tightest timeout.
#
# SEMICOLON, NOT SPACE, AND THAT IS NOT A STYLE CHOICE. The first version of
# this joined the entries with a space and split on it, which worked on
# pg_roles (a role name and a timeout literal contain no spaces) and broke on
# pg_db_role_setting the moment a cluster-wide entry rendered as
# "<all databases>/somerole=5ms": the label split into two tokens, the first
# was reported as an unparseable timeout, and only luck left the real value
# intact in the second. Measured on a live database, not theorised. A
# semicolon cannot appear in a Postgres timeout literal, and the value is taken
# after the LAST '=' so a label containing one is harmless too.
c17_split_entries() {
    local blob="$1" kind="$2" entry
    local _old_ifs="$IFS"
    IFS=';'
    # shellcheck disable=SC2206 # deliberate split on the IFS set above
    local entries=( $blob )
    IFS="$_old_ifs"
    # The count guard is for bash 3.2, which macOS still ships as /bin/bash and
    # which this script is otherwise careful to stay inside. There,
    # "${entries[@]}" on an EMPTY array under `set -u` is not an empty loop, it
    # is "unbound variable" and the script dies. Measured on 3.2.57; bash 5
    # accepts it, so the whole self-test passed on the development machine while
    # the shipped path aborted on an operator's.
    [[ "${#entries[@]}" -eq 0 ]] && return 0
    for entry in "${entries[@]}"; do
        [[ -z "$entry" ]] && continue
        c17_consider "$kind ${entry%=*}" "${entry##*=}"
    done
    return 0
}

# c17_consider LABEL RAWVALUE - fold one configured timeout into the tightest.
# ZERO IS NOT A CANDIDATE: in Postgres a statement_timeout of 0 means disabled,
# so treating it as "0 ms, the tightest of all" would FAIL every deployment that
# has correctly turned the timeout off.
c17_consider() {
    local label="$1" raw="$2" ms=""
    [[ -z "$raw" ]] && return 0
    if ! ms="$(pg_timeout_to_ms "$raw")"; then
        info "  could not parse a statement_timeout of '$raw' ($label) - reporting it rather than guessing"
        C17_SOURCES_UNREADABLE=1  # an unparsed value is not "none configured"
        return 0
    fi
    [[ "$ms" == "0" ]] && return 0
    if [[ -z "$C17_TIGHTEST_MS" ]] || [[ "$ms" -lt "$C17_TIGHTEST_MS" ]]; then
        C17_TIGHTEST_MS="$ms"
        C17_TIGHTEST_SRC="$label"
    fi
    return 0
}

# component_names COMPONENT - resolve the three names a component is known by,
# into COMP_UPPER / COMP_DEFAULT_SVC / COMP_ECS_NAMES. Returns 1 for a
# component this script does not know.
#
# ONE table, because the alternative is two. discover_env needs these names and
# so does the ECS secrets[] probe used by checks 8 and 18, and two call sites
# spelling out "the portal's ECS container definition is called customer-portal,
# not axonflow-portal" is two call sites that will eventually disagree about it.
#
# The names are not derivable from the component word and that is the point:
# the portal's Compose service is axonflow-customer-portal while its ECS
# container definition is customer-portal. Deriving them worked only for as
# long as every component happened to be named after itself.
COMP_UPPER=""
COMP_DEFAULT_SVC=""
COMP_ECS_NAMES=""
component_names() {
    COMP_UPPER=""; COMP_DEFAULT_SVC=""; COMP_ECS_NAMES=""
    case "$1" in
        agent)
            COMP_UPPER="AGENT"; COMP_DEFAULT_SVC="axonflow-agent"
            COMP_ECS_NAMES="name=='agent'||name=='axonflow-agent'" ;;
        orchestrator)
            COMP_UPPER="ORCHESTRATOR"; COMP_DEFAULT_SVC="axonflow-orchestrator"
            COMP_ECS_NAMES="name=='orchestrator'||name=='axonflow-orchestrator'" ;;
        portal)
            COMP_UPPER="PORTAL"; COMP_DEFAULT_SVC="axonflow-customer-portal"
            COMP_ECS_NAMES="name=='customer-portal'||name=='axonflow-customer-portal'||name=='portal'" ;;
        *) return 1 ;;
    esac
    return 0
}

# A snapshot of THIS shell's environment, taken before any check assigns a
# variable. Discovery source (5) reads from the snapshot rather than from the
# live shell, so a later `ORG_ID="$DISC_VALUE"` cannot make a subsequent lookup
# report the script's own working value as if it came from the operator.
SHELL_ENV_SNAPSHOT="$(env)"

# ---------------------------------------------------------------------------
# DEPLOYMENT_MODE classification
# ---------------------------------------------------------------------------
# Defined up here, next to the other pure helpers, rather than inside check 10:
# it is the one piece of judgement in this script that can be tested WITHOUT a
# database, and `--self-test` below does exactly that.
#
# Sets MODE_CLASS to recognised | unset | unrecognised, and MODE_HINT to the
# diagnosis for the unrecognised case. The value is compared EXACTLY, because
# that is what the platform does; the trimming and case-folding here exist ONLY
# to explain the failure, never to accept the value.
MODE_CLASS=""
MODE_HINT=""
classify_mode() {
    local raw="$1" m trimmed folded tf
    MODE_CLASS=""; MODE_HINT=""
    if [[ -z "$raw" ]]; then MODE_CLASS="unset"; return 0; fi
    for m in "${RECOGNISED_MODES[@]}"; do
        if [[ "$raw" == "$m" ]]; then MODE_CLASS="recognised"; return 0; fi
    done
    MODE_CLASS="unrecognised"
    trimmed="$(trim_ws "$raw")"
    folded="$(lower "$raw")"
    tf="$(lower "$trimmed")"
    for m in "${RECOGNISED_MODES[@]}"; do
        if [[ "$tf" == "$m" ]]; then
            if [[ "$trimmed" != "$raw" && "$folded" != "$raw" ]]; then
                MODE_HINT="it differs from '$m' by BOTH surrounding whitespace and capitalisation; the platform matches EXACTLY — no trimming, no case-folding"
            elif [[ "$trimmed" != "$raw" ]]; then
                MODE_HINT="it is '$m' with leading/trailing whitespace; the platform matches EXACTLY and does not trim"
            else
                MODE_HINT="it is '$m' in the wrong case; the platform matches EXACTLY and does not case-fold"
            fi
            return 0
        fi
    done
    MODE_HINT="it is not any recognised value, in any spelling"
    return 0
}

# ---------------------------------------------------------------------------
# Customer-portal admin-auth requirement (check 16)
# ---------------------------------------------------------------------------
# The DEPLOYMENT_MODE values on which the customer-portal's admin middleware
# leaves authentication OPTIONAL. MUST equal the enumerated arms of the switch
# in isAdminAuthRequired() (ee/platform/customer-portal/middleware/admin_auth.go).
#
# This is deliberately a SEPARATE list from RECOGNISED_MODES above, not a reuse
# of it. The two happen to hold the same strings today plus the empty one, and
# reusing the array would make a future addition to the migration selector
# silently widen the set of modes this check believes may run without admin
# auth - a fail-open direction. The platform's default arm is `true` (fail
# closed on a mode nobody enumerated), and the loop below reproduces that by
# treating any value NOT in this list as requiring auth.
#
# The empty entry is real and is the "" case arm in the Go switch: an unset
# DEPLOYMENT_MODE leaves admin auth optional outside production.
PORTAL_ADMIN_AUTH_OPTIONAL_MODES=(
  ""
  community
  community-saas
  enterprise
  evaluation
  in-vpc-banking
  in-vpc-enterprise
  in-vpc-healthcare
  in-vpc-travel
  invpc
  saas
)

# admin_auth_required MODE ENVIRONMENT KEY - sets ADMIN_AUTH_REQUIRED to 1 or 0.
#
# Mirrors isAdminAuthRequired(deploymentMode, environment, adminAPIKey):
#   ENVIRONMENT is "production"  -> required, whatever the mode says
#   a key is configured          -> required (setting it IS how an operator
#                                   turns enforcement on)
#   an enumerated mode, no key   -> not required (anonymous admin API)
#   anything else, no key        -> required (fail closed)
#
# The normalisation is NOT decorative and is the opposite of classify_mode's.
# check 10 must compare DEPLOYMENT_MODE byte-for-byte because the migration
# selector does; this predicate must TRIM and CASE-FOLD because the portal does:
# it reads ENVIRONMENT through strings.ToLower and then TrimSpace, TrimSpaces the
# mode, and reads the key through secretenv.Get, which trims it once so that
# "is a key configured" and the constant-time compare cannot disagree.
#
# The last of those is the one that bites an operator here: ADMIN_API_KEY set to
# whitespace is a non-empty environment variable that the portal reads as BLANK.
# A check testing the raw value for non-emptiness would report the recovery path
# as armed on a deployment where every admin route answers 500.
#
# KEY is never printed by this function, and nothing downstream prints it either
# - only whether it is blank is ever reported.
ADMIN_AUTH_REQUIRED=0
admin_auth_required() {
    local mode_norm env_norm key_norm m
    mode_norm="$(trim_ws "$1")"
    env_norm="$(lower "$(trim_ws "$2")")"
    key_norm="$(trim_ws "$3")"
    ADMIN_AUTH_REQUIRED=1
    if [[ "$env_norm" == "production" ]]; then return 0; fi
    if [[ -n "$key_norm" ]]; then return 0; fi
    for m in "${PORTAL_ADMIN_AUTH_OPTIONAL_MODES[@]}"; do
        if [[ "$mode_norm" == "$m" ]]; then ADMIN_AUTH_REQUIRED=0; return 0; fi
    done
    return 0
}

# ---------------------------------------------------------------------------
# --self-test — prove the pure logic, with no database and no deployment
# ---------------------------------------------------------------------------
# Runs in CI (tests/regression-test-required/preflight_self_test.sh). It exists
# because everything interesting about check 10 is a string comparison, and a
# string comparison that nobody watched fail is not a check. Each case below is
# a claim about the PLATFORM's behaviour, so a change here is a change to what
# this script asserts about the product.
#
# Deliberately includes DECOYS that must NOT be classified as recognised —
# `communityx`, `com munity`, `in-vpc` — because a matcher that used a substring
# or a prefix would pass every positive case and still be wrong.
# is_multiline_result RAW -> 0 (true) when RAW carries a newline that is not
# just psql's single trailing one. Split out of q() so --self-test can drive it
# without a database; see the assertions there for both directions.
is_multiline_result() {
    local raw="$1" stripped
    [[ "$raw" == *$'\n'* ]] || return 1
    stripped="${raw%$'\n'}"
    [[ "$stripped" == *$'\n'* ]]
}

# rls_verdict RLS_ACTIVE ROWS_SEEN -> echoes blind | filtered | clear | unknown
#
# THE ONE QUESTION A CHECK MUST ANSWER BEFORE IT PRINTS AN ALL-CLEAR: can this
# connection see the rows it just counted zero of?
#
# A ZERO IS NOT AN ANSWER UNLESS YOU KNOW IT COULD HAVE BEEN NON-ZERO. Under
# row-level security a filtered read returns an empty set with psql exit 0 and
# no error, so "no affected rows" and "no visible rows" are the same bytes. The
# discriminator cannot be another SELECT against the same table - that read
# comes back through the same filter, so a blind connection is invisible to a
# blindness probe that reads through the blindfold. It has to come from
# pg_catalog, which row-level security does not filter:
# `row_security_active(tbl)` is true exactly when this connection's reads of
# `tbl` are subject to RLS policies, and it already accounts for BYPASSRLS, for
# ownership, for FORCE, and for the row_security GUC.
#
# The two inputs are therefore RLS-activeness (from the catalogue) and the row
# count (from the table), and the verdicts are:
#
#   clear     RLS is not applied to this connection here. The count is the
#             whole truth and every downstream verdict is safe.
#   blind     RLS IS applied and the table read as EMPTY. The count is
#             worthless: it is what a filtered read and an empty table both
#             look like. No affirmative all-clear may be built on it.
#   filtered  RLS IS applied and rows were visible. The count is real but may
#             be PARTIAL - some rows can still be hidden - so findings stand
#             and an all-clear is qualified.
#   unknown   a probe did not execute, or returned something that is not a
#             boolean/among-int. Never silently folded into "clear".
#
# Kept as a pure function of two strings precisely so --self-test can drive
# every arm with no database; see the assertions there. The DIRECTION is the
# part worth testing: three of the four verdicts must block a pass, and a
# version that returned "clear" on a malformed probe would pass every positive
# case and still print the all-clear this exists to prevent.
rls_verdict() {
    local active="$1" rows="$2"
    case "$active" in
        t|true|TRUE|True) ;;
        f|false|FALSE|False) printf 'clear'; return 0 ;;
        *) printf 'unknown'; return 0 ;;
    esac
    if ! is_uint "$rows"; then printf 'unknown'; return 0; fi
    if [[ "$rows" -eq 0 ]]; then printf 'blind'; else printf 'filtered'; fi
}

# rls_blocks_all_clear VERDICT -> 0 (true) when VERDICT forbids an affirmative
# pass. Spelled out rather than inlined as [[ $v == blind ]] at each call site:
# `unknown` must block too, and a per-site comparison is where that gets
# forgotten on the fourth copy.
rls_blocks_all_clear() {
    case "$1" in
        blind|unknown) return 0 ;;
        *) return 1 ;;
    esac
}

_ST_FAILURES=0
_st_eq() { # _st_eq WHAT GOT WANT
    if [[ "$2" == "$3" ]]; then
        printf "  ok    %s\n" "$1"
    else
        printf "  FAIL  %s\n        got:  %s\n        want: %s\n" "$1" "$2" "$3"
        _ST_FAILURES=$((_ST_FAILURES + 1))
    fi
}
_st_contains() { # _st_contains WHAT HAYSTACK NEEDLE
    case "$2" in
        *"$3"*) printf "  ok    %s\n" "$1" ;;
        *) printf "  FAIL  %s\n        %s\n        does not contain: %s\n" "$1" "$2" "$3"
           _ST_FAILURES=$((_ST_FAILURES + 1)) ;;
    esac
}
run_self_test() {
    local m prev=""
    printf "preflight --self-test\n\n"

    printf "RECOGNISED_MODES is sorted, deduplicated and non-empty\n"
    _st_eq "array is non-empty" "$([[ "${#RECOGNISED_MODES[@]}" -gt 0 ]] && echo yes || echo no)" "yes"
    for m in "${RECOGNISED_MODES[@]}"; do
        if [[ -n "$prev" ]]; then
            _st_eq "sorted: '$prev' < '$m'" "$([[ "$prev" < "$m" ]] && echo yes || echo no)" "yes"
        fi
        prev="$m"
    done

    printf "\nevery recognised mode classifies as recognised\n"
    for m in "${RECOGNISED_MODES[@]}"; do
        classify_mode "$m"
        _st_eq "classify('$m')" "$MODE_CLASS" "recognised"
    done

    printf "\nunset is LEGAL — it must never classify as unrecognised\n"
    classify_mode ""
    _st_eq "classify('')" "$MODE_CLASS" "unset"

    printf "\ndecoys must NOT be recognised (a substring or prefix matcher passes the cases above and fails these)\n"
    for m in communityx xcommunity "com munity" in-vpc saa community-saas-x "" ; do
        [[ -z "$m" ]] && continue
        classify_mode "$m"
        _st_eq "classify('$m')" "$MODE_CLASS" "unrecognised"
    done

    printf "\nthe realistic typos are diagnosed, not just rejected\n"
    classify_mode " community"
    _st_eq       "classify(' community')" "$MODE_CLASS" "unrecognised"
    _st_contains "hint(' community')"     "$MODE_HINT"  "whitespace"
    classify_mode "community "
    _st_contains "hint('community ')"     "$MODE_HINT"  "whitespace"
    classify_mode "Community"
    _st_eq       "classify('Community')"  "$MODE_CLASS" "unrecognised"
    _st_contains "hint('Community')"      "$MODE_HINT"  "wrong case"
    classify_mode "IN-VPC-BANKING"
    _st_contains "hint('IN-VPC-BANKING')" "$MODE_HINT"  "wrong case"
    classify_mode " Community"
    _st_contains "hint(' Community')"     "$MODE_HINT"  "BOTH"
    classify_mode "in-vpc-enterprize"
    _st_contains "hint('in-vpc-enterprize')" "$MODE_HINT" "not any recognised value"

    printf "\ncustomer-portal admin-auth requirement (check 16; mirrors isAdminAuthRequired)\n"
    # ENVIRONMENT=production requires the key whatever the mode says. This is the
    # rule the shipped bundle runs under, so it is the arm check 16 nearly always
    # takes.
    admin_auth_required "in-vpc-enterprise" "production" ""
    _st_eq "auth(in-vpc-enterprise, production, no key)" "$ADMIN_AUTH_REQUIRED" "1"
    admin_auth_required "community" "production" ""
    _st_eq "auth(community, production, no key)" "$ADMIN_AUTH_REQUIRED" "1"
    admin_auth_required "" "production" ""
    _st_eq "auth(unset mode, production, no key)" "$ADMIN_AUTH_REQUIRED" "1"
    # The portal lower-cases ENVIRONMENT and trims it, so both of these ARE
    # production. A comparison that skipped either would silently downgrade a
    # production deployment to the optional path.
    admin_auth_required "in-vpc-enterprise" "PRODUCTION" ""
    _st_eq "auth(in-vpc-enterprise, PRODUCTION, no key)" "$ADMIN_AUTH_REQUIRED" "1"
    admin_auth_required "in-vpc-enterprise" "  production  " ""
    _st_eq "auth(in-vpc-enterprise, ' production ', no key)" "$ADMIN_AUTH_REQUIRED" "1"
    # ...but the match is EXACT, not a substring: a substring matcher passes
    # every case above and wrongly requires auth here.
    admin_auth_required "in-vpc-enterprise" "production-like" ""
    _st_eq "auth(in-vpc-enterprise, production-like, no key)" "$ADMIN_AUTH_REQUIRED" "0"

    printf "\noutside production, an enumerated mode with no key leaves admin auth OPTIONAL\n"
    admin_auth_required "in-vpc-enterprise" "dev" ""
    _st_eq "auth(in-vpc-enterprise, dev, no key)" "$ADMIN_AUTH_REQUIRED" "0"
    admin_auth_required "" "dev" ""
    _st_eq "auth(unset mode, dev, no key)" "$ADMIN_AUTH_REQUIRED" "0"
    admin_auth_required "community" "" ""
    _st_eq "auth(community, unset env, no key)" "$ADMIN_AUTH_REQUIRED" "0"
    admin_auth_required "saas" "staging" ""
    _st_eq "auth(saas, staging, no key)" "$ADMIN_AUTH_REQUIRED" "0"
    # The portal TRIMS the mode here, unlike the migration selector in check 10
    # which matches it byte-for-byte. Both behaviours are the platform's; this
    # case pins that the two are not confused with each other.
    admin_auth_required " in-vpc-enterprise" "dev" ""
    _st_eq "auth(' in-vpc-enterprise', dev, no key)" "$ADMIN_AUTH_REQUIRED" "0"

    printf "\na configured key turns enforcement ON, and a whitespace-only key is NOT configured\n"
    admin_auth_required "in-vpc-enterprise" "dev" "0123456789abcdef"
    _st_eq "auth(in-vpc-enterprise, dev, key set)" "$ADMIN_AUTH_REQUIRED" "1"
    # secretenv.Get trims once, so this reads as blank to the portal. A check
    # testing the RAW value for non-emptiness reports 'recovery armed' on a
    # deployment whose every admin route answers 500.
    admin_auth_required "in-vpc-enterprise" "dev" "   "
    _st_eq "auth(in-vpc-enterprise, dev, whitespace-only key)" "$ADMIN_AUTH_REQUIRED" "0"

    printf "\na mode nobody enumerated FAILS CLOSED (the platform's default arm is 'required')\n"
    admin_auth_required "in-vpc-enterprize" "dev" ""
    _st_eq "auth(in-vpc-enterprize, dev, no key)" "$ADMIN_AUTH_REQUIRED" "1"
    admin_auth_required "IN-VPC-ENTERPRISE" "dev" ""
    _st_eq "auth(IN-VPC-ENTERPRISE, dev, no key)" "$ADMIN_AUTH_REQUIRED" "1"

    printf "\nstring helpers\n"
    _st_eq "trim_ws('  a b  ')" "$(trim_ws '  a b  ')" "a b"
    _st_eq "trim_ws('')"        "$(trim_ws '')"        ""
    _st_eq "trim_ws('   ')"     "$(trim_ws '   ')"     ""
    _st_eq "lower('AbC-D')"     "$(lower 'AbC-D')"     "abc-d"

    printf "\nnumeric helpers (these guard every \$(( )) in the script)\n"
    _st_eq "is_uint('12')"   "$(is_uint 12   && echo yes || echo no)" "yes"
    _st_eq "is_uint('0')"    "$(is_uint 0    && echo yes || echo no)" "yes"
    _st_eq "is_uint('')"     "$(is_uint ''   && echo yes || echo no)" "no"
    _st_eq "is_uint('1.2')"  "$(is_uint 1.2  && echo yes || echo no)" "no"
    _st_eq "is_uint('-1')"   "$(is_uint -1   && echo yes || echo no)" "no"
    _st_eq "is_uint('12a')"  "$(is_uint 12a  && echo yes || echo no)" "no"
    _st_eq "ms_to_us('12.345')" "$(ms_to_us '12.345' || echo ERR)" "12345"
    _st_eq "ms_to_us('0.066')"  "$(ms_to_us '0.066'  || echo ERR)" "66"
    # 08/09 are the classic base-8 trap: without 10# these abort the script.
    _st_eq "ms_to_us('0.080')"  "$(ms_to_us '0.080'  || echo ERR)" "80"
    _st_eq "ms_to_us('0.09')"   "$(ms_to_us '0.09'   || echo ERR)" "90"
    _st_eq "ms_to_us('7')"      "$(ms_to_us '7'      || echo ERR)" "7000"
    _st_eq "ms_to_us('abc')"    "$(ms_to_us 'abc'    || echo ERR)" "ERR"
    _st_eq "fmt_us(500)"        "$(fmt_us 500)"       "500 µs"
    _st_eq "fmt_us(1500)"       "$(fmt_us 1500)"      "1 ms"
    _st_eq "fmt_us(2500000)"    "$(fmt_us 2500000)"   "2.5 s"

    printf "\nPostgres timeout literals (check 17 compares statement_timeout against a measured scan)\n"
    # The units are the whole point. statement_timeout is an integer GUC whose
    # implicit unit is milliseconds, so a bare number is ms and never seconds.
    _st_eq "pg_timeout_to_ms('0')"      "$(pg_timeout_to_ms '0'      || echo ERR)" "0"
    _st_eq "pg_timeout_to_ms('5000')"   "$(pg_timeout_to_ms '5000'   || echo ERR)" "5000"
    _st_eq "pg_timeout_to_ms('500ms')"  "$(pg_timeout_to_ms '500ms'  || echo ERR)" "500"
    _st_eq "pg_timeout_to_ms('30s')"    "$(pg_timeout_to_ms '30s'    || echo ERR)" "30000"
    _st_eq "pg_timeout_to_ms('2min')"   "$(pg_timeout_to_ms '2min'   || echo ERR)" "120000"
    _st_eq "pg_timeout_to_ms('1h')"     "$(pg_timeout_to_ms '1h'     || echo ERR)" "3600000"
    _st_eq "pg_timeout_to_ms('1d')"     "$(pg_timeout_to_ms '1d'     || echo ERR)" "86400000"
    # A trailing 's' must never swallow the 'm' of 'ms', and 'min' must never
    # be read as a bare 'm'. Both mistakes move the value by three orders of
    # magnitude in opposite directions, which is exactly enough to make the
    # FAIL below either unreachable or permanent.
    _st_eq "pg_timeout_to_ms('1ms') is not 1s"   "$(pg_timeout_to_ms '1ms'   || echo ERR)" "1"
    _st_eq "pg_timeout_to_ms('1s') is not 1ms"   "$(pg_timeout_to_ms '1s'    || echo ERR)" "1000"
    _st_eq "pg_timeout_to_ms('1min') is not 1ms" "$(pg_timeout_to_ms '1min'  || echo ERR)" "60000"
    # A sub-millisecond literal rounds UP. Truncating it to 0 would report the
    # tightest timeout a deployment can carry as 'no timeout configured'.
    _st_eq "pg_timeout_to_ms('500us')"  "$(pg_timeout_to_ms '500us'  || echo ERR)" "1"
    _st_eq "pg_timeout_to_ms('1500us')" "$(pg_timeout_to_ms '1500us' || echo ERR)" "2"
    _st_eq "pg_timeout_to_ms('0us')"    "$(pg_timeout_to_ms '0us'    || echo ERR)" "0"
    # Whitespace and case, because a rolconfig entry carries whatever was typed.
    _st_eq "pg_timeout_to_ms(' 30S ')"  "$(pg_timeout_to_ms ' 30S '  || echo ERR)" "30000"
    _st_eq "pg_timeout_to_ms('2MIN')"   "$(pg_timeout_to_ms '2MIN'   || echo ERR)" "120000"
    # Unparseable input must be REPORTED, never silently read as zero: zero
    # means 'no timeout' to this check, so a parse failure resolving to 0 would
    # be a fail-open.
    _st_eq "pg_timeout_to_ms('')"       "$(pg_timeout_to_ms ''       || echo ERR)" "ERR"
    _st_eq "pg_timeout_to_ms('abc')"    "$(pg_timeout_to_ms 'abc'    || echo ERR)" "ERR"
    _st_eq "pg_timeout_to_ms('-5s')"    "$(pg_timeout_to_ms '-5s'    || echo ERR)" "ERR"
    _st_eq "pg_timeout_to_ms('1.5s')"   "$(pg_timeout_to_ms '1.5s'   || echo ERR)" "ERR"
    _st_eq "pg_timeout_to_ms('s')"      "$(pg_timeout_to_ms 's'      || echo ERR)" "ERR"
    # 08/09 are the base-8 trap that ms_to_us already guards against.
    _st_eq "pg_timeout_to_ms('08s')"    "$(pg_timeout_to_ms '08s'    || echo ERR)" "8000"
    _st_eq "pg_timeout_to_ms('09ms')"   "$(pg_timeout_to_ms '09ms'   || echo ERR)" "9"

    printf "\ntightest-timeout folding (check 17 compares the TIGHTEST configured value)\n"
    _c17_reset() { C17_TIGHTEST_MS=""; C17_TIGHTEST_SRC=""; C17_SOURCES_UNREADABLE=0; }
    _c17_reset
    c17_split_entries "axonflow_app_role=5ms;axonflow=30s" "role" >/dev/null
    _st_eq       "tightest of 5ms and 30s"     "$C17_TIGHTEST_MS"  "5"
    _st_contains "tightest names its source"   "$C17_TIGHTEST_SRC" "axonflow_app_role"
    _c17_reset
    c17_split_entries "axonflow=30s;axonflow_app_role=5ms" "role" >/dev/null
    _st_eq "order does not decide the tightest" "$C17_TIGHTEST_MS" "5"
    # THE CASE THAT BROKE THE FIRST VERSION, on a live database rather than in
    # theory: pg_db_role_setting renders a cluster-wide entry with a SPACE in
    # its label. Split on spaces, "<all" became its own token, was reported as
    # an unparseable timeout, and only the accident of the remainder still
    # carrying "=5ms" left the real value reachable.
    _c17_reset
    c17_split_entries "<all databases>/axonflow_app_role=5ms" "setting" >/dev/null
    _st_eq "a label containing a space still yields its value"       "$C17_TIGHTEST_MS"        "5"
    _st_eq "a label containing a space is not parsed as a timeout"   "$C17_SOURCES_UNREADABLE" "0"
    # Zero means DISABLED in Postgres. Folding it in as "0 ms, the tightest of
    # all" would FAIL every deployment that has correctly turned the timeout off.
    _c17_reset
    c17_split_entries "r1=0;r2=30s" "role" >/dev/null
    _st_eq "a zero timeout is not a candidate" "$C17_TIGHTEST_MS" "30000"
    _c17_reset
    c17_split_entries "r1=0" "role" >/dev/null
    _st_eq "a lone zero leaves no tightest" "$C17_TIGHTEST_MS" ""
    # An unparseable value must be FLAGGED, never silently folded in as zero and
    # never silently dropped: "none configured" is the reassuring answer here.
    _c17_reset
    c17_split_entries "r1=banana" "role" >/dev/null
    _st_eq "an unparseable timeout leaves no tightest" "$C17_TIGHTEST_MS"        ""
    _st_eq "an unparseable timeout is flagged"         "$C17_SOURCES_UNREADABLE" "1"
    _c17_reset
    c17_split_entries "" "role" >/dev/null
    _st_eq "an empty blob folds nothing"       "$C17_TIGHTEST_MS"        ""
    _st_eq "an empty blob flags nothing"       "$C17_SOURCES_UNREADABLE" "0"
    _c17_reset

    printf "\ncomponent name table (one table, used by discover_env and the ECS secrets probe)\n"
    # The portal is the one component NOT named after itself in either place,
    # and it is the one checks 16 and 18 both depend on.
    component_names agent
    _st_eq "component_names(agent).upper"    "$COMP_UPPER"       "AGENT"
    _st_eq "component_names(agent).svc"      "$COMP_DEFAULT_SVC" "axonflow-agent"
    component_names orchestrator
    _st_eq "component_names(orchestrator).upper" "$COMP_UPPER"       "ORCHESTRATOR"
    _st_eq "component_names(orchestrator).svc"   "$COMP_DEFAULT_SVC" "axonflow-orchestrator"
    component_names portal
    _st_eq "component_names(portal).upper"   "$COMP_UPPER"       "PORTAL"
    _st_eq "component_names(portal).svc"     "$COMP_DEFAULT_SVC" "axonflow-customer-portal"
    _st_contains "component_names(portal).ecs" "$COMP_ECS_NAMES" "name=='customer-portal'"
    # An unknown component must return non-zero AND leave nothing behind. A
    # version that returned 0 would hand its caller the previous component's
    # names, which is a confident answer about the wrong container.
    # Called DIRECTLY, not through $(...). The first version of this pair ran
    # `$(component_names nonsense && ...)`, which is a SUBSHELL: the return
    # status survived and the globals did not, so the second assertion read the
    # PREVIOUS component's value out of the parent shell and reported the reset
    # as broken. The same subshell trap the query layer documents at length,
    # met here in a test rather than in a check.
    _cn_rc=0
    component_names nonsense || _cn_rc=$?
    _st_eq "component_names(nonsense) returns non-zero" \
        "$([[ "$_cn_rc" -ne 0 ]] && echo yes || echo no)" "yes"
    _st_eq "component_names(nonsense) clears COMP_UPPER" "$COMP_UPPER" ""
    _st_eq "component_names(nonsense) clears COMP_DEFAULT_SVC" "$COMP_DEFAULT_SVC" ""

    # q()'s multi-line guard (#3490 R3 round 2)
    #
    # q() keeps the LAST line of psql output, which is right for a scalar and
    # silently truncating for an aggregate containing a newline -
    # policy_overrides.override_reason is operator-authored TEXT. The
    # truncation printed a fragment with QOK=1 and recorded nothing, so it
    # could not be seen from the output.
    #
    # The decision is a pure function of the raw output, so it is tested as
    # one. It must fire on a genuinely multi-line value and must NOT fire on
    # either shape psql produces normally: a bare scalar, and a scalar with the
    # trailing newline psql appends. Both directions are asserted - a test that
    # only checks the firing case passes on a guard that fires every time.
    printf "\nq() truncation guard: a multi-line value is a failure, not a shortened answer\n"
    _st_eq "bare scalar is single-line"        "$(is_multiline_result "7" && echo yes || echo no)"    "no"
    _st_eq "psql trailing newline is not multi-line" "$(is_multiline_result "7
" && echo yes || echo no)"                                                                            "no"
    _st_eq "empty output is not multi-line"    "$(is_multiline_result "" && echo yes || echo no)"     "no"
    _st_eq "two lines ARE multi-line"          "$(is_multiline_result "line one
line two" && echo yes || echo no)"                                                                    "yes"
    _st_eq "three lines ARE multi-line"        "$(is_multiline_result "a
b
c" && echo yes || echo no)"                                                                           "yes"
    _st_eq "a blank line in the middle counts" "$(is_multiline_result "a

c" && echo yes || echo no)"                                                                           "yes"

    # rls_verdict / rls_blocks_all_clear (#3490 R3 round 3)
    #
    # The decision that stops checks 3, 9, 23 and 24 printing a green all-clear
    # from a connection that can read none of their inputs. It is a pure
    # function of two strings, so every arm is driven here with no database -
    # which matters because the arm that MATTERS is the one nobody exercises on
    # a working machine: the developer and the CI runner both connect as a
    # superuser, where the verdict is always `clear`.
    #
    # BOTH DIRECTIONS ARE ASSERTED, and the negative ones are the point. A
    # version that returned `blind` unconditionally would pass every "must
    # block" case below and turn every clean compose install into a false
    # alarm; a version that returned `clear` on an unparseable probe would pass
    # every "must not block" case and print exactly the all-clear this exists to
    # prevent. Neither survives the pairs below.
    printf "\nrls_verdict: a zero row count is only an answer when RLS is not filtering the read\n"
    _st_eq "RLS off, no rows          -> clear"    "$(rls_verdict f 0)"      "clear"
    _st_eq "RLS off, rows             -> clear"    "$(rls_verdict f 103)"    "clear"
    _st_eq "RLS on, no rows           -> blind"    "$(rls_verdict t 0)"      "blind"
    _st_eq "RLS on, rows              -> filtered" "$(rls_verdict t 12)"     "filtered"
    _st_eq "psql 'true' spelling      -> blind"    "$(rls_verdict true 0)"   "blind"
    _st_eq "psql 'false' spelling     -> clear"    "$(rls_verdict false 0)"  "clear"
    # A probe that did not execute leaves Q empty. That must NOT read as "RLS
    # is off", which is the fail-open direction and the one an empty string
    # falls into under any naive truth test.
    _st_eq "empty activeness          -> unknown"  "$(rls_verdict '' 0)"     "unknown"
    _st_eq "garbage activeness        -> unknown"  "$(rls_verdict wat 0)"    "unknown"
    _st_eq "empty row count           -> unknown"  "$(rls_verdict t '')"     "unknown"
    _st_eq "non-numeric row count     -> unknown"  "$(rls_verdict t 'ERROR')" "unknown"
    _st_eq "negative row count        -> unknown"  "$(rls_verdict t -1)"     "unknown"

    printf "\nrls_blocks_all_clear: 'unknown' must block as firmly as 'blind'\n"
    _st_eq "blind blocks"        "$(rls_blocks_all_clear blind    && echo yes || echo no)" "yes"
    _st_eq "unknown blocks"      "$(rls_blocks_all_clear unknown  && echo yes || echo no)" "yes"
    _st_eq "clear does NOT block"    "$(rls_blocks_all_clear clear    && echo yes || echo no)" "no"
    _st_eq "filtered does NOT block" "$(rls_blocks_all_clear filtered && echo yes || echo no)" "no"
    # Composed end to end, because the two halves are only correct together:
    # the compose-bundle posture (owner, RLS not applied to the ENABLE-only
    # policy tables, zero interesting rows) must remain a PASS, and the
    # app-role posture (RLS applied, zero rows) must not.
    _st_eq "compose owner posture stays passable" \
        "$(rls_blocks_all_clear "$(rls_verdict f 0)" && echo blocked || echo passable)" "passable"
    _st_eq "app-role posture is blocked" \
        "$(rls_blocks_all_clear "$(rls_verdict t 0)" && echo blocked || echo passable)" "blocked"

    printf "\n"
    if [[ "$_ST_FAILURES" -gt 0 ]]; then
        printf "%b%d self-test assertion(s) FAILED%b\n" "$RED" "$_ST_FAILURES" "$NC"
        return 1
    fi
    printf "%bself-test passed%b\n" "$GREEN" "$NC"
    return 0
}

case "${1:-}" in
    --self-test) run_self_test; exit $? ;;
    "") ;;
    *)
        printf "%bScript error:%b unknown argument '%s'. This script takes no arguments (or --self-test); it is configured entirely through the environment — see the header.\n" \
            "$RED" "$NC" "$1"
        exit 2
        ;;
esac

# ---------------------------------------------------------------------------
# Setup: choose a psql transport, resolve DATABASE_URL, prove connectivity
# ---------------------------------------------------------------------------

printf "%b%bAxonFlow Self-Hosted Preflight (v9 and v10 lines)%b\n" "$BOLD" "$BLUE" "$NC"
printf "Date: %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf "Run as: %s\n\n" "$(id -un 2>/dev/null || echo unknown)"

# PSQL_TRANSPORT is "host" or "docker:<container>". There is no third mode and
# no guessing: a preflight that silently connects to the WRONG database reports
# a confident verdict about a deployment it never looked at, which is worse than
# refusing to run. So the container transport requires the operator to NAME the
# container.
#
# AXONFLOW_PG_CONTAINER wins over a host psql when it is set. It is an explicit
# operator instruction, and the two transports resolve the SAME DSN against
# different networks — `localhost:5432` means the database itself inside the
# container and something else entirely on the host. Preferring host psql
# whenever it happens to be installed would silently ignore the variable and
# then either fail to connect or, worse, connect to a DIFFERENT Postgres that
# happens to answer on that address.
PSQL_TRANSPORT=""
if [[ -n "${AXONFLOW_PG_CONTAINER:-}" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
        printf "%bScript error:%b AXONFLOW_PG_CONTAINER is set but docker is not on PATH.\n" "$RED" "$NC"
        exit 2
    fi
    if ! docker exec "$AXONFLOW_PG_CONTAINER" psql --version >/dev/null 2>&1; then
        printf "%bScript error:%b cannot run psql inside container '%s'. Check the container id/name and that it is running.\n" \
            "$RED" "$NC" "$AXONFLOW_PG_CONTAINER"
        exit 2
    fi
    PSQL_TRANSPORT="docker:${AXONFLOW_PG_CONTAINER}"
elif command -v psql >/dev/null 2>&1; then
    PSQL_TRANSPORT="host"
else
    printf "%bScript error:%b psql not found on PATH.\n" "$RED" "$NC"
    printf "  Either install postgresql-client, OR point this script at the Postgres CONTAINER:\n"
    printf "    AXONFLOW_PG_CONTAINER=\"\$(docker compose ps -q postgres)\" \\\\\n"
    printf "    DATABASE_URL=\"postgres://<user>:<pw>@localhost:5432/<db>\" %s\n" "$0"
    printf "  (with the container transport the DSN is resolved from INSIDE that container,\n"
    printf "   so 'localhost' means the database itself.)\n"
    exit 2
fi

if [[ -z "${DATABASE_URL:-}" && -z "${PGHOST:-}" ]]; then
    printf "%bScript error:%b set DATABASE_URL or PGHOST/PGUSER/PGDATABASE before invoking.\n" "$RED" "$NC"
    exit 2
fi
if [[ "$PSQL_TRANSPORT" == docker:* && -z "${DATABASE_URL:-}" ]]; then
    printf "%bScript error:%b the container transport needs DATABASE_URL (PG* env vars are read from THIS shell, not from inside the container).\n" "$RED" "$NC"
    exit 2
fi

# ---------------------------------------------------------------------------
# Query layer — fail-CLOSED
# ---------------------------------------------------------------------------
# Every result is returned through GLOBALS, never through $(...).
#
# That is not a style choice. A helper invoked as `X=$(psql_q "…")` runs in a
# SUBSHELL: the exit status of psql is lost, an `exit` inside the helper exits
# only the subshell, and a query that FAILED is indistinguishable from a query
# that legitimately returned no rows. Every "0 affected policies" this script
# prints would then also be what a dropped connection looks like.
#
# So: psql_exec sets PSQL_OUT/PSQL_RC/PSQL_ERR in the caller's shell, q()
# records any failure in PSQL_FAILURES, and the final verdict FAILs if that list
# is non-empty. An unexecuted query can never be read as a clean result.
PSQL_OUT=""
PSQL_RC=0
PSQL_ERR=""
PSQL_FAILURES=()

psql_exec() {
    local sql="$1" raw=""
    PSQL_OUT=""; PSQL_ERR=""; PSQL_RC=0
    case "$PSQL_TRANSPORT" in
        host)
            if [[ -n "${DATABASE_URL:-}" ]]; then
                raw=$(PGOPTIONS='--client-min-messages=warning' \
                    psql --no-psqlrc -At -v ON_ERROR_STOP=1 -d "$DATABASE_URL" -c "$sql" 2>&1) || PSQL_RC=$?
            else
                raw=$(PGOPTIONS='--client-min-messages=warning' \
                    psql --no-psqlrc -At -v ON_ERROR_STOP=1 -c "$sql" 2>&1) || PSQL_RC=$?
            fi
            ;;
        docker:*)
            raw=$(docker exec \
                    -e PGOPTIONS='--client-min-messages=warning' \
                    "${PSQL_TRANSPORT#docker:}" \
                    psql --no-psqlrc -At -v ON_ERROR_STOP=1 -d "$DATABASE_URL" -c "$sql" 2>&1) || PSQL_RC=$?
            ;;
        *)
            PSQL_RC=99
            PSQL_ERR="internal error: no psql transport resolved"
            return 1
            ;;
    esac
    if [[ "$PSQL_RC" -ne 0 ]]; then
        PSQL_ERR="$raw"
        return 1
    fi
    PSQL_OUT="$raw"
    return 0
}

# q LABEL SQL — run SQL, put the LAST output line in Q, set QOK=1 on success.
#
# Always returns 0 so `set -e` cannot abort a check mid-way; QOK is the only
# thing a caller may branch on. Q is "" when QOK=0, and the caller must not
# treat that as data.
#
# Last line, not whole output, for the same reason the previous revision piped
# to `tail -1`: a stray server WARNING can precede the scalar. Extracted with
# bash parameter expansion rather than a pipe — `printf | grep -q` style
# pipelines return 141 (SIGPIPE) under `set -o pipefail` once the left side
# outgrows the pipe buffer, and a preflight is not the place to discover that.
Q=""
QOK=0
q() {
    local label="$1" sql="$2"
    Q=""; QOK=0
    if psql_exec "$sql"; then
        Q="${PSQL_OUT##*$'\n'}"
        QOK=1
        # A NEWLINE INSIDE THE VALUE IS INDISTINGUISHABLE FROM A NEWLINE BEFORE
        # IT. Taking the last line defends against a stray server WARNING, and
        # it silently truncates any value that contains a newline of its own -
        # which the detail aggregations do, because policy_overrides.reason is
        # operator-authored TEXT (core/030) and an operator can press Return in
        # it. The result was a fragment printed with QOK=1 and nothing
        # recorded, i.e. a partial answer that looks complete.
        #
        # Detail queries therefore flatten newlines to spaces IN SQL, at every
        # site that aggregates free text, so the value reaching this expansion
        # is single-line by construction. That is asserted rather than assumed:
        # a value that still arrives multi-line means a site was added without
        # the flattening, and it is reported as a query failure rather than
        # quietly shortened.
        if is_multiline_result "$PSQL_OUT"; then
            PSQL_FAILURES+=("${label}: multi-line result truncated to its last line - flatten newlines in SQL (translate(<expr>, E'\n\r', '  ')) at this query")
            QOK=0
        fi
    else
        PSQL_FAILURES+=("${label} (psql exit ${PSQL_RC}): $(printf '%s' "$PSQL_ERR" | tr '\n' ' ')")
    fi
    return 0
}

# table_exists NAME / column_exists TABLE COLUMN — both distinguish "absent"
# from "the probe did not run". A probe that could not run returns 1 AND has
# already recorded itself in PSQL_FAILURES, so it can never read as "absent".
#
# BOTH READ pg_catalog, NOT information_schema, AND THAT IS LOAD BEARING.
# information_schema is PRIVILEGE-FILTERED: it only shows objects the connecting
# role has some privilege on. A preflight run under a read-only reporting role
# that was never granted SELECT on dynamic_policies therefore sees the table as
# ABSENT — and every check keyed on the probe then reports "core/155 has nothing
# to repair here", which is a confident all-clear derived from a permission
# error. Measured, not theorised: it is what this script did before this comment
# existed.
#
# pg_class / pg_attribute are not filtered that way, so the table is found, the
# subsequent SELECT raises "permission denied", and that lands in PSQL_FAILURES
# and fails the run. Loud and wrong-way-up is the only acceptable outcome here.
table_exists() {
    q "table-exists($1)" "SELECT COUNT(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = '$1' AND c.relkind IN ('r','p','v','m','f')"
    [[ "$QOK" -eq 1 && "$Q" != "0" && -n "$Q" ]]
}
column_exists() {
    q "column-exists($1.$2)" "SELECT COUNT(*) FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = '$1' AND a.attname = '$2' AND a.attnum > 0 AND NOT a.attisdropped"
    [[ "$QOK" -eq 1 && "$Q" != "0" && -n "$Q" ]]
}

# probe_rls TABLE - sets RLS_STATE to the rls_verdict() for TABLE on THIS
# connection. TABLE must already have been established to exist; regclass casts
# on a missing relation raise rather than return NULL.
#
# One round trip, both inputs, so the activeness and the count cannot be read
# from two different sessions. row_security_active() is executable by PUBLIC and
# reads pg_catalog, so it answers for the blind role as readily as for the
# migration role - which is the whole point: the probe must not need the
# privilege whose absence it is detecting.
RLS_STATE="unknown"
probe_rls() {
    local tbl="$1"
    RLS_STATE="unknown"
    q "rls-visibility($tbl)" "SELECT row_security_active('public.$tbl'::regclass)::text || '|' || (SELECT COUNT(*) FROM public.$tbl)::text"
    if [[ "$QOK" -ne 1 ]]; then return 0; fi
    RLS_STATE="$(rls_verdict "${Q%%|*}" "${Q##*|}")"
    return 0
}

# ---------------------------------------------------------------------------
# Connection posture - reported, because the operator chooses it
# ---------------------------------------------------------------------------
# Printed up front rather than buried in the check that first suffers from it.
# The script previously never asked what role it was running as; it looked up
# two roles BY NAME in pg_roles (check 8) and never once asked about its own
# connection, so a run under a role that can see nothing looked exactly like a
# run under the migration role that can see everything.
PF_CONN_ROLE=""
PF_CONN_SUPER=""
PF_CONN_BYPASSRLS=""

# Probe connectivity early — every other check assumes the DB is reachable.
if ! psql_exec "SELECT 1"; then
    printf "%bScript error:%b cannot connect to Postgres via the %s transport.\n" "$RED" "$NC" "${PSQL_TRANSPORT%%:*}"
    printf "  psql exit %s: %s\n" "$PSQL_RC" "$PSQL_ERR"
    exit 2
fi
info "Database connectivity OK (transport: ${PSQL_TRANSPORT})"

q "connection posture" "SELECT current_user::text || '|' || COALESCE((SELECT r.rolsuper::text FROM pg_catalog.pg_roles r WHERE r.rolname = current_user), '?') || '|' || COALESCE((SELECT r.rolbypassrls::text FROM pg_catalog.pg_roles r WHERE r.rolname = current_user), '?')"
if [[ "$QOK" -eq 1 ]]; then
    PF_CONN_ROLE="${Q%%|*}"
    PF_CONN_BYPASSRLS="${Q##*|}"
    PF_CONN_SUPER="${Q#*|}"; PF_CONN_SUPER="${PF_CONN_SUPER%%|*}"
    info "Connected as role '${PF_CONN_ROLE}' (rolsuper=${PF_CONN_SUPER}, rolbypassrls=${PF_CONN_BYPASSRLS}) - see 'WHICH DATABASE ROLE TO RUN THIS AS' in this script's header."
else
    info "Connected role could not be determined (the pg_roles probe did not execute) - checks that need to know what this connection can see will say so."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Per-component environment discovery (used by checks 4, 8, 10, 12 and 16)
# ---------------------------------------------------------------------------
# Reads ONE environment variable off ONE component (agent | orchestrator |
# portal), from whichever of five sources is available, and reports WHICH one
# answered.
#
# Sets, in the caller's shell:
#   DISC_VALUE   the raw value, NOT trimmed and NOT case-folded (the platform
#                matches it exactly, so normalising it here would hide the
#                exact defect this script exists to catch)
#   DISC_STATE   set | empty | absent | unknown
#                  set     — a value is configured
#                  empty   — the variable is declared with an empty value
#                  absent  — the variable is not declared on that component
#                  unknown — NOTHING could be read; never treat as "not set"
#   DISC_SOURCE  human-readable provenance, printed so the operator can tell
#                whether the answer came from the deployment or from their shell
#   DISC_ORIGIN  the same provenance as a STABLE TOKEN, for callers that must
#                branch on it: ecs | container | compose | file | shell | none
#
# DISC_ORIGIN exists because DISC_SOURCE is prose and a caller keying on prose
# is a caller that silently stops keying on anything the day the wording
# changes. Check 16 needs the distinction for real: a value found in source (5),
# the operator's own shell, is not evidence about the component, and the upgrade
# guide tells operators to load .env into that shell before running the admin
# commands - so for a secret that also lives in .env, the shell is a likely
# FALSE positive rather than a weak reading.
#
# `absent` and `empty` are reported separately even where the platform treats
# them identically, because they need different remediation.
DISC_VALUE=""
DISC_STATE=""
DISC_SOURCE=""
DISC_ORIGIN=""

# _extract_env_line VARNAME BLOB — find "VARNAME=..." in a newline-delimited
# blob of KEY=VALUE pairs. Sets DISC_VALUE/DISC_STATE; returns 1 if not found.
_extract_env_line() {
    local var="$1" blob="$2" line
    while IFS= read -r line; do
        case "$line" in
            "$var="*)
                DISC_VALUE="${line#*=}"
                if [[ -z "$DISC_VALUE" ]]; then DISC_STATE="empty"; else DISC_STATE="set"; fi
                return 0
                ;;
        esac
    done <<EOF
$blob
EOF
    return 1
}

# _env_from_docker CONTAINER VARNAME
_env_from_docker() {
    local cid="$1" var="$2" blob="" rc=0
    # --type container is load bearing: `docker inspect` also resolves images,
    # networks and volumes, and an IMAGE has a .Config.Env too. Without it,
    # AXONFLOW_AGENT_CONTAINER=postgres:15-alpine inspected successfully and the
    # variable came back "absent" — a confident answer about the wrong object.
    blob=$(docker inspect --type container --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null) || rc=$?
    [[ "$rc" -ne 0 ]] && return 1
    [[ -z "$blob" ]] && return 1
    if _extract_env_line "$var" "$blob"; then return 0; fi
    DISC_VALUE=""; DISC_STATE="absent"
    return 0
}

# _env_from_file PATH VARNAME — an .env / systemd EnvironmentFile.
# Strips ONE layer of surrounding quotes, matching how docker-compose and
# systemd read these files.
_env_from_file() {
    local f="$1" var="$2" line
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            "$var="*)
                DISC_VALUE="${line#*=}"
                # Strip a trailing CR. A .env written on Windows reaches the
                # CONTAINER without it — docker's --env-file and compose both
                # strip it — so leaving it here makes the same value read as
                # `community` by the platform and as `community\r` by us. That
                # produced a hard FAIL telling the operator their agent would not
                # boot, about a value that was correct. A guard whose false
                # positive instructs the operator to break a working config is
                # worse than no guard.
                DISC_VALUE="${DISC_VALUE%$'\r'}"
                # Strip one matched pair of surrounding quotes, if present.
                case "$DISC_VALUE" in
                    \"*\") DISC_VALUE="${DISC_VALUE#\"}"; DISC_VALUE="${DISC_VALUE%\"}" ;;
                    \'*\') DISC_VALUE="${DISC_VALUE#\'}"; DISC_VALUE="${DISC_VALUE%\'}" ;;
                esac
                if [[ -z "$DISC_VALUE" ]]; then DISC_STATE="empty"; else DISC_STATE="set"; fi
                return 0
                ;;
        esac
    done < "$f"
    DISC_VALUE=""; DISC_STATE="absent"
    return 0
}

# discover_env COMPONENT VARNAME
#   COMPONENT is "agent", "orchestrator" or "portal".
#
# The portal is the customer-portal API container, NOT customer-portal-ui: the
# UI is a Next.js front end that proxies to it and holds none of the
# configuration any check here reads.
discover_env() {
    local comp="$1" var="$2"
    local upper svc_env cid_env file_env ecs_env default_svc ecs_names
    local taskdef val cid
    DISC_VALUE=""; DISC_STATE="unknown"; DISC_SOURCE="nothing readable"; DISC_ORIGIN="none"

    # The three names a component is known by come from component_names(), the
    # one table, so this and the ECS secrets[] probe used by checks 8 and 18
    # cannot drift apart about them. See that function for why they are a table
    # rather than a derivation.
    if ! component_names "$comp"; then
        DISC_SOURCE="internal error: unknown component '$comp'"; DISC_ORIGIN="none"; return 0
    fi
    upper="$COMP_UPPER"; default_svc="$COMP_DEFAULT_SVC"; ecs_names="$COMP_ECS_NAMES"
    eval "ecs_env=\${ECS_${upper}_SERVICE:-}"
    eval "cid_env=\${AXONFLOW_${upper}_CONTAINER:-}"
    eval "svc_env=\${AXONFLOW_${upper}_SERVICE:-}"
    eval "file_env=\${${upper}_ENV_FILE:-}"
    [[ -z "$svc_env" ]] && svc_env="$default_svc"

    # (1) ECS task definition.
    if [[ -n "${ECS_CLUSTER:-}" && -n "$ecs_env" ]] && command -v aws >/dev/null 2>&1; then
        taskdef=$(aws ecs describe-services --cluster "$ECS_CLUSTER" --services "$ecs_env" \
            --query 'services[0].taskDefinition' --output text 2>/dev/null || echo "")
        if [[ -n "$taskdef" && "$taskdef" != "None" ]]; then
            val=$(aws ecs describe-task-definition --task-definition "$taskdef" \
                --query "taskDefinition.containerDefinitions[?${ecs_names}].environment[?name=='${var}'].value | [0][0]" \
                --output text 2>/dev/null || echo "")
            DISC_SOURCE="ECS task def ${ECS_CLUSTER}/${ecs_env}"
            DISC_ORIGIN="ecs"
            if [[ -z "$val" || "$val" == "None" ]]; then
                # Distinguish "declared but empty" from "not declared": ask for
                # the NAME rather than the value.
                val=$(aws ecs describe-task-definition --task-definition "$taskdef" \
                    --query "taskDefinition.containerDefinitions[?${ecs_names}].environment[?name=='${var}'].name | [0][0]" \
                    --output text 2>/dev/null || echo "")
                if [[ -n "$val" && "$val" != "None" ]]; then
                    DISC_VALUE=""; DISC_STATE="empty"
                else
                    DISC_VALUE=""; DISC_STATE="absent"
                fi
            else
                DISC_VALUE="$val"; DISC_STATE="set"
            fi
            return 0
        fi
    fi

    # (2) An explicitly named docker container.
    #
    # A NAMED container that cannot be inspected is a DEAD END, not a reason to
    # try the next source. Setting AXONFLOW_<COMP>_CONTAINER is an explicit
    # operator instruction; falling through on a typo would answer from the
    # operator's own shell and print a confident verdict about a component
    # nobody looked at. That is the same rule the Postgres transport already
    # applies one layer up, where a named-but-unreachable container is exit 2.
    if [[ -n "$cid_env" ]]; then
        if ! command -v docker >/dev/null 2>&1; then
            DISC_STATE="unknown"
            DISC_SOURCE="AXONFLOW_${upper}_CONTAINER=${cid_env} is set but docker is not on PATH"
            return 0
        fi
        if _env_from_docker "$cid_env" "$var"; then
            DISC_SOURCE="docker container ${cid_env}"
            DISC_ORIGIN="container"
            return 0
        fi
        DISC_STATE="unknown"
        DISC_SOURCE="AXONFLOW_${upper}_CONTAINER=${cid_env} could not be inspected (wrong name/id, or the container does not exist)"
        return 0
    fi

    # (3) The Compose project rooted at $PWD. Only attempted when a compose file
    #     is actually present here — this must resolve the operator's own stack,
    #     never some other container that happens to share a name.
    if command -v docker >/dev/null 2>&1 && \
       { [[ -f docker-compose.yml ]] || [[ -f docker-compose.yaml ]] || \
         [[ -f compose.yml ]] || [[ -f compose.yaml ]]; }; then
        cid=$(docker compose ps -q "$svc_env" 2>/dev/null || echo "")
        cid="${cid%%$'\n'*}"
        if [[ -n "$cid" ]] && _env_from_docker "$cid" "$var"; then
            DISC_SOURCE="Compose service '${svc_env}' in $(pwd)"
            DISC_ORIGIN="compose"
            return 0
        fi
    fi

    # (4) An operator-supplied env file. Named-but-unusable is a dead end here
    #     too — and `-r` is TRUE for a directory, so the file test alone is not
    #     enough: `read` then fails, the loop body never runs, and the variable
    #     reads as "absent" on a path nobody could parse.
    if [[ -n "$file_env" ]]; then
        if [[ ! -f "$file_env" || ! -r "$file_env" ]]; then
            DISC_STATE="unknown"
            DISC_SOURCE="${upper}_ENV_FILE=${file_env} is not a readable regular file"
            return 0
        fi
        _env_from_file "$file_env" "$var"
        DISC_SOURCE="${upper}_ENV_FILE=${file_env}"
        DISC_ORIGIN="file"
        return 0
    fi

    # (5) This shell. Cannot distinguish one component from another, so it is
    #     last and it says so.
    if _extract_env_line "$var" "$SHELL_ENV_SNAPSHOT"; then
        DISC_SOURCE="current shell environment (NOT component-specific)"
        DISC_ORIGIN="shell"
        return 0
    fi

    DISC_STATE="unknown"
    DISC_SOURCE="nothing readable (no ECS service, no container, no env file, not in this shell)"
    return 0
}

# ecs_secret_declared COMPONENT VARNAME - is VARNAME wired on COMPONENT's ECS
# task definition as a secrets[] reference rather than a literal environment[]
# value? Sets ECS_SECRET_DECLARED to 1 or 0 and ECS_SECRET_SOURCE to the
# provenance.
#
# It exists because discover_env reads environment[] only, so on ECS a DSN or a
# key wired through Secrets Manager legitimately comes back "absent" - and a
# check that concluded "unset" from that would fail a correctly configured
# deployment.
#
# A 0 ALSO MEANS "there was no ECS deployment to ask", so a caller must never
# read 0 as "the variable is not wired". It is only ever evidence in the
# positive direction.
#
# It asks for the entry's NAME and never its valueFrom. Answering "is this
# wired?" does not require the script to hold a secret ARN, and a script that
# never reads one cannot print one. Check 16 already took that line for
# ADMIN_API_KEY; check 8 used to ask for valueFrom, for no gain, since it only
# ever tested the answer for emptiness.
ECS_SECRET_DECLARED=0
ECS_SECRET_SOURCE=""
ecs_secret_declared() {
    local comp="$1" var="$2" svc="" td="" ref=""
    ECS_SECRET_DECLARED=0; ECS_SECRET_SOURCE=""
    if ! component_names "$comp"; then return 0; fi
    if [[ -z "${ECS_CLUSTER:-}" ]]; then return 0; fi
    eval "svc=\${ECS_${COMP_UPPER}_SERVICE:-}"
    if [[ -z "$svc" ]]; then return 0; fi
    if ! command -v aws >/dev/null 2>&1; then return 0; fi
    td=$(aws ecs describe-services --cluster "$ECS_CLUSTER" --services "$svc" \
        --query 'services[0].taskDefinition' --output text 2>/dev/null || echo "")
    if [[ -z "$td" || "$td" == "None" ]]; then return 0; fi
    ref=$(aws ecs describe-task-definition --task-definition "$td" \
        --query "taskDefinition.containerDefinitions[?${COMP_ECS_NAMES}].secrets[?name=='${var}'].name | [0][0]" \
        --output text 2>/dev/null || echo "")
    if [[ -n "$ref" && "$ref" != "None" ]]; then
        ECS_SECRET_DECLARED=1
        ECS_SECRET_SOURCE="ECS task def ${ECS_CLUSTER}/${svc}, secrets[] reference"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Check 1 — Postgres version ≥ 14
# ---------------------------------------------------------------------------
section "Postgres version"

q "server_version_num" "SHOW server_version_num"; PG_VERSION_NUM="$Q"; PG_NUM_OK="$QOK"
q "server_version"     "SHOW server_version";     PG_VERSION="$Q"

if [[ "$PG_NUM_OK" -ne 1 ]]; then
    fail "Could not read the Postgres server version" \
        "\`SHOW server_version_num\` did not execute. The preflight cannot make any statement about this deployment until it does — see the query-failure list at the end."
elif [[ "$PG_VERSION_NUM" -ge 140000 ]]; then
    pass "Postgres $PG_VERSION (≥14 required)"
elif [[ "$PG_VERSION_NUM" -ge 95000 ]]; then
    warn "Postgres $PG_VERSION" \
        "v9 schema requires PG14+ for concurrent-index ergonomics + pg_dump --section. \
FORCE ROW LEVEL SECURITY works on PG9.5+, but the v9 preflight + rollback tooling assumes PG14+."
else
    fail "Postgres $PG_VERSION too old" \
        "v9 requires Postgres ≥14. Upgrade Postgres before pulling the v9 image."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 2 — schema_migrations state (all v8.x migrations applied, no boot loop)
# ---------------------------------------------------------------------------
section "Schema migrations state"

if ! table_exists "schema_migrations"; then
    fail "schema_migrations table missing" \
        "This deployment has never run the AxonFlow migration runner. Run on a v8.x install first, then re-run preflight."
else
    # Highest version applied. v8.x ships through migration 087; v9 ships
    # 088-103 in the next image pull. Anything ≥088 means the operator is
    # already on v9 (re-run is harmless).
    q "max applied migration" "SELECT COALESCE(MAX(CAST(version AS INTEGER)), 0) FROM schema_migrations WHERE success = true AND version ~ '^[0-9]+\$'"
    MAX_APPLIED="$Q"; MAX_OK="$QOK"
    # Count of failed migrations — boot loop indicator.
    q "failed migration count" "SELECT COUNT(*) FROM schema_migrations WHERE success = false"
    FAILED_COUNT="$Q"; FAILED_OK="$QOK"

    if [[ "$MAX_OK" -ne 1 || "$FAILED_OK" -ne 1 ]]; then
        fail "Could not read schema_migrations" \
            "The migration-state queries did not execute — see the query-failure list at the end. This is NOT the same as 'the table is clean'."
    elif [[ "$FAILED_COUNT" -gt 0 ]]; then
        q "failed migration list" "SELECT string_agg(version || ':' || COALESCE(name, '<unnamed>'), ', ' ORDER BY version) FROM (SELECT version, name FROM schema_migrations WHERE success = false ORDER BY version LIMIT 5) s"
        fail "Failed migrations present (boot loop risk)" \
            "$FAILED_COUNT migration(s) marked success=false. Fix or manually mark resolved before the upgrade. First 5: ${Q:-<list unavailable>}"
    elif [[ "$MAX_APPLIED" -lt 87 ]]; then
        fail "Latest applied migration is $MAX_APPLIED" \
            "v9 requires v8.x baseline (migrations ≤087) applied. Upgrade to v8.x first, then re-run preflight."
    elif [[ "$MAX_APPLIED" -ge 88 ]]; then
        info "Already on v9 schema (latest=$MAX_APPLIED). Preflight is still useful — checks below validate ongoing v9 invariants."
        pass "schema_migrations state OK (latest applied: $MAX_APPLIED, 0 failed)"
    else
        pass "schema_migrations state OK (latest applied: $MAX_APPLIED, 0 failed)"
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 3 — Empty/NULL org_id row scan (what Migration 094 Pass-2 will stamp)
# ---------------------------------------------------------------------------
section "Empty org_id row scan (Migration 094 Pass-2 preview)"

# Tables that Migration 094 backfills. Same set as the migration's verification
# report. For each table that exists with an org_id column, count rows with
# empty/NULL org_id AND a tenant_id NOT matching cs_* (so we count only Pass-2
# candidates, not the Pass-1 cs_* rows which get a different value).
TOTAL_EMPTY=0
PASS2_SCAN_OK=1
PASS2_BLIND_TABLES=""
PASS2_TABLES="audit_logs agent_audit_logs mcp_query_audits llm_call_audits static_policies dynamic_policies policy_evaluations service_identities execution_history"

# The same blindness guard checks 23 and 24 carry, for the same reason: nine of
# the tables below carry core/018's tenant-isolation policy, so a connection
# without ownership or BYPASSRLS counts 0 candidate rows on every one of them
# and this check prints "clean v9 schema or v9 already applied". Measured on a
# database holding exactly one Pass-2 candidate: the blind role reported none,
# the BYPASSRLS role on the same database reported the row. See rls_verdict().
for tname in $PASS2_TABLES; do
    if ! table_exists "$tname"; then continue; fi
    if ! column_exists "$tname" "org_id"; then continue; fi

    probe_rls "$tname"
    if rls_blocks_all_clear "$RLS_STATE"; then
        PASS2_BLIND_TABLES="${PASS2_BLIND_TABLES:+$PASS2_BLIND_TABLES, }${tname}"
    fi

    if column_exists "$tname" "tenant_id"; then
        q "094-preview($tname)" "SELECT COUNT(*) FROM $tname WHERE (org_id IS NULL OR org_id = '') AND (tenant_id IS NULL OR tenant_id NOT LIKE 'cs\\_%' ESCAPE '\\')"
    else
        q "094-preview($tname)" "SELECT COUNT(*) FROM $tname WHERE org_id IS NULL OR org_id = ''"
    fi
    if [[ "$QOK" -ne 1 ]] || ! is_uint "$Q"; then PASS2_SCAN_OK=0; continue; fi

    if [[ "$Q" -gt 0 ]]; then
        info "  $tname: $Q row(s) will be stamped with app.deployment_org_id"
        TOTAL_EMPTY=$((TOTAL_EMPTY + Q))
    fi
done

if [[ "$PASS2_SCAN_OK" -ne 1 ]]; then
    fail "Migration 094 Pass-2 preview is incomplete" \
        "At least one table scan did not execute — see the query-failure list at the end. A partial scan must not be read as 'no candidate rows'."
elif [[ "$TOTAL_EMPTY" -eq 0 && -n "$PASS2_BLIND_TABLES" ]]; then
    warn "This connection cannot read the tables Pass-2 backfills, so 'no candidate rows' is not a measurement" \
        "Row-level security is applied to this connection on: ${PASS2_BLIND_TABLES} - and each read as ZERO rows, which is what a filtered read and an empty table both look like. Connected as role '${PF_CONN_ROLE:-unknown}' (rolsuper=${PF_CONN_SUPER:-unknown}, rolbypassrls=${PF_CONN_BYPASSRLS:-unknown}). Re-run as axonflow_platform_admin, or as the table owner on a docker-compose bundle; see 'WHICH DATABASE ROLE TO RUN THIS AS' in this script's header."
elif [[ "$TOTAL_EMPTY" -eq 0 ]]; then
    pass "No Pass-2 candidate rows — clean v9 schema or v9 already applied"
else
    info "Total Pass-2 candidate rows: $TOTAL_EMPTY"
    info "These will be stamped with the value of app.deployment_org_id at migration time."
    info "On a real deployment, that value is the agent's ORG_ID env. Verify (Check 4) BEFORE upgrading."
    pass "Pass-2 candidate rows enumerated"
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 4 — DEPLOYMENT_KIND + ORG_ID env vars on the agent task def
# ---------------------------------------------------------------------------
section "Agent task env vars (DEPLOYMENT_KIND, ORG_ID)"

# THERE IS NO DATABASE-SIDE FALLBACK FOR THESE TWO, AND THERE CANNOT BE.
#
# An earlier revision read app.deployment_org_id / app.deployment_kind out of
# pg_settings and used them to corroborate an empty env-side read. That was
# dead code dressed as a safety net. setMigrationSessionVars
# (platform/agent/run.go) seeds those GUCs with
# `set_config(..., is_local => false)`, which means "for the rest of THIS
# SESSION" — not persisted. Nothing does an `ALTER DATABASE ... SET` or
# `ALTER ROLE ... SET` for either key, so a NEW connection — which is what this
# script opens — always reads NULL. Measured: set_config then read back in the
# same session returns the value; a second session returns NULL.
#
# So when discovery cannot read the agent, this check has NOTHING, and it now
# says so instead of PASSing. The old wording produced
# "PASS ORG_ID unset, DEPLOYMENT_KIND=dev — local-dev-org fallback is the
# intended path" on a run that had read neither variable, and on a production
# ECS stack whose operator forgot ECS_CLUSTER that made the FAIL below
# unreachable in exactly the state it exists for.
discover_env agent DEPLOYMENT_KIND
DEPLOYMENT_KIND="$DISC_VALUE"; DEPLOYMENT_KIND_STATE="$DISC_STATE"
info "DEPLOYMENT_KIND source: $DISC_SOURCE (state: $DISC_STATE)"

discover_env agent ORG_ID
ORG_ID="$DISC_VALUE"; ORG_ID_STATE="$DISC_STATE"
info "ORG_ID source: $DISC_SOURCE (state: $DISC_STATE)"

if [[ "$DEPLOYMENT_KIND_STATE" == "unknown" || "$ORG_ID_STATE" == "unknown" ]]; then
    warn "DEPLOYMENT_KIND / ORG_ID on the agent were NOT VERIFIED" \
        "Nothing readable answered for the agent, so this check makes NO statement about either value — do not read the absence of a FAIL as an all-clear. In particular it cannot tell you whether migration 094's #2320 prod-safety branch will ABORT the upgrade, which is what it exists for. Set AXONFLOW_AGENT_CONTAINER, AGENT_ENV_FILE, or ECS_CLUSTER+ECS_AGENT_SERVICE and re-run, or check by hand: \`docker compose exec axonflow-agent printenv DEPLOYMENT_KIND ORG_ID\`."
else
    # DEPLOYMENT_KIND check
    if [[ -z "$DEPLOYMENT_KIND" ]]; then
        warn "DEPLOYMENT_KIND is not set on the agent" \
            "On a real (non-docker-compose) deployment, set DEPLOYMENT_KIND=production on the agent task def. CFN templates already do this. If this is local docker-compose, the default 'dev' is correct and this WARN is expected."
    elif [[ "$DEPLOYMENT_KIND" == "production" ]]; then
        pass "DEPLOYMENT_KIND=production (real deployment)"
    elif [[ "$DEPLOYMENT_KIND" == "dev" ]]; then
        info "DEPLOYMENT_KIND=dev — preflight will treat this as local docker-compose."
        info "If this is a real customer deployment, change to 'production' BEFORE upgrade (Migration 094 #2320 prod-safety branch fires otherwise)."
        pass "DEPLOYMENT_KIND=dev (acceptable for local docker-compose / community-mode)"
    else
        warn "DEPLOYMENT_KIND='$DEPLOYMENT_KIND' (unexpected value)" \
            "Expected 'production' on real stacks or 'dev' on docker-compose. Verify task def env before upgrade."
    fi

    # ORG_ID check.
    #
    # THE SAFE ARM IS `dev`, NOT `not production`. Migration 094's prod-safety
    # branch aborts on deployment_kind='production' AND deployment_org =
    # 'local-dev-org' (migrations/core/094, RAISE EXCEPTION), so predicting that
    # abort is this check's whole job — and it can only be predicted from a value
    # positively read as `dev`.
    #
    # An earlier revision keyed the reassuring arm on `!= production`, so
    # ANYTHING it could not classify — a value it had read as `absent`, or a
    # `production` carrying a stray CR that docker strips and we did not — landed
    # in "local-dev-org fallback is the intended path". The printed line then
    # contradicted itself in the same breath: "unexpected value 'production'"
    # immediately above "ORG_ID unset with DEPLOYMENT_KIND='production' — the
    # intended path". The abort it exists to predict was unreachable in exactly
    # that state.
    if [[ "$DEPLOYMENT_KIND" == "production" ]]; then
        kind_arm="production"
    elif [[ "$DEPLOYMENT_KIND" == "dev" ]]; then
        kind_arm="dev"
    else
        kind_arm="unclassified"
    fi

    if [[ -z "$ORG_ID" ]]; then
        case "$kind_arm" in
            production)
                fail "ORG_ID env not set on a production deployment" \
                    "Migration 094 #2320 prod-safety branch will ABORT the upgrade. Set ORG_ID to your customer/account identifier (NOT the literal 'local-dev-org' — that's the dev sentinel) BEFORE pulling the new image." ;;
            dev)
                info "ORG_ID env unset — agent will default to 'local-dev-org' (acceptable for docker-compose / community-mode)."
                pass "ORG_ID unset with DEPLOYMENT_KIND=dev — local-dev-org fallback is the intended path" ;;
            *)
                warn "ORG_ID is unset and DEPLOYMENT_KIND is '${DEPLOYMENT_KIND:-<not declared>}'" \
                    "This check cannot tell you whether the upgrade will abort. Migration 094 refuses to run when DEPLOYMENT_KIND is exactly 'production' and the org resolves to the 'local-dev-org' sentinel, which is what an unset ORG_ID gives you. It aborts on nothing else. Since the kind read here is neither 'production' nor 'dev', set ORG_ID explicitly, or set DEPLOYMENT_KIND to one of the two, and re-run. Do NOT read this as 'the dev fallback is fine'." ;;
        esac
    elif [[ "$ORG_ID" == "local-dev-org" ]]; then
        case "$kind_arm" in
            production)
                fail "ORG_ID='local-dev-org' on a production deployment" \
                    "This is the dev sentinel. Set ORG_ID to your real customer/account identifier (e.g., 'acme-corp')." ;;
            dev)
                pass "ORG_ID=local-dev-org (intended for docker-compose / community-mode)" ;;
            *)
                warn "ORG_ID is the 'local-dev-org' sentinel and DEPLOYMENT_KIND is '${DEPLOYMENT_KIND:-<not declared>}'" \
                    "Migration 094 aborts on this org value when DEPLOYMENT_KIND is exactly 'production'. The kind read here is neither 'production' nor 'dev', so this check cannot tell you which way it goes. Resolve the kind and re-run." ;;
        esac
    else
        pass "ORG_ID='$ORG_ID' set"
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 5 — axonflow_app_role exists + NOBYPASSRLS (migration 098 will create
# it if absent; this check is informational for operators who pre-create roles)
# ---------------------------------------------------------------------------
section "Postgres roles (axonflow_app_role + axonflow_platform_admin)"

q "app role exists"   "SELECT COUNT(*) FROM pg_roles WHERE rolname = 'axonflow_app_role'";       APP_ROLE_EXISTS="$Q";   APP_ROLE_OK="$QOK"
q "admin role exists" "SELECT COUNT(*) FROM pg_roles WHERE rolname = 'axonflow_platform_admin'"; ADMIN_ROLE_EXISTS="$Q"; ADMIN_ROLE_OK="$QOK"

if [[ "$APP_ROLE_OK" -ne 1 ]]; then
    fail "Could not read pg_roles for axonflow_app_role" \
        "The role probe did not execute — see the query-failure list at the end."
elif [[ "$APP_ROLE_EXISTS" == "0" ]]; then
    info "axonflow_app_role does not exist — migration 098 will create it."
    pass "axonflow_app_role absent (will be created by migration 098)"
else
    q "app role bypassrls" "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'axonflow_app_role'"; APP_ROLE_BYPASSRLS="$Q"
    q "app role canlogin"  "SELECT rolcanlogin  FROM pg_roles WHERE rolname = 'axonflow_app_role'"; APP_ROLE_CANLOGIN="$Q"
    if [[ "$APP_ROLE_BYPASSRLS" == "t" ]]; then
        fail "axonflow_app_role exists with BYPASSRLS=true" \
            "v9 contract: app role MUST NOT bypass RLS (otherwise FORCE RLS is decorative). Run: ALTER ROLE axonflow_app_role NOBYPASSRLS;"
    elif [[ "$APP_ROLE_CANLOGIN" != "t" ]]; then
        # Role exists but cannot login — migration 098 creates with LOGIN, so this
        # implies an operator manually ALTERed it. Block the upgrade.
        fail "axonflow_app_role exists but lacks LOGIN" \
            "Run: ALTER ROLE axonflow_app_role LOGIN; then provision a password via scripts/operators/provision-app-role.sh."
    else
        pass "axonflow_app_role exists with NOBYPASSRLS + LOGIN (v9 contract)"
        # Password-set check (informational). pg_authid.rolpassword IS NOT NULL
        # iff a password has been set. RDS master can read this; some hosted PGs
        # hide it. That read is EXPECTED to fail on such a platform, so it is the
        # one probe whose failure is not recorded as a preflight failure — it is
        # reported as "not readable" instead, never as "no password".
        if psql_exec "SELECT CASE WHEN rolpassword IS NOT NULL THEN 't' ELSE 'f' END FROM pg_authid WHERE rolname = 'axonflow_app_role'"; then
            APP_ROLE_HAS_PW="${PSQL_OUT##*$'\n'}"
        else
            APP_ROLE_HAS_PW="unreadable"
            info "pg_authid is not readable by this role — cannot tell whether axonflow_app_role has a password. Verify manually before flipping AXONFLOW_DB_USE_APP_ROLE=true."
        fi
        if [[ "$APP_ROLE_HAS_PW" == "f" ]]; then
            warn "axonflow_app_role has no password set" \
                "Migration 098 creates the role with LOGIN capability but no password — the role cannot authenticate until provisioned. BEFORE flipping AXONFLOW_DB_USE_APP_ROLE=true, run: scripts/operators/provision-app-role.sh (see technical-docs/v9_phase8_rls_rollout.md §'Mechanism recap'). Skipping this step results in the agent failing to connect on boot."
        fi
    fi
fi

if [[ "$ADMIN_ROLE_OK" -ne 1 ]]; then
    fail "Could not read pg_roles for axonflow_platform_admin" \
        "The role probe did not execute — see the query-failure list at the end."
elif [[ "$ADMIN_ROLE_EXISTS" == "0" ]]; then
    info "axonflow_platform_admin does not exist — migration 098 will create it."
    pass "axonflow_platform_admin absent (will be created by migration 098)"
else
    q "admin role bypassrls" "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'axonflow_platform_admin'"; ADMIN_ROLE_BYPASSRLS="$Q"
    q "admin role canlogin"  "SELECT rolcanlogin  FROM pg_roles WHERE rolname = 'axonflow_platform_admin'"; ADMIN_ROLE_CANLOGIN="$Q"
    if [[ "$ADMIN_ROLE_BYPASSRLS" != "t" ]]; then
        fail "axonflow_platform_admin exists but lacks BYPASSRLS" \
            "v9 contract: platform admin role MUST bypass RLS for cross-org workers. Run: ALTER ROLE axonflow_platform_admin BYPASSRLS;"
    elif [[ "$ADMIN_ROLE_CANLOGIN" != "t" ]]; then
        fail "axonflow_platform_admin exists but lacks LOGIN" \
            "Run: ALTER ROLE axonflow_platform_admin LOGIN; then provision a password via scripts/operators/provision-app-role.sh."
    else
        pass "axonflow_platform_admin exists with BYPASSRLS + LOGIN (v9 contract)"
        if psql_exec "SELECT CASE WHEN rolpassword IS NOT NULL THEN 't' ELSE 'f' END FROM pg_authid WHERE rolname = 'axonflow_platform_admin'"; then
            ADMIN_ROLE_HAS_PW="${PSQL_OUT##*$'\n'}"
        else
            ADMIN_ROLE_HAS_PW="unreadable"
        fi
        if [[ "$ADMIN_ROLE_HAS_PW" == "f" ]]; then
            warn "axonflow_platform_admin has no password set" \
                "Cross-org workers (community-saas sweep, recovery, node-monitor) cannot connect as this role until a password is provisioned. Run scripts/operators/provision-app-role.sh BEFORE flipping AXONFLOW_DB_USE_APP_ROLE=true — otherwise OpenPlatformAdminConnection (platform/agent/db_connection.go) returns a nil-with-nil-err signal and the workers fall through to their fallback DB pool, which is the master role (BYPASSRLS by table-owner). RLS is not silently leaked, but cross-org worker behavior under FORCE RLS becomes undefined."
        fi
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 6 — Backup / snapshot policy
# ---------------------------------------------------------------------------
section "Backup / snapshot policy"

# Three discovery modes:
#   (1) RDS_INSTANCE_IDENTIFIER set + aws CLI available → query RDS
#   (2) PG_BACKUP_TOOL set (e.g., "pgbackrest", "barman") → trust the operator
#   (3) Else → WARN; rollback contract requires snapshot
#
# This matters more on the v9.13.0 train than on any before it: BOTH migrations
# in that release MUTATE DATA (core/155 disables rows, core/156 stamps a
# sentinel), and core/156's down migration deliberately leaves its stamps in
# place. Rolling the schema back does NOT undo the data change. A snapshot is
# the only rollback.
if [[ -n "${RDS_INSTANCE_IDENTIFIER:-}" ]] && command -v aws >/dev/null 2>&1; then
    info "Querying RDS instance $RDS_INSTANCE_IDENTIFIER for backup settings"
    BACKUP_RETENTION=$(aws rds describe-db-instances --db-instance-identifier "$RDS_INSTANCE_IDENTIFIER" \
        --query 'DBInstances[0].BackupRetentionPeriod' --output text 2>/dev/null || echo "0")
    if [[ "$BACKUP_RETENTION" =~ ^[0-9]+$ ]] && [[ "$BACKUP_RETENTION" -ge 7 ]]; then
        pass "RDS automated backups enabled (retention: $BACKUP_RETENTION days)"
    elif [[ "$BACKUP_RETENTION" =~ ^[0-9]+$ ]] && [[ "$BACKUP_RETENTION" -ge 1 ]]; then
        warn "RDS backup retention is $BACKUP_RETENTION day(s)" \
            "v9 rollback contract recommends ≥7 days. Increase BackupRetentionPeriod on the RDS instance."
    else
        fail "RDS automated backups DISABLED (or unreadable: '$BACKUP_RETENTION')" \
            "v9 schema migrations are forward-only and v9.13.0's two migrations MUTATE DATA — a snapshot is the rollback contract. Set BackupRetentionPeriod ≥7 on the RDS instance, OR take a manual snapshot BEFORE pulling the new image, then re-run preflight."
    fi
elif [[ -n "${PG_BACKUP_TOOL:-}" ]]; then
    pass "Operator-declared backup tool: $PG_BACKUP_TOOL (operator-verified)"
else
    warn "No backup/snapshot tool discovered" \
        "Set RDS_INSTANCE_IDENTIFIER (for AWS RDS) or PG_BACKUP_TOOL (for pgbackrest/barman/etc.) before re-running. The rollback contract REQUIRES a snapshot — operator MUST manually verify a recent snapshot exists before pulling the new image. On the v9.13.0 train this is not a formality: core/155 disables rows and core/156 stamps a sentinel that its own down migration deliberately does NOT remove."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 7 — local-dev-org default preservation (Phase 7 contract guard)
# ---------------------------------------------------------------------------
section "local-dev-org default preservation"

# This check is informational/contractual: any historical row with
# org_id='local-dev-org' must remain intact after v9 upgrade. We don't
# REWRITE this value — we just inform the operator.
if ! table_exists "organizations"; then
    info "organizations table does not exist on this deployment yet — clean install."
    pass "local-dev-org row absent (organizations table not yet created)"
else
    # Same blindness guard as checks 3, 9, 20, 21, 23 and 24, for the same
    # reason. `organizations` is FORCE row-level security (core/103), so it
    # reads EMPTY not only for a role without ownership or BYPASSRLS but for
    # the table OWNER too - the compose bundle's own posture. A zero here is
    # therefore what a filtered read and a genuinely absent row both look like,
    # and only the "row absent" arm below is an affirmative claim built on it.
    # The "row present" arm needs no guard: RLS can hide a row, never invent
    # one, so a non-zero count is true under every posture.
    C7_BLIND=0
    probe_rls organizations
    if rls_blocks_all_clear "$RLS_STATE"; then C7_BLIND=1; fi

    q "local-dev-org rows" "SELECT COUNT(*) FROM organizations WHERE org_id = 'local-dev-org'"
    if [[ "$QOK" -ne 1 ]]; then
        fail "Could not count local-dev-org organizations" \
            "The query did not execute — see the query-failure list at the end."
    elif [[ "$Q" -gt 0 ]]; then
        info "organizations table contains $Q row(s) keyed on 'local-dev-org'."
        info "This is the protected default for unset-ORG_ID installs. v9 preserves it; no action needed."
        pass "local-dev-org default preserved across upgrade contract"
    elif [[ "$C7_BLIND" -eq 1 ]]; then
        warn "This connection cannot read organizations, so 'no local-dev-org row' is not a measurement" \
            "Row-level security is applied to this connection on organizations, and it read as ZERO rows - which is what a filtered read and an empty table both look like. Connected as role '${PF_CONN_ROLE:-unknown}' (rolsuper=${PF_CONN_SUPER:-unknown}, rolbypassrls=${PF_CONN_BYPASSRLS:-unknown}). organizations is FORCE row-level security (core/103), so ownership alone does not lift the filter and the compose bundle's own database user is affected too. Re-run as axonflow_platform_admin, the BYPASSRLS role the migrations use; see 'WHICH DATABASE ROLE TO RUN THIS AS' in this script's header. Nothing is wrong with the deployment on this evidence - the check simply could not look."
    else
        info "No 'local-dev-org' organizations row found — clean install or ORG_ID was always set."
        pass "local-dev-org row absent (acceptable on installs with ORG_ID always set)"
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 8 — AXONFLOW_DB_USE_APP_ROLE / AXONFLOW_DB_PLATFORM_ADMIN_URL pairing
# ---------------------------------------------------------------------------
section "App-role env pairing (refuse-to-boot guard preview)"

# The v9 agent / orchestrator / customer-portal binaries refuse to boot when
# AXONFLOW_DB_USE_APP_ROLE=true (the v9.0.0 default — unset also means true) AND
# AXONFLOW_DB_PLATFORM_ADMIN_URL is unset. Surfacing it here lets the operator
# fix the env BEFORE pulling the image, instead of finding out from a FATAL log
# line on first boot.
discover_env agent AXONFLOW_DB_USE_APP_ROLE
USE_APP_ROLE="$DISC_VALUE"; USE_APP_ROLE_STATE="$DISC_STATE"
info "AXONFLOW_DB_USE_APP_ROLE source: $DISC_SOURCE (state: $DISC_STATE)"

discover_env agent AXONFLOW_DB_PLATFORM_ADMIN_URL
ADMIN_URL_VALUE="$(trim_ws "$DISC_VALUE")"; ADMIN_URL_STATE="$DISC_STATE"
info "AXONFLOW_DB_PLATFORM_ADMIN_URL source: $DISC_SOURCE (state: $DISC_STATE)"

# On ECS the admin DSN is usually a secret ref, not a literal env value, so the
# environment[] read above legitimately comes back absent. Check secrets[] too
# before concluding it is unset.
#
# ADMIN_URL_VIA_SECRET is a separate flag rather than a sentinel written into
# ADMIN_URL_VALUE, mirroring PORTAL_KEY_VIA_SECRET in check 16: the value
# variable then only ever holds something the deployment really set, and a
# future line that prints it cannot print a placeholder as if it were a DSN.
ADMIN_URL_VIA_SECRET=0
if [[ -z "$ADMIN_URL_VALUE" ]]; then
    ecs_secret_declared agent AXONFLOW_DB_PLATFORM_ADMIN_URL
    if [[ "$ECS_SECRET_DECLARED" -eq 1 ]]; then
        ADMIN_URL_VIA_SECRET=1
        ADMIN_URL_STATE="set"
        info "AXONFLOW_DB_PLATFORM_ADMIN_URL is wired as an ECS secret reference (${ECS_SECRET_SOURCE})."
    fi
fi

# Mirror the binary's UseAppRoleEnabled() semantics: unset OR truthy → true.
# Only explicit "false"/"FALSE"/"False"/"0" disables.
USE_APP_ROLE_EFFECTIVE="true"
case "$USE_APP_ROLE" in
    false|FALSE|False|0) USE_APP_ROLE_EFFECTIVE="false" ;;
esac

if [[ "$USE_APP_ROLE_STATE" == "unknown" || "$ADMIN_URL_STATE" == "unknown" ]]; then
    warn "The app-role env pairing could not be read from this deployment" \
        "NOT VERIFIED — nothing readable answered for the agent, so this check makes NO statement about the refuse-to-boot combination. Do not read the absence of a FAIL as an all-clear. Set AXONFLOW_AGENT_CONTAINER, AGENT_ENV_FILE, or ECS_CLUSTER+ECS_AGENT_SERVICE and re-run, or check by hand: \`docker compose exec axonflow-agent printenv AXONFLOW_DB_USE_APP_ROLE AXONFLOW_DB_PLATFORM_ADMIN_URL\`."
elif [[ "$USE_APP_ROLE_EFFECTIVE" == "false" ]]; then
    info "AXONFLOW_DB_USE_APP_ROLE='$USE_APP_ROLE' — legacy v8.x posture (master role connects, FORCE RLS dormant)."
    pass "App-role posture is legacy (no admin pool required)"
elif [[ -n "$ADMIN_URL_VALUE" || "$ADMIN_URL_VIA_SECRET" -eq 1 ]]; then
    pass "AXONFLOW_DB_USE_APP_ROLE=true paired with AXONFLOW_DB_PLATFORM_ADMIN_URL set"
else
    fail "AXONFLOW_DB_USE_APP_ROLE=true with AXONFLOW_DB_PLATFORM_ADMIN_URL unset" \
        "The v9 ORCHESTRATOR and CUSTOMER-PORTAL binaries REFUSE TO BOOT under this combination, unconditionally (platform/orchestrator/run.go initializeComponents, ee/platform/customer-portal/main.go). On the AGENT the equivalent refusals sit behind feature gates (marketplace metering, node monitor, community-saas sweep), so an agent may well start while the orchestrator beside it does not — which is the confusing half. The reason the combination is refused at all is that the silent fallback to the request-traffic pool would defeat FORCE RLS on cross-org workers (marketplace metering, community-saas sweep / recovery, node monitor, customer-portal admin handlers). Either set AXONFLOW_DB_PLATFORM_ADMIN_URL to a DSN authenticating as axonflow_platform_admin (mirrors AXONFLOW_DB_APP_ROLE_URL), or set AXONFLOW_DB_USE_APP_ROLE=false to opt out of the v9.0.0 default and run under the legacy v8.x posture. See technical-docs/v9_phase7_self_hosted_migration.md §'Change 4'."
fi

# Customized-handler advisory (informational — preflight can't scan the
# operator's fork from inside the script). Always emit at WARN-level when
# USE_APP_ROLE_EFFECTIVE is true so a fork operator sees the audit ask.
if [[ "$USE_APP_ROLE_EFFECTIVE" == "true" && "$USE_APP_ROLE_STATE" != "unknown" && "$ADMIN_URL_STATE" != "unknown" ]]; then
    warn "Customized-handler audit required before flip" \
        "Operators running stock v9 code can ignore this. Operators with FORKED or in-tree-customized handlers MUST audit every db.ExecContext / tx.ExecContext write into a v9-RLS table (see migrations/core/018 ENABLE-RLS template + migrations/core/099/101/103/105/107 FORCE batches). Each write must either wrap WithOrgScope(ctx, db, orgID, …), use a SECURITY DEFINER helper, or run on the OpenPlatformAdminConnection pool. Unwrapped writes under axonflow_app_role fail with 'pq: new row violates row-level security policy'. Rehearse on a staging snapshot for at least one full diurnal cycle before flipping in production. See technical-docs/v9_phase7_self_hosted_migration.md §'Change 4' for the audit recipe."
fi
printf "\n"

# ═══════════════════════════════════════════════════════════════════════════
# v9.13.0 — checks 9 to 12
# ═══════════════════════════════════════════════════════════════════════════
printf "%b%b── v9.13.0 (epic #3071) ────────────────────────────────────────────────%b\n\n" "$BOLD" "$BLUE" "$NC"

# ---------------------------------------------------------------------------
# Check 9 — Migration core/155: policies carrying tenant_id = ''
# ---------------------------------------------------------------------------
section "Policies with an empty tenant_id (Migration core/155 preview)"

# core/155 normalises tenant_id = '' to NULL on both policy tables, and on
# dynamic_policies it ALSO sets enabled = false. That second half is the one an
# operator has to know about in advance, because the repaired row is then NOT
# reachable through the portal or the policy API — PolicyRepository.GetByID
# filters `(tenant_id = $2 OR tenant_id = 'global')` and List fills tenant_id
# per scope, and `NULL = $n` evaluates to NULL, not true. Remediation is direct
# SQL, against policy_ids that only exist BEFORE the migration runs: afterwards
# the `tenant_id = ''` predicate matches nothing and the ids are unrecoverable
# except from the migration's own RAISE WARNING output.
#
# Naming them here, before the upgrade, is the entire point of this check. The
# alternative — the one this replaces — is asking the operator to grep migration
# logs after the fact.
CHK155_STATE_OK=1
# Probe failures are counted, not inferred. table_exists/column_exists return
# "false" both when a table is genuinely absent and when the probe itself did not
# run, and only the second case is a lie — so the number of recorded query
# failures is sampled around the existence probes and any increase demotes the
# whole check.
CHK155_FAILURES_BEFORE="${#PSQL_FAILURES[@]}"
DYN155_IDS=""
DYN155_IDS_SQL=""
DYN155_ENABLED="0"
DYN155_COUNT="0"
STATIC155_IDS=""
STATIC155_COUNT="0"
STATIC155_LIVE="0"
STATIC155_DETAIL=""
CHK155_TABLES_PRESENT=0
CHK155_BLIND_TABLES=""

# The same blindness guard as checks 3, 23 and 24. Both tables read here carry
# core/018's tenant-isolation policy, so under a role with neither ownership nor
# BYPASSRLS `SELECT COUNT(*) ... WHERE tenant_id = ''` is 0 whatever the table
# holds, and the pass below says core/155 has nothing to repair. Measured on a
# database holding one such dynamic_policies row: the blind role printed the
# all-clear while the BYPASSRLS role on the same database reported the row that
# core/155 will DISABLE. That direction matters here - the affected row becomes
# unreachable through the portal and the policy API, and the ids printed below
# are the only record of which rows to repair, because after the migration runs
# nothing can find them again. See rls_verdict().
for tname in dynamic_policies static_policies; do
    if ! table_exists "$tname" || ! column_exists "$tname" "tenant_id"; then continue; fi
    probe_rls "$tname"
    if rls_blocks_all_clear "$RLS_STATE"; then
        CHK155_BLIND_TABLES="${CHK155_BLIND_TABLES:+$CHK155_BLIND_TABLES, }${tname}"
    fi
done

if table_exists "dynamic_policies" && column_exists "dynamic_policies" "tenant_id"; then
    CHK155_TABLES_PRESENT=$((CHK155_TABLES_PRESENT + 1))
    q "155 dynamic count"   "SELECT COUNT(*) FROM dynamic_policies WHERE tenant_id = ''"
    if [[ "$QOK" -eq 1 ]]; then DYN155_COUNT="$Q"; else CHK155_STATE_OK=0; fi
    q "155 dynamic enabled" "SELECT COUNT(*) FROM dynamic_policies WHERE tenant_id = '' AND enabled = true"
    if [[ "$QOK" -eq 1 ]]; then DYN155_ENABLED="$Q"; else CHK155_STATE_OK=0; fi
    q "155 dynamic ids"     "SELECT COALESCE(string_agg(policy_id, ', ' ORDER BY policy_id), '') FROM dynamic_policies WHERE tenant_id = ''"
    if [[ "$QOK" -eq 1 ]]; then DYN155_IDS="$Q"; else CHK155_STATE_OK=0; fi
    # Server-side quoting, so the remediation SQL printed below is a statement
    # the operator can paste rather than one they have to repair. quote_literal
    # also makes an id containing a quote safe instead of a syntax error.
    q "155 dynamic ids (quoted)" "SELECT COALESCE(string_agg(quote_literal(policy_id), ', ' ORDER BY policy_id), '') FROM dynamic_policies WHERE tenant_id = ''"
    if [[ "$QOK" -eq 1 ]]; then DYN155_IDS_SQL="$Q"; else CHK155_STATE_OK=0; fi
else
    info "dynamic_policies.tenant_id not present on this deployment — core/155 will skip that table."
fi

if table_exists "static_policies" && column_exists "static_policies" "tenant_id"; then
    CHK155_TABLES_PRESENT=$((CHK155_TABLES_PRESENT + 1))
    q "155 static count" "SELECT COUNT(*) FROM static_policies WHERE tenant_id = ''"
    if [[ "$QOK" -eq 1 ]]; then STATIC155_COUNT="$Q"; else CHK155_STATE_OK=0; fi
    q "155 static ids"   "SELECT COALESCE(string_agg(policy_id, ', ' ORDER BY policy_id), '') FROM static_policies WHERE tenant_id = ''"
    if [[ "$QOK" -eq 1 ]]; then STATIC155_IDS="$Q"; else CHK155_STATE_OK=0; fi
    # tier and enabled are the discriminator between a genuinely inert row and
    # one that is being enforced today. Guarded on the columns existing so a
    # legacy schema degrades to "unknown" rather than erroring the whole check.
    if column_exists "static_policies" "tier" && column_exists "static_policies" "enabled"; then
        # tier = 'system' AND enabled, because that is EXACTLY the population the
        # WARN below describes. GetEffective's system pass is the only reader
        # with no tenant predicate; its tenant pass matches neither '' nor NULL,
        # so a tier='tenant' row is dormant on both sides of the migration.
        # Counting every enabled row would headline a number the same message
        # then says is unaffected.
        q "155 static at-risk" "SELECT COUNT(*) FROM static_policies WHERE tenant_id = '' AND enabled = true AND tier = 'system'"
        if [[ "$QOK" -eq 1 ]]; then STATIC155_LIVE="$Q"; else CHK155_STATE_OK=0; fi
        q "155 static detail"  "SELECT COALESCE(string_agg(policy_id || ' (tier=' || COALESCE(tier,'?') || ', enabled=' || COALESCE(enabled::text,'?') || ')', ', ' ORDER BY policy_id), '') FROM static_policies WHERE tenant_id = ''"
        if [[ "$QOK" -eq 1 ]]; then STATIC155_DETAIL="$Q"; else CHK155_STATE_OK=0; fi
    else
        # NOT "zero at risk". `tier` is added by migrations/core/030, so a schema
        # without it is a pre-030 one — precisely the legacy shape this branch
        # exists for. An unmeasured count reported as 0 is the fail-open the rest
        # of this script spends its length avoiding.
        STATIC155_DETAIL="tier/enabled columns absent on this schema — the at-risk subset could not be measured"
        STATIC155_LIVE="unknown"
    fi
else
    info "static_policies.tenant_id not present on this deployment — core/155 will skip that table."
fi

if [[ "${#PSQL_FAILURES[@]}" -ne "$CHK155_FAILURES_BEFORE" ]]; then
    CHK155_STATE_OK=0
fi

if [[ "$CHK155_STATE_OK" -ne 1 ]]; then
    fail "Migration core/155 preview did not complete" \
        "At least one policy scan did not execute — see the query-failure list at the end. An unexecuted scan must NOT be read as 'no affected policies'."
elif [[ "$CHK155_TABLES_PRESENT" -eq 0 ]]; then
    pass "core/155 has no policy tables to repair here (neither table has a tenant_id column)"
elif [[ "$DYN155_COUNT" == "0" && "$STATIC155_COUNT" == "0" && -n "$CHK155_BLIND_TABLES" ]]; then
    warn "This connection cannot read the policy tables, so 'nothing to repair' is not a measurement" \
        "Row-level security is applied to this connection on: ${CHK155_BLIND_TABLES} - and each read as ZERO rows, which is indistinguishable from an empty table. Connected as role '${PF_CONN_ROLE:-unknown}' (rolsuper=${PF_CONN_SUPER:-unknown}, rolbypassrls=${PF_CONN_BYPASSRLS:-unknown}). This check names policy_ids that only exist BEFORE core/155 runs, so a missed row here cannot be recovered afterwards except from the migration's own RAISE WARNING output. Re-run as axonflow_platform_admin, or as the table owner on a docker-compose bundle; see 'WHICH DATABASE ROLE TO RUN THIS AS' in this script's header."
elif [[ "$DYN155_COUNT" == "0" && "$STATIC155_COUNT" == "0" ]]; then
    pass "No policy rows carry tenant_id='' — core/155 has nothing to repair here"
else
    if [[ "$DYN155_COUNT" != "0" ]]; then
        info "  dynamic_policies: $DYN155_COUNT row(s) with tenant_id='' ($DYN155_ENABLED currently enabled)"
        info "  affected policy_id(s): $DYN155_IDS"
        warn "core/155 will DISABLE $DYN155_COUNT dynamic policy row(s)" \
            "policy_id(s): ${DYN155_IDS}. core/155 sets tenant_id=NULL AND enabled=false on these rows. Enforcement does not change on the engine production runs (an empty-tenant row already matched NO tenant there), but after the migration the row is NOT reachable through the portal or the policy API — a NULL tenant matches neither of their tenant predicates. Remediation is direct SQL, and the ids above are your only record of which rows to fix: once the migration has run, no row has an empty tenant any more, so nothing can find them again. Paste-ready: UPDATE dynamic_policies SET tenant_id = '<your-real-tenant-id>', enabled = true WHERE policy_id IN (${DYN155_IDS_SQL}); — run it per tenant, and decide BEFORE upgrading whether each policy should come back at all."
    fi
    if [[ "$STATIC155_COUNT" != "0" ]]; then
        info "  static_policies: $STATIC155_COUNT row(s) with tenant_id='' — policy_id(s): $STATIC155_IDS"
        info "  tier/enabled: $STATIC155_DETAIL"
        info "  core/155 normalises these to NULL and does NOT disable them."
        if [[ "$STATIC155_LIVE" == "unknown" ]]; then
            warn "core/155 touches $STATIC155_COUNT static policy row(s) and the at-risk subset could NOT be measured" \
                "policy_id(s): ${STATIC155_IDS}. This schema has no tier/enabled columns (they arrive in migrations/core/030), so the query that identifies the at-risk subset — enabled, tier='system' — could not run. Treat the whole set as unclassified rather than as clear. Record these ids and confirm after upgrading that each policy still fires."
        elif [[ "$STATIC155_LIVE" != "0" ]]; then
            warn "core/155 normalises $STATIC155_LIVE ENABLED tier=system static policy row(s) whose effect is not provable here" \
                "policy_id(s) with tier/enabled: ${STATIC155_DETAIL}. The migration header calls this a proven no-op because the static loader filters (tenant_id = caller OR tenant_id = 'global'), which excludes both '' and NULL. That holds for ONE of the two readers and not the other. platform/shared/policy/loader.go's loadFromDatabase does carry the equivalent predicate live, as two passes of tenant_id = \$1, so nothing changes there. But StaticPolicyRepository.GetEffective's SYSTEM pass (platform/agent/static_policy_repository.go) selects tier='system' with NO tenant predicate at all, and scans tenant_id into a plain Go string — which cannot take the SQL NULL this migration writes. The scan error is swallowed by a bare continue, so the row is dropped silently. An ENABLED tier=system row of this shape is therefore plausibly enforced today and gone afterwards: a DE-enforcement, in the fail-open direction, with no log line. This preflight cannot settle it from outside the process. Record these ids and confirm after upgrading that each policy still fires. Rows that are already disabled, or whose tier is not 'system', are unaffected on both readers."
        else
            pass "static_policies tenant_id='' rows enumerated — none is an enabled tier=system row, the only shape at risk"
        fi
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 10 — DEPLOYMENT_MODE on the agent AND the orchestrator
# ---------------------------------------------------------------------------
section "DEPLOYMENT_MODE (agent + orchestrator)"

# Since #3167 an UNRECOGNISED DEPLOYMENT_MODE is fatal to the agent rather than
# selecting the widest migration set. UNSET is a different thing and is
# deliberately NOT fatal — see unsetDeploymentMode in
# platform/agent/migration_helpers.go — so this check must never FAIL on unset.
#
# The consequence differs per component, and saying "it will not boot" about the
# orchestrator would be false:
#   agent        — runs the migration selector; collectMigrations() failing is
#                  log.Fatalf, so the container does not start. That path is
#                  inside `if dbURL != ""`, i.e. every deployment with a
#                  database configured.
#   orchestrator — does NOT run the migration selector, so it still starts. But
#                  isCommunityMode() matches the exact string "community", so an
#                  unrecognised value silently gives it the non-Community
#                  (enterprise) posture, and CORS denies every cross-origin
#                  request. Silent, not loud — which is worse to debug.
#
# Still a FAIL on both: the two processes now disagree about what deployment
# this is, and the operator asserted a value the platform cannot honour.

# classify_mode is defined with the other pure helpers near the top of the
# script, so that `--self-test` can exercise it without a database.

MODE_VERDICT_OK=1
for comp in agent orchestrator; do
    case "$comp" in
        agent) comp_upper="AGENT" ;;
        *)     comp_upper="ORCHESTRATOR" ;;
    esac
    discover_env "$comp" DEPLOYMENT_MODE
    raw="$DISC_VALUE"; state="$DISC_STATE"; src="$DISC_SOURCE"
    info "  $comp: source=$src state=$state"

    if [[ "$state" == "unknown" ]]; then
        MODE_VERDICT_OK=0
        warn "DEPLOYMENT_MODE on the $comp was NOT VERIFIED" \
            "Nothing readable answered for the $comp, so this preflight makes NO statement about it — do not read the absence of a FAIL as an all-clear. Check by hand: \`docker compose exec axonflow-$comp printenv DEPLOYMENT_MODE\` (or read the ECS task def). Then re-run with AXONFLOW_${comp_upper}_CONTAINER set."
        continue
    fi

    classify_mode "$raw"
    case "$MODE_CLASS" in
        recognised)
            pass "DEPLOYMENT_MODE='$raw' on the $comp is a recognised value"
            ;;
        unset)
            if [[ "$state" == "empty" ]]; then
                info "  DEPLOYMENT_MODE is declared but empty on the $comp — the platform treats that as unset."
            else
                info "  DEPLOYMENT_MODE is not declared on the $comp."
            fi
            info "  Unset is LEGAL and is not fatal: the migration selector resolves it to 'community' (core/ only)."
            info "  Be aware of the asymmetry (#3128): the RUNTIME posture of an unset value is the ENTERPRISE one,"
            info "  and for CORS an unset value is NOT community — cross-origin browser requests are denied (see check 12)."
            pass "DEPLOYMENT_MODE unset on the $comp (legal; not a blocker)"
            ;;
        unrecognised)
            MODE_VERDICT_OK=0
            if [[ "$comp" == "agent" ]]; then
                fail "DEPLOYMENT_MODE='$raw' on the agent is NOT a recognised value" \
                    "The agent REFUSES TO BOOT on this value — collectMigrations() returns an error and run.go log.Fatalf's rather than guessing which schema to apply. That refusal sits inside the agent's database-configured branch in run.go, which is every deployment that runs migrations — including this one, since you are pointing this script at its database. Diagnosis: $MODE_HINT. Recognised values (matched exactly): ${RECOGNISED_MODES[*]}. Fix the value BEFORE pulling the new image. Do NOT 'fix' it by unsetting the variable — unset selects core/ migrations only while the runtime posture of an unset value is the enterprise one (#3128); name the mode this deployment actually is."
            else
                fail "DEPLOYMENT_MODE='$raw' on the orchestrator is NOT a recognised value" \
                    "The orchestrator does NOT run the migration selector, so unlike the agent it will still START — which is worse, not better. isCommunityMode() matches the exact string 'community', so this value silently gives the orchestrator the non-Community (enterprise) posture, while the agent next to it refuses to boot on the same value. (It also removes the Community CORS fallback — but only where AXONFLOW_CORS_ALLOWED_ORIGINS is unset, since a configured allowlist is honoured regardless of mode. Check 12 resolves that properly.) Diagnosis: $MODE_HINT. Recognised values (matched exactly): ${RECOGNISED_MODES[*]}."
            fi
            ;;
    esac
done

if [[ "$MODE_VERDICT_OK" -eq 1 ]]; then
    info "Both components carry a DEPLOYMENT_MODE the platform accepts."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 11 — Migration core/156 maintenance-window sizing
# ---------------------------------------------------------------------------
section "Migration core/156 window sizing (5 tables, ONE transaction)"

# core/156 runs SET NOT NULL + ADD CHECK on org_id and tenant_id across five
# tables, ALL INSIDE ONE TRANSACTION. Neither operation rewrites the table, so
# each is a sequential scan — but the ACCESS EXCLUSIVE locks are held until
# COMMIT rather than released per table, so the window is the SUM.
#
# Row counts alone do not size a window, so this check also MEASURES the scan.
# `EXPLAIN (ANALYZE, TIMING OFF) SELECT count(*)` executes exactly the shape of
# read the ALTER performs, and Postgres reports its own execution time. That is
# a measured LOWER BOUND — the real window additionally includes waiting for
# existing transactions to release their locks — and it is reported as such
# rather than dressed up as an estimate.
CORE156_TABLES="plans workflows workflow_checkpoints execution_summaries webhook_subscriptions"
C156_OK=1
C156_TOTAL_ROWS=0
C156_TOTAL_US=0
C156_US_MEASURED=1
C156_STAMPED_ROWS=0
C156_STAMPED_VALUES=0
C156_PRESENT=0

for tname in $CORE156_TABLES; do
    if ! table_exists "$tname"; then
        info "  $tname: absent — core/156 skips it"
        continue
    fi
    C156_PRESENT=$((C156_PRESENT + 1))

    q "156 rowcount($tname)" "SELECT COUNT(*) FROM $tname"
    if [[ "$QOK" -ne 1 ]] || ! is_uint "$Q"; then C156_OK=0; continue; fi
    rows="$Q"
    C156_TOTAL_ROWS=$((C156_TOTAL_ROWS + rows))

    # Measured scan cost. Parsed off EXPLAIN's own "Execution Time: N ms" line.
    # A shape this parser does not recognise sets the "not measured" flag rather
    # than contributing 0 — an unparsed timing must not read as an instant scan.
    us=""
    if psql_exec "EXPLAIN (ANALYZE, TIMING OFF) SELECT COUNT(*) FROM $tname"; then
        _last="${PSQL_OUT##*$'\n'}"
        case "$_last" in
            "Execution Time: "*)
                _ms="${_last#Execution Time: }"
                _ms="${_ms% ms}"
                us="$(ms_to_us "$_ms" || true)"
                ;;
        esac
    fi
    if [[ -z "$us" ]]; then
        scan_desc="scan not measured"
        C156_US_MEASURED=0
    else
        scan_desc="scan $(fmt_us "$us")"
        C156_TOTAL_US=$((C156_TOTAL_US + us))
    fi

    # What core/156 will stamp with the inert '__axonflow_unowned__' sentinel.
    #
    # TWO numbers, because they answer different questions and only one of them
    # is the one an operator asks. The migration UPDATEs per COLUMN, so the sum
    # of its own RAISE WARNING counts is a count of blank VALUES — a single row
    # with both keys blank is reported twice. "How many of my rows become
    # unreachable" is a count of distinct ROWS. Reporting only the value count
    # overstates the blast radius; reporting only the row count would not
    # reconcile against the migration's log output. So: both.
    blank_values=0
    blank_pred=""
    for col in org_id tenant_id; do
        if column_exists "$tname" "$col"; then
            q "156 blank($tname.$col)" "SELECT COUNT(*) FROM $tname WHERE $col IS NULL OR btrim($col) = ''"
            if [[ "$QOK" -ne 1 ]] || ! is_uint "$Q"; then C156_OK=0; continue; fi
            blank_values=$((blank_values + Q))
            blank_pred="${blank_pred:+$blank_pred OR }${col} IS NULL OR btrim(${col}) = ''"
        fi
    done
    blank_rows=0
    if [[ -n "$blank_pred" ]]; then
        q "156 blank-rows($tname)" "SELECT COUNT(*) FROM $tname WHERE $blank_pred"
        if [[ "$QOK" -ne 1 ]] || ! is_uint "$Q"; then C156_OK=0; else blank_rows="$Q"; fi
    fi
    C156_STAMPED_VALUES=$((C156_STAMPED_VALUES + blank_values))
    C156_STAMPED_ROWS=$((C156_STAMPED_ROWS + blank_rows))

    if [[ "$blank_rows" -gt 0 ]]; then
        info "  $tname: $rows row(s), $scan_desc — $blank_rows row(s) / $blank_values blank key value(s) → SENTINEL-STAMPED"
    else
        info "  $tname: $rows row(s), $scan_desc — no blank tenancy keys"
    fi
done

if [[ "$C156_OK" -ne 1 ]]; then
    fail "core/156 window sizing is incomplete" \
        "At least one count did not execute — see the query-failure list at the end. Sizing a lock window from a partial scan is worse than not sizing it."
elif [[ "$C156_PRESENT" -eq 0 ]]; then
    info "None of core/156's five tables exist on this deployment — the migration will skip all of them."
    pass "core/156 has no tables to constrain here"
else
    info "  TOTAL across $C156_PRESENT present table(s): $C156_TOTAL_ROWS row(s)"
    if [[ "$C156_US_MEASURED" -eq 1 ]]; then
        info "  MEASURED scan cost: $(fmt_us "$C156_TOTAL_US") for one pass over all five tables."
        info "  core/156 scans EACH constrained column (SET NOT NULL, then ADD CHECK), so the arithmetic"
        info "  lower bound for the lock window is roughly 4x that: $(fmt_us $((C156_TOTAL_US * 4)))."
        info "  It is a LOWER BOUND, not an estimate: ACCESS EXCLUSIVE also waits for every in-flight"
        info "  transaction on these tables, and all five ALTERs commit together, so nothing is released early."
    else
        info "  Scan cost could not be measured on at least one table (EXPLAIN output not in the expected"
        info "  shape). Size the window from the row counts above, and measure it yourself with:"
        info "    EXPLAIN (ANALYZE, TIMING OFF) SELECT COUNT(*) FROM execution_summaries;"
    fi
    if [[ "$C156_STAMPED_ROWS" -gt 0 ]]; then
        warn "core/156 will sentinel-stamp $C156_STAMPED_ROWS row(s) ($C156_STAMPED_VALUES blank key value(s))" \
            "Those rows were readable by EVERY tenant before the migration — that is the vulnerability being closed — and afterwards they are reachable and writable by NOBODY, including you. The migration does NOT try to determine an owner, so re-attributing a row needs direct SQL. The migration's own log reports the VALUE count ($C156_STAMPED_VALUES, one line per table+column); the number of rows you lose access to is $C156_STAMPED_ROWS. Practical consequence: an execution that starts before the upgrade and finishes after it fails its final update instead of being marked completed. Drain in-flight executions if you can."
    else
        pass "core/156: no blank tenancy keys to stamp ($C156_TOTAL_ROWS row(s) across $C156_PRESENT table(s))"
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 12 — CORS is deny-by-default outside Community mode
# ---------------------------------------------------------------------------
section "Cross-origin browser access (AXONFLOW_CORS_ALLOWED_ORIGINS)"

# corspolicy.Resolve(): if AXONFLOW_CORS_ALLOWED_ORIGINS is unset and
# DEPLOYMENT_MODE is not EXACTLY "community", every cross-origin browser request
# is denied. The failure is silent from the server's side — the browser blocks
# the request, so there is no per-request error to find in a log. The only
# server-side trace is one line at startup.
#
# Note the trap in the mode comparison: corspolicy.IsCommunityMode() reads
# os.Getenv("DEPLOYMENT_MODE") == "community", so an UNSET mode is NOT the
# Community posture here even though the migration selector resolves unset to
# `community`. Unset therefore lands in the deny branch.
for comp in agent orchestrator; do
    discover_env "$comp" AXONFLOW_CORS_ALLOWED_ORIGINS
    cors_raw="$DISC_VALUE"; cors_state="$DISC_STATE"; cors_src="$DISC_SOURCE"
    # Parse it the way corspolicy.ParseAllowedOrigins does — split on commas,
    # trim each entry, drop the empties — because THAT decides whether the
    # platform sees a list at all. A value of "," or " , " has a non-empty
    # string but yields zero origins, so the platform denies everything while a
    # naive -n test reads it as configured. Same for the whole-string trim: a
    # value of "   " is not an allowlist.
    cors_val=""
    _rest="$cors_raw"
    while [[ -n "$_rest" ]]; do
        case "$_rest" in
            *,*) _piece="${_rest%%,*}"; _rest="${_rest#*,}" ;;
            *)   _piece="$_rest"; _rest="" ;;
        esac
        _piece="$(trim_ws "$_piece")"
        [[ -n "$_piece" ]] && cors_val="${cors_val:+$cors_val,}$_piece"
    done
    discover_env "$comp" DEPLOYMENT_MODE
    mode_val="$DISC_VALUE"; mode_state="$DISC_STATE"; mode_src="$DISC_SOURCE"

    if [[ "$cors_state" == "unknown" ]]; then
        warn "AXONFLOW_CORS_ALLOWED_ORIGINS on the $comp was NOT VERIFIED" \
            "Nothing readable answered for the $comp. Check by hand: \`docker compose exec axonflow-$comp printenv AXONFLOW_CORS_ALLOWED_ORIGINS DEPLOYMENT_MODE\`."
        continue
    fi

    info "  $comp: DEPLOYMENT_MODE source: $mode_src (state: $mode_state)"

    if [[ -n "$cors_val" ]]; then
        info "  $comp: AXONFLOW_CORS_ALLOWED_ORIGINS='$cors_val' (source: $cors_src)"
        if [[ "$cors_val" != "$(trim_ws "$cors_raw")" ]]; then
            info "  (raw value was '$cors_raw'; empty entries dropped, as the platform does)"
        fi
        case "$cors_val" in
            *"*"*)
                warn "$comp CORS allowlist contains a wildcard" \
                    "'$cors_val'. AxonFlow honours the entry, but CREDENTIALS ARE NOT ADVERTISED for any origin in a list containing '*' — a bare '*' allows all origins without credentials, and a pattern like https://*.example.com is prefix/suffix-matched by the CORS library (NOT exact, contrary to what older docs said), so it admits a set nobody enumerated. A browser front-end that relies on cookies/credentials will break. List exact origins instead."
                ;;
            *)
                pass "$comp: cross-origin browser access is allow-listed to exact origin(s)"
                ;;
        esac
        continue
    fi

    # Unset (or declared-empty). Whether that is a problem depends entirely on
    # the mode, matched exactly.
    if [[ -n "$cors_raw" ]]; then
        info "  $comp: AXONFLOW_CORS_ALLOWED_ORIGINS='$cors_raw' contains no usable origin after parsing —"
        info "  the platform reads this as UNSET, not as an allowlist."
    fi
    if [[ "$mode_val" == "community" ]]; then
        info "  $comp: AXONFLOW_CORS_ALLOWED_ORIGINS unset, DEPLOYMENT_MODE=community"
        pass "$comp: Community-mode CORS fallback applies (unset is the supported posture here)"
    else
        if [[ "$mode_state" == "unknown" ]]; then
            mode_desc="the mode could not be read"
        elif [[ -z "$mode_val" ]]; then
            mode_desc="DEPLOYMENT_MODE is unset, which is NOT 'community' as far as CORS is concerned"
        else
            mode_desc="DEPLOYMENT_MODE='$mode_val'"
        fi
        warn "$comp will DENY every cross-origin browser request" \
            "AXONFLOW_CORS_ALLOWED_ORIGINS is not set and $mode_desc. Who is affected: only a browser front-end served from a DIFFERENT origin that calls the AxonFlow API directly. The bundled Customer Portal is same-origin and is fine; SDKs, curl and CI ignore CORS entirely. If you do have such a front-end, set AXONFLOW_CORS_ALLOWED_ORIGINS to its EXACT origin(s) — scheme + host + optional port, comma-separated, no suffix matching (https://example.com does NOT cover https://app.example.com) — on CloudFormation the CorsAllowedOrigins parameter. This failure is invisible server-side: the browser blocks the request, and the only trace is one startup line reading '[CORS] AXONFLOW_CORS_ALLOWED_ORIGINS is not set and DEPLOYMENT_MODE is not community: cross-origin browser requests are denied. Set AXONFLOW_CORS_ALLOWED_ORIGINS if a browser on another origin must call this API.'"
    fi
done
printf "\n"

# ===========================================================================
# v9.14.0 - checks 13 to 15
# ===========================================================================
printf "%b%b-- v9.14.0 --------------------------------------------------------------%b\n\n" "$BOLD" "$BLUE" "$NC"

# These three checks are INTEGRATION-SHAPE dependent. They describe governance
# gates that tightened in the 9.14.x line and that this script cannot observe
# from the database alone: they live in HTTP request handling and credential
# shape, not in the schema. So each is WARN or advisory, never a hard FAIL. A
# preflight cannot prove which endpoints an operator's automation calls, or what
# credential it presents, so it advises on the one thing it can read (the
# deployment posture) and is explicit about what it cannot see.
#
# All three only bite in an ENTERPRISE runtime posture. Community mode
# (DEPLOYMENT_MODE matched EXACTLY as "community") does not register the
# compliance-export endpoints and does not govern /api/request, so the checks
# report "not applicable" there. Anything that is NOT exactly "community",
# INCLUDING unset (whose runtime posture is the enterprise one, #3128; see also
# checks 10 and 12), is treated as enterprise here.
discover_env agent DEPLOYMENT_MODE
V914_MODE="$DISC_VALUE"; V914_MODE_STATE="$DISC_STATE"; V914_MODE_SRC="$DISC_SOURCE"
if [[ "$V914_MODE_STATE" == "unknown" ]]; then
    discover_env orchestrator DEPLOYMENT_MODE
    V914_MODE="$DISC_VALUE"; V914_MODE_STATE="$DISC_STATE"; V914_MODE_SRC="$DISC_SOURCE"
fi

# V914_POSTURE: community | enterprise | unknown. "community" ONLY on an exact
# match, mirroring the platform. A value read as empty/unset is enterprise
# runtime posture. A mode nobody could read is "unknown", and the checks say so
# rather than guessing an all-clear.
if [[ "$V914_MODE_STATE" == "unknown" ]]; then
    V914_POSTURE="unknown"
elif [[ "$V914_MODE" == "community" ]]; then
    V914_POSTURE="community"
else
    V914_POSTURE="enterprise"
fi
info "v9.14.0 checks use DEPLOYMENT_MODE from: $V914_MODE_SRC (state: $V914_MODE_STATE, posture: $V914_POSTURE)"
printf "\n"

# ---------------------------------------------------------------------------
# Check 13 - Compliance-export admin authority (#3248)
# ---------------------------------------------------------------------------
section "Compliance-export admin authority (#3248, new in 9.14.0)"

# As of 9.14.0 the compliance-export endpoints require ADMIN AUTHORITY, not just
# tenant-wide read. A tenant-scoped internal-service / license credential that
# carried these calls before now gets 403. This preflight cannot see which
# endpoints an operator's automation hits or what credential it sends, so it
# advises purely on posture and is honest that it is doing so.
if [[ "$V914_POSTURE" == "community" ]]; then
    pass "Community posture: the compliance-export endpoints are an Enterprise-only surface, so the #3248 admin-authority gate does not apply here"
elif [[ "$V914_POSTURE" == "unknown" ]]; then
    warn "Compliance-export admin authority was NOT VERIFIED (#3248)" \
        "DEPLOYMENT_MODE could not be read for either component, so this preflight cannot tell whether the compliance-export endpoints are even present. If this deployment drives compliance-export automation (POST /api/v1/ojk/audit/export and the evidence / SEBI / euaiact / media-governance exports, plus compliance-report generate and download), be aware that as of 9.14.0 those endpoints require ADMIN AUTHORITY, not merely tenant-wide read. A tenant-scoped internal-service or license credential with no admin per-user token and no portal session now receives 403. Remedy: mint an admin or owner X-User-Token with mint-admin-token.sh and send it alongside the Basic license credential on those calls. Set AXONFLOW_AGENT_CONTAINER (or ECS_CLUSTER + ECS_AGENT_SERVICE) and re-run to resolve the mode."
else
    warn "Compliance-export endpoints now require ADMIN AUTHORITY, not tenant-wide read (#3248)" \
        "As of 9.14.0, POST /api/v1/ojk/audit/export, the evidence / SEBI / euaiact / media-governance exports, and compliance-report generate and download all require ADMIN AUTHORITY rather than just tenant-wide read. A tenant-scoped credential (a Basic license credential with no admin per-user token and no portal session) now gets 403 instead of a report, so any automation that generates or downloads compliance evidence with a non-admin credential will break on upgrade. Remedy: mint an admin or owner X-User-Token with mint-admin-token.sh and send it ALONGSIDE the Basic license credential on those calls. Honest scope: this preflight cannot see your automation's credentials or which endpoints it calls (posture read: enterprise), so it advises on DEPLOYMENT_MODE alone. If you do NOT drive compliance-export automation, no action is needed."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 14 - /api/request empty-email segment gate (#3057, ADR-060)
# ---------------------------------------------------------------------------
section "/api/request email-claim gate (#3057, ADR-060, new in 9.14.0)"

# In enterprise mode a governed /api/request call whose token carries no email
# claim fail-closes to 403 (ADR-060). This is scoped to /api/request only; the
# decide plane and the MCP planes do not take this path. The platform fix lands
# in 9.15.0, after which an empty email proceeds org-only rather than refusing.
if [[ "$V914_POSTURE" == "community" ]]; then
    pass "Community posture: /api/request is not governed by the ADR-060 email-claim gate here"
elif [[ "$V914_POSTURE" == "unknown" ]]; then
    warn "/api/request email-claim gate was NOT VERIFIED (#3057)" \
        "DEPLOYMENT_MODE could not be read, so this preflight cannot tell whether the ADR-060 email-claim gate is active. In enterprise mode, a governed /api/request call whose token carries no email claim fail-closes to 403. If any caller uses /api/request, mint its token WITH an email claim (mint --kind user --email ... --org-id ...). This affects ONLY /api/request: it does NOT affect /api/v1/decide or the MCP planes. The platform fix ships in 9.15.0, after which an empty email proceeds org-only. Set AXONFLOW_AGENT_CONTAINER (or ECS_CLUSTER + ECS_AGENT_SERVICE) and re-run to resolve the mode."
else
    warn "/api/request fail-closes to 403 for a token with no email claim (#3057, ADR-060)" \
        "In enterprise mode, a governed /api/request call whose token has no email claim fail-closes to 403 (ADR-060). Any caller that uses /api/request must present a token that carries an email claim: mint it with mint --kind user --email ... --org-id .... This affects ONLY /api/request. It does NOT affect /api/v1/decide or the MCP planes, whose governance does not take this path. The platform fix ships in 9.15.0, after which an empty email proceeds org-only rather than refusing; until you are on 9.15.0, ensure every /api/request token carries an email. Honest scope: this preflight cannot inspect your callers' tokens (posture read: enterprise), so it advises on DEPLOYMENT_MODE alone."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 15 - Target version carries the /api/request email fix (#3278)
# ---------------------------------------------------------------------------
section "Target version carries the /api/request email fix (#3278)"

# ADVISORY. The empty-email landmine from check 14 is present in the version
# range [9.14.0, 9.15.0): #3278 (the org-only fallback) lands in 9.15.0. This
# check cannot inspect the target image tag, so it prints guidance keyed on the
# deployment posture and passes; it never blocks.
if [[ "$V914_POSTURE" == "community" ]]; then
    pass "Community posture: the /api/request email-claim landmine does not apply here"
else
    info "  Upgrading an enterprise deployment whose /api/request tokens can lack an email to a version in"
    info "  the range [9.14.0, 9.15.0) carries the #3057 empty-email landmine from check 14: those calls"
    info "  fail-close to 403 until the target carries #3278."
    info "  Target 9.15.0 or later (which carries #3278, so an empty email proceeds org-only), OR ensure"
    info "  every /api/request token carries an email claim before upgrading."
    info "  This check cannot read the target image tag; it is advisory guidance keyed on DEPLOYMENT_MODE"
    info "  posture only (posture read: $V914_POSTURE)."
    pass "Target-version guidance emitted for #3278 (advisory: preflight cannot inspect the target image tag)"
fi
printf "\n"

# ===========================================================================
# v9.17.0 - check 16
# ===========================================================================
printf "%b%b-- v9.17.0 --------------------------------------------------------------%b\n\n" "$BOLD" "$BLUE" "$NC"

# ---------------------------------------------------------------------------
# Check 16 - break-glass admin key on the customer-portal (ADMIN_API_KEY)
# ---------------------------------------------------------------------------
section "Break-glass admin key on the customer-portal (ADMIN_API_KEY)"

# WHY THIS IS A PREFLIGHT CHECK AND NOT AN INSTALLER FIX.
#
# install.sh generates an ADMIN_API_KEY on a FRESH install and never rotates it
# (axonflow-install #62). An UPGRADE does not re-run install.sh - the documented
# flow is swap digests, compose pull, compose up, verify - so a deployment
# installed before that change still has a blank key, and nothing has ever told
# its operator. Generating one from here was considered and rejected: this
# script does not write to a running deployment, and silently minting a
# credential into somebody's .env during an upgrade is a surprise, not a fix. So
# it reports, with the exact remedy, and never blocks.
#
# WHY THE PORTAL AND NOT .env. The 500 is produced by the RUNNING portal
# process, and its environment can differ from .env by exactly one restart -
# which is the state RECOVERY.md's own troubleshooting table names ("blank in
# the running portal container. Set it in .env and docker compose up -d"). A
# check that read .env would report the recovery path as armed for precisely
# that deployment. So discovery goes through discover_env, whose Compose and
# container sources read the process, and whose PORTAL_ENV_FILE source remains
# available for an operator who wants to point it at a file deliberately.
discover_env portal ADMIN_API_KEY
PORTAL_KEY_VALUE="$DISC_VALUE"; PORTAL_KEY_STATE="$DISC_STATE"
PORTAL_KEY_SRC="$DISC_SOURCE"; PORTAL_KEY_ORIGIN="$DISC_ORIGIN"
PORTAL_KEY_VIA_SECRET=0

# Source (5), the operator's own shell, is NOT evidence about the portal, and
# for this variable it is actively misleading: UPGRADING.md tells the operator
# to load ADMIN_API_KEY out of .env before running the admin commands, and
# RECOVERY.md's curl examples read it from there. Accepting that reading would
# turn "I sourced .env" into "recovery is armed" on a portal whose own copy is
# blank - the one false all-clear this check must not produce.
if [[ "$PORTAL_KEY_ORIGIN" == "shell" ]]; then
    PORTAL_KEY_STATE="unknown"
    PORTAL_KEY_SRC="ADMIN_API_KEY was set in YOUR SHELL only, which says nothing about the running portal (sourcing .env does this)"
fi

# On ECS the admin key is a secrets[] reference (CloudFormation AdminAPIKeySecret
# -> ADMIN_API_KEY on the customer-portal container), not a literal env value, so
# the environment[] read above legitimately comes back absent. Ask for the entry
# NAME rather than its valueFrom: answering "is a key wired?" does not require
# this script to hold a secret ARN, and a script that never reads one cannot
# print one.
if [[ "$PORTAL_KEY_STATE" != "set" && -n "${ECS_CLUSTER:-}" && -n "${ECS_PORTAL_SERVICE:-}" ]] && command -v aws >/dev/null 2>&1; then
    _ptd=$(aws ecs describe-services --cluster "$ECS_CLUSTER" --services "$ECS_PORTAL_SERVICE" \
        --query 'services[0].taskDefinition' --output text 2>/dev/null || echo "")
    if [[ -n "$_ptd" && "$_ptd" != "None" ]]; then
        _pkeyref=$(aws ecs describe-task-definition --task-definition "$_ptd" \
            --query "taskDefinition.containerDefinitions[?name=='customer-portal'||name=='axonflow-customer-portal'||name=='portal'].secrets[?name=='ADMIN_API_KEY'].name | [0][0]" \
            --output text 2>/dev/null || echo "")
        if [[ -n "$_pkeyref" && "$_pkeyref" != "None" ]]; then
            PORTAL_KEY_STATE="set"
            PORTAL_KEY_VIA_SECRET=1
            PORTAL_KEY_SRC="ECS task def ${ECS_CLUSTER}/${ECS_PORTAL_SERVICE}, secrets[] reference"
        fi
    fi
fi

info "ADMIN_API_KEY source: $PORTAL_KEY_SRC (state: $PORTAL_KEY_STATE)"

# ENVIRONMENT and DEPLOYMENT_MODE decide WHICH way a blank key fails, so they
# are read from the same component. A shell reading is demoted for them too: it
# would let the operator's environment answer a question about the deployment.
discover_env portal ENVIRONMENT
PORTAL_ENVIRONMENT="$DISC_VALUE"; PORTAL_ENV_STATE="$DISC_STATE"; PORTAL_ENV_SRC="$DISC_SOURCE"
if [[ "$DISC_ORIGIN" == "shell" ]]; then PORTAL_ENV_STATE="unknown"; PORTAL_ENV_SRC="your shell only"; fi
discover_env portal DEPLOYMENT_MODE
PORTAL_MODE="$DISC_VALUE"; PORTAL_MODE_STATE="$DISC_STATE"; PORTAL_MODE_SRC="$DISC_SOURCE"
if [[ "$DISC_ORIGIN" == "shell" ]]; then PORTAL_MODE_STATE="unknown"; PORTAL_MODE_SRC="your shell only"; fi
info "  portal ENVIRONMENT: $PORTAL_ENV_SRC (state: $PORTAL_ENV_STATE)"
info "  portal DEPLOYMENT_MODE: $PORTAL_MODE_SRC (state: $PORTAL_MODE_STATE)"

# Trimmed, because the portal trims once on read (secretenv.Get). A value of
# "   " is a non-empty environment variable that the platform sees as blank, so
# testing the raw value here would report a 500-ing deployment as armed.
PORTAL_KEY_CONFIGURED=0
if [[ "$PORTAL_KEY_STATE" == "set" && -n "$(trim_ws "$PORTAL_KEY_VALUE")" ]]; then PORTAL_KEY_CONFIGURED=1; fi
if [[ "$PORTAL_KEY_VIA_SECRET" -eq 1 ]]; then PORTAL_KEY_CONFIGURED=1; fi

# A declared-but-whitespace value is called out separately: it is the one state
# that looks correct to every check an operator would run by hand on .env.
PORTAL_KEY_NOTE=""
if [[ "$PORTAL_KEY_STATE" == "set" && "$PORTAL_KEY_CONFIGURED" -eq 0 ]]; then
    PORTAL_KEY_NOTE="ADMIN_API_KEY is declared with a WHITESPACE-ONLY value. The portal trims it once on read, so it is blank there while still matching a grep for a set variable in .env. "
elif [[ "$PORTAL_KEY_STATE" == "empty" ]]; then
    PORTAL_KEY_NOTE="ADMIN_API_KEY is declared and empty. "
elif [[ "$PORTAL_KEY_STATE" == "absent" ]]; then
    PORTAL_KEY_NOTE="ADMIN_API_KEY is not declared on the portal at all. "
fi

PORTAL_POSTURE_KNOWN=1
if [[ "$PORTAL_ENV_STATE" == "unknown" || "$PORTAL_MODE_STATE" == "unknown" ]]; then PORTAL_POSTURE_KNOWN=0; fi

if [[ "$PORTAL_KEY_STATE" == "unknown" ]]; then
    warn "The customer-portal's ADMIN_API_KEY was NOT VERIFIED" \
        "Nothing component-specific answered, so this check makes NO statement about whether break-glass admin recovery is available here - do not read the absence of a finding as an all-clear. What was tried: ${PORTAL_KEY_SRC}. Re-run from the install bundle directory with the portal container running, or set AXONFLOW_PORTAL_CONTAINER to the portal container id, or PORTAL_ENV_FILE to the file the portal is started from, or ECS_CLUSTER plus ECS_PORTAL_SERVICE. To answer it by hand without printing the secret: grep -cE '^ADMIN_API_KEY=.+' .env, and expect 1. What matters is the value in the RUNNING portal rather than in .env - a key added to .env after the last 'docker compose up -d axonflow-customer-portal' is not in the container yet, and RECOVERY.md's troubleshooting table lists that as its own failure. See RECOVERY.md."
elif [[ "$PORTAL_KEY_CONFIGURED" -eq 1 && "$PORTAL_KEY_VIA_SECRET" -eq 1 ]]; then
    info "The admin key is wired as a secrets manager reference on the portal task."
    pass "ADMIN_API_KEY is wired on the customer-portal task - break-glass admin recovery (RECOVERY.md path 1) is armed. Honest scope: this reads the task definition, not the secret's value; an empty secret would still answer 500"
elif [[ "$PORTAL_KEY_CONFIGURED" -eq 1 ]]; then
    pass "ADMIN_API_KEY is set on the customer-portal - the break-glass admin password reset in RECOVERY.md is available (source: ${PORTAL_KEY_SRC}; the value is never printed)"
elif [[ "$PORTAL_POSTURE_KNOWN" -ne 1 ]]; then
    warn "The customer-portal has NO ADMIN_API_KEY, and which way that fails could not be determined" \
        "${PORTAL_KEY_NOTE}Source: ${PORTAL_KEY_SRC}. ENVIRONMENT and/or DEPLOYMENT_MODE could not be read for the portal, so this check will not tell you which of the two outcomes you have. Both need the same fix. Where admin authentication is required - any portal running ENVIRONMENT=production, which is how this bundle ships - every /api/v1/admin/* route answers 500 'Admin API key not configured', and that takes out the admin password reset, the only ONLINE way back into the Customer Portal when the login password is lost. Where it is not required, that same admin surface is served ANONYMOUSLY to anyone who can reach the portal's port. Remedy: generate a value with 'openssl rand -hex 32', set it on the ADMIN_API_KEY= line in this bundle's .env, then 'docker compose up -d axonflow-customer-portal'. Full procedure, verification and the offline fallback: RECOVERY.md. This preflight never prints the value and never writes to your .env."
else
    admin_auth_required "$PORTAL_MODE" "$PORTAL_ENVIRONMENT" ""
    if [[ "$ADMIN_AUTH_REQUIRED" -eq 1 ]]; then
        warn "The customer-portal has NO ADMIN_API_KEY - break-glass admin recovery returns 500" \
            "${PORTAL_KEY_NOTE}Source: ${PORTAL_KEY_SRC}. This portal runs ENVIRONMENT='${PORTAL_ENVIRONMENT}' with DEPLOYMENT_MODE='${PORTAL_MODE}', so its admin middleware REQUIRES a key on every /api/v1/admin/* call and, with none configured, answers 500 'Admin API key not configured' before it authenticates anything. The consequence is narrow and only appears on the day you need it: the admin password reset is on that surface, and it is the only ONLINE way back into the Customer Portal when the portal login password is lost. What is left is the offline path, reset-portal-credential.sh, which needs a shell on the host and the database. Nothing about the upgrade causes this and the upgrade does not clear it: install.sh generates a key on a FRESH install and never rotates it, but an upgrade never re-runs install.sh, so a deployment installed before that behaviour existed still has none. Remedy, one container restart and no data change: generate a value with 'openssl rand -hex 32', set it on the ADMIN_API_KEY= line in this bundle's .env, then 'docker compose up -d axonflow-customer-portal'. Treat it as a high-value secret: it can list organizations, disclose an organization's plaintext license key and reset any organization's portal password. Full procedure and verification: RECOVERY.md. This preflight never prints the value and never writes to your .env."
    else
        warn "The customer-portal has NO ADMIN_API_KEY, and its admin API is answering ANONYMOUSLY" \
            "${PORTAL_KEY_NOTE}Source: ${PORTAL_KEY_SRC}. With ENVIRONMENT='${PORTAL_ENVIRONMENT}', DEPLOYMENT_MODE='${PORTAL_MODE}' and no key configured, the portal's admin middleware does not require authentication at all, so /api/v1/admin/* is served to anyone who can reach the portal's port. That surface can list organizations, disclose an organization's plaintext license key - which is the platform's HTTP Basic credential - and reset any organization's portal password. Break-glass recovery does work here, but only because the door is open, and the portal logs that posture once at startup. Worth confirming you meant it: the shipped install bundle sets ENVIRONMENT=production on the customer-portal, where a blank key means 500 on those same routes instead. Remedy either way: generate a value with 'openssl rand -hex 32', set it on the ADMIN_API_KEY= line in this bundle's .env, then 'docker compose up -d axonflow-customer-portal'. See RECOVERY.md. This preflight never prints the value and never writes to your .env."
    fi
fi
printf "\n"

# ===========================================================================
# v10.0.0 - checks 17 to 22
# ===========================================================================
printf "%b%b-- v10.0.0 --------------------------------------------------------------%b\n\n" "$BOLD" "$BLUE" "$NC"

# ---------------------------------------------------------------------------
# Check 17 - statement_timeout vs the core/161 + core/162 audit_logs backfills
# ---------------------------------------------------------------------------
section "statement_timeout vs audit_logs (migrations core/161 + core/162)"

# THIS IS THE FIRST RELEASE IN WHICH A MIGRATION'S RUNTIME SCALES WITH AUDIT
# HISTORY RATHER THAN WITH SCHEMA SIZE, AND A TIGHT statement_timeout IS A BOOT
# LOOP RATHER THAN A SKIPPED STEP. The migration runner answers a migration
# error with a fatal exit, so a 161 or 162 that trips a per-session, per-role or
# per-database statement_timeout fails the container, which restarts, and fails
# again.
#
# WHAT IS MEASURED AND WHAT IS ASSUMED, because the difference is the whole
# value of this check. Each migration is one UPDATE in one transaction. Its READ
# half is a sequential scan of audit_logs under the migration's own predicate,
# and that is measured here with EXPLAIN (ANALYZE, TIMING OFF) over exactly that
# predicate, which is the same scan the UPDATE performs. Its WRITE half is one
# new row version per MATCHED row, and that cannot be measured from a read-only
# script at all. So the measurement is a LOWER BOUND on the read half alone, and
# the margin applied to it below is stated as a margin, never dressed up as an
# estimate.
#
# The planner will not use idx_audit_logs_timestamp here: both migrations are
# bounded by "timestamp < NOW()", which selects essentially the whole table, and
# the remaining predicate columns carry no index. So the scan is sequential and
# its cost is fixed by the table size.
#
# THIS CHECK ISSUES ITS OWN "SET statement_timeout = 0" ON EVERY MEASUREMENT
# QUERY, DELIBERATELY. On the deployment this check exists to catch, the
# configured timeout is too tight for a full scan, so the measurement would be
# the first thing it killed and the check would report "scan not measured"
# exactly where it needed a number. The value being compared against is read
# separately, BEFORE any SET, and never from a session this script has already
# widened.
#
# Note that both migrations skip themselves outright when audit_logs, or a
# column they name, is absent, so this check reports "nothing to size" for that
# case rather than inventing a window.
C17_ROWS=""
C17_M161=""
C17_M162=""
C17_SCAN_US=0
C17_MEASURED=0
C17_COUNTS_OK=1
C17_TIGHTEST_MS=""
C17_TIGHTEST_SRC=""
C17_SOURCES_UNREADABLE=0

if ! table_exists "audit_logs"; then
    info "audit_logs does not exist on this deployment - core/161 and core/162 both skip themselves."
    pass "core/161 and core/162 have no audit_logs to rewrite here"
elif ! column_exists "audit_logs" "timestamp"; then
    info "audit_logs has no timestamp column - core/161 and core/162 both skip themselves."
    pass "core/161 and core/162 have no audit_logs to rewrite here"
elif ! column_exists "audit_logs" "response_time_ms" \
     && ! { column_exists "audit_logs" "tokens_used" && column_exists "audit_logs" "cost" \
            && column_exists "audit_logs" "provider" && column_exists "audit_logs" "model"; }; then
    # Both migrations guard on their own columns and RETURN early when one is
    # missing, so on this schema neither has anything to do. Decided BEFORE the
    # row count rather than after: counting audit_logs is itself a full scan,
    # and running one to size a migration that will not run is the same waste
    # this check exists to help an operator avoid.
    info "audit_logs is missing the columns core/161 and core/162 name - both skip themselves."
    pass "core/161 and core/162 have nothing to rewrite on this schema"
else
    # Told to the operator, not just written in a comment: this check is the
    # most expensive thing in this script and it deliberately removes their own
    # statement_timeout for the duration of its two measurements. Both facts
    # belong on screen before the wait starts, on a stack that is still serving
    # traffic.
    info "  This check performs TWO read-only sequential scans of audit_logs, each with"
    info "  statement_timeout disabled FOR THAT QUERY ONLY. On a large table each takes about"
    info "  as long as the read half of the migration it is sizing, which is the number being"
    info "  reported. Nothing is written and no lock is taken beyond a normal read."

    # --- what is configured, read BEFORE this check widens anything ---------
    q "session statement_timeout" "SHOW statement_timeout"
    if [[ "$QOK" -eq 1 ]]; then
        info "  this connection's effective statement_timeout: ${Q:-<empty>}"
        c17_consider "this connection" "$Q"
    fi

    # pg_roles and pg_db_role_setting go through psql_exec rather than q, so a
    # hosted Postgres that restricts either catalog is reported as UNREADABLE
    # instead of failing the whole run. This mirrors the pg_authid probe in
    # check 5. An unreadable source is NOT the same as an empty one, and the
    # verdict below refuses to claim a clean sizing when one of them could not
    # be read.
    if psql_exec "SELECT COALESCE(string_agg(r.rolname || '=' || split_part(cfg, '=', 2), ';' ORDER BY r.rolname), '') FROM pg_catalog.pg_roles r, LATERAL unnest(COALESCE(r.rolconfig, ARRAY[]::text[])) AS cfg WHERE split_part(cfg, '=', 1) = 'statement_timeout'"; then
        _roles="${PSQL_OUT##*$'\n'}"
        if [[ -n "$_roles" ]]; then
            info "  per-role statement_timeout (pg_roles.rolconfig): $_roles"
            c17_split_entries "$_roles" "role"
        else
            info "  no per-role statement_timeout is set (pg_roles.rolconfig)"
        fi
    else
        C17_SOURCES_UNREADABLE=1
        info "  pg_roles.rolconfig is not readable by this role - per-role statement_timeout overrides could NOT be checked"
    fi

    # pg_db_role_setting is the superset: it carries the per-database and the
    # per-database-per-role entries that pg_roles.rolconfig does not show at
    # all. Reading only pg_roles would miss an ALTER DATABASE ... SET
    # statement_timeout, which is the shape a managed-Postgres console usually
    # writes.
    if psql_exec "SELECT COALESCE(string_agg(COALESCE(d.datname, '<all databases>') || '/' || COALESCE(r.rolname, '<all roles>') || '=' || split_part(cfg, '=', 2), ';'), '') FROM pg_catalog.pg_db_role_setting s LEFT JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase LEFT JOIN pg_catalog.pg_roles r ON r.oid = s.setrole, LATERAL unnest(COALESCE(s.setconfig, ARRAY[]::text[])) AS cfg WHERE split_part(cfg, '=', 1) = 'statement_timeout'"; then
        _dbroles="${PSQL_OUT##*$'\n'}"
        if [[ -n "$_dbroles" ]]; then
            info "  per-database / per-role statement_timeout (pg_db_role_setting): $_dbroles"
            c17_split_entries "$_dbroles" "setting"
        else
            info "  no per-database or per-database-per-role statement_timeout is set"
        fi
    else
        C17_SOURCES_UNREADABLE=1
        info "  pg_db_role_setting is not readable by this role - database-level statement_timeout overrides could NOT be checked"
    fi

    # --- what the migrations will actually do ------------------------------
    # The two match counts are the migrations' own predicates, verbatim. They
    # are what the write half of each UPDATE costs, and 162 is NOT implied by
    # 161: 162 never references response_time_ms, so neither predicate entails
    # the other and both are counted rather than one inferred from the other.
    q "audit_logs row count" "SET statement_timeout = 0; SET TimeZone = 'UTC'; SELECT count(*) FROM audit_logs"
    if [[ "$QOK" -eq 1 ]] && is_uint "$Q"; then C17_ROWS="$Q"; else C17_COUNTS_OK=0; fi

    if column_exists "audit_logs" "response_time_ms"; then
        q "core/161 match count" "SET statement_timeout = 0; SET TimeZone = 'UTC'; SELECT count(*) FROM audit_logs WHERE response_time_ms = 0 AND timestamp < NOW()"
        if [[ "$QOK" -eq 1 ]] && is_uint "$Q"; then C17_M161="$Q"; else C17_COUNTS_OK=0; fi
        if psql_exec "SET statement_timeout = 0; SET TimeZone = 'UTC'; EXPLAIN (ANALYZE, TIMING OFF) SELECT count(*) FROM audit_logs WHERE response_time_ms = 0 AND timestamp < NOW()"; then
            _last="${PSQL_OUT##*$'\n'}"
            case "$_last" in
                "Execution Time: "*)
                    _ms="${_last#Execution Time: }"; _ms="${_ms% ms}"
                    if _us="$(ms_to_us "$_ms")"; then
                        C17_MEASURED=1
                        [[ "$_us" -gt "$C17_SCAN_US" ]] && C17_SCAN_US="$_us"
                    fi
                    ;;
            esac
        fi
    else
        info "  audit_logs has no response_time_ms column - core/161 skips itself on this schema."
    fi

    if column_exists "audit_logs" "tokens_used" && column_exists "audit_logs" "cost" \
       && column_exists "audit_logs" "provider" && column_exists "audit_logs" "model"; then
        q "core/162 match count" "SET statement_timeout = 0; SET TimeZone = 'UTC'; SELECT count(*) FROM audit_logs WHERE COALESCE(tokens_used, 0) = 0 AND COALESCE(cost, 0) = 0 AND (tokens_used IS NOT NULL OR cost IS NOT NULL) AND (provider IS NULL OR provider = '') AND (model IS NULL OR model = '') AND timestamp < NOW()"
        if [[ "$QOK" -eq 1 ]] && is_uint "$Q"; then C17_M162="$Q"; else C17_COUNTS_OK=0; fi
        if psql_exec "SET statement_timeout = 0; SET TimeZone = 'UTC'; EXPLAIN (ANALYZE, TIMING OFF) SELECT count(*) FROM audit_logs WHERE COALESCE(tokens_used, 0) = 0 AND COALESCE(cost, 0) = 0 AND (tokens_used IS NOT NULL OR cost IS NOT NULL) AND (provider IS NULL OR provider = '') AND (model IS NULL OR model = '') AND timestamp < NOW()"; then
            _last="${PSQL_OUT##*$'\n'}"
            case "$_last" in
                "Execution Time: "*)
                    _ms="${_last#Execution Time: }"; _ms="${_ms% ms}"
                    if _us="$(ms_to_us "$_ms")"; then
                        C17_MEASURED=1
                        [[ "$_us" -gt "$C17_SCAN_US" ]] && C17_SCAN_US="$_us"
                    fi
                    ;;
            esac
        fi
    else
        info "  audit_logs is missing one of tokens_used/cost/provider/model - core/162 skips itself on this schema."
    fi

    info "  audit_logs holds ${C17_ROWS:-<unmeasured>} row(s)"
    info "  core/161 will rewrite ${C17_M161:-<not applicable on this schema>} row(s)"
    info "  core/162 will rewrite ${C17_M162:-<not applicable on this schema>} row(s)"
    if [[ "$C17_MEASURED" -eq 1 ]]; then
        info "  MEASURED read half, the slower of the two scans: $(fmt_us "$C17_SCAN_US")"
    fi

    # --- verdict ------------------------------------------------------------
    # The FAIL threshold is the one comparison that needs no judgement: the
    # UPDATE cannot possibly finish faster than a measured scan of the same rows
    # under the same predicate, so a timeout at or below that measurement WILL
    # trip. The WARN threshold does carry judgement, and says so: 4x covers the
    # write half, the bloat those row versions leave until autovacuum catches
    # up, and waiting on in-flight transactions. It is a margin, not a
    # measurement, and no arithmetic here can substitute for an actual timed run
    # on a restored copy of a large table.
    _timeout_desc="none"
    _timeout_us=0
    if [[ -n "$C17_TIGHTEST_MS" ]]; then
        _timeout_us=$(( C17_TIGHTEST_MS * 1000 ))
        _timeout_desc="$(fmt_us "$_timeout_us") (from ${C17_TIGHTEST_SRC})"
    fi

    if [[ "$C17_COUNTS_OK" -ne 1 ]]; then
        fail "The core/161 and core/162 sizing did not complete" \
            "At least one count did not execute - see the query-failure list at the end. Sizing a migration window from a partial scan is worse than not sizing it, and an unexecuted count must NOT be read as 'nothing to rewrite'."
    elif [[ -z "$C17_M161" && -z "$C17_M162" ]]; then
        pass "core/161 and core/162 both skip themselves on this schema (the columns they name are absent)"
    elif [[ -z "$C17_TIGHTEST_MS" ]]; then
        info "  No statement_timeout is configured on this connection, on any role, or on any database."
        info "  Postgres will not interrupt either migration. Note the honest limit of that statement:"
        info "  a connection pooler, a proxy or a managed-platform default sitting between the agent and"
        info "  Postgres can impose its own deadline, and this script cannot see one from inside Postgres."
        if [[ "$C17_SOURCES_UNREADABLE" -eq 1 ]]; then
            warn "No statement_timeout was found, but at least one place one could be set was NOT READABLE" \
                "The catalogs naming the per-role or per-database overrides could not be read by this role, so 'none configured' is a statement about the places this script COULD look, not about your deployment. Re-run as a role that can read pg_roles and pg_db_role_setting, or confirm by hand: SELECT setdatabase, setrole, setconfig FROM pg_db_role_setting;"
        else
            pass "No statement_timeout is set anywhere this preflight can see, so core/161 and core/162 cannot be interrupted by one"
        fi
    elif [[ "$C17_MEASURED" -ne 1 ]]; then
        warn "A statement_timeout of ${_timeout_desc} is configured and the scan could NOT be measured" \
            "EXPLAIN did not report an execution time in the shape this script parses, so it has no lower bound to compare the timeout against and makes NO statement about whether core/161 or core/162 will complete inside it. Do not read the absence of a FAIL as an all-clear. Measure it yourself against the counts above: SET statement_timeout = 0; EXPLAIN (ANALYZE, TIMING OFF) SELECT count(*) FROM audit_logs; and size the timeout against a full-table scan plus one row version per rewritten row."
    elif [[ "$_timeout_us" -le "$C17_SCAN_US" ]]; then
        fail "statement_timeout of ${_timeout_desc} is BELOW the measured read half of core/161 / core/162" \
            "The slower of the two scans took $(fmt_us "$C17_SCAN_US") on this database, measured with EXPLAIN (ANALYZE, TIMING OFF) over the migration's own predicate. The UPDATE performs that same scan and then writes a new row version for each of the rows counted above, so it CANNOT finish inside ${_timeout_desc}. The migration runner answers a migration error with a fatal exit, so this is a BOOT LOOP on upgrade and not a skipped step. Raise statement_timeout for the migration role for the duration of the upgrade (ALTER ROLE <migration role> SET statement_timeout = '<value>'; and reset it afterwards), or raise it on the database, and re-run this preflight. If audit_logs is large, take an actual timing on a restored copy rather than extrapolating from this measurement."
    elif [[ "$_timeout_us" -lt $(( C17_SCAN_US * 4 )) ]]; then
        warn "statement_timeout of ${_timeout_desc} leaves little headroom over the measured read half" \
            "The slower of the two scans took $(fmt_us "$C17_SCAN_US"), which is the READ half only. The write half, one new row version per rewritten row, is not measurable from a read-only script, and the migration additionally waits on in-flight transactions. This preflight wants at least 4x the measured read half, i.e. $(fmt_us $(( C17_SCAN_US * 4 ))), before it will call the timeout comfortable. That factor is a stated margin and not a measurement. A migration that trips the timeout is a BOOT LOOP, so raise it for the migration role for the duration of the upgrade, or take an actual timing on a restored copy."
    elif [[ "$C17_SOURCES_UNREADABLE" -eq 1 ]]; then
        warn "The tightest statement_timeout found (${_timeout_desc}) clears the measured scan, but one source was NOT READABLE" \
            "A tighter override could exist in a catalog this role cannot read, so the comparison above is against the tightest value this script COULD see, not necessarily the tightest one that applies. Re-run as a role that can read pg_roles and pg_db_role_setting."
    else
        pass "statement_timeout (${_timeout_desc}) clears the measured read half of core/161 / core/162 ($(fmt_us "$C17_SCAN_US")) with the 4x margin this check asks for"
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 18 - the app-role admin pool on the ORCHESTRATOR and the PORTAL (#3367)
# ---------------------------------------------------------------------------
section "App-role admin pool on the orchestrator and portal (#3367)"

# WHY THIS IS NOT A DUPLICATE OF CHECK 8. Check 8 reads
# AXONFLOW_DB_USE_APP_ROLE and AXONFLOW_DB_PLATFORM_ADMIN_URL off the AGENT and
# nothing else. The env can differ per component, which is the entire reason
# discover_env is per component, and the two components that refuse hardest on
# this pair are the two check 8 never looks at.
#
# WHAT ACTUALLY HAPPENS, READ OFF THE SOURCE RATHER THAN OFF THE RELEASE NOTES.
# With AXONFLOW_DB_USE_APP_ROLE not explicitly false (unset means true since
# v9.0.0) and AXONFLOW_DB_PLATFORM_ADMIN_URL blank:
#
#   orchestrator - platform/orchestrator/run.go calls
#                  RequirePlatformAdminOrFatal("DatabaseDynamicPolicyEngine")
#                  unconditionally inside initializeComponents(), which Run()
#                  calls unconditionally. The process logs a FATAL and exits.
#   portal       - ee/platform/customer-portal/main.go does the same at
#                  RequirePlatformAdminOrFatal("customer-portal"). Same outcome.
#
# So the operator-visible consequence is a component that does not start, which
# is LOUDER and worse than the one the v10 release notes describe for #3367
# (a 500 on the portal Executions list instead of a confident empty page). Both
# are named below, and the wording deliberately does not repeat the release
# notes' "the orchestrator has no fatal boot guard on that variable": that is
# not true of this tree, and a preflight that told an operator their stack would
# boot and merely degrade would be sending them to debug the wrong thing.
#
# The 500 arm is still real and still worth naming, because it is what a
# deployment reaches if a future change relaxes the boot guard, and because the
# release notes will send operators looking for it.
C18_VERDICT_OK=1
for comp in orchestrator portal; do
    component_names "$comp" || continue
    comp_upper="$COMP_UPPER"

    discover_env "$comp" AXONFLOW_DB_USE_APP_ROLE
    c18_role_raw="$DISC_VALUE"; c18_role_state="$DISC_STATE"; c18_role_src="$DISC_SOURCE"
    discover_env "$comp" AXONFLOW_DB_PLATFORM_ADMIN_URL
    c18_url_val="$(trim_ws "$DISC_VALUE")"; c18_url_state="$DISC_STATE"; c18_url_src="$DISC_SOURCE"

    c18_url_via_secret=0
    if [[ -z "$c18_url_val" ]]; then
        ecs_secret_declared "$comp" AXONFLOW_DB_PLATFORM_ADMIN_URL
        if [[ "$ECS_SECRET_DECLARED" -eq 1 ]]; then
            c18_url_via_secret=1
            c18_url_state="set"
            c18_url_src="$ECS_SECRET_SOURCE"
        fi
    fi

    info "  $comp: AXONFLOW_DB_USE_APP_ROLE source: $c18_role_src (state: $c18_role_state)"
    info "  $comp: AXONFLOW_DB_PLATFORM_ADMIN_URL source: $c18_url_src (state: $c18_url_state)"

    # Mirror UseAppRoleEnabled(): unset OR anything truthy is true, and only an
    # explicit false/FALSE/False/0 disables. Keyed the same way as check 8 so
    # the two cannot disagree about what "app role is on" means.
    c18_role_effective="true"
    case "$c18_role_raw" in
        false|FALSE|False|0) c18_role_effective="false" ;;
    esac

    if [[ "$c18_role_state" == "unknown" || "$c18_url_state" == "unknown" ]]; then
        C18_VERDICT_OK=0
        warn "The app-role admin pool on the $comp was NOT VERIFIED" \
            "Nothing readable answered for the $comp, so this check makes NO statement about whether it will start after the upgrade. Do not read the absence of a FAIL as an all-clear. Set AXONFLOW_${comp_upper}_CONTAINER, ${comp_upper}_ENV_FILE, or ECS_CLUSTER plus ECS_${comp_upper}_SERVICE and re-run, or check by hand: docker compose exec ${COMP_DEFAULT_SVC} printenv AXONFLOW_DB_USE_APP_ROLE AXONFLOW_DB_PLATFORM_ADMIN_URL."
        continue
    fi

    if [[ "$c18_role_effective" == "false" ]]; then
        info "  $comp: AXONFLOW_DB_USE_APP_ROLE='$c18_role_raw' - legacy v8.x posture, no admin pool required."
        pass "$comp: app-role posture is legacy, so the admin pool is not required"
    elif [[ -n "$c18_url_val" || "$c18_url_via_secret" -eq 1 ]]; then
        pass "$comp: AXONFLOW_DB_USE_APP_ROLE is on and AXONFLOW_DB_PLATFORM_ADMIN_URL is wired"
    else
        C18_VERDICT_OK=0
        fail "$comp: AXONFLOW_DB_USE_APP_ROLE is on with AXONFLOW_DB_PLATFORM_ADMIN_URL unset" \
            "This component REFUSES TO BOOT under that pair. The orchestrator refuses at RequirePlatformAdminOrFatal('DatabaseDynamicPolicyEngine') in platform/orchestrator/run.go, which initializeComponents() reaches unconditionally; the customer-portal refuses at RequirePlatformAdminOrFatal('customer-portal') in ee/platform/customer-portal/main.go. Both log a FATAL naming the variable and exit, so the container restarts and fails again. Do not expect the message to be identical on every deployment: where the app role itself was never provisioned, a component dies one step EARLIER still, on the app-role DSN's own role assertion ('OpenAppRoleConnection: role assertion failed: expected current_user=\"axonflow_app_role\"'), which is the same misconfiguration reported by whichever guard reaches it first. Note that unset means TRUE for AXONFLOW_DB_USE_APP_ROLE: it has been the default since v9.0.0 and only an explicit false, FALSE, False or 0 turns it off. Second-order consequence, in case a later release relaxes that boot guard: v10.0.0's #3367 makes the portal's org-wide Executions read answer 500 rather than a confident empty page on exactly this pair, because the read would otherwise be filtered to zero rows by the tenant-keyed RLS on execution_history. Remedy, either way: set AXONFLOW_DB_PLATFORM_ADMIN_URL to a DSN authenticating as axonflow_platform_admin, or set AXONFLOW_DB_USE_APP_ROLE=false on this component to run under the legacy v8.x posture. The shipped docker-compose bundle sets it to false."
    fi
done
if [[ "$C18_VERDICT_OK" -eq 1 ]]; then
    info "Both the orchestrator and the portal carry a workable app-role pairing."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 19 - AXONFLOW_DEBUG_POLICIES is removed in v10.0.0 (#3319)
# ---------------------------------------------------------------------------
section "AXONFLOW_DEBUG_POLICIES (removed in v10.0.0)"

# ADVISORY, AND IT NEVER FAILS. The variable only ever controlled the verbose
# logging of the in-memory DynamicPolicyEngine, which v10.0.0 deletes. Setting
# it after the upgrade does nothing at all: no error, no warning, no log line.
# There is no failure to predict, so there is nothing here to FAIL on. What is
# worth telling an operator is that a line in their deployment configuration
# will start implying a behaviour that no longer exists, which is how a stale
# config outlives the person who wrote it.
C19_FOUND=0
C19_UNREADABLE=0
for comp in agent orchestrator; do
    discover_env "$comp" AXONFLOW_DEBUG_POLICIES
    case "$DISC_STATE" in
        set)
            C19_FOUND=1
            info "  $comp: AXONFLOW_DEBUG_POLICIES='$DISC_VALUE' (source: $DISC_SOURCE)" ;;
        empty)
            info "  $comp: AXONFLOW_DEBUG_POLICIES is declared and empty (source: $DISC_SOURCE)" ;;
        absent)
            info "  $comp: AXONFLOW_DEBUG_POLICIES is not declared (source: $DISC_SOURCE)" ;;
        *)
            C19_UNREADABLE=1
            info "  $comp: AXONFLOW_DEBUG_POLICIES could not be read ($DISC_SOURCE)" ;;
    esac
done

if [[ "$C19_FOUND" -eq 1 ]]; then
    warn "AXONFLOW_DEBUG_POLICIES is set, and v10.0.0 removes it" \
        "It only ever controlled the verbose logging of the in-memory DynamicPolicyEngine that #3319 deletes, so after the upgrade it is a no-op: nothing reads it and nothing warns about it. Nothing breaks and nothing needs to be done before upgrading. Remove the line from your deployment configuration afterwards so it stops implying a behaviour the platform no longer has."
elif [[ "$C19_UNREADABLE" -eq 1 ]]; then
    info "  At least one component could not be read. The only consequence either way is a stale"
    info "  configuration line, so this check does not treat that as a finding."
    pass "AXONFLOW_DEBUG_POLICIES advisory emitted (removed in v10.0.0; a set value is a no-op afterwards)"
else
    pass "AXONFLOW_DEBUG_POLICIES is not set on either component"
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 20 - segment-scoped policies and the MCP X-User-Token consequence
# ---------------------------------------------------------------------------
section "Segment-scoped policies in force (#3430 X-User-Token consequence)"

# ADVISORY, in the same honest-scope register as checks 13 to 15. What this can
# see is the POLICY TABLES. What it cannot see, at all, is which callers reach
# this deployment or what credential each of them presents, so it must not claim
# to know whether anybody will actually be refused.
#
# The consequence it reports is real and narrow: on the MCP-server check_policy
# and check_output tools, v10.0.0 makes X-User-Token MANDATORY for any
# organisation that holds an enabled segment-scoped STATIC policy for that
# phase. A caller with no validated per-user token is refused with the
# identifier segment_identity_unresolved instead of being evaluated as though
# no segment restriction existed.
#
# THE WORD "STATIC" ABOVE IS LOAD-BEARING, AND IS WHY THIS CHECK COUNTS THE TWO
# TABLES SEPARATELY. The census that decides the refusal is
# segmentScopedPoliciesInScope -> UnifiedPolicyEngine.HasSegmentScopedPolicies
# -> PolicyLoader.GetPolicies -> loadFromDatabase, whose SQL reads FROM
# static_policies and nothing else. The code says so itself, at
# platform/agent/mcp_identity.go: "this censuses the STATIC engine's policy set
# (static_policies) only ... An org whose ONLY segment-scoped rows are dynamic
# therefore still answers false here and proceeds". So a dynamic_policies row
# with a segment_id is real governance, but it does not make any caller start
# needing a token on this plane, and reporting it as though it did would tell
# an operator to go mint credentials for a requirement that never binds.
# Both counts are still reported, because knowing the dynamic plane has adopted
# segment targeting is useful context; only the static count carries the
# MANDATORY claim.
#
# segment_id arrives on static_policies in core/157 and on dynamic_policies in
# core/159, so a deployment older than those columns cannot hold a
# segment-scoped row at all. That is a genuine "nothing to report", not an
# unmeasured zero, and the column probes distinguish the two.
#
# THE COUNTS BELOW ARE RLS-FILTERED READS, so they carry the same blindness
# guard as checks 3, 9, 23 and 24. Both policy tables carry core/018's
# tenant-isolation policy, and a connection with neither ownership nor
# BYPASSRLS counts 0 on each of them with psql exit 0 and no error - which is
# indistinguishable from an org that has adopted no segment targeting at all.
# Measured on a database holding exactly one enabled segment-scoped row: the
# app-role reported "No enabled segment-scoped policy exists, so the #3430
# X-User-Token requirement binds no caller here" while the BYPASSRLS role on
# the same database at the same instant reported the row. The zero-total arm is
# the only affirmative claim built on the counts, so it is the only one gated;
# a non-zero count is true under every posture, because RLS can hide a row but
# never invent one.
C20_TOTAL=0
C20_STATIC=0
C20_DYNAMIC=0
C20_OK=1
C20_TABLES=0
C20_BLIND_TABLES=""
C20_FAILURES_BEFORE="${#PSQL_FAILURES[@]}"
C20_DETAIL=""

for tname in static_policies dynamic_policies; do
    if ! table_exists "$tname"; then
        info "  $tname is absent on this deployment."
        continue
    fi
    probe_rls "$tname"
    if rls_blocks_all_clear "$RLS_STATE"; then
        C20_BLIND_TABLES="${C20_BLIND_TABLES:+$C20_BLIND_TABLES, }${tname}"
    fi
    if ! column_exists "$tname" "segment_id"; then
        info "  $tname has no segment_id column - this schema predates core/157 / core/159, so no row here can be segment-scoped."
        continue
    fi
    if ! column_exists "$tname" "enabled"; then
        info "  $tname has no enabled column - the in-force subset could not be measured on this schema."
        C20_OK=0
        continue
    fi
    C20_TABLES=$((C20_TABLES + 1))
    q "segment-scoped count($tname)" "SELECT COUNT(*) FROM $tname WHERE segment_id IS NOT NULL AND enabled = true"
    if [[ "$QOK" -ne 1 ]] || ! is_uint "$Q"; then C20_OK=0; continue; fi
    if [[ "$Q" -gt 0 ]]; then
        C20_TOTAL=$((C20_TOTAL + Q))
        # Split BEFORE the ids query below, which overwrites Q with the id list.
        if [[ "$tname" == "static_policies" ]]; then
            C20_STATIC=$((C20_STATIC + Q))
        else
            C20_DYNAMIC=$((C20_DYNAMIC + Q))
        fi
        q "segment-scoped ids($tname)" "SELECT COALESCE(string_agg(policy_id, ', ' ORDER BY policy_id), '') FROM (SELECT policy_id FROM $tname WHERE segment_id IS NOT NULL AND enabled = true ORDER BY policy_id LIMIT 10) s"
        if [[ "$QOK" -eq 1 ]]; then
            C20_DETAIL="${C20_DETAIL:+$C20_DETAIL; }${tname}: ${Q}"
        else
            C20_OK=0
        fi
    fi
done

if [[ "${#PSQL_FAILURES[@]}" -ne "$C20_FAILURES_BEFORE" ]]; then
    C20_OK=0
fi

if [[ "$C20_OK" -ne 1 ]]; then
    fail "The segment-scoped policy scan did not complete" \
        "At least one count did not execute, or a column it needs is absent - see the query-failure list at the end. An unexecuted scan must NOT be read as 'no segment-scoped policies', because that reading is what would tell an operator no caller is about to start needing a per-user token."
elif [[ "$C20_TABLES" -eq 0 ]]; then
    pass "No policy table on this deployment can hold a segment-scoped row (the segment_id columns are absent)"
elif [[ "$C20_TOTAL" -eq 0 && -n "$C20_BLIND_TABLES" ]]; then
    warn "This connection cannot read the policy tables, so 'no segment-scoped policy' is not a measurement" \
        "Row-level security is applied to this connection on: ${C20_BLIND_TABLES} - and each read as ZERO rows, which is what a filtered read and an empty table both look like. Connected as role '${PF_CONN_ROLE:-unknown}' (rolsuper=${PF_CONN_SUPER:-unknown}, rolbypassrls=${PF_CONN_BYPASSRLS:-unknown}). core/018 puts \`org_id = get_current_org_id()\` on these tables and a bare psql never sets \`app.current_org_id\`, so the policy matches nothing. This check exists to tell you whether v10.0.0 makes X-User-Token MANDATORY for callers of the MCP-server check_policy and check_output tools, and on this evidence it cannot: a green all-clear here would be the one reading that stops you minting the per-user tokens those callers are about to need. Re-run as axonflow_platform_admin (the same role the migrations use), or - on a docker-compose bundle - as the database user that OWNS the tables; see 'WHICH DATABASE ROLE TO RUN THIS AS' in this script's header."
elif [[ "$C20_TOTAL" -eq 0 ]]; then
    pass "No enabled segment-scoped policy exists, so the #3430 X-User-Token requirement binds no caller here"
else
    info "  enabled segment-scoped policies: $C20_TOTAL (static_policies: $C20_STATIC, dynamic_policies: $C20_DYNAMIC)"
    info "  first ten policy_id(s) per table: $C20_DETAIL"
    if [[ "$C20_STATIC" -eq 0 ]]; then
        info "  Why this is a pass and not a warning: the MCP-server census that decides the refusal reads"
        info "  static_policies only, so an organisation whose only segment-scoped rows are dynamic answers"
        info "  'no segment-scoped policy' there and proceeds without a per-user token. The dynamic plane has"
        info "  its own segment_id column and its own gate (#3052). Nothing here needs a token minted for it."
        pass "The $C20_DYNAMIC enabled segment-scoped polic(ies) here are all in dynamic_policies, which does not drive the #3430 X-User-Token requirement"
    else
        C20_DYN_NOTE=""
        if [[ "$C20_DYNAMIC" -gt 0 ]]; then
            C20_DYN_NOTE=" Reported for context, and deliberately NOT part of the requirement above: this deployment also holds $C20_DYNAMIC enabled segment-scoped dynamic_policies row(s). Those do not drive this requirement and no caller needs a token on their account. The census behind the refusal reads static_policies only, and the dynamic-policy plane has its own segment_id column and its own gate (#3052); count those rows as segment targeting you have already adopted, not as callers about to be refused."
        fi
        warn "$C20_STATIC enabled segment-scoped static_policies row(s) make X-User-Token MANDATORY on two MCP-server tools" \
            "As of v10.0.0 the MCP-server check_policy and check_output tools resolve the caller's governance segments before evaluating, and an organisation holding an enabled segment-scoped policy in static_policies for that phase refuses a caller with no validated per-user token. The refusal is an HTTP 200 JSON-RPC result carrying allowed=false with the stable identifier segment_identity_unresolved in blocked_by; match on that identifier, never on the human-readable reason, whose punctuation differs between planes (#3465). X-User-Email is explicitly refused as a substitute, even under AXONFLOW_TRUST_IDENTITY_HEADERS, and a token naming a shared synthetic identity is refused too. Mint per-user tokens for the callers that use those tools before upgrading. Honest scope: this preflight reads your POLICY TABLES. It cannot see which callers reach this deployment or what credential any of them presents, so it cannot tell you whether anybody will actually be refused, only that the requirement now has something to bind to. It also says nothing about the separate, UNCONDITIONAL segment_resolution_failed refusal, which denies a token-bearing caller whenever segment resolution errors, whether or not any segment-scoped policy exists.${C20_DYN_NOTE}"
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 21 - the two seeded risk policies begin evaluating (#3321, core/160)
# ---------------------------------------------------------------------------
section "Seeded risk policies begin evaluating (#3321, migration core/160)"

# Until v10.0.0 the database-backed engine had no computed risk score to read,
# so a bare risk_score condition silently fell back to reading
# context.risk_score out of the caller's own request body. Two seeded, enabled
# policies have therefore been unable to fire on a real signal since January.
# v10.0.0 computes risk_score from the request itself, so both start evaluating.
#
# NEITHER NEWLY BLOCKS: sys_dyn_high_risk_block was downgraded to warn by
# migration core/036 and sys_dyn_anomalous_access has always been alert, and
# both are allow-but-annotate. The thing an operator has to decide is whether
# the thresholds still mean what they meant when nothing could reach them.
#
# The conditions are DUMPED rather than described. The release notes summarise
# sys_dyn_anomalous_access as "risk_score > 0.6", and the seeded row carries a
# SECOND condition alongside it, so a description would be a paraphrase of a
# paraphrase. Printing the row's own JSON is the only version that cannot drift.
if ! table_exists "dynamic_policies"; then
    info "dynamic_policies is absent on this deployment - nothing seeded here to re-evaluate."
    pass "No dynamic_policies table, so #3321 changes nothing here"
else
    # The same blindness guard as checks 3, 9, 20, 23 and 24, for the same
    # reason. dynamic_policies carries core/018's tenant-isolation policy, so a
    # connection with neither ownership nor BYPASSRLS reads every row below as
    # `<absent>` and reports "Neither seeded risk policy is enabled here".
    # Measured on a database where both rows are enabled: the app-role reported
    # exactly that, while the BYPASSRLS role on the same database at the same
    # instant warned about both. That pass is the reading which suppresses the
    # threshold review this check's own WARN asks the operator to do, so it is
    # gated; the WARN arm is not, because RLS can hide a seeded row but never
    # invent one.
    C21_OK=1
    C21_ENABLED=0
    C21_BLIND=0
    probe_rls dynamic_policies
    if rls_blocks_all_clear "$RLS_STATE"; then C21_BLIND=1; fi
    C21_FAILURES_BEFORE="${#PSQL_FAILURES[@]}"
    for pid in sys_dyn_high_risk_block sys_dyn_anomalous_access; do
        q "seeded policy($pid)" "SELECT COALESCE(string_agg('enabled=' || COALESCE(enabled::text, '?') || ' actions=' || COALESCE(actions::text, '?') || ' conditions=' || COALESCE(conditions::text, '?'), ' | '), '<absent>') FROM dynamic_policies WHERE policy_id = '$pid'"
        if [[ "$QOK" -ne 1 ]]; then C21_OK=0; continue; fi
        info "  $pid: $Q"
        case "$Q" in
            *"enabled=true"*) C21_ENABLED=$((C21_ENABLED + 1)) ;;
        esac
    done

    # core/160's delete preview. high_risk_block is the 2025 duplicate that
    # migration 036's block-to-warn downgrade never touched, so on a deployment
    # that still carries it, it is the one row that WOULD have started blocking
    # production traffic on upgrade beside its tuned twin.
    q "core/160 delete preview" "SELECT COUNT(*) FROM dynamic_policies WHERE policy_id = 'high_risk_block'"
    if [[ "$QOK" -ne 1 ]] || ! is_uint "$Q"; then
        C21_OK=0
        C21_DUP=""
    else
        C21_DUP="$Q"
    fi

    if [[ "${#PSQL_FAILURES[@]}" -ne "$C21_FAILURES_BEFORE" ]]; then C21_OK=0; fi

    if [[ "$C21_OK" -ne 1 ]]; then
        fail "The seeded risk-policy report did not complete" \
            "At least one read did not execute - see the query-failure list at the end. An unexecuted read must NOT be presented as 'these policies are absent', because that reading would suppress the one review this release asks an operator to do."
    else
        if [[ "$C21_DUP" != "0" ]]; then
            info "  high_risk_block: $C21_DUP row(s) present - migration core/160 DELETES these."
        else
            info "  high_risk_block: absent - migration core/160 has nothing to delete here."
        fi
        if [[ "$C21_ENABLED" -gt 0 ]]; then
            warn "$C21_ENABLED seeded risk polic(ies) start evaluating on a real signal in v10.0.0" \
                "Their conditions are printed above, read from your own rows rather than paraphrased. Since January the engine read risk_score out of the caller's request body instead of computing it, so these rows have been unable to fire; v10.0.0 computes it from the request. Neither newly BLOCKS: sys_dyn_high_risk_block was downgraded to warn by migration core/036 and sys_dyn_anomalous_access is alert, and both are allow-but-annotate. Review the thresholds against the new weights before rolling out: an SQL-injection pattern contributes +0.9, a word-boundary-anchored sensitive-data keyword +0.7, and a 'select *' query +0.3, and role no longer contributes at all. If high_risk_block is listed above as present, migration core/160 deletes it, which is deliberate: it is the never-tuned 2025 duplicate that migration core/036's downgrade did not touch, and with a computed risk_score it would have started BLOCKING production traffic beside its tuned twin. The threshold each policy enforces lives in its own conditions JSON and is tunable through the policy API and the portal, NOT in the dynamic_policies.risk_threshold column both rows also carry, which this codebase reads nowhere."
        elif [[ "$C21_BLIND" -eq 1 ]]; then
            warn "This connection cannot read dynamic_policies, so 'neither policy is enabled' is not a measurement" \
                "Row-level security is applied to this connection on dynamic_policies, and it read as ZERO rows - which is why both seeded policies are reported as <absent> above. A filtered read and an absent row are the same result: psql exits 0 and reports nothing either way. Connected as role '${PF_CONN_ROLE:-unknown}' (rolsuper=${PF_CONN_SUPER:-unknown}, rolbypassrls=${PF_CONN_BYPASSRLS:-unknown}). core/018 puts \`org_id = get_current_org_id()\` on this table and a bare psql never sets \`app.current_org_id\`, so the policy matches nothing. Taking this as an all-clear is what would skip the threshold review this release asks for, and it would also hide whether migration core/160 has a high_risk_block row to delete here. Re-run as axonflow_platform_admin (the same role the migrations use), or - on a docker-compose bundle - as the database user that OWNS the tables; see 'WHICH DATABASE ROLE TO RUN THIS AS' in this script's header."
        else
            pass "Neither seeded risk policy is enabled here, so #3321's computed risk_score changes no verdict"
        fi
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 22 - the plane="memory" metric label is retired (#3319)
# ---------------------------------------------------------------------------
section "Retired metric label plane=\"memory\" (#3319)"

# THIS CHECK HAS NO FAIL BRANCH AND NO WARN BRANCH, DELIBERATELY, and the reason
# is stronger than check 12's. Check 12 reports a posture change it can at least
# read out of the deployment. This one describes something that lives entirely
# in Prometheus, Grafana, or whatever else scrapes this deployment. This script
# talks to Postgres and to a container's environment. It has never seen a
# recording rule, a dashboard panel or an alert, and it never will.
#
# So it prints prose, and it prints who it is for. Inventing a WARN here would
# make a green run mean less everywhere else in this file, because the operator
# would reasonably read it as "my dashboards were checked".
info "  v10.0.0 deletes the in-memory DynamicPolicyEngine (#3319), and with it the"
info "  plane=\"memory\" label value of axonflow_policy_condition_unevaluable_total."
info "  The remaining values, database / mcp / policy_test, are unchanged."
info ""
info "  WHO THIS AFFECTS: anything that MATCHES on that label value rather than"
info "  aggregating over the label. A recording rule, dashboard panel or alert"
info "  written as ...{plane=\"memory\"} goes permanently empty after the upgrade."
info "  A panel that sums over plane, or groups by it, simply loses one series."
info "  An alert on an empty series does not fire, so this fails quiet."
info ""
info "  HONEST SCOPE: this preflight cannot see your Prometheus, your recording"
info "  rules or your Grafana. It has not checked anything here and is not"
info "  reporting a result about your monitoring. Grep your own dashboards and"
info "  rules for plane=\"memory\" before upgrading."
pass "plane=\"memory\" retirement advisory emitted (this check inspects nothing; see its note above)"
printf "\n"

# ---------------------------------------------------------------------------
# Check 23 - per-tenant policy targeting is dropped (#3490, Decision 5)
# ---------------------------------------------------------------------------
section "Per-tenant policy targeting is dropped (#3490, new in v10.0.0)"

# WHAT CHANGES. Before v10.0.0 a policy row was selected by tenant_id, and
# tenant_id is the Basic-auth USERNAME the client types - platform's own auth
# code assigns it with the comment "From Basic auth username", and nothing
# validates it. So the set of policies governing a caller was a set the caller
# chose: measured on a live stack, one licence and three usernames selected
# three different policy sets, and a username that named no policy was governed
# by no tenant-tier policy at all. v10.0.0 selects on org_id instead, which
# comes from the signed licence payload.
#
# WHY THIS CHECK EXISTS. For the overwhelming majority of deployments - one
# tenant per organisation - this is a functional no-op, and the check says so
# and passes. It is the deployments where ONE ORGANISATION OWNS SEVERAL TENANTS
# with DIFFERENT policy rows that change behaviour, and only the database can
# say whether this is one of them.
#
# WHAT IT MEASURES, IN TWO PARTS, BECAUSE THE TWO HAVE OPPOSITE DIRECTIONS.
#
#   Part A - tenant-tier POLICY rows. After the upgrade a policy authored for
#   one tenant applies to every tenant in the same organisation. The direction
#   is over-blocking: a restriction applies more broadly. Nothing stops being
#   enforced. This is reported as a WARNING, never a FAIL, because the safe
#   direction is still a direction an operator must consent to.
#
#   Part B - tenant-scoped policy_overrides rows. These are reported for
#   AWARENESS, not for action, and the distinction matters: overrides are NOT
#   made organisation-wide by v10.0.0. An override can downgrade an action
#   (block -> warn) or disable a policy outright, so applying one across an
#   organisation is the only part of this change that could loosen enforcement
#   - which is exactly why it is the one part that was not made org-wide.
#   Override selection still narrows to the caller's own tenant plus the
#   organisation's own rows. They are listed here because an operator changing
#   how tenancy works wants to know which of their overrides diverge per
#   tenant, not because anything about those rows changes on upgrade.
#
#   Do NOT tell an operator to revoke them for this upgrade's sake. An earlier
#   revision of this check did, and an operator who followed it would have
#   revoked a deliberate block -> warn downgrade and put a production workload
#   into hard block for no reason at all.
#
# HONEST SCOPE. This reads your policy tables. It cannot tell you whether the
# divergence was deliberate (two tenants that genuinely want different rules,
# which is the case that needs re-authoring) or incidental (rows that happen to
# carry different tenant_ids but express the same intent, which needs nothing).
# It names the rows so you can decide; it does not decide for you.
C23_OK=1
C23_POLICY_ORGS=0
C23_OVERRIDE_ORGS=0
C23_TABLES=0
C23_POLICY_DETAIL=""
C23_OVERRIDE_DETAIL=""
C23_UNDERCOVERED=0
C23_UNDERCOVERED_DETAIL=""
C23_ORGWIDE_OVERRIDES=0
C23_TENANTS_BLIND=0
C23_BLIND_TABLES=""
C23_FILTERED_TABLES=""
C23_FAILURES_BEFORE="${#PSQL_FAILURES[@]}"

# CAN THIS CONNECTION SEE THE POLICY TABLES AT ALL? (#3490 R3)
#
# THIS IS THE FIRST QUESTION, NOT A FOOTNOTE, AND THE EARLIER REVISION OF THIS
# CHECK GOT IT HALF RIGHT IN THE MOST EXPENSIVE WAY.
#
# That revision knew `tenants` was FORCE row-level security and guarded for it.
# But the guard keyed ONLY on `tenants`, and it corroborated the zero by reading
# tenant_ids off `static_policies` and `dynamic_policies` - which carry
# core/018's `tenant_isolation_select` policy, `org_id = get_current_org_id()`,
# never true while `app.current_org_id` is unset, which a bare psql never sets.
# So on the platform's DEFAULT deployment shape the corroborating read came back
# through the same blindfold, returned 0, and the guard concluded there was
# nothing to guard. A BLIND CONNECTION IS INVISIBLE TO A BLINDNESS PROBE THAT
# READS THROUGH THE SAME BLINDFOLD.
#
# Measured, not reasoned about. On a database built from migrations/core with
# 103 static_policies rows and 3 tenants, connected as a non-superuser,
# non-BYPASSRLS role shaped like `axonflow_app_role`: every one of those tables
# read as 0 rows, psql exited 0, nothing was logged, and checks 23 and 24 both
# printed a green PASS - "a no-op on this deployment" - about a database that
# the very same instant reported, read with BYPASSRLS, one under-covered
# organisation and one policy row about to be stamped __axonflow_unowned__.
#
# That role is not an exotic configuration. AXONFLOW_DB_USE_APP_ROLE defaults to
# enabled (check 19 says so), it has since v9.0.0, and until this revision this
# script's own usage header told the operator to connect as `axonflow`.
#
# THE DISCRIMINATOR MUST COME FROM pg_catalog, which RLS does not filter:
# row_security_active(). See rls_verdict() for the full argument. The policy
# tables are the PRIMARY inputs - every count in this check comes from them - so
# a blind read of any of them forbids an affirmative pass outright.
#
# `tenants` is deliberately NOT in that set and keeps its own corroborated arm
# below. It is FORCE row-level security, so it reads empty even for the table
# OWNER - which is exactly the docker-compose bundle's posture, where the policy
# tables ARE fully visible because they are ENABLE-only and the owner bypasses
# them. Folding `tenants` into the primary set would fire this warning on every
# clean compose install, i.e. would trade a false all-clear for a false alarm on
# the one deployment shape that was already answering correctly.
for tname in static_policies dynamic_policies policy_overrides; do
    if ! table_exists "$tname"; then continue; fi
    probe_rls "$tname"
    if rls_blocks_all_clear "$RLS_STATE"; then
        C23_BLIND_TABLES="${C23_BLIND_TABLES:+$C23_BLIND_TABLES, }${tname}"
    elif [[ "$RLS_STATE" == "filtered" ]]; then
        C23_FILTERED_TABLES="${C23_FILTERED_TABLES:+$C23_FILTERED_TABLES, }${tname}"
    fi
done

# CAN THIS CONNECTION SEE THE tenants TABLE AT ALL?
#
# The org resolution below reads `tenants`, and `tenants` is not like the policy
# tables. core/103 runs ALTER TABLE tenants FORCE ROW LEVEL SECURITY, so RLS
# applies to the table OWNER too, and the policy is
# org_id = current_setting('app.current_org_id', true). This script connects
# with a bare psql and never sets that GUC, so the setting is NULL, the policy
# matches nothing, and every read of `tenants` returns zero rows WITHOUT
# erroring. The policy tables are ENABLE-only - static_policies and
# dynamic_policies from core/018_row_level_security.sql:35,62 (the table is
# named in the array at :35 and the ENABLE is issued at :62), policy_overrides
# from core/030_policy_tier_columns.sql:103 - so the table OWNER reads them
# normally, which is what makes this so easy to miss on a compose install: the
# check appears to work. (An earlier revision credited this posture to
# core/010 and core/110. Those two migrations add the org_id COLUMN, which is
# what the loop below probes for; neither contains a row-level-security
# statement at all - `grep -c "ROW LEVEL SECURITY" core/010_policy_tables.sql`
# is 0. A reader following the citation to core/010 to check the posture would
# have found nothing and had no way to tell whether the claim or their reading
# was wrong.)
#
# Migration 165 itself runs as axonflow_platform_admin, which is BYPASSRLS, so
# the migration DOES see the mapping this connection cannot. A silent zero here
# would therefore mean the preflight tells the operator "no-op" about precisely
# the deployment where the migration is about to resolve two tenants to one org.
#
# Measured, not assumed: a zero from `tenants` alongside non-global tenant_ids
# on the policy tables is the signature, and it is reported rather than
# swallowed. It is not a FAIL - a deployment can legitimately have an empty
# tenants table - but it downgrades every affirmative all-clear below to a
# qualified one, because an all-clear that cannot see its own inputs is worse
# than no answer.
if table_exists "tenants" && column_exists "tenants" "org_id"; then
    q "tenants visible" "SELECT COUNT(*) FROM tenants"
    if [[ "$QOK" -eq 1 ]] && is_uint "$Q"; then
        C23_TENANTS_SEEN="$Q"
        if [[ "$C23_TENANTS_SEEN" -eq 0 ]]; then
            q "policy tenants referenced" "SELECT COUNT(*) FROM (
                 SELECT tenant_id FROM static_policies
                  WHERE COALESCE(btrim(tenant_id), '') NOT IN ('', 'global') AND deleted_at IS NULL
                 UNION
                 SELECT tenant_id FROM dynamic_policies
                  WHERE COALESCE(btrim(tenant_id), '') NOT IN ('', 'global') AND deleted_at IS NULL) u"
            if [[ "$QOK" -eq 1 ]] && is_uint "$Q" && [[ "$Q" -gt 0 ]]; then
                C23_TENANTS_BLIND=1
            fi
        fi
    else
        C23_OK=0
    fi
fi

# The org_id column arrives on the policy tables in core/010 (static/dynamic)
# and core/110 (overrides). A schema without it cannot express the divergence
# this check looks for, which is a genuine "nothing to report" rather than an
# unmeasured zero - and the column probes are what distinguish the two.
for tname in static_policies dynamic_policies; do
    if ! table_exists "$tname"; then
        info "  $tname is absent on this deployment."
        continue
    fi
    if ! column_exists "$tname" "org_id" || ! column_exists "$tname" "tenant_id"; then
        info "  $tname lacks org_id or tenant_id on this schema - the divergence cannot be expressed here."
        continue
    fi
    C23_TABLES=$((C23_TABLES + 1))

    # An organisation "diverges" when its tenant-tier rows carry more than one
    # DISTINCT tenant_id. One tenant per org, however many rows, is the no-op
    # case. The 'global' sentinel is excluded on both keys: those rows already
    # apply to everyone and always did, so counting them would report every
    # deployment as divergent.
    #
    # THE org_id EXPRESSION IS COALESCE'D THROUGH THE MIGRATION'S OWN
    # RESOLUTION, and an earlier revision of this check was wrong for exactly
    # that reason. It required org_id IS NOT NULL, so a legacy row carrying a
    # tenant but NO org was invisible here - and those are precisely the rows
    # migration 165 steps 3 and 4 resolve, by the tenants mapping or by the
    # org_id == tenant_id collapse. A deployment whose divergence lives
    # entirely in such rows was told, affirmatively, that dropping per-tenant
    # targeting was "a no-op on this deployment", and then had those rows
    # applied org-wide on upgrade. Grouping on the RESOLVED key is what makes
    # this check answer the question an operator is actually asking.
    #
    # deleted_at is excluded because the loader excludes it: a soft-deleted row
    # is not going to start applying to anybody, and warning about one sends an
    # operator to re-author a row that does not exist.
    q "divergent orgs($tname)" "SELECT COUNT(*) FROM (
         SELECT COALESCE(NULLIF(btrim(COALESCE(org_id, '')), ''), (SELECT t.org_id FROM tenants t WHERE t.tenant_id = p.tenant_id AND COALESCE(btrim(t.org_id),'') <> '' LIMIT 1), p.tenant_id) AS resolved_org FROM $tname p
          WHERE p.enabled = true
            AND p.deleted_at IS NULL
            AND COALESCE(p.tenant_id, '') <> 'global'
            AND COALESCE(btrim(p.tenant_id), '') <> ''
            AND COALESCE(btrim(p.org_id), '') <> 'global'
          GROUP BY 1 HAVING COUNT(DISTINCT p.tenant_id) > 1) d"
    if [[ "$QOK" -ne 1 ]] || ! is_uint "$Q"; then C23_OK=0; continue; fi
    # q() overwrites $Q, and the queries below call it several times before the
    # divergent-org count is consumed. Captured here so the arm that reports it
    # cannot end up reading some later query's answer instead.
    C23_DIVERGENT="$Q"

    # THE SECOND SHAPE, AND THE COMMONER ONE.
    #
    # The count above asks "does this organisation target more than one tenant",
    # which measures divergence AMONG POLICY ROWS. It cannot see the shape that
    # is far more likely in practice: an organisation with three tenants and
    # ONE policy row scoped to `prod`. That is a single distinct tenant_id, so
    # the query above does not count it - and after the upgrade that rule
    # governs `staging` and `dev` as well, which is exactly the widening this
    # check exists to surface. Reporting it as a no-op would be worse than not
    # running the check.
    #
    # The answer needs the tenants table, so it is only asked when this
    # connection can actually read it (see C23_TENANTS_BLIND above). An
    # organisation with a single tenant is excluded: there is nothing to widen
    # onto.
    if [[ "$C23_TENANTS_BLIND" -eq 0 ]] && table_exists "tenants" && column_exists "tenants" "org_id"; then
        q "under-covered orgs($tname)" "SELECT COUNT(*) FROM (
             SELECT r.resolved_org
               FROM (SELECT COALESCE(NULLIF(btrim(COALESCE(org_id, '')), ''), (SELECT t.org_id FROM tenants t WHERE t.tenant_id = p.tenant_id AND COALESCE(btrim(t.org_id),'') <> '' LIMIT 1), p.tenant_id) AS resolved_org,
                            p.tenant_id
                       FROM $tname p
                      WHERE p.enabled = true
                        AND p.deleted_at IS NULL
                        AND COALESCE(p.tenant_id, '') <> 'global'
                        AND COALESCE(btrim(p.tenant_id), '') <> ''
                        AND COALESCE(btrim(p.org_id), '') <> 'global') r
              GROUP BY r.resolved_org
             HAVING COUNT(DISTINCT r.tenant_id) <
                    (SELECT COUNT(*) FROM tenants t2 WHERE t2.org_id = r.resolved_org)) d"
        if [[ "$QOK" -eq 1 ]] && is_uint "$Q" && [[ "$Q" -gt 0 ]]; then
            C23_UNDERCOVERED=$((C23_UNDERCOVERED + Q))
            q "under-covered names($tname)" "SELECT COALESCE(string_agg(line, '; ' ORDER BY line), '') FROM (
                 SELECT r.resolved_org || ' (policy targets ' || COUNT(DISTINCT r.tenant_id)::text || ' of ' ||
                        (SELECT COUNT(*) FROM tenants t2 WHERE t2.org_id = r.resolved_org)::text || ' tenants)' AS line
                   FROM (SELECT COALESCE(NULLIF(btrim(COALESCE(org_id, '')), ''), (SELECT t.org_id FROM tenants t WHERE t.tenant_id = p.tenant_id AND COALESCE(btrim(t.org_id),'') <> '' LIMIT 1), p.tenant_id) AS resolved_org,
                                p.tenant_id
                           FROM $tname p
                          WHERE p.enabled = true
                            AND p.deleted_at IS NULL
                            AND COALESCE(p.tenant_id, '') <> 'global'
                            AND COALESCE(btrim(p.tenant_id), '') <> ''
                            AND COALESCE(btrim(p.org_id), '') <> 'global') r
                  GROUP BY r.resolved_org
                 HAVING COUNT(DISTINCT r.tenant_id) <
                        (SELECT COUNT(*) FROM tenants t2 WHERE t2.org_id = r.resolved_org)
                  LIMIT 25) x"
            if [[ "$QOK" -eq 1 ]]; then
                C23_UNDERCOVERED_DETAIL="${C23_UNDERCOVERED_DETAIL:+$C23_UNDERCOVERED_DETAIL | }${tname} -> ${Q}"
            else
                C23_OK=0
            fi
        elif [[ "$QOK" -ne 1 ]]; then
            C23_OK=0
        fi
    fi

    if [[ "$C23_DIVERGENT" -gt 0 ]]; then
        C23_POLICY_ORGS=$((C23_POLICY_ORGS + C23_DIVERGENT))
        # BY NAME, not by count. An operator cannot re-author a number.
        q "divergent policy names($tname)" "SELECT COALESCE(string_agg(line, '; ' ORDER BY line), '') FROM (
             SELECT COALESCE(NULLIF(btrim(COALESCE(org_id, '')), ''), (SELECT t.org_id FROM tenants t WHERE t.tenant_id = p.tenant_id AND COALESCE(btrim(t.org_id),'') <> '' LIMIT 1), p.tenant_id) || ' / ' || p.tenant_id || ' / ' || p.policy_id AS line
               FROM $tname p
               JOIN (SELECT COALESCE(NULLIF(btrim(COALESCE(org_id, '')), ''), (SELECT t.org_id FROM tenants t WHERE t.tenant_id = x.tenant_id AND COALESCE(btrim(t.org_id),'') <> '' LIMIT 1), x.tenant_id) AS resolved_org FROM $tname x
                      WHERE x.enabled = true
                        AND x.deleted_at IS NULL
                        AND COALESCE(x.tenant_id, '') <> 'global'
                        AND COALESCE(btrim(x.tenant_id), '') <> ''
                        AND COALESCE(btrim(x.org_id), '') <> 'global'
                      GROUP BY 1 HAVING COUNT(DISTINCT x.tenant_id) > 1) d
                 ON d.resolved_org = COALESCE(NULLIF(btrim(COALESCE(org_id, '')), ''), (SELECT t.org_id FROM tenants t WHERE t.tenant_id = p.tenant_id AND COALESCE(btrim(t.org_id),'') <> '' LIMIT 1), p.tenant_id)
              WHERE p.enabled = true AND p.deleted_at IS NULL
                AND COALESCE(btrim(p.tenant_id), '') <> '' AND p.tenant_id <> 'global'
              ORDER BY line LIMIT 25) s"
        if [[ "$QOK" -eq 1 ]]; then
            C23_POLICY_DETAIL="${C23_POLICY_DETAIL:+$C23_POLICY_DETAIL | }${tname} -> ${Q}"
        else
            C23_OK=0
        fi
    fi
done

# Part B. policy_overrides is Enterprise-only, so its absence is normal and is
# not a gap in the measurement.
if table_exists "policy_overrides" && column_exists "policy_overrides" "org_id" && column_exists "policy_overrides" "tenant_id"; then
    # revoked_at is excluded because the enforcement read excludes it. Without
    # this the check warns about an override the operator has ALREADY disposed
    # of in the way the upgrade guide recommends - remediation that does not
    # clear the warning teaches an operator to ignore the warning.
    # ORG-SCOPED OVERRIDE ROWS (tenant_id IS NULL) ARE A SEPARATE, SMALLER
    # THING, AND THEY ARE THE ONE PART OF THE OVERRIDE STORY THAT LOOSENS.
    #
    # Before v10.0.0 the enforcement plane's org leg read
    # `organization_id::text = $2`, and the agent passed that argument as a
    # literal nil (run.go), so it was empty and the leg could not match: an
    # override authored with no tenant was INERT on that path. It is keyed on
    # org_id now and it applies. That is the correct reading of a row whose
    # author left the tenant NULL - it is an organisation-wide grant by
    # construction - but an override downgrades or disables, so a row moving
    # from never-applied to always-applied loosens enforcement, and an operator
    # is entitled to see it before pulling the image rather than after.
    #
    # Both shipped writers set tenant_id, so in practice this finds
    # hand-inserted or pre-v9 rows and usually nothing at all. Counted anyway:
    # "usually nothing" is a prediction, and this is a measurement.
    #
    # IT MUST RESOLVE org_id THE WAY core/165 DOES, OR IT CANNOT SEE ITS OWN
    # STATED TARGET POPULATION. An earlier revision required org_id to be
    # already populated - and this is a PRE-upgrade check, run against a
    # database where core/165 has NOT yet populated org_id for legacy rows.
    #
    # The shape it missed is not hypothetical, it is the LEGAL one. core/030's
    # `valid_override_scope` CHECK is
    #   (organization_id IS NOT NULL AND tenant_id IS NULL) OR (tenant_id IS NOT NULL)
    # so a tenant-less override is permitted precisely when the LEGACY
    # `organization_id` is set - the column this count never consulted. A row
    # with organization_id=1, tenant_id=NULL, org_id=NULL was reported as 0
    # here; core/165 step 5 then resolves it through `organizations` to a real
    # org_id and org-keyed selection applies it across the organisation. The
    # comment two paragraphs up says this count exists to find "hand-inserted
    # or pre-v9 rows", which is exactly the population that carries the legacy
    # column and not the new one.
    #
    # Check 24 already implements this same step-5 lookup (C24_PRED_OVERRIDES)
    # for the same reason. The two now agree, which they must: they are reading
    # one migration's one resolution chain.
    #
    # WHAT THIS COUNT STILL CANNOT SEE, STATED BECAUSE IT IS A REAL POPULATION
    # AND NOT A ROUNDING ERROR. Step 5 joins organizations.id::text against
    # policy_overrides.organization_id::text, and those two were never the same
    # kind of value: organizations.id is SERIAL, an integer, since core/002:10,
    # while organization_id was declared UUID in core/030:80 and stayed UUID
    # until core/133 retyped it to text. An integer's text form can never equal
    # a UUID's, so step 5 resolves ONLY integer-shaped legacy values - the ones
    # that became representable after core/133 - and a UUID-shaped one falls
    # straight through it.
    #
    # So this count is complete for rows core/165 will RESOLVE and silent about
    # rows it will NOT. That is the safe division of labour rather than a gap:
    # a UUID-shaped legacy value resolves to no organisation, so the row is
    # stamped __axonflow_unowned__ and reported by CHECK 24 instead - as a row
    # that stops firing, which is what it will do. The two checks partition the
    # population between them; neither silently drops it.
    C23_ORGWIDE_RESOLVED="COALESCE(btrim(po.org_id), '') NOT IN ('', 'global')"
    if column_exists policy_overrides organization_id && table_exists organizations; then
        C23_ORGWIDE_RESOLVED="($C23_ORGWIDE_RESOLVED OR EXISTS (
             SELECT 1 FROM organizations o
              WHERE o.id::text = po.organization_id::text
                AND COALESCE(btrim(o.org_id), '') NOT IN ('', 'global')))"
    fi
    q "org-scoped overrides" "SELECT COUNT(*) FROM policy_overrides po
         WHERE po.tenant_id IS NULL
           AND $C23_ORGWIDE_RESOLVED
           AND (po.expires_at IS NULL OR po.expires_at > NOW())
           AND po.revoked_at IS NULL"
    if [[ "$QOK" -eq 1 ]] && is_uint "$Q"; then
        C23_ORGWIDE_OVERRIDES="$Q"
    else
        C23_OK=0
    fi

    q "divergent override orgs" "SELECT COUNT(*) FROM (
         SELECT COALESCE(NULLIF(btrim(COALESCE(org_id, '')), ''), tenant_id) AS resolved_org
           FROM policy_overrides
          WHERE COALESCE(btrim(org_id), '') <> 'global'
            AND COALESCE(btrim(tenant_id), '') <> '' AND tenant_id <> 'global'
            AND (expires_at IS NULL OR expires_at > NOW())
            AND revoked_at IS NULL
          GROUP BY 1 HAVING COUNT(DISTINCT tenant_id) > 1) d"
    if [[ "$QOK" -eq 1 ]] && is_uint "$Q"; then
        C23_OVERRIDE_ORGS="$Q"
        if [[ "$Q" -gt 0 ]]; then
            q "divergent override detail" "SELECT COALESCE(string_agg(line, '; ' ORDER BY line), '') FROM (
                 SELECT COALESCE(NULLIF(btrim(COALESCE(o.org_id, '')), ''), o.tenant_id) || ' / ' || o.tenant_id
                        || ' / ' || COALESCE(o.action_override, '(no action)')
                        || ' / ' || translate(COALESCE(o.override_reason, '(no reason)'), E'\n\r', '  ') AS line
                   FROM policy_overrides o
                   JOIN (SELECT COALESCE(NULLIF(btrim(COALESCE(org_id, '')), ''), tenant_id) AS resolved_org
                           FROM policy_overrides
                          WHERE COALESCE(btrim(org_id), '') <> 'global'
                            AND COALESCE(btrim(tenant_id), '') <> '' AND tenant_id <> 'global'
                            AND (expires_at IS NULL OR expires_at > NOW())
                            AND revoked_at IS NULL
                          GROUP BY 1 HAVING COUNT(DISTINCT tenant_id) > 1) d
                     ON d.resolved_org = COALESCE(NULLIF(btrim(COALESCE(o.org_id, '')), ''), o.tenant_id)
                  WHERE COALESCE(btrim(o.tenant_id), '') <> '' AND o.tenant_id <> 'global'
                    AND (o.expires_at IS NULL OR o.expires_at > NOW())
                    AND o.revoked_at IS NULL
                  ORDER BY line LIMIT 25) s"
            if [[ "$QOK" -eq 1 ]]; then
                C23_OVERRIDE_DETAIL="$Q"
            else
                C23_OK=0
            fi
        fi
    else
        C23_OK=0
    fi
else
    info "  policy_overrides is absent or lacks its tenancy columns (Enterprise-only table) - the override half is not applicable here."
fi

if [[ "${#PSQL_FAILURES[@]}" -ne "$C23_FAILURES_BEFORE" ]]; then
    C23_OK=0
fi

C23_FILTER_NOTE=""
if [[ -n "$C23_FILTERED_TABLES" ]]; then
    C23_FILTER_NOTE=" Note also that row-level security IS applied to this connection on: ${C23_FILTERED_TABLES}. Rows were visible there, so the findings above are real, but the counts may be PARTIAL - rows outside the org this connection resolves to are filtered out of them."
fi

if [[ "$C23_OK" -ne 1 ]]; then
    fail "The per-tenant policy divergence scan did not complete" \
        "At least one count did not execute - see the query-failure list at the end. An unexecuted scan must NOT be read as 'no divergence', because that reading is exactly what would let a per-tenant override start applying org-wide without anyone seeing it."
elif [[ -n "$C23_BLIND_TABLES" ]]; then
    # THE PRIMARY INPUTS WERE UNREADABLE. This arm outranks every affirmative
    # result below it, including the "no policy table can express this" pass:
    # that pass is derived from pg_catalog column probes, which are NOT
    # RLS-filtered, so it can be reached with a true column list and a set of
    # counts that are all zero for the wrong reason.
    #
    # It is a WARN and not a FAIL on purpose. Nothing is wrong with the
    # DEPLOYMENT - the operator connected with a role that cannot see the
    # tables, which is a fixable property of the invocation and not of the
    # database. FAIL would print "DO NOT UPGRADE" about a stack that may be
    # perfectly ready. What must never happen is the third option: a green
    # PASS, which is what this replaced.
    warn "This connection cannot read the policy tables, so no verdict on per-tenant divergence is available" \
        "Row-level security is applied to this connection on: ${C23_BLIND_TABLES} - and every one of those tables read as ZERO rows. That is not a measurement, because a filtered read and an empty table are the same result: psql exits 0 and reports nothing either way. Connected as role '${PF_CONN_ROLE:-unknown}' (rolsuper=${PF_CONN_SUPER:-unknown}, rolbypassrls=${PF_CONN_BYPASSRLS:-unknown}). core/018 puts \`org_id = get_current_org_id()\` on these tables and a bare psql never sets \`app.current_org_id\`, so the policy matches nothing. Migration core/165 runs as axonflow_platform_admin, which carries BYPASSRLS, and WILL see every row this connection cannot. RE-RUN THIS SCRIPT as axonflow_platform_admin (the same role the migrations use), or - on a docker-compose bundle - as the database user that OWNS the tables. Detected by pg_catalog's row_security_active(), which row-level security does not filter; the row counts themselves cannot answer this, because they come back through the filter being detected. See 'WHICH DATABASE ROLE TO RUN THIS AS' in this script's header."
elif [[ "$C23_TABLES" -eq 0 && "$C23_OVERRIDE_ORGS" -eq 0 ]]; then
    # The override half is measured from policy_overrides, which is NOT one of
    # C23_TABLES. Testing the table count alone would discard an
    # already-measured, non-zero override divergence into an affirmative pass.
    pass "No policy table on this deployment can express per-tenant divergence (the tenancy columns are absent)"
elif [[ "$C23_TENANTS_BLIND" -eq 1 ]]; then
    # An all-clear that could not read its own inputs is not an all-clear.
    # See the C23_TENANTS_BLIND probe above: core/103 FORCEs RLS on `tenants`,
    # so this connection reads zero rows from it without erroring while the
    # migration - which runs BYPASSRLS - reads the mapping in full.
    warn "The tenancy mapping could not be read on this connection, so this scan may understate the change" \
        "The policy tables were read (they are ENABLE-only), but every read of \`tenants\` returned zero rows while your policy rows do reference tenants. core/103 runs ALTER TABLE tenants FORCE ROW LEVEL SECURITY and its policy keys on app.current_org_id, which this preflight does not set, so the rows are filtered out rather than refused. Migration core/165 runs as axonflow_platform_admin, which is BYPASSRLS, and WILL see the mapping this connection cannot - so a clean result here is not evidence of a no-op. Re-run this check with a role that carries BYPASSRLS (the same platform-admin role the migrations use) before treating the tenancy change as safe. Measured, not inferred: SELECT count(*) FROM tenants returned 0 on this DSN. ${C23_POLICY_ORGS} organisation(s) with divergent policy rows and ${C23_OVERRIDE_ORGS} with divergent overrides were still found without it."
elif [[ "$C23_POLICY_ORGS" -eq 0 && "$C23_OVERRIDE_ORGS" -eq 0 && "$C23_UNDERCOVERED" -eq 0 && "$C23_ORGWIDE_OVERRIDES" -eq 0 && -n "$C23_FILTERED_TABLES" ]]; then
    # Rows WERE visible, so this is not the blind case - but RLS is still
    # narrowing the reads, so "none found" is only "none found in what this
    # connection is scoped to". Reported as a qualified pass rather than an
    # affirmative one: the distinction is the entire subject of this check.
    warn "No per-tenant divergence found, but this connection sees only part of the policy tables" \
        "Row-level security is applied to this connection on: ${C23_FILTERED_TABLES}. Rows were visible, so the scan ran - but it ran over the subset this connection is scoped to, and an organisation whose rows are outside that subset would produce this same clean result. Connected as role '${PF_CONN_ROLE:-unknown}' (rolsuper=${PF_CONN_SUPER:-unknown}, rolbypassrls=${PF_CONN_BYPASSRLS:-unknown}). Re-run as axonflow_platform_admin for a deployment-wide answer; see 'WHICH DATABASE ROLE TO RUN THIS AS' in this script's header."
elif [[ "$C23_POLICY_ORGS" -eq 0 && "$C23_OVERRIDE_ORGS" -eq 0 && "$C23_UNDERCOVERED" -eq 0 && "$C23_ORGWIDE_OVERRIDES" -eq 0 ]]; then
    pass "No organisation here scopes policy to a subset of its tenants, so dropping per-tenant targeting is a no-op on this deployment"
else
    if [[ "$C23_POLICY_ORGS" -gt 0 ]]; then
        info "  organisation(s) with tenant-tier policy rows across MORE THAN ONE tenant: $C23_POLICY_ORGS"
        info "  first 25, as org_id / tenant_id / policy_id:"
        info "    $C23_POLICY_DETAIL"
    fi
    if [[ "$C23_OVERRIDE_ORGS" -gt 0 ]]; then
        info ""
        info "  organisation(s) with tenant-scoped OVERRIDE rows across MORE THAN ONE tenant: $C23_OVERRIDE_ORGS"
        info "  first 25, as org_id / tenant_id / action / reason:"
        info "    $C23_OVERRIDE_DETAIL"
    fi
    if [[ "$C23_UNDERCOVERED" -gt 0 ]]; then
        info ""
        info "  organisation(s) whose policy rows cover only SOME of the organisation's tenants: $C23_UNDERCOVERED"
        info "  first 25, as org (policy targets N of M tenants):"
        info "    $C23_UNDERCOVERED_DETAIL"
    fi
    if [[ "$C23_ORGWIDE_OVERRIDES" -gt 0 ]]; then
        info ""
        info "  ORG-SCOPED override row(s) with no tenant_id, inert on the enforcement path before v10.0.0 and applying now: $C23_ORGWIDE_OVERRIDES"
        info "  this is the one part of the change that LOOSENS - review these before pulling the image"
        info "  counted here are the rows core/165 can RESOLVE an organisation for. A legacy"
        info "  organization_id that is UUID-shaped resolves to none - organizations.id is an"
        info "  integer - so such a row is reported by CHECK 24 as one that stops firing instead"
    fi
    C23_LOOSEN_NOTE=""
    if [[ "$C23_OVERRIDE_ORGS" -gt 0 ]]; then
        C23_LOOSEN_NOTE=" THE OVERRIDE ROWS NEED NO ACTION FOR THIS UPGRADE. Overrides are deliberately NOT made organisation-wide - that is the only direction of this change that could loosen enforcement, so it is the one part that was left narrowed to the caller's own tenant plus the organisation's own rows. They are listed so you can confirm the per-tenant divergence is what you intended. One related fix does ship with them: this read never filtered revoked_at, so a REVOKED override went on being applied; it is filtered now, which makes revoking work the way you would already have assumed it did."
    fi
    warn "$C23_POLICY_ORGS organisation(s) target policy per tenant, $C23_UNDERCOVERED cover only some of their tenants, and $C23_OVERRIDE_ORGS target overrides per tenant" \
        "${C23_FILTER_NOTE:+${C23_FILTER_NOTE# } }v10.0.0 selects policy by org_id, not by the caller-chosen tenant_id, so every row listed above starts applying to EVERY tenant in its organisation. Both policy shapes matter and the second is the easier one to miss: an organisation with one rule scoped to a single tenant carries no divergence AMONG its rows, and that rule still starts governing every sibling tenant. For the policy rows the direction is over-blocking - a restriction applies more broadly and nothing stops being enforced.${C23_LOOSEN_NOTE} The re-authoring path is in the v10 upgrade guide: a rule that genuinely belongs to a subset of an organisation's people becomes SEGMENT-scoped (ADR-060), which is the platform's verified sub-org dimension; a rule whose per-tenant scoping was incidental is consciously accepted as org-wide and needs no change. Honest scope: this preflight reads your policy tables. It cannot tell whether a divergence is deliberate or incidental, so it names the rows rather than deciding for you."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 24 - policy rows with no resolvable org key (#3490, migration core/165)
# ---------------------------------------------------------------------------
section "Policy rows with no org key (#3490, migration core/165)"

# Migration core/165 makes org_id NOT NULL on the policy tables, because after
# v10.0.0 org_id is the ONLY thing that selects a policy row. It resolves what
# it can - the 'global' wildcard, then the tenants mapping, then the legacy
# org_id == tenant_id collapse, then (for overrides) the organizations lookup -
# and stamps anything left with the sentinel __axonflow_unowned__, which the
# platform refuses on both sides of every comparison.
#
# A STAMPED POLICY ROW STOPS BEING ABLE TO FIRE. That is a LOOSENING, and it is
# the one thing in this upgrade that removes enforcement rather than widening
# it. The migration itself raises a WARNING naming those rows - but it raises
# it DURING the upgrade, in the agent's boot log, which is the wrong moment to
# find out. This check reports the same rows READ-ONLY, beforehand, using the
# migration's own resolution chain so the answer matches what 165 will actually
# do.
C24_OK=1
C24_TOTAL=0
C24_DETAIL=""
C24_TABLES=0
C24_BLIND_TABLES=""
C24_FILTERED_TABLES=""
C24_ORGS_BLIND=0
C24_FAILURES_BEFORE="${#PSQL_FAILURES[@]}"

# SAME QUESTION CHECK 23 ASKS, AND FOR THE SAME REASON (#3490 R3).
#
# This check's affirmative pass - "every policy row here has an org key or a
# tenant key core/165 can resolve through" - is a claim about rows, derived
# entirely from COUNT(*) over the policy tables. Under a role subject to
# core/018's tenant-isolation policy those counts are 0 no matter what the
# tables hold, and the pass printed above them says a LOOSENING will not happen
# when it is about to. It is the more dangerous of the two: check 23 reports
# rules that start applying more widely, this one reports rules that STOP BEING
# ENFORCED, and a green result here is what an operator would rely on to skip
# reading the list.
#
# Detected exactly as in check 23, from pg_catalog rather than from the counts;
# see rls_verdict(). No corroborating read is used, because a corroborating read
# is what failed in check 23's first revision.
for tname in static_policies policy_overrides; do
    if ! table_exists "$tname"; then continue; fi
    probe_rls "$tname"
    if rls_blocks_all_clear "$RLS_STATE"; then
        C24_BLIND_TABLES="${C24_BLIND_TABLES:+$C24_BLIND_TABLES, }${tname}"
    elif [[ "$RLS_STATE" == "filtered" ]]; then
        C24_FILTERED_TABLES="${C24_FILTERED_TABLES:+$C24_FILTERED_TABLES, }${tname}"
    fi
done

# `organizations` is a CORROBORATING table here, not a primary input: it appears
# only inside C24_PRED_OVERRIDES' NOT EXISTS. It is FORCE row-level security
# (core/103), so it reads empty even for the table owner - the compose bundle's
# posture - and an empty read makes every NOT EXISTS true, which OVER-counts
# unowned overrides. That is the fail-safe direction (it warns about rows
# core/165 will actually resolve, rather than staying silent about rows it will
# not), so it does not block the check; it is disclosed in the warning instead
# of being left for an operator to discover by chasing a policy_id that turns
# out to be fine.
if table_exists organizations; then
    probe_rls organizations
    if rls_blocks_all_clear "$RLS_STATE"; then C24_ORGS_BLIND=1; fi
fi

# The predicate below is core/165's resolution chain, inverted. It does NOT
# consult the tenants table, and that is not an omission: 165's step 4 collapses
# org_id = tenant_id verbatim for ANY row with a non-empty tenant_id, so step 3's
# tenants lookup only ever changes WHICH org a row resolves to, never WHETHER it
# resolves. A row is unresolvable exactly when it has no org key and no tenant
# key at all. (An earlier draft branched on the tenants table's presence and
# produced the identical predicate on both sides - a distinction with no
# difference, which would have told the next reader the join mattered.)
C24_PRED="(org_id IS NULL OR btrim(org_id) = '') AND COALESCE(btrim(tenant_id), '') = ''"
# policy_overrides has one more resolution step (165's step 5: the
# organizations lookup by the legacy organization_id), so a row that step can
# resolve is NOT unowned. Subtracting it here is what keeps this check's claim
# to reproduce the migration's chain true for all three tables.
C24_PRED_OVERRIDES="$C24_PRED AND NOT EXISTS (SELECT 1 FROM organizations o WHERE o.id::text = policy_overrides.organization_id::text AND COALESCE(btrim(o.org_id), '') <> '')"

# policy_overrides is in the list because migration 165 constrains THREE
# tables, and an earlier revision of this check read only two - while its own
# pass message, the CHANGELOG and UPGRADING.md all claimed it reproduced "the
# migration's own resolution chain". An affirmative all-clear across a table
# the check never read is worse than no check.
#
# dynamic_policies is deliberately EXCLUDED from the unowned count. Migration
# 165 step 2 maps its NULL/empty-tenant rows to 'global' rather than to the
# sentinel, because on that table an absent tenant is the apply-to-every-tenant
# shape. Counting them here would tell an operator that policies which will go
# on governing everybody are about to stop firing.
for tname in static_policies policy_overrides; do
    if ! table_exists "$tname"; then
        continue
    fi
    if ! column_exists "$tname" "org_id" || ! column_exists "$tname" "tenant_id"; then
        info "  $tname lacks org_id or tenant_id on this schema - core/165 will skip it."
        continue
    fi
    C24_TABLES=$((C24_TABLES + 1))

    C24_THIS_PRED="$C24_PRED"
    if [[ "$tname" == "policy_overrides" ]] && column_exists policy_overrides organization_id && table_exists organizations; then
        C24_THIS_PRED="$C24_PRED_OVERRIDES"
    fi
    q "unowned policy rows($tname)" "SELECT COUNT(*) FROM $tname WHERE $C24_THIS_PRED"
    if [[ "$QOK" -ne 1 ]] || ! is_uint "$Q"; then C24_OK=0; continue; fi
    if [[ "$Q" -gt 0 ]]; then
        C24_TOTAL=$((C24_TOTAL + Q))
        # NAMED THE WAY THE MIGRATION NAMES THEM. core/165's step-6 WARNING
        # aggregates policy_id where the column exists, and it exists on all
        # three tables (core/010, core/030). Listing `id` here meant the
        # preflight and the migration printed two unrelated identifiers for the
        # same row - and on policy_overrides `policy_id` is the FK to the
        # OVERRIDDEN policy, so an operator matching one list against the other
        # would have found nothing in common. Check 23 already uses policy_id;
        # the two new checks now agree with each other as well as with 165.
        C24_NAME_COL="id"
        if column_exists "$tname" "policy_id"; then C24_NAME_COL="policy_id"; fi
        q "unowned policy names($tname)" "SELECT COALESCE(string_agg(${C24_NAME_COL}::text, ', ' ORDER BY ${C24_NAME_COL}::text), '') FROM (SELECT ${C24_NAME_COL} FROM $tname WHERE $C24_THIS_PRED ORDER BY ${C24_NAME_COL} LIMIT 25) s"
        if [[ "$QOK" -eq 1 ]]; then
            C24_DETAIL="${C24_DETAIL:+$C24_DETAIL | }${tname} -> ${Q}"
        else
            C24_OK=0
        fi
    fi
done

if [[ "${#PSQL_FAILURES[@]}" -ne "$C24_FAILURES_BEFORE" ]]; then
    C24_OK=0
fi

C24_ORGS_NOTE=""
if [[ "$C24_ORGS_BLIND" -eq 1 && "$C24_DETAIL" == *policy_overrides* ]]; then
    C24_ORGS_NOTE=" One caveat on the policy_overrides rows specifically: \`organizations\` is FORCE row-level security (core/103) and read as empty on this connection, so core/165's step-5 lookup could not be reproduced and those rows may be OVER-reported - core/165 itself, running with BYPASSRLS, may resolve some of them through the legacy organization_id and leave them owned. Re-run as axonflow_platform_admin to get the exact set."
fi

if [[ "$C24_OK" -ne 1 ]]; then
    fail "The unowned-policy-row scan did not complete" \
        "At least one count did not execute - see the query-failure list at the end. An unexecuted scan must NOT be read as 'no unowned rows', because that reading would let a policy silently stop being enforced during the upgrade."
elif [[ -n "$C24_BLIND_TABLES" ]]; then
    # Ahead of BOTH passes below, for the same reason as check 23: the
    # "no tenancy columns" pass comes from pg_catalog probes that are not
    # RLS-filtered, so it is reachable while every count is a filtered zero.
    warn "This connection cannot read the policy tables, so no verdict on unowned policy rows is available" \
        "Row-level security is applied to this connection on: ${C24_BLIND_TABLES} - and every one of those tables read as ZERO rows, which is indistinguishable from an empty table: psql exits 0 either way. Connected as role '${PF_CONN_ROLE:-unknown}' (rolsuper=${PF_CONN_SUPER:-unknown}, rolbypassrls=${PF_CONN_BYPASSRLS:-unknown}). This is the check that reports the one change in v10.0.0 which REMOVES enforcement, so a green result here is the last thing that should be produced from an unreadable table. Migration core/165 runs as axonflow_platform_admin, which carries BYPASSRLS and will see every row this connection cannot. RE-RUN as axonflow_platform_admin, or - on a docker-compose bundle - as the database user that OWNS the tables. See 'WHICH DATABASE ROLE TO RUN THIS AS' in this script's header."
elif [[ "$C24_TABLES" -eq 0 ]]; then
    pass "No policy table on this deployment has the tenancy columns core/165 constrains"
elif [[ "$C24_TOTAL" -eq 0 && -n "$C24_FILTERED_TABLES" ]]; then
    warn "No unowned policy rows found, but this connection sees only part of the policy tables" \
        "Row-level security is applied to this connection on: ${C24_FILTERED_TABLES}. Rows were visible, so the scan ran - over the subset this connection is scoped to. An unowned row outside that subset produces this same clean result, and an unowned row is one that stops being enforced after the upgrade. Connected as role '${PF_CONN_ROLE:-unknown}' (rolsuper=${PF_CONN_SUPER:-unknown}, rolbypassrls=${PF_CONN_BYPASSRLS:-unknown}). Re-run as axonflow_platform_admin for a deployment-wide answer."
elif [[ "$C24_TOTAL" -eq 0 ]]; then
    pass "Every enabled and disabled policy row here has an org key or a tenant key core/165 can resolve through"
else
    info "  policy rows with NO org key and NO resolvable tenant key: $C24_TOTAL"
    info "  first 25 policy_id(s): $C24_DETAIL"
    warn "$C24_TOTAL policy row(s) will be stamped __axonflow_unowned__ by migration core/165 and will stop firing" \
        "${C24_ORGS_NOTE:+${C24_ORGS_NOTE# } }A SEPARATE, EXPECTED WARNING: core/166 raises its own RAISE WARNING naming any row that still carries a value in the legacy organization_id column it drops. That warning is about a column being retired, NOT about scope being lost, and a row can appear there while carrying a perfectly good org_id - some shipped policy bundles populate both. Read core/166's warning as an inventory of what the drop discarded; read THIS check for what stops being enforced. They are different questions and only this one costs you enforcement. These rows carry no organisation key and no tenant key that core/165 can resolve one through, so after the upgrade they are selectable by NOBODY. This is the one change in v10.0.0 that REMOVES enforcement rather than widening it, which is why it is reported before the upgrade rather than left to the migration's own boot-time warning. Decide per row: stamp it with the owning organisation (UPDATE the org_id column) if the rule should keep applying, or accept that it stops - a rule with no owner was already unreachable under row-level security on any app-role deployment. Honest scope: this reproduces core/165's resolution chain read-only. It counts rows the migration cannot resolve; it does not modify anything."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Internal consistency: every section must have been numbered.
# ---------------------------------------------------------------------------
if [[ "$SECTION_NO" -ne "$TOTAL_CHECKS" ]]; then
    printf "%bScript error:%b ran %d sections but TOTAL_CHECKS says %d. The banner numbering is wrong, which means a check was added or removed without updating the constant — refusing to print a verdict.\n" \
        "$RED" "$NC" "$SECTION_NO" "$TOTAL_CHECKS"
    exit 2
fi

# ---------------------------------------------------------------------------
# Final verdict
# ---------------------------------------------------------------------------
printf "%b%b═══════════════════════════════════════════════════════════════════════%b\n" "$BOLD" "$BLUE" "$NC"
printf "%b%bAxonFlow Self-Hosted Preflight — Final Verdict%b\n" "$BOLD" "$BLUE" "$NC"
printf "%b%b═══════════════════════════════════════════════════════════════════════%b\n\n" "$BOLD" "$BLUE" "$NC"

# Any query that did not EXECUTE is a failure of the preflight itself, and it
# outranks every green check above it: an empty result set and a dropped
# connection look identical downstream, so a run with unexecuted queries can
# never be reported as clean.
if [[ "${#PSQL_FAILURES[@]}" -gt 0 ]]; then
    fail "${#PSQL_FAILURES[@]} preflight quer(ies) did not execute" \
        "The checks above are INCOMPLETE. An empty result from a failed query is indistinguishable from a genuinely empty table, so no verdict is available until these run."
    printf "\n%bQueries that did not execute:%b\n" "$RED" "$NC"
    for entry in "${PSQL_FAILURES[@]}"; do
        printf "  - %s\n" "$entry"
    done
    printf "\n"
fi

printf "  %bPASS%b: %d checks\n" "$GREEN" "$NC" "${#PASS_CHECKS[@]}"
printf "  %bWARN%b: %d checks\n" "$YELLOW" "$NC" "${#WARN_CHECKS[@]}"
printf "  %bFAIL%b: %d checks\n\n" "$RED" "$NC" "${#FAIL_CHECKS[@]}"

if [[ "${#FAIL_CHECKS[@]}" -gt 0 ]]; then
    printf "%b❌ DO NOT UPGRADE.%b At least one FAIL — resolve before pulling the new image:\n\n" "$RED" "$NC"
    for entry in "${FAIL_CHECKS[@]}"; do
        printf "  - %s\n" "${entry%%|*}"
        printf "    %s\n" "${entry#*|}"
    done
    printf "\n"
    exit 1
fi

if [[ "${#WARN_CHECKS[@]}" -gt 0 ]]; then
    printf "%b⚠️  PROCEED WITH CAUTION.%b WARNINGs require operator review:\n\n" "$YELLOW" "$NC"
    for entry in "${WARN_CHECKS[@]}"; do
        printf "  - %s\n" "${entry%%|*}"
        printf "    %s\n" "${entry#*|}"
    done
    printf "\n  Acknowledge each WARNING before proceeding. Re-run preflight if anything changes.\n\n"
    exit 0
fi

printf "%b✅ PASS — ready to upgrade.%b\n\n" "$GREEN" "$NC"
printf "Next steps:\n"
printf "  1. Take a fresh RDS snapshot (or equivalent for non-RDS Postgres)\n"
printf "  2. Drain in-flight executions if you can (core/156 behaviour change)\n"
printf "  3. Read the version-specific notes for your TARGET release before pulling it.\n"
printf "     A green run above means nothing this script can see will stop the upgrade; it\n"
printf "     does not mean there is nothing to decide. Checks 20 to 24 in particular\n"
printf "     report consequences this script cannot verify from outside the platform.\n"
printf "     In the install bundle that is UPGRADING.md, section 'Version-specific notes'.\n"
printf "  4. Pull the new platform image and restart agent + orchestrator\n"
printf "  5. Verify /health advertises the platform_version you expect\n"
printf "  6. Re-run this script; it is idempotent and read-only\n\n"
printf "Upgrade guides:\n"
printf "  https://docs.getaxonflow.com/docs/deployment/v9-12-to-v9-13-upgrade/\n"
printf "  https://docs.getaxonflow.com/docs/deployment/v8-self-hosted-upgrade-guide/\n\n"
exit 0
