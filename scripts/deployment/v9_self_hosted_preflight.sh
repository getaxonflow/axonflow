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
# It never needs the NEW image, never writes to the database, and never restarts
# anything. Every statement it issues is a SELECT, a SHOW, or an EXPLAIN.
#
# ---------------------------------------------------------------------------
# WHY THE NAME STILL SAYS v9 (read before renaming it)
# ---------------------------------------------------------------------------
# The sections below are grouped by the release that introduced them:
#
#   [1/16]-[8/16]   v8.x -> v9.0 baseline (epic #2230 Phase 7)
#   [9/16]-[12/16]  v9.13.0 (the cross-tenant remediation train, epic #3071)
#   [13/16]-[15/16] v9.14.0 governance-gate advisories (#3248, #3057, #3278)
#   [16/16]         v9.17.0 break-glass recovery readiness (ADMIN_API_KEY)
#
# The name is therefore accurate for the whole v9 line, and it is a PUBLISHED
# entry point: docs/deployment/v7-to-v8-migration.md,
# v8-enterprise-migration-guide.md and v8-self-hosted-upgrade-guide.md all name
# this file, and `.github/workflows/sync-community-repo.yml` re-includes it BY
# NAME after excluding `/scripts/*` wholesale. Renaming it therefore silently
# stops it reaching the public mirror unless that include is edited in the same
# commit, and breaks every operator runbook that already names it. When v10
# arrives, the rename is a deliberate change with a redirect — not a side effect
# of adding a check.
#
# In the partner install bundle (getaxonflow/axonflow-install) this same file is
# vendored BYTE-IDENTICALLY as `preflight.sh`, so the partner never sees the
# version prefix. `scripts/check-partner-preflight-parity.sh` fails CI if the two
# copies diverge; see that file for the full mechanism.
#
# Companion docs:
#   technical-docs/v9_phase7_self_hosted_migration.md          (v8 → v9)
#   https://docs.getaxonflow.com/docs/deployment/v9-12-to-v9-13-upgrade/
#   https://docs.getaxonflow.com/docs/deployment/v8-self-hosted-upgrade-guide/
#
# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
#   DATABASE_URL="postgres://..." ./v9_self_hosted_preflight.sh
#
#   With explicit env vars (override DATABASE_URL parsing):
#   PGHOST=db.internal PGPORT=5432 PGUSER=axonflow PGPASSWORD=... PGDATABASE=axonflow \
#     ./v9_self_hosted_preflight.sh
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
#   0 — all checks pass (possibly with WARNINGs)
#   1 — at least one FAIL
#   2 — script error (no usable psql transport, DATABASE_URL unset, internal
#       inconsistency). Never a verdict about the deployment.

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
TOTAL_CHECKS=16
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

printf "%b%bAxonFlow Self-Hosted Preflight (v9 line)%b\n" "$BOLD" "$BLUE" "$NC"
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

# Probe connectivity early — every other check assumes the DB is reachable.
if ! psql_exec "SELECT 1"; then
    printf "%bScript error:%b cannot connect to Postgres via the %s transport.\n" "$RED" "$NC" "${PSQL_TRANSPORT%%:*}"
    printf "  psql exit %s: %s\n" "$PSQL_RC" "$PSQL_ERR"
    exit 2
fi
info "Database connectivity OK (transport: ${PSQL_TRANSPORT})"
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

    # default_svc and ecs_names are per component rather than derived from the
    # component word, because the portal's names are not "axonflow-portal" in
    # either place: the Compose service is axonflow-customer-portal and the ECS
    # container definition is customer-portal. Deriving them worked only for as
    # long as every component happened to be named after itself.
    case "$comp" in
        agent)
            upper="AGENT"; default_svc="axonflow-agent"
            ecs_names="name=='agent'||name=='axonflow-agent'" ;;
        orchestrator)
            upper="ORCHESTRATOR"; default_svc="axonflow-orchestrator"
            ecs_names="name=='orchestrator'||name=='axonflow-orchestrator'" ;;
        portal)
            upper="PORTAL"; default_svc="axonflow-customer-portal"
            ecs_names="name=='customer-portal'||name=='axonflow-customer-portal'||name=='portal'" ;;
        *) DISC_SOURCE="internal error: unknown component '$comp'"; DISC_ORIGIN="none"; return 0 ;;
    esac
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
PASS2_TABLES="audit_logs agent_audit_logs mcp_query_audits llm_call_audits static_policies dynamic_policies policy_evaluations service_identities execution_history"

for tname in $PASS2_TABLES; do
    if ! table_exists "$tname"; then continue; fi
    if ! column_exists "$tname" "org_id"; then continue; fi

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
    q "local-dev-org rows" "SELECT COUNT(*) FROM organizations WHERE org_id = 'local-dev-org'"
    if [[ "$QOK" -ne 1 ]]; then
        fail "Could not count local-dev-org organizations" \
            "The query did not execute — see the query-failure list at the end."
    elif [[ "$Q" -gt 0 ]]; then
        info "organizations table contains $Q row(s) keyed on 'local-dev-org'."
        info "This is the protected default for unset-ORG_ID installs. v9 preserves it; no action needed."
        pass "local-dev-org default preserved across upgrade contract"
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

# On ECS the admin DSN is usually a secret ref (valueFrom), not a literal env
# value, so the environment[] read above legitimately comes back absent. Check
# secrets[] too before concluding it is unset.
if [[ -z "$ADMIN_URL_VALUE" && -n "${ECS_CLUSTER:-}" && -n "${ECS_AGENT_SERVICE:-}" ]] && command -v aws >/dev/null 2>&1; then
    _td=$(aws ecs describe-services --cluster "$ECS_CLUSTER" --services "$ECS_AGENT_SERVICE" \
        --query 'services[0].taskDefinition' --output text 2>/dev/null || echo "")
    if [[ -n "$_td" && "$_td" != "None" ]]; then
        _secret=$(aws ecs describe-task-definition --task-definition "$_td" \
            --query "taskDefinition.containerDefinitions[?name=='agent'||name=='axonflow-agent'].secrets[?name=='AXONFLOW_DB_PLATFORM_ADMIN_URL'].valueFrom | [0][0]" \
            --output text 2>/dev/null || echo "")
        if [[ -n "$_secret" && "$_secret" != "None" ]]; then
            ADMIN_URL_VALUE="$_secret"
            ADMIN_URL_STATE="set"
            info "AXONFLOW_DB_PLATFORM_ADMIN_URL is wired as an ECS secret reference."
        fi
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
elif [[ -n "$ADMIN_URL_VALUE" ]]; then
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
printf "  3. Pull the new platform image and restart agent + orchestrator\n"
printf "  4. Verify /health advertises the platform_version you expect\n"
printf "  5. Re-run this script — it is idempotent and read-only\n\n"
printf "Upgrade guides:\n"
printf "  https://docs.getaxonflow.com/docs/deployment/v9-12-to-v9-13-upgrade/\n"
printf "  https://docs.getaxonflow.com/docs/deployment/v8-self-hosted-upgrade-guide/\n\n"
exit 0
