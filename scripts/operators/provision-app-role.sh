#!/usr/bin/env bash
#
# v9 Provision App Role — Epic #2230 Phase 8 / Brief 11.5 operator runbook
#
# Purpose: Set login passwords on the two Postgres roles created by migration
#          098 (axonflow_app_role + axonflow_platform_admin) and verify each
#          can authenticate end-to-end. This is the prerequisite for
#          AXONFLOW_DB_USE_APP_ROLE=true and FORCE ROW LEVEL SECURITY taking
#          effect on a real deployment.
#
# Migration 098 creates both roles with LOGIN capability but no password —
# CREATE ROLE … LOGIN by itself sets the role's password to NULL, which makes
# the role unable to authenticate via password auth. Operators (or this
# repo's provision-app-role.yml workflow on AxonFlow-internal stacks) run
# this script post-098 to issue ALTER ROLE … WITH PASSWORD, generate Secrets
# Manager-shaped DSNs (workflow side), and prove connectivity before the CFN
# env flip.
#
# This script is pure-bash + psql with no AWS dependencies — operators of
# self-hosted / in-VPC deployments can run it directly against their RDS or
# native-Postgres database. The companion .github/workflows/provision-app-role.yml
# wraps this script with AWS-specific orchestration for AxonFlow's own stacks.
#
# Companion docs:
#   - technical-docs/v9_phase7_self_hosted_migration.md
#   - technical-docs/v9_phase8_rls_rollout.md
#   - axonflow-docs/docs/operators/_v9-self-hosted-upgrade-guide.md
#
# Usage:
#   # Master DSN (used to ALTER ROLE both new roles):
#   DATABASE_URL="postgres://axonflow:masterpw@db.internal:5432/axonflow" \
#   APP_ROLE_PASSWORD="$(openssl rand -base64 32 | tr -d '\n')" \
#   PLATFORM_ADMIN_PASSWORD="$(openssl rand -base64 32 | tr -d '\n')" \
#       ./scripts/operators/provision-app-role.sh
#
#   # Idempotent re-run (skips ALTER if both roles already have a password):
#   FORCE_RESET=1 …same envs as above… ./provision-app-role.sh
#
# Required env vars:
#   DATABASE_URL              — master / superuser DSN that can issue ALTER ROLE.
#                              MUST connect as a role with the SUPERUSER or
#                              CREATEROLE privilege. RDS master meets this.
#                              (PGHOST/PGUSER/PGDATABASE form is also accepted.)
#   APP_ROLE_PASSWORD         — password to set on axonflow_app_role.
#   PLATFORM_ADMIN_PASSWORD   — password to set on axonflow_platform_admin.
#
# Optional env vars:
#   FORCE_RESET=1             — re-issue ALTER ROLE even if the role already
#                              has a password (rolpassword IS NOT NULL).
#                              Default: skip ALTER if a password is already set.
#   PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE — used iff DATABASE_URL unset.
#   SKIP_CONNECTIVITY_TEST=1  — skip the post-ALTER connectivity probe (NOT
#                              recommended; the probe is the only proof the
#                              ALTER actually took).
#
# Security:
#   - Passwords are NEVER echoed, NEVER passed on the psql command line, and
#     NEVER appear in any process listing (/proc/<pid>/cmdline). All ALTER
#     ROLE statements run via a temp SQL file (mode 0600) deleted on EXIT.
#   - The script issues `SET LOCAL log_statement = 'none'` before each ALTER
#     ROLE to suppress server-side DDL logging of the literal password.
#   - Server-side audit log (pgaudit, log_statement=all) may still record
#     the ALTER ROLE; on hosted Postgres (RDS), enable parameter group changes
#     before running this script if your compliance posture forbids password
#     logging.
#
# Exit codes:
#   0 — both roles provisioned + connectivity verified
#   1 — at least one check FAILed
#   2 — script error (psql missing, DATABASE_URL unset, password unset, etc.)

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors (degrade gracefully when not a TTY) + lightweight tracking
# ---------------------------------------------------------------------------
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

PASS_CHECKS=()
WARN_CHECKS=()
FAIL_CHECKS=()

pass() { PASS_CHECKS+=("$1"); printf "%b✅ PASS%b  %s\n" "$GREEN" "$NC" "$1"; }
warn() { WARN_CHECKS+=("$1|$2"); printf "%b⚠️  WARN%b  %s\n         %s\n" "$YELLOW" "$NC" "$1" "$2"; }
fail() { FAIL_CHECKS+=("$1|$2"); printf "%b❌ FAIL%b  %s\n         %s\n" "$RED" "$NC" "$1" "$2"; }
info() { printf "%bℹ️  INFO%b  %s\n" "$BLUE" "$NC" "$1"; }

# ---------------------------------------------------------------------------
# Setup: tempfile, locate psql, resolve DSN, prove connectivity
# ---------------------------------------------------------------------------

TMPSQL=""
# shellcheck disable=SC2329  # invoked via trap below
cleanup() {
    if [[ -n "$TMPSQL" && -f "$TMPSQL" ]]; then
        # shred-like overwrite first to defeat undelete on hostile filesystems,
        # then unlink. `shred` is not on alpine by default so use dd as fallback.
        if command -v shred >/dev/null 2>&1; then
            shred -u "$TMPSQL" 2>/dev/null || rm -f "$TMPSQL"
        else
            dd if=/dev/urandom of="$TMPSQL" bs=4096 count=1 conv=notrunc 2>/dev/null || true
            rm -f "$TMPSQL"
        fi
    fi
}
trap cleanup EXIT INT TERM

printf "%b%bv9 Provision App Role — Epic #2230%b\n" "$BOLD" "$BLUE" "$NC"
printf "Date: %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf "Run as: %s\n\n" "$(id -un 2>/dev/null || echo unknown)"

if ! command -v psql >/dev/null 2>&1; then
    printf "%bScript error:%b psql not found on PATH. Install postgresql-client and retry.\n" "$RED" "$NC" >&2
    exit 2
fi

if [[ -z "${DATABASE_URL:-}" && -z "${PGHOST:-}" ]]; then
    printf "%bScript error:%b set DATABASE_URL (or PGHOST/PGUSER/PGDATABASE) before invoking.\n" "$RED" "$NC" >&2
    exit 2
fi

if [[ -z "${APP_ROLE_PASSWORD:-}" ]]; then
    printf "%bScript error:%b APP_ROLE_PASSWORD env var not set.\n" "$RED" "$NC" >&2
    exit 2
fi

if [[ -z "${PLATFORM_ADMIN_PASSWORD:-}" ]]; then
    printf "%bScript error:%b PLATFORM_ADMIN_PASSWORD env var not set.\n" "$RED" "$NC" >&2
    exit 2
fi

# Mask passwords from any subsequent GitHub Actions output. ::add-mask::
# directives are interpreted by the GHA runner; emit ONLY when running
# inside Actions so CloudWatch Logs (Fargate captures everything to CW
# via awslogs driver) don't retain the literal directive line.
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    printf "::add-mask::%s\n" "$APP_ROLE_PASSWORD" >&2
    printf "::add-mask::%s\n" "$PLATFORM_ADMIN_PASSWORD" >&2
fi

# Reject ASCII single-quote in passwords: they would break the ALTER ROLE
# string literal (no SQL injection vector since we control both sides, but
# would corrupt the password). openssl rand -base64 produces only the
# base64 alphabet, so this catches operator hand-typed passwords with a
# stray apostrophe.
if [[ "$APP_ROLE_PASSWORD" == *"'"* ]]; then
    printf "%bScript error:%b APP_ROLE_PASSWORD contains a single quote — not supported. Re-generate via 'openssl rand -base64 32'.\n" "$RED" "$NC" >&2
    exit 2
fi
if [[ "$PLATFORM_ADMIN_PASSWORD" == *"'"* ]]; then
    printf "%bScript error:%b PLATFORM_ADMIN_PASSWORD contains a single quote — not supported.\n" "$RED" "$NC" >&2
    exit 2
fi

# Parse the master DSN into host/port/user/password/dbname/sslmode parts
# ONCE at startup so we never pass the full URL on the psql command line
# (which leaks the master password via /proc/<pid>/cmdline). All psql
# invocations below use -h/-p/-U/-d + PGPASSWORD env.
MASTER_HOST=""
MASTER_PORT=""
MASTER_USER=""
MASTER_PASSWORD=""
MASTER_DBNAME=""
MASTER_SSLMODE=""
if [[ -n "${DATABASE_URL:-}" ]]; then
    # postgres://user:pass@host:port/dbname?sslmode=…
    _u="${DATABASE_URL#postgres://}"
    _u="${_u#postgresql://}"
    # Optional userinfo
    if [[ "$_u" == *"@"* ]]; then
        _userinfo="${_u%%@*}"
        _u="${_u#*@}"
        MASTER_USER="${_userinfo%%:*}"
        if [[ "$_userinfo" == *":"* ]]; then
            MASTER_PASSWORD="${_userinfo#*:}"
        fi
    fi
    # Query string sslmode
    if [[ "$_u" == *"?"* ]]; then
        _query="${_u#*\?}"
        _u="${_u%%\?*}"
        IFS='&' read -ra _kvs <<<"$_query"
        for _kv in "${_kvs[@]}"; do
            case "$_kv" in
                sslmode=*) MASTER_SSLMODE="${_kv#sslmode=}" ;;
            esac
        done
    fi
    # host:port/dbname
    _hostpart="${_u%%/*}"
    MASTER_DBNAME="${_u#*/}"
    MASTER_HOST="${_hostpart%%:*}"
    if [[ "$_hostpart" == *":"* ]]; then
        MASTER_PORT="${_hostpart#*:}"
    fi
else
    MASTER_HOST="${PGHOST}"
    MASTER_USER="${PGUSER:-}"
    MASTER_PASSWORD="${PGPASSWORD:-}"
    MASTER_DBNAME="${PGDATABASE:-axonflow}"
fi
[[ -z "$MASTER_PORT" ]] && MASTER_PORT="${PGPORT:-5432}"
[[ -z "$MASTER_SSLMODE" ]] && MASTER_SSLMODE="${PGSSLMODE:-prefer}"

# Re-mask master password if we extracted it from DATABASE_URL — operators
# inside GHA may have masked the URL but not the parsed parts.
if [[ -n "${GITHUB_ACTIONS:-}" ]] && [[ -n "$MASTER_PASSWORD" ]]; then
    printf "::add-mask::%s\n" "$MASTER_PASSWORD" >&2
fi

# Wrapper: run a SQL snippet via the master DSN, suppress NOTICE noise.
# Uses --no-psqlrc so an operator's interactive .psqlrc doesn't change
# output. Output is the LAST line (defends against multi-line debug noise).
# Password flows via PGPASSWORD env, NOT command line, per process-table
# safety.
psql_master() {
    local sql="$1"
    PGPASSWORD="$MASTER_PASSWORD" \
        PGSSLMODE="$MASTER_SSLMODE" \
        PGOPTIONS='--client-min-messages=warning' \
        psql --no-psqlrc -At \
            -h "$MASTER_HOST" -p "$MASTER_PORT" \
            -U "$MASTER_USER" -d "$MASTER_DBNAME" \
            -c "$sql" 2>/dev/null | tail -1
}

# psql_as_role: connect AS a given role using the password we just set,
# return the result of a smoke query. Reuses the master DSN's host/port/dbname
# (parsed once at startup). Password flows via PGPASSWORD env.
#
# Note on sslmode: libpq's `sslmode` is a CLIENT-side connection parameter,
# NOT a server-side SET. We propagate the master's value (parsed from the
# DATABASE_URL query string or PGSSLMODE env) so the per-role connection
# honors the same SSL posture as the master.
psql_as_role() {
    local role="$1"
    local password="$2"
    local sql="$3"

    PGPASSWORD="$password" \
        PGSSLMODE="$MASTER_SSLMODE" \
        PGOPTIONS='--client-min-messages=warning' \
        psql --no-psqlrc -At \
            -h "$MASTER_HOST" -p "$MASTER_PORT" \
            -U "$role" -d "$MASTER_DBNAME" \
            -v ON_ERROR_STOP=1 \
            -c "$sql" 2>/dev/null | tail -1
}

# Probe master connectivity — every other check assumes the master can ALTER.
if ! psql_master "SELECT 1" >/dev/null 2>&1; then
    printf "%bScript error:%b cannot connect to Postgres via DATABASE_URL/PG* envs. Verify the master DSN.\n" "$RED" "$NC" >&2
    exit 2
fi
info "Master DB connectivity OK"
printf "\n"

# ---------------------------------------------------------------------------
# Check 1 — Migration 098 ran (both roles exist)
# ---------------------------------------------------------------------------
printf "%b%b[1/5] Migration 098 roles exist%b\n" "$BOLD" "$BLUE" "$NC"

APP_EXISTS=$(psql_master "SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role'" 2>/dev/null || echo "")
ADMIN_EXISTS=$(psql_master "SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin'" 2>/dev/null || echo "")

if [[ "$APP_EXISTS" != "1" ]]; then
    fail "axonflow_app_role does not exist" \
        "Run migration 098 first (pull the v9.0.0 platform image — the agent's boot-time runner applies migrations 088-108 automatically). Without 098 this script has nothing to ALTER."
    APP_EXISTS=""
fi
if [[ "$ADMIN_EXISTS" != "1" ]]; then
    fail "axonflow_platform_admin does not exist" \
        "Run migration 098 first. Cross-org workers (sweep, recovery, node-monitor) need this role under v9.0.0 with AXONFLOW_DB_USE_APP_ROLE=true."
    ADMIN_EXISTS=""
fi

if [[ -n "$APP_EXISTS" && -n "$ADMIN_EXISTS" ]]; then
    pass "Both roles exist (migration 098 has been applied)"
else
    # Cannot proceed without roles — render verdict and bail.
    printf "\n%b❌ FAIL — roles missing. Run migration 098 then re-run this script.%b\n" "$RED" "$NC"
    exit 1
fi

# Confirm role attribute parity with the migration's intent.
APP_BYPASS=$(psql_master "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'axonflow_app_role'")
APP_LOGIN=$(psql_master "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'axonflow_app_role'")
ADMIN_BYPASS=$(psql_master "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'axonflow_platform_admin'")
ADMIN_LOGIN=$(psql_master "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'axonflow_platform_admin'")

if [[ "$APP_BYPASS" != "f" ]]; then
    fail "axonflow_app_role has BYPASSRLS=true" \
        "v9 contract: app role MUST NOT bypass RLS. Run: ALTER ROLE axonflow_app_role NOBYPASSRLS;"
fi
if [[ "$APP_LOGIN" != "t" ]]; then
    fail "axonflow_app_role missing LOGIN" \
        "Run: ALTER ROLE axonflow_app_role LOGIN;"
fi
if [[ "$ADMIN_BYPASS" != "t" ]]; then
    fail "axonflow_platform_admin missing BYPASSRLS" \
        "v9 contract: admin role MUST bypass RLS for cross-org workers. Run: ALTER ROLE axonflow_platform_admin BYPASSRLS;"
fi
if [[ "$ADMIN_LOGIN" != "t" ]]; then
    fail "axonflow_platform_admin missing LOGIN" \
        "Run: ALTER ROLE axonflow_platform_admin LOGIN;"
fi

if [[ ${#FAIL_CHECKS[@]} -eq 0 ]]; then
    pass "Role attributes match v9 contract (app=NOBYPASSRLS+LOGIN, admin=BYPASSRLS+LOGIN)"
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 2 — Idempotency: did somebody already provision a password?
# ---------------------------------------------------------------------------
printf "%b%b[2/5] Idempotency check (rolpassword state)%b\n" "$BOLD" "$BLUE" "$NC"

# pg_authid.rolpassword is NULL iff no password is set. Cluster-superuser-only
# table — the master role can read it on RDS (RDS master is granted
# rds_superuser which can SELECT pg_authid). Some hosted Postgres flavors hide
# this; we degrade to WARN if the read fails.
APP_HAS_PW=""
ADMIN_HAS_PW=""
if APP_HAS_PW=$(psql_master "SELECT CASE WHEN rolpassword IS NOT NULL THEN 't' ELSE 'f' END FROM pg_authid WHERE rolname = 'axonflow_app_role'" 2>/dev/null) \
        && ADMIN_HAS_PW=$(psql_master "SELECT CASE WHEN rolpassword IS NOT NULL THEN 't' ELSE 'f' END FROM pg_authid WHERE rolname = 'axonflow_platform_admin'" 2>/dev/null); then
    info "axonflow_app_role rolpassword set: $APP_HAS_PW"
    info "axonflow_platform_admin rolpassword set: $ADMIN_HAS_PW"
else
    APP_HAS_PW="unknown"
    ADMIN_HAS_PW="unknown"
    warn "pg_authid read failed (likely hosted PG with rolpassword hidden)" \
        "Cannot inspect existing password state. Proceeding with ALTER ROLE — pass FORCE_RESET=1 explicitly if this is a re-run."
fi

SKIP_APP_ALTER="false"
SKIP_ADMIN_ALTER="false"
if [[ "${FORCE_RESET:-}" != "1" ]]; then
    if [[ "$APP_HAS_PW" == "t" ]]; then
        info "axonflow_app_role already has a password — skipping ALTER (set FORCE_RESET=1 to rotate)."
        SKIP_APP_ALTER="true"
    fi
    if [[ "$ADMIN_HAS_PW" == "t" ]]; then
        info "axonflow_platform_admin already has a password — skipping ALTER (set FORCE_RESET=1 to rotate)."
        SKIP_ADMIN_ALTER="true"
    fi
fi
pass "Idempotency state read"
printf "\n"

# ---------------------------------------------------------------------------
# Check 3 — ALTER ROLE … WITH PASSWORD (via secure tempfile)
# ---------------------------------------------------------------------------
printf "%b%b[3/5] ALTER ROLE WITH PASSWORD%b\n" "$BOLD" "$BLUE" "$NC"

TMPSQL=$(mktemp /tmp/v9-provision-app-role.XXXXXX.sql)
chmod 600 "$TMPSQL"

# Build the SQL — single transaction so partial failures don't half-apply.
# Wrap `SET LOCAL log_statement TO none` in a DO block with EXCEPTION
# handling: log_statement is a superuser-context GUC, and some hosted PG
# flavors (Aurora Serverless v2, RDS Proxy) reject the SET even for the
# RDS master. EXCEPTION WHEN insufficient_privilege swallows the rejection
# so the ALTER ROLE still runs — the only cost is that the literal password
# may appear in the server's pg_stat_statements (which redacts ALTER ROLE
# passwords anyway) or in log_statement=ddl audit logs.
# Re-affirms NOBYPASSRLS / BYPASSRLS so any prior accidental ALTER is
# corrected in the same pass.
{
    echo "BEGIN;"
    echo "DO \$\$ BEGIN"
    echo "  EXECUTE 'SET LOCAL log_statement TO none';"
    echo "EXCEPTION WHEN insufficient_privilege THEN"
    echo "  RAISE NOTICE 'log_statement SET rejected (host policy); ALTER ROLE may appear in server audit log';"
    echo "END \$\$;"
    if [[ "$SKIP_APP_ALTER" != "true" ]]; then
        echo "ALTER ROLE axonflow_app_role WITH LOGIN NOBYPASSRLS PASSWORD '${APP_ROLE_PASSWORD}';"
    else
        echo "-- skip: axonflow_app_role already has a password (FORCE_RESET not set)"
    fi
    if [[ "$SKIP_ADMIN_ALTER" != "true" ]]; then
        echo "ALTER ROLE axonflow_platform_admin WITH LOGIN BYPASSRLS PASSWORD '${PLATFORM_ADMIN_PASSWORD}';"
    else
        echo "-- skip: axonflow_platform_admin already has a password (FORCE_RESET not set)"
    fi
    echo "COMMIT;"
} > "$TMPSQL"

# Execute. Password flows via PGPASSWORD env, NOT command line. ON_ERROR_STOP=1
# so transient errors abort instead of half-committing.
if ! PGPASSWORD="$MASTER_PASSWORD" \
        PGSSLMODE="$MASTER_SSLMODE" \
        PGOPTIONS='--client-min-messages=warning' \
        psql --no-psqlrc -v ON_ERROR_STOP=1 \
            -h "$MASTER_HOST" -p "$MASTER_PORT" \
            -U "$MASTER_USER" -d "$MASTER_DBNAME" \
            -f "$TMPSQL" >/dev/null 2>&1; then
    fail "ALTER ROLE transaction failed" \
        "Common causes: master role lacks CREATEROLE/SUPERUSER, password violates pg_password_check rules, or 'SET LOCAL log_statement TO none' is rejected by the host's parameter group (hosted PG flavors that block superuser-only SETs). Re-run with PGOPTIONS unset (or via psql -e -f) to see the underlying error."
    printf "\n%b❌ FAIL — ALTER ROLE failed. See psql output above.%b\n" "$RED" "$NC"
    exit 1
fi

if [[ "$SKIP_APP_ALTER" == "true" && "$SKIP_ADMIN_ALTER" == "true" ]]; then
    pass "ALTER ROLE skipped — both passwords already set (idempotent)"
elif [[ "$SKIP_APP_ALTER" == "true" ]]; then
    pass "ALTER ROLE axonflow_platform_admin issued; axonflow_app_role skipped (idempotent)"
elif [[ "$SKIP_ADMIN_ALTER" == "true" ]]; then
    pass "ALTER ROLE axonflow_app_role issued; axonflow_platform_admin skipped (idempotent)"
else
    pass "ALTER ROLE issued for both roles"
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 4 — Connectivity probe AS each role using its new password
# ---------------------------------------------------------------------------
printf "%b%b[4/5] Connectivity AS axonflow_app_role + axonflow_platform_admin%b\n" "$BOLD" "$BLUE" "$NC"

if [[ "${SKIP_CONNECTIVITY_TEST:-}" == "1" ]]; then
    warn "Connectivity test skipped via SKIP_CONNECTIVITY_TEST=1" \
        "Re-run without SKIP_CONNECTIVITY_TEST to prove the ALTER actually took. This is the only smoke that catches a wrong-password ALTER."
else
    # AS app role: SELECT current_user should return 'axonflow_app_role'.
    APP_USER=$(psql_as_role "axonflow_app_role" "$APP_ROLE_PASSWORD" "SELECT current_user" 2>/dev/null || echo "")
    if [[ "$APP_USER" == "axonflow_app_role" ]]; then
        pass "Connected AS axonflow_app_role (current_user matches)"
    else
        fail "Could not connect AS axonflow_app_role" \
            "psql returned current_user='$APP_USER' (expected 'axonflow_app_role'). Likely causes: pg_hba.conf rejects this role, password did not take, or PGSSLMODE mismatch."
    fi

    # AS admin role: SELECT current_user should return 'axonflow_platform_admin'.
    ADMIN_USER=$(psql_as_role "axonflow_platform_admin" "$PLATFORM_ADMIN_PASSWORD" "SELECT current_user" 2>/dev/null || echo "")
    if [[ "$ADMIN_USER" == "axonflow_platform_admin" ]]; then
        pass "Connected AS axonflow_platform_admin (current_user matches)"
    else
        fail "Could not connect AS axonflow_platform_admin" \
            "psql returned current_user='$ADMIN_USER' (expected 'axonflow_platform_admin'). Same diagnostics as above."
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 5 — Functional smoke: app_role honors RLS, admin role bypasses
# ---------------------------------------------------------------------------
printf "%b%b[5/5] RLS attribute smoke (NOBYPASSRLS vs BYPASSRLS)%b\n" "$BOLD" "$BLUE" "$NC"

if [[ "${SKIP_CONNECTIVITY_TEST:-}" == "1" ]]; then
    info "Skipped (SKIP_CONNECTIVITY_TEST=1)"
else
    # Re-read rolbypassrls after the ALTER. The ALTER ROLE … WITH LOGIN … PASSWORD
    # syntax doesn't reset rolbypassrls in the same statement, but we also
    # included NOBYPASSRLS / BYPASSRLS clauses defensively above. This smoke
    # verifies the post-state matches the contract.
    APP_BYPASS_POST=$(psql_master "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'axonflow_app_role'")
    ADMIN_BYPASS_POST=$(psql_master "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'axonflow_platform_admin'")

    if [[ "$APP_BYPASS_POST" == "f" ]]; then
        pass "axonflow_app_role NOBYPASSRLS (RLS-honoring; contract OK)"
    else
        fail "axonflow_app_role BYPASSRLS unexpectedly true post-ALTER" \
            "Run: ALTER ROLE axonflow_app_role NOBYPASSRLS;"
    fi
    if [[ "$ADMIN_BYPASS_POST" == "t" ]]; then
        pass "axonflow_platform_admin BYPASSRLS (cross-org workers OK; contract OK)"
    else
        fail "axonflow_platform_admin BYPASSRLS unexpectedly false post-ALTER" \
            "Run: ALTER ROLE axonflow_platform_admin BYPASSRLS;"
    fi
fi
printf "\n"

# ---------------------------------------------------------------------------
# Final verdict
# ---------------------------------------------------------------------------
printf "%b%b═══════════════════════════════════════════════════════════════════════%b\n" "$BOLD" "$BLUE" "$NC"
printf "%b%bv9 Provision App Role — Final Verdict%b\n" "$BOLD" "$BLUE" "$NC"
printf "%b%b═══════════════════════════════════════════════════════════════════════%b\n\n" "$BOLD" "$BLUE" "$NC"

printf "  %bPASS%b: %d checks\n" "$GREEN" "$NC" "${#PASS_CHECKS[@]}"
printf "  %bWARN%b: %d checks\n" "$YELLOW" "$NC" "${#WARN_CHECKS[@]}"
printf "  %bFAIL%b: %d checks\n\n" "$RED" "$NC" "${#FAIL_CHECKS[@]}"

if [[ ${#FAIL_CHECKS[@]} -gt 0 ]]; then
    printf "%b❌ FAIL — DO NOT FLIP AXONFLOW_DB_USE_APP_ROLE=true.%b Resolve all FAILs:\n\n" "$RED" "$NC"
    for entry in "${FAIL_CHECKS[@]}"; do
        printf "  - %s\n" "${entry%%|*}"
        printf "    %s\n" "${entry#*|}"
    done
    printf "\n"
    exit 1
fi

if [[ ${#WARN_CHECKS[@]} -gt 0 ]]; then
    printf "%b⚠️  PROCEED WITH CAUTION.%b WARNINGs require operator review:\n\n" "$YELLOW" "$NC"
    for entry in "${WARN_CHECKS[@]}"; do
        printf "  - %s\n" "${entry%%|*}"
        printf "    %s\n" "${entry#*|}"
    done
    printf "\n"
fi

printf "%b✅ PASS — passwords provisioned and connectivity verified.%b\n\n" "$GREEN" "$NC"
printf "Next steps:\n"
printf "  1. Store the two passwords as Secrets Manager DSN entries (or your\n"
printf "     environment's secret store) — see provision-app-role.yml for the\n"
printf "     AWS-specific naming convention (db-app-role-url, db-platform-admin-url).\n"
printf "  2. Add AXONFLOW_DB_APP_ROLE_URL + AXONFLOW_DB_PLATFORM_ADMIN_URL env refs\n"
printf "     to the agent + orchestrator task definitions.\n"
printf "  3. Remove any explicit AXONFLOW_DB_USE_APP_ROLE='false' override (the\n"
printf "     v9.0.0 binary defaults to true).\n"
printf "  4. Roll the image (ECS force-new-deployment) so tasks pick up the new env.\n"
printf "  5. Verify pg_stat_activity shows agent connections under usename=axonflow_app_role.\n\n"
exit 0
