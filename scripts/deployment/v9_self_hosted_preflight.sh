#!/usr/bin/env bash
#
# v9 Self-Hosted Preflight — Epic #2230 Phase 7
#
# Purpose: Operators of self-hosted / in-VPC AxonFlow deployments run this BEFORE
#          pulling the v9 platform image. The script validates that the
#          deployment can migrate cleanly from v7.x/v8.x to v9 — every check
#          either PASSes, WARNs, or FAILs with concrete remediation.
#
# Refuses to print a final PASS unless every check passes. WARNINGs prompt
# explicit operator confirmation; FAILs require operator action before retry.
#
# Companion doc: technical-docs/v9_phase7_self_hosted_migration.md
# Customer guide: axonflow-docs/docs/operators/_v9-self-hosted-upgrade-guide.md
#
# Usage:
#   DATABASE_URL="postgres://..." ./v9_self_hosted_preflight.sh
#
#   With explicit env vars (override DATABASE_URL parsing):
#   PGHOST=db.internal PGPORT=5432 PGUSER=axonflow PGPASSWORD=... PGDATABASE=axonflow \
#     ./v9_self_hosted_preflight.sh
#
#   For an ECS-Fargate deployment, also export:
#   ECS_CLUSTER=axonflow-cluster ECS_AGENT_SERVICE=axonflow-agent \
#     ./v9_self_hosted_preflight.sh
#
# Exit codes:
#   0 — all checks pass
#   1 — at least one FAIL
#   2 — script error (psql missing, DATABASE_URL unset, etc.)

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
# Setup: locate psql, resolve DATABASE_URL, prove connectivity
# ---------------------------------------------------------------------------

printf "%b%bv9 Self-Hosted Preflight — Epic #2230 Phase 7%b\n" "$BOLD" "$BLUE" "$NC"
printf "Date: %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf "Run as: %s\n\n" "$(id -un 2>/dev/null || echo unknown)"

if ! command -v psql >/dev/null 2>&1; then
    printf "%bScript error:%b psql not found on PATH. Install postgresql-client and retry.\n" "$RED" "$NC"
    exit 2
fi

if [[ -z "${DATABASE_URL:-}" && -z "${PGHOST:-}" ]]; then
    printf "%bScript error:%b set DATABASE_URL or PGHOST/PGUSER/PGDATABASE before invoking.\n" "$RED" "$NC"
    exit 2
fi

# Wrapper: run a SQL snippet, suppress NOTICE+WARNING noise, return raw stdout.
# Uses --no-psqlrc so an operator's interactive .psqlrc doesn't change output.
# tail -1 defends against multi-line output where stderr/stdout interleaving or
# `RAISE NOTICE` debug from a prior migration sneaks ahead of the numeric result —
# we always want the LAST line, which is the actual scalar return value.
psql_q() {
    local sql="$1"
    if [[ -n "${DATABASE_URL:-}" ]]; then
        PGOPTIONS='--client-min-messages=warning' \
            psql --no-psqlrc -At -d "$DATABASE_URL" -c "$sql" 2>/dev/null | tail -1
    else
        PGOPTIONS='--client-min-messages=warning' \
            psql --no-psqlrc -At -c "$sql" 2>/dev/null | tail -1
    fi
}

# psql_q_exists wraps a table-existence probe. Many checks below need to
# distinguish "table absent" (legitimate on fresh installs) from "connectivity
# failed" — the latter must surface as a script error, not a silent zero.
psql_table_exists() {
    local tname="$1"
    [[ "$(psql_q "SELECT 1 FROM information_schema.tables WHERE table_name = '$tname'")" == "1" ]]
}

# Probe connectivity early — every other check assumes the DB is reachable.
if ! psql_q "SELECT 1" >/dev/null 2>&1; then
    printf "%bScript error:%b cannot connect to Postgres. Verify DATABASE_URL/PG* envs.\n" "$RED" "$NC"
    exit 2
fi
info "Database connectivity OK"
printf "\n"

# ---------------------------------------------------------------------------
# Check 1 — Postgres version ≥ 14
# ---------------------------------------------------------------------------
printf "%b%b[1/8] Postgres version%b\n" "$BOLD" "$BLUE" "$NC"

PG_VERSION_NUM=$(psql_q "SHOW server_version_num" 2>/dev/null || echo "0")
PG_VERSION=$(psql_q "SHOW server_version" 2>/dev/null || echo "unknown")

if [[ "$PG_VERSION_NUM" -ge 140000 ]]; then
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
printf "%b%b[2/8] Schema migrations state%b\n" "$BOLD" "$BLUE" "$NC"

if ! psql_q "SELECT 1 FROM information_schema.tables WHERE table_name = 'schema_migrations'" | grep -q 1; then
    fail "schema_migrations table missing" \
        "This deployment has never run the AxonFlow migration runner. Run on a v8.x install first, then re-run preflight."
else
    # Highest version applied. v8.x ships through migration 087; v9 ships
    # 088-103 in the next image pull. Anything ≥088 means the operator is
    # already on v9 (re-run is harmless).
    MAX_APPLIED=$(psql_q "SELECT COALESCE(MAX(CAST(version AS INTEGER)), 0) FROM schema_migrations WHERE success = true AND version ~ '^[0-9]+\$'" 2>/dev/null || echo "0")
    # Count of failed migrations — boot loop indicator.
    FAILED_COUNT=$(psql_q "SELECT COUNT(*) FROM schema_migrations WHERE success = false" 2>/dev/null || echo "0")

    if [[ "$FAILED_COUNT" -gt 0 ]]; then
        FAILED_LIST=$(psql_q "SELECT version || ':' || COALESCE(name, '<unnamed>') FROM schema_migrations WHERE success = false ORDER BY version LIMIT 5")
        fail "Failed migrations present (boot loop risk)" \
            "$FAILED_COUNT migration(s) marked success=false. Fix or manually mark resolved before v9 upgrade. First 5: $FAILED_LIST"
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
printf "%b%b[3/8] Empty org_id row scan (Migration 094 Pass-2 preview)%b\n" "$BOLD" "$BLUE" "$NC"

# Tables that Migration 094 backfills. Same set as the migration's verification
# report (lines 555-567 of 094_v9_org_id_backfill.sql). For each table that
# exists with an org_id column, count rows with empty/NULL org_id AND a
# tenant_id NOT matching cs_* (so we count only Pass-2 candidates, not the
# Pass-1 cs_* rows which get a different value).
TOTAL_EMPTY=0
PASS2_TABLES="audit_logs agent_audit_logs mcp_query_audits llm_call_audits static_policies dynamic_policies policy_evaluations service_identities execution_history"

for tname in $PASS2_TABLES; do
    EXISTS=$(psql_q "SELECT 1 FROM information_schema.tables WHERE table_name = '$tname'" 2>/dev/null || echo "")
    HAS_ORG=$(psql_q "SELECT 1 FROM information_schema.columns WHERE table_name = '$tname' AND column_name = 'org_id'" 2>/dev/null || echo "")
    HAS_TENANT=$(psql_q "SELECT 1 FROM information_schema.columns WHERE table_name = '$tname' AND column_name = 'tenant_id'" 2>/dev/null || echo "")

    if [[ -z "$EXISTS" || -z "$HAS_ORG" ]]; then
        continue
    fi

    if [[ -n "$HAS_TENANT" ]]; then
        CNT=$(psql_q "SELECT COUNT(*) FROM $tname WHERE (org_id IS NULL OR org_id = '') AND (tenant_id IS NULL OR tenant_id NOT LIKE 'cs\\_%' ESCAPE '\\')" 2>/dev/null || echo "0")
    else
        CNT=$(psql_q "SELECT COUNT(*) FROM $tname WHERE org_id IS NULL OR org_id = ''" 2>/dev/null || echo "0")
    fi

    if [[ "$CNT" -gt 0 ]]; then
        info "  $tname: $CNT row(s) will be stamped with app.deployment_org_id"
        TOTAL_EMPTY=$((TOTAL_EMPTY + CNT))
    fi
done

if [[ "$TOTAL_EMPTY" -eq 0 ]]; then
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
printf "%b%b[4/8] Agent task env vars (DEPLOYMENT_KIND, ORG_ID)%b\n" "$BOLD" "$BLUE" "$NC"

# Three discovery modes, in order of preference:
#   (1) ECS_CLUSTER + ECS_AGENT_SERVICE — query the live ECS task def
#   (2) AGENT_ENV_FILE — operator path to a docker-compose .env or systemd EnvironmentFile
#   (3) Read this process's env (operator ran preflight ON the agent host)
#
# The Postgres-side proxy: regardless of source, app.deployment_org_id +
# app.deployment_kind GUCs are seeded by the agent before the migration
# runner fires (run.go::setMigrationSessionVars). If the agent has already
# run migrations on this DB, those GUCs are visible in pg_settings → we
# can read them post-hoc as a soft sanity check.

# Capture inherited env values FIRST, before the discovery branches below
# (which would shadow them). Operator-provided env values are the "current
# shell environment" discovery mode's source of truth.
_ENV_DEPLOYMENT_KIND="${DEPLOYMENT_KIND:-}"
_ENV_ORG_ID="${ORG_ID:-}"
DEPLOYMENT_KIND=""
ORG_ID=""

if [[ -n "${ECS_CLUSTER:-}" && -n "${ECS_AGENT_SERVICE:-}" ]] && command -v aws >/dev/null 2>&1; then
    info "Discovering env vars from ECS task def ($ECS_CLUSTER/$ECS_AGENT_SERVICE)"
    TASK_DEF_ARN=$(aws ecs describe-services --cluster "$ECS_CLUSTER" --services "$ECS_AGENT_SERVICE" \
        --query 'services[0].taskDefinition' --output text 2>/dev/null || echo "")
    if [[ -n "$TASK_DEF_ARN" && "$TASK_DEF_ARN" != "None" ]]; then
        # Use aws --query jmespath directly to extract env values — avoids the
        # python3 dependency that v1 had. The double-bracket [0][0] flattens
        # the per-container array + per-env-var array.
        DEPLOYMENT_KIND=$(aws ecs describe-task-definition --task-definition "$TASK_DEF_ARN" \
            --query 'taskDefinition.containerDefinitions[?name==`agent`||name==`axonflow-agent`].environment[?name==`DEPLOYMENT_KIND`].value | [0][0]' \
            --output text 2>/dev/null || echo "")
        ORG_ID=$(aws ecs describe-task-definition --task-definition "$TASK_DEF_ARN" \
            --query 'taskDefinition.containerDefinitions[?name==`agent`||name==`axonflow-agent`].environment[?name==`ORG_ID`].value | [0][0]' \
            --output text 2>/dev/null || echo "")
        # aws CLI returns "None" (literal string) when the JMESPath finds no match — normalize to empty.
        [[ "$DEPLOYMENT_KIND" == "None" ]] && DEPLOYMENT_KIND=""
        [[ "$ORG_ID" == "None" ]] && ORG_ID=""
    fi
elif [[ -n "${AGENT_ENV_FILE:-}" && -r "${AGENT_ENV_FILE}" ]]; then
    info "Discovering env vars from AGENT_ENV_FILE=$AGENT_ENV_FILE"
    # Strip surrounding double OR single quotes (sed handles both); operators
    # write `ORG_ID="..."` or `ORG_ID='...'` interchangeably in docker-compose envs.
    DEPLOYMENT_KIND=$(grep -E '^DEPLOYMENT_KIND=' "$AGENT_ENV_FILE" | head -1 | cut -d= -f2- | sed -E "s/^[\"']//; s/[\"']$//" || echo "")
    ORG_ID=$(grep -E '^ORG_ID=' "$AGENT_ENV_FILE" | head -1 | cut -d= -f2- | sed -E "s/^[\"']//; s/[\"']$//" || echo "")
else
    info "Discovering env vars from current shell environment"
    DEPLOYMENT_KIND="$_ENV_DEPLOYMENT_KIND"
    ORG_ID="$_ENV_ORG_ID"
fi

# Cross-check with Postgres GUCs from a prior agent boot (if any). Used as a
# warning signal when the env-side read returns empty.
GUC_ORG=$(psql_q "SELECT current_setting('app.deployment_org_id', true)" 2>/dev/null || echo "")
GUC_KIND=$(psql_q "SELECT current_setting('app.deployment_kind', true)" 2>/dev/null || echo "")

# DEPLOYMENT_KIND check
if [[ -z "$DEPLOYMENT_KIND" && -z "$GUC_KIND" ]]; then
    warn "DEPLOYMENT_KIND not discoverable from env or DB GUC" \
        "On a real (non-docker-compose) deployment, set DEPLOYMENT_KIND=production on the agent task def. CFN templates already do this. If this is local docker-compose, the default 'dev' is correct and this WARN is expected."
elif [[ "$DEPLOYMENT_KIND" == "production" || "$GUC_KIND" == "production" ]]; then
    pass "DEPLOYMENT_KIND=production (real deployment)"
elif [[ "$DEPLOYMENT_KIND" == "dev" || "$GUC_KIND" == "dev" ]]; then
    info "DEPLOYMENT_KIND=dev — preflight will treat this as local docker-compose."
    info "If this is a real customer deployment, change to 'production' BEFORE upgrade (Migration 094 #2320 prod-safety branch fires otherwise)."
    pass "DEPLOYMENT_KIND=dev (acceptable for local docker-compose / community-mode)"
else
    warn "DEPLOYMENT_KIND='$DEPLOYMENT_KIND' (unexpected value)" \
        "Expected 'production' on real stacks or 'dev' on docker-compose. Verify task def env before upgrade."
fi

# ORG_ID check
if [[ -z "$ORG_ID" && -z "$GUC_ORG" ]]; then
    if [[ "$DEPLOYMENT_KIND" == "production" || "$GUC_KIND" == "production" ]]; then
        fail "ORG_ID env not set on a production deployment" \
            "Migration 094 #2320 prod-safety branch will ABORT the upgrade. Set ORG_ID to your customer/account identifier (NOT the literal 'local-dev-org' — that's the dev sentinel) BEFORE pulling the v9 image."
    else
        info "ORG_ID env unset — agent will default to 'local-dev-org' (acceptable for docker-compose / community-mode)."
        pass "ORG_ID unset, DEPLOYMENT_KIND=dev — local-dev-org fallback is the intended path"
    fi
elif [[ "$ORG_ID" == "local-dev-org" || "$GUC_ORG" == "local-dev-org" ]]; then
    if [[ "$DEPLOYMENT_KIND" == "production" || "$GUC_KIND" == "production" ]]; then
        fail "ORG_ID='local-dev-org' on a production deployment" \
            "This is the dev sentinel. Set ORG_ID to your real customer/account identifier (e.g., 'acme-corp')."
    else
        pass "ORG_ID=local-dev-org (intended for docker-compose / community-mode)"
    fi
else
    pass "ORG_ID='${ORG_ID:-$GUC_ORG}' set"
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 5 — axonflow_app_role exists + NOBYPASSRLS (migration 098 will create
# it if absent; this check is informational for operators who pre-create roles)
# ---------------------------------------------------------------------------
printf "%b%b[5/8] Postgres roles (axonflow_app_role + axonflow_platform_admin)%b\n" "$BOLD" "$BLUE" "$NC"

APP_ROLE_EXISTS=$(psql_q "SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role'" 2>/dev/null || echo "")
ADMIN_ROLE_EXISTS=$(psql_q "SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin'" 2>/dev/null || echo "")

if [[ -z "$APP_ROLE_EXISTS" ]]; then
    info "axonflow_app_role does not exist — migration 098 will create it."
    pass "axonflow_app_role absent (will be created by migration 098)"
else
    APP_ROLE_BYPASSRLS=$(psql_q "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'axonflow_app_role'" 2>/dev/null || echo "f")
    APP_ROLE_CANLOGIN=$(psql_q "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'axonflow_app_role'" 2>/dev/null || echo "f")
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
        # hide it — degrade silently. If unset, the role cannot authenticate
        # via password auth and AXONFLOW_DB_USE_APP_ROLE=true will fail to
        # connect. Point operators at the canonical fix.
        APP_ROLE_HAS_PW=$(psql_q "SELECT CASE WHEN rolpassword IS NOT NULL THEN 't' ELSE 'f' END FROM pg_authid WHERE rolname = 'axonflow_app_role'" 2>/dev/null || echo "unknown")
        if [[ "$APP_ROLE_HAS_PW" == "f" ]]; then
            warn "axonflow_app_role has no password set" \
                "Migration 098 creates the role with LOGIN capability but no password — the role cannot authenticate until provisioned. BEFORE flipping AXONFLOW_DB_USE_APP_ROLE=true, run: scripts/operators/provision-app-role.sh (see technical-docs/v9_phase8_rls_rollout.md §'Mechanism recap'). Skipping this step results in the agent failing to connect on boot."
        fi
    fi
fi

if [[ -z "$ADMIN_ROLE_EXISTS" ]]; then
    info "axonflow_platform_admin does not exist — migration 098 will create it."
    pass "axonflow_platform_admin absent (will be created by migration 098)"
else
    ADMIN_ROLE_BYPASSRLS=$(psql_q "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'axonflow_platform_admin'" 2>/dev/null || echo "f")
    ADMIN_ROLE_CANLOGIN=$(psql_q "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'axonflow_platform_admin'" 2>/dev/null || echo "f")
    if [[ "$ADMIN_ROLE_BYPASSRLS" != "t" ]]; then
        fail "axonflow_platform_admin exists but lacks BYPASSRLS" \
            "v9 contract: platform admin role MUST bypass RLS for cross-org workers. Run: ALTER ROLE axonflow_platform_admin BYPASSRLS;"
    elif [[ "$ADMIN_ROLE_CANLOGIN" != "t" ]]; then
        fail "axonflow_platform_admin exists but lacks LOGIN" \
            "Run: ALTER ROLE axonflow_platform_admin LOGIN; then provision a password via scripts/operators/provision-app-role.sh."
    else
        pass "axonflow_platform_admin exists with BYPASSRLS + LOGIN (v9 contract)"
        ADMIN_ROLE_HAS_PW=$(psql_q "SELECT CASE WHEN rolpassword IS NOT NULL THEN 't' ELSE 'f' END FROM pg_authid WHERE rolname = 'axonflow_platform_admin'" 2>/dev/null || echo "unknown")
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
printf "%b%b[6/8] Backup / snapshot policy%b\n" "$BOLD" "$BLUE" "$NC"

# Three discovery modes:
#   (1) RDS_INSTANCE_IDENTIFIER set + aws CLI available → query RDS
#   (2) PG_BACKUP_TOOL set (e.g., "pgbackrest", "barman") → trust the operator
#   (3) Else → WARN; rollback contract requires snapshot
if [[ -n "${RDS_INSTANCE_IDENTIFIER:-}" ]] && command -v aws >/dev/null 2>&1; then
    info "Querying RDS instance $RDS_INSTANCE_IDENTIFIER for backup settings"
    BACKUP_RETENTION=$(aws rds describe-db-instances --db-instance-identifier "$RDS_INSTANCE_IDENTIFIER" \
        --query 'DBInstances[0].BackupRetentionPeriod' --output text 2>/dev/null || echo "0")
    if [[ "$BACKUP_RETENTION" -ge 7 ]]; then
        pass "RDS automated backups enabled (retention: $BACKUP_RETENTION days)"
    elif [[ "$BACKUP_RETENTION" -ge 1 ]]; then
        warn "RDS backup retention is $BACKUP_RETENTION day(s)" \
            "v9 rollback contract recommends ≥7 days. Increase BackupRetentionPeriod on the RDS instance."
    else
        fail "RDS automated backups DISABLED" \
            "v9 schema migrations are forward-only — a snapshot is the rollback contract. Set BackupRetentionPeriod ≥7 on the RDS instance, OR take a manual snapshot BEFORE pulling the v9 image, then re-run preflight."
    fi
elif [[ -n "${PG_BACKUP_TOOL:-}" ]]; then
    pass "Operator-declared backup tool: $PG_BACKUP_TOOL (operator-verified)"
else
    warn "No backup/snapshot tool discovered" \
        "Set RDS_INSTANCE_IDENTIFIER (for AWS RDS) or PG_BACKUP_TOOL (for pgbackrest/barman/etc.) before re-running. v9 rollback contract REQUIRES a snapshot — operator MUST manually verify a recent snapshot exists before pulling the v9 image."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Check 7 — local-dev-org default preservation (Phase 7 contract guard)
# ---------------------------------------------------------------------------
printf "%b%b[7/8] local-dev-org default preservation%b\n" "$BOLD" "$BLUE" "$NC"

# This check is informational/contractual: any historical row with
# org_id='local-dev-org' must remain intact after v9 upgrade. We don't
# REWRITE this value — we just inform the operator.
if ! psql_table_exists "organizations"; then
    info "organizations table does not exist on this deployment yet — clean install."
    pass "local-dev-org row absent (organizations table not yet created)"
else
    LOCAL_DEV_ROWS=$(psql_q "SELECT COUNT(*) FROM organizations WHERE org_id = 'local-dev-org'")
    [[ -z "$LOCAL_DEV_ROWS" ]] && LOCAL_DEV_ROWS="0"
    if [[ "$LOCAL_DEV_ROWS" -gt 0 ]]; then
        info "organizations table contains $LOCAL_DEV_ROWS row(s) keyed on 'local-dev-org'."
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
printf "%b%b[8/8] App-role env pairing (refuse-to-boot guard preview)%b\n" "$BOLD" "$BLUE" "$NC"

# Discover the two env vars using the same precedence as Check 4 (ECS task def,
# then AGENT_ENV_FILE, then current shell). The v9 agent / orchestrator /
# customer-portal binaries refuse to boot when AXONFLOW_DB_USE_APP_ROLE=true
# (the v9.0.0 default — unset also means true) AND
# AXONFLOW_DB_PLATFORM_ADMIN_URL is unset. Surfacing it here lets the operator
# fix the env BEFORE pulling the image, instead of finding out from a FATAL
# log line on first boot.

# Capture inherited shell values, then clear so the discovery branches don't
# silently shadow them (same idiom as Check 4).
_ENV_USE_APP_ROLE="${AXONFLOW_DB_USE_APP_ROLE:-}"
# Treat whitespace-only as unset (mirror the binary's TrimSpace check).
_ENV_ADMIN_URL_TRIMMED="${AXONFLOW_DB_PLATFORM_ADMIN_URL:-}"
_ENV_ADMIN_URL_TRIMMED="${_ENV_ADMIN_URL_TRIMMED#"${_ENV_ADMIN_URL_TRIMMED%%[![:space:]]*}"}"
_ENV_ADMIN_URL_TRIMMED="${_ENV_ADMIN_URL_TRIMMED%"${_ENV_ADMIN_URL_TRIMMED##*[![:space:]]}"}"
_ENV_PLATFORM_ADMIN_URL_SET="no"
[[ -n "$_ENV_ADMIN_URL_TRIMMED" ]] && _ENV_PLATFORM_ADMIN_URL_SET="yes"
USE_APP_ROLE=""
PLATFORM_ADMIN_URL_SET=""

if [[ -n "${ECS_CLUSTER:-}" && -n "${ECS_AGENT_SERVICE:-}" ]] && command -v aws >/dev/null 2>&1; then
    info "Discovering app-role env vars from ECS task def ($ECS_CLUSTER/$ECS_AGENT_SERVICE)"
    if [[ -n "${TASK_DEF_ARN:-}" && "$TASK_DEF_ARN" != "None" ]]; then
        USE_APP_ROLE=$(aws ecs describe-task-definition --task-definition "$TASK_DEF_ARN" \
            --query 'taskDefinition.containerDefinitions[?name==`agent`||name==`axonflow-agent`].environment[?name==`AXONFLOW_DB_USE_APP_ROLE`].value | [0][0]' \
            --output text 2>/dev/null || echo "")
        [[ "$USE_APP_ROLE" == "None" ]] && USE_APP_ROLE=""

        # AXONFLOW_DB_PLATFORM_ADMIN_URL is typically wired as a secret ref
        # (valueFrom), not a literal env value. We treat either "name in
        # environment[]" OR "name in secrets[]" as "set".
        ADMIN_URL_LITERAL=$(aws ecs describe-task-definition --task-definition "$TASK_DEF_ARN" \
            --query 'taskDefinition.containerDefinitions[?name==`agent`||name==`axonflow-agent`].environment[?name==`AXONFLOW_DB_PLATFORM_ADMIN_URL`].value | [0][0]' \
            --output text 2>/dev/null || echo "")
        ADMIN_URL_SECRET=$(aws ecs describe-task-definition --task-definition "$TASK_DEF_ARN" \
            --query 'taskDefinition.containerDefinitions[?name==`agent`||name==`axonflow-agent`].secrets[?name==`AXONFLOW_DB_PLATFORM_ADMIN_URL`].valueFrom | [0][0]' \
            --output text 2>/dev/null || echo "")
        if [[ ( -n "$ADMIN_URL_LITERAL" && "$ADMIN_URL_LITERAL" != "None" ) \
           || ( -n "$ADMIN_URL_SECRET"  && "$ADMIN_URL_SECRET"  != "None" ) ]]; then
            PLATFORM_ADMIN_URL_SET="yes"
        else
            PLATFORM_ADMIN_URL_SET="no"
        fi
    fi
elif [[ -n "${AGENT_ENV_FILE:-}" && -r "${AGENT_ENV_FILE}" ]]; then
    info "Discovering app-role env vars from AGENT_ENV_FILE=$AGENT_ENV_FILE"
    USE_APP_ROLE=$(grep -E '^AXONFLOW_DB_USE_APP_ROLE=' "$AGENT_ENV_FILE" | head -1 | cut -d= -f2- | sed -E "s/^[\"']//; s/[\"']$//" || echo "")
    # Extract the VALUE (not just key presence) and treat empty/whitespace as
    # unset — mirrors the binary's strings.TrimSpace(os.Getenv(…)) != "" check.
    # An env file with the line `AXONFLOW_DB_PLATFORM_ADMIN_URL=` (placeholder
    # stub) would PASS a key-only grep but FATAL the binary on boot.
    ADMIN_URL_VALUE=$(grep -E '^AXONFLOW_DB_PLATFORM_ADMIN_URL=' "$AGENT_ENV_FILE" | head -1 | cut -d= -f2- | sed -E "s/^[\"']//; s/[\"']$//" || echo "")
    # Trim leading/trailing whitespace.
    ADMIN_URL_VALUE="${ADMIN_URL_VALUE#"${ADMIN_URL_VALUE%%[![:space:]]*}"}"
    ADMIN_URL_VALUE="${ADMIN_URL_VALUE%"${ADMIN_URL_VALUE##*[![:space:]]}"}"
    if [[ -n "$ADMIN_URL_VALUE" ]]; then
        PLATFORM_ADMIN_URL_SET="yes"
    else
        PLATFORM_ADMIN_URL_SET="no"
    fi
else
    info "Discovering app-role env vars from current shell environment"
    USE_APP_ROLE="$_ENV_USE_APP_ROLE"
    PLATFORM_ADMIN_URL_SET="$_ENV_PLATFORM_ADMIN_URL_SET"
fi

# Mirror the binary's UseAppRoleEnabled() semantics: unset OR truthy → true.
# Only explicit "false"/"FALSE"/"False"/"0" disables.
USE_APP_ROLE_EFFECTIVE="true"
case "$USE_APP_ROLE" in
    false|FALSE|False|0) USE_APP_ROLE_EFFECTIVE="false" ;;
esac

if [[ "$USE_APP_ROLE_EFFECTIVE" == "false" ]]; then
    info "AXONFLOW_DB_USE_APP_ROLE='$USE_APP_ROLE' — legacy v8.x posture (RDS master role connects, FORCE RLS dormant)."
    pass "App-role posture is legacy (no admin pool required)"
elif [[ "$PLATFORM_ADMIN_URL_SET" == "yes" ]]; then
    pass "AXONFLOW_DB_USE_APP_ROLE=true paired with AXONFLOW_DB_PLATFORM_ADMIN_URL set"
else
    fail "AXONFLOW_DB_USE_APP_ROLE=true with AXONFLOW_DB_PLATFORM_ADMIN_URL unset" \
        "The v9 agent / orchestrator / customer-portal binaries REFUSE TO BOOT under this combination — the silent fallback to the request-traffic pool would defeat FORCE RLS on cross-org workers (marketplace metering, community-saas sweep / recovery, node monitor, customer-portal admin handlers). Either set AXONFLOW_DB_PLATFORM_ADMIN_URL to a DSN authenticating as axonflow_platform_admin (mirrors AXONFLOW_DB_APP_ROLE_URL), or set AXONFLOW_DB_USE_APP_ROLE=false to opt out of the v9.0.0 default and run under the legacy v8.x posture. See technical-docs/v9_phase7_self_hosted_migration.md §'Change 4'."
fi

# Customized-handler advisory (informational — preflight can't scan the
# operator's fork from inside the script). Always emit at WARN-level when
# USE_APP_ROLE_EFFECTIVE is true so a fork operator sees the audit ask.
if [[ "$USE_APP_ROLE_EFFECTIVE" == "true" ]]; then
    warn "Customized-handler audit required before flip" \
        "Operators running stock v9 code can ignore this. Operators with FORKED or in-tree-customized handlers MUST audit every db.ExecContext / tx.ExecContext write into a v9-RLS table (see migrations/core/018 ENABLE-RLS template + migrations/core/099/101/103/105/107 FORCE batches). Each write must either wrap WithOrgScope(ctx, db, orgID, …), use a SECURITY DEFINER helper, or run on the OpenPlatformAdminConnection pool. Unwrapped writes under axonflow_app_role fail with 'pq: new row violates row-level security policy'. Rehearse on a staging snapshot for at least one full diurnal cycle before flipping in production. See technical-docs/v9_phase7_self_hosted_migration.md §'Change 4' for the audit recipe."
fi
printf "\n"

# ---------------------------------------------------------------------------
# Final verdict
# ---------------------------------------------------------------------------
printf "%b%b═══════════════════════════════════════════════════════════════════════%b\n" "$BOLD" "$BLUE" "$NC"
printf "%b%bv9 Self-Hosted Preflight — Final Verdict%b\n" "$BOLD" "$BLUE" "$NC"
printf "%b%b═══════════════════════════════════════════════════════════════════════%b\n\n" "$BOLD" "$BLUE" "$NC"

printf "  %bPASS%b: %d checks\n" "$GREEN" "$NC" "${#PASS_CHECKS[@]}"
printf "  %bWARN%b: %d checks\n" "$YELLOW" "$NC" "${#WARN_CHECKS[@]}"
printf "  %bFAIL%b: %d checks\n\n" "$RED" "$NC" "${#FAIL_CHECKS[@]}"

if [[ "${#FAIL_CHECKS[@]}" -gt 0 ]]; then
    printf "%b❌ DO NOT UPGRADE.%b At least one FAIL — resolve before pulling the v9 image:\n\n" "$RED" "$NC"
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
printf "Next steps (see axonflow-docs/docs/operators/_v9-self-hosted-upgrade-guide.md):\n"
printf "  1. Take a fresh RDS snapshot (or equivalent for non-RDS Postgres)\n"
printf "  2. Pull the v9 platform image (axonflow-agent:v9.0.0)\n"
printf "  3. Restart agent + orchestrator services\n"
printf "  4. Tail agent logs for 'Migration 094 Pass-2' row counts\n"
printf "  5. Verify /health advertises platform_version=9.x.x\n\n"
exit 0
