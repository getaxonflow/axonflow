#!/usr/bin/env bash
# db_helpers.sh — DB-side helpers for the issue #1885 license-rework E2E
# harness. Routes all SQL through `aws ecs execute-command` against a
# running orchestrator container; the container has private-VPC reach to
# the RDS instance and `apk add postgresql-client` makes psql available
# on the fly.
#
# All helpers expect:
#   STACK     — community-saas-staging stack name (e.g. axonflow-community-saas-staging-20260505-103251)
#   DB_PASS   — DATABASE_PASSWORD as exposed inside the orchestrator container env
#   ORCH_TASK — a running orchestrator task ARN (resolved once by harness)
#   DB_HOST   — RDS endpoint
#
# Sourced, not exec'd. Functions write SQL to a base64 envelope to avoid
# shell-quoting hell when bcrypt hashes (which contain $) cross multiple
# layers of nested shells.

set -uo pipefail

# Run an arbitrary SQL string against the staging DB via ECS exec.
# Returns the psql tabular output to stdout. Sessions Manager bookend
# lines are filtered out so callers can scan the actual SQL output.
#
# Concurrency note: writes to /tmp/q.sql inside the orchestrator
# container per call. The harness runs sequentially per-plugin, so
# parallel calls would race; if you parallelize, wrap the temp file in a
# per-call mktemp.
db_run_sql() {
  local sql="$1"
  local b64
  b64=$(printf '%s' "$sql" | base64)
  aws ecs execute-command --region us-east-1 \
    --cluster "${STACK}-cluster" \
    --task "$ORCH_TASK" \
    --container orchestrator \
    --interactive \
    --command "sh -c \"export PGPASSWORD='${DB_PASS}'; echo ${b64} | base64 -d > /tmp/q.sql; psql -h ${DB_HOST} -U axonflow -d axonflow -f /tmp/q.sql; rm /tmp/q.sql\"" 2>&1 \
    | grep -vE '^The Session Manager|^Starting session|^Cannot perform start session|^$' || true
}

# db_register_tenant <tenant_id> <plaintext_secret> [label]
# Inserts a synthetic registration row directly. Bypasses the per-IP 5/hr
# rate limit on /api/v1/register (a hardcoded const, not env-tunable).
# Bcrypt cost matches the agent (12 — see platform/agent/community_saas_register.go:48).
db_register_tenant() {
  local tenant="$1"
  local secret="$2"
  local label="${3:-session-d-e2e}"
  local hash
  hash=$(python3 -c "
import bcrypt
print(bcrypt.hashpw(b'${secret}', bcrypt.gensalt(12)).decode())
")
  local prefix="${secret:0:8}"
  local sql="INSERT INTO community_saas_registrations (tenant_id, secret_hash, secret_prefix, label) \
    VALUES ('${tenant}', '${hash}', '${prefix}', '${label}') \
    ON CONFLICT (tenant_id) DO UPDATE \
      SET secret_hash = EXCLUDED.secret_hash, \
          secret_prefix = EXCLUDED.secret_prefix, \
          label = EXCLUDED.label, \
          expires_at = now() + interval '30 days', \
          terminated_at = NULL, \
          disabled_at = NULL \
    RETURNING tenant_id;"
  db_run_sql "$sql" | grep -E "^[[:space:]]*${tenant}|INSERT 0|UPDATE [0-9]" >/dev/null
}

# db_set_daily_usage <tenant_id> <count>
# Pre-populate the per-tenant per-day request counter so the next request
# is at the boundary (used by §1 to set 199 → next req lands as 200 →
# subsequent req returns 429 without sending 200 actual requests).
db_set_daily_usage() {
  local tenant="$1"
  local count="$2"
  local sql="INSERT INTO community_saas_daily_usage (tenant_id, day, req_count) \
    VALUES ('${tenant}', CURRENT_DATE, ${count}) \
    ON CONFLICT (tenant_id, day) DO UPDATE SET req_count = EXCLUDED.req_count;"
  db_run_sql "$sql" >/dev/null
}

# db_get_daily_usage <tenant_id>
# Return the integer req_count for the tenant on the current UTC day, or
# 0 if no row.
db_get_daily_usage() {
  local tenant="$1"
  local sql="SELECT COALESCE(req_count, 0) FROM community_saas_daily_usage WHERE tenant_id = '${tenant}' AND day = CURRENT_DATE;"
  # Strip whitespace + trailing CR so caller can `[ "$x" = "199" ]` cleanly.
  db_run_sql "$sql" | awk 'NR==3 {gsub(/[[:space:]\r]/,""); print; exit}'
}

# db_revoke_license <jti> [reason]
# Set revoked_at = NOW() so the next per-request lookup
# (lookupActivePluginLicenseTier) returns errPluginLicenseNotFound → 401.
db_revoke_license() {
  local jti="$1"
  local reason="${2:-dispute}"
  local sql="UPDATE plugin_user_licenses SET revoked_at = NOW(), revocation_reason = '${reason}' WHERE license_token_jti = '${jti}' RETURNING license_id, revoked_at;"
  db_run_sql "$sql" | grep -E "UPDATE [0-9]+|license_id" >/dev/null
}

# db_insert_audit_row <tenant_id> <days_ago>
# Insert a synth audit_logs row with timestamp = NOW() - <days_ago>. Used
# for retention proofs — synth rows + on-demand cleanup SQL beats waiting
# for the periodic worker (which runs every 1 hour).
#
# audit_logs requires a wide set of NOT NULL columns; we fill placeholder
# values for the e2e_synth provenance and let the caller distinguish via
# request_id prefix `e2e-<tenant>-<days_ago>d`.
db_insert_audit_row() {
  local tenant="$1"
  local days_ago="$2"
  local sql="INSERT INTO audit_logs ( \
    id, request_id, timestamp, user_id, user_email, user_role, \
    client_id, tenant_id, request_type, query, query_hash, policy_decision \
  ) VALUES ( \
    'e2e-${tenant}-${days_ago}d-' || gen_random_uuid()::text, \
    'e2e-${tenant}-${days_ago}d', \
    NOW() - INTERVAL '${days_ago} days', \
    0, 'session-d-e2e@axonflow-test.invalid', 'e2e_synth', \
    '${tenant}', '${tenant}', 'e2e_synth', '', '', 'allow' \
  );"
  db_run_sql "$sql" >/dev/null
}

# db_count_audit_rows <tenant_id>
db_count_audit_rows() {
  local tenant="$1"
  local sql="SELECT COUNT(*) FROM audit_logs WHERE tenant_id = '${tenant}';"
  db_run_sql "$sql" | awk 'NR==3 {gsub(/[[:space:]\r]/,""); print; exit}'
}

# db_run_retention_cleanup
# Mirror the per-tenant retention logic from
# platform/orchestrator/audit_cleanup.go (loadPerTenantRetentionBuckets +
# the bucketed DELETE loop) as a single CTE-driven statement so the
# harness can prove tier-based retention without waiting for the 1-hour
# periodic worker. Free default = 3d (deployment-wide), Pro = 30d,
# Premium = 90d. Stays in sync with retentionForSaasPluginTier in the Go
# source.
db_run_retention_cleanup() {
  local sql="\
WITH pro_tenants AS ( \
  SELECT tenant_id FROM plugin_user_licenses WHERE revoked_at IS NULL AND tier = 'Pro' \
), \
premium_tenants AS ( \
  SELECT tenant_id FROM plugin_user_licenses WHERE revoked_at IS NULL AND tier = 'Premium' \
), \
delete_pro AS ( \
  DELETE FROM audit_logs WHERE tenant_id = ANY(ARRAY(SELECT tenant_id FROM pro_tenants)) AND timestamp < NOW() - INTERVAL '30 days' RETURNING 1 \
), \
delete_premium AS ( \
  DELETE FROM audit_logs WHERE tenant_id = ANY(ARRAY(SELECT tenant_id FROM premium_tenants)) AND timestamp < NOW() - INTERVAL '90 days' RETURNING 1 \
), \
delete_default AS ( \
  DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '3 days' \
    AND tenant_id NOT IN (SELECT tenant_id FROM pro_tenants) \
    AND tenant_id NOT IN (SELECT tenant_id FROM premium_tenants) \
    RETURNING 1 \
) \
SELECT (SELECT COUNT(*) FROM delete_pro) AS pro_deleted, \
       (SELECT COUNT(*) FROM delete_premium) AS premium_deleted, \
       (SELECT COUNT(*) FROM delete_default) AS default_deleted;"
  db_run_sql "$sql"
}

# db_cleanup_e2e_rows
# Best-effort cleanup of session-d-e2e rows. Called at end of a run.
db_cleanup_e2e_rows() {
  local sql="\
DELETE FROM audit_logs WHERE request_id LIKE 'e2e-cs_e2e_%'; \
DELETE FROM plugin_user_licenses WHERE tenant_id LIKE 'cs_e2e_%' OR tenant_id LIKE 'cs_synth-%'; \
DELETE FROM community_saas_daily_usage WHERE tenant_id LIKE 'cs_e2e_%'; \
DELETE FROM community_saas_registrations WHERE tenant_id LIKE 'cs_e2e_%';"
  db_run_sql "$sql" >/dev/null
}
