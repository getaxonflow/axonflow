-- Migration 082: Tenant deletion (GDPR right-to-erasure) audit trail + deletion tokens
-- Date: 2026-05-05
-- Context: Issue #1896 — DELETE /api/v1/tenant/<id> endpoint to back the
--          GDPR Right-to-Erasure claim in the public Privacy Policy and replace
--          the manual SQL-cascade runbook (V1_GDPR_DELETION_RUNBOOK.md).
--
-- Provides:
--   community_saas_deletion_tokens — short-lived single-use confirm tokens,
--                                    issued by POST /api/v1/tenant/<id>/delete-request
--                                    and consumed by POST /api/v1/tenant/<id>/delete-confirm.
--   tenant_deletion_log            — append-only audit trail of completed
--                                    erasures. Survives the deletion of the
--                                    tenant's own audit_logs (which is the whole
--                                    point — GDPR requires a record that erasure
--                                    occurred even after the data is gone).
--
-- Why two tables (mirrors W3 recovery design in migration 076):
--   The ephemeral token store is a different lifecycle from the immutable
--   deletion record. Tokens get cleaned up routinely (purge expired/consumed
--   rows older than 7 days); the deletion log is forever.
--
-- Token storage: token is HASHED before storage (SHA-256 with optional
-- HMAC server-side pepper via AXONFLOW_TENANT_DELETE_TOKEN_PEPPER) — same
-- pattern as 076 recovery_tokens. The plain token is sent in the email
-- and never stored server-side after the row is written.
--
-- Anti-enumeration: tokens are keyed by token_hash (PK), not by tenant_id.
-- An attacker who guesses tenant_ids gets no signal from the tokens table.
--
-- Forward-only: no down migration. The deletion log is append-only audit
-- data; we never want a path that drops it. Tokens table can be left in
-- place forever — schema is small.

-- =============================================================================
-- community_saas_deletion_tokens — ephemeral 1-hour confirm tokens
-- =============================================================================

CREATE TABLE IF NOT EXISTS community_saas_deletion_tokens (
    token_hash         VARCHAR(64) PRIMARY KEY,            -- HMAC-SHA256 hex of the plain token (with server pepper)
    tenant_id          VARCHAR(255) NOT NULL,              -- tenant being deleted
    email              VARCHAR(255) NOT NULL,              -- email at time of request (must match registration)
    requesting_ip_hash VARCHAR(64),                        -- SHA-256 hex of the requesting IP (audit)
    created_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMP WITH TIME ZONE NOT NULL,  -- typically NOW() + 1 hour
    consumed_at        TIMESTAMP WITH TIME ZONE            -- set on successful delete-confirm
);

-- Index for cleanup queries (purge expired/consumed tokens older than 7 days).
CREATE INDEX IF NOT EXISTS idx_csaas_deletion_expires
    ON community_saas_deletion_tokens(expires_at);

-- Index for per-tenant rate limit lookups (block if a recent unconsumed token exists).
CREATE INDEX IF NOT EXISTS idx_csaas_deletion_tenant_recent
    ON community_saas_deletion_tokens(tenant_id, created_at DESC);

-- =============================================================================
-- tenant_deletion_log — immutable audit trail of completed erasures
-- =============================================================================
--
-- One row written per successful POST /api/v1/tenant/<id>/delete-confirm,
-- BEFORE the cascade DELETEs run, in the same transaction. If the cascade
-- rolls back, this row rolls back too — so there is no risk of an audit
-- entry without the deletion. After commit, this row is immutable evidence
-- the deletion happened.
--
-- The audit row INTENTIONALLY does NOT have a FK to community_saas_registrations
-- — the tenant row is being deleted in the same transaction; an FK would cascade
-- or block. This is the one place tenant_id is stored as a free-form string with
-- no referential integrity and that's correct.
--
-- Privacy note: the email is stored here because GDPR Article 30 records-of-
-- processing-activities require us to be able to prove WHO requested erasure
-- if a regulator asks. Retain indefinitely (small table — at most 1 row per
-- tenant lifetime) unless a future policy decision says otherwise.

CREATE TABLE IF NOT EXISTS tenant_deletion_log (
    id                 BIGSERIAL PRIMARY KEY,
    tenant_id          VARCHAR(255) NOT NULL,              -- the deleted tenant_id
    email              VARCHAR(255) NOT NULL,              -- email at deletion time
    deletion_token_jti VARCHAR(64),                        -- token_hash that was consumed (forensic correlation)
    requested_at       TIMESTAMP WITH TIME ZONE NOT NULL,  -- when delete-request was issued
    confirmed_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Per-table deletion counts (defense-in-depth: lets ops verify the cascade
    -- actually touched everything it should have touched).
    deleted_registrations INTEGER NOT NULL DEFAULT 0,
    deleted_licenses      INTEGER NOT NULL DEFAULT 0,
    deleted_audit_logs    INTEGER NOT NULL DEFAULT 0,
    deleted_daily_usage   INTEGER NOT NULL DEFAULT 0,
    deleted_usage_events  INTEGER NOT NULL DEFAULT 0,

    -- Best-effort flags. Stripe customer archive is a network call; on failure
    -- we still complete the DB-side erasure and log here for ops follow-up.
    stripe_customer_id   VARCHAR(255),                     -- if any active Pro license existed
    stripe_archive_ok    BOOLEAN,                          -- NULL = no Stripe customer to archive; true = archived; false = best-effort failure
    stripe_archive_error TEXT,                             -- populated when stripe_archive_ok = false

    -- If the tenant had an active Pro license that wasn't yet 14-day-refund-
    -- eligible, V1 trade-off is to log+proceed (manual refund follow-up).
    -- This flag lets ops query for tenants needing manual refund.
    refund_needed        BOOLEAN NOT NULL DEFAULT FALSE,
    refund_note          TEXT
);

CREATE INDEX IF NOT EXISTS idx_tenant_deletion_log_tenant
    ON tenant_deletion_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_deletion_log_email
    ON tenant_deletion_log(email);
CREATE INDEX IF NOT EXISTS idx_tenant_deletion_log_confirmed
    ON tenant_deletion_log(confirmed_at);
CREATE INDEX IF NOT EXISTS idx_tenant_deletion_log_refund_needed
    ON tenant_deletion_log(refund_needed) WHERE refund_needed = TRUE;

DO $$
BEGIN
    RAISE NOTICE 'Migration 082: community_saas_deletion_tokens + tenant_deletion_log tables created';
END $$;
