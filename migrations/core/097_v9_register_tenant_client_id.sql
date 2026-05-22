-- Migration 097: v9 register_tenant() function writes client_id
-- Date: 2026-05-19
--
-- The register_tenant() PL/pgSQL function (migration 062) auto-populates the
-- tenants table on first authenticated request via INSERT ON CONFLICT DO
-- NOTHING. After migration 088 added the client_id column on tenants with a
-- one-time backfill, this function still only writes (tenant_id, org_id,
-- name) — every NEW tenant row landed via register_tenant() post-2026-05-19
-- carries client_id=NULL until manually updated.
--
-- This migration replaces the function body so client_id is written with
-- the same value as tenant_id (v9 compat window). tenant_id remains as the
-- deprecated alias until a future major version drops it.
--
-- Idempotency: CREATE OR REPLACE FUNCTION is idempotent by definition. The
-- INSERT inside still uses ON CONFLICT (tenant_id) DO NOTHING so re-runs on
-- existing tenant_ids remain no-ops. The function signature is unchanged so
-- every existing caller continues to work — only the body widens.
--
-- Rollback: paired 097_v9_register_tenant_client_id_down.sql restores the
-- pre-097 function body (no client_id write).
--
-- Depends on: 062_tenants_table, 088_v9_credential_client_id.

CREATE OR REPLACE FUNCTION register_tenant(
    p_tenant_id VARCHAR(255),
    p_org_id VARCHAR(255),
    p_name VARCHAR(255) DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
    -- v9 compat: client_id mirrors tenant_id during the v9 compatibility
    -- window. Plugin Pro + community-saas auth + every downstream reader
    -- that picked up client_id post-migration 088 now sees a populated
    -- column for tenant rows minted via this function.
    INSERT INTO tenants (tenant_id, client_id, org_id, name)
    VALUES (p_tenant_id, p_tenant_id, p_org_id, COALESCE(p_name, p_tenant_id))
    ON CONFLICT (tenant_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;
