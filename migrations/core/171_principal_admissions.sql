-- Migration 171: principal_admissions - the append-only tier-admission ledger
--                (#3593, decision D4 of the v11.0.0 plan)
-- Date: 2026-09-08
--
-- EDITION: core. This is RESTRICTION code: it is what makes Community and
--          Evaluation smaller, so it ships in the community tree and runs in
--          the community binary. The feature code that raises or removes a
--          limit lives under ee/ and never touches this table.
--
-- ════════════════════════════════════════════════════════════════════════════
-- WHAT THIS TABLE IS
-- ════════════════════════════════════════════════════════════════════════════
--
-- TWO tables, because the four ruled dimensions are of two kinds:
--
--   dimension          what a principal is                   Community / Evaluation / Enterprise
--   human_principal    a per-user identity (token-resolved)  25 / 75 / unlimited     ledger
--   service_principal  an API credential / tenant identity   5 / 25 / unlimited      ledger
--   org_root_policy    an organization-root policy           0 / 0 / unlimited       ledger
--   node               an agent instance                     1 / unlimited / unlimited  LEASE
--
-- principal_admissions is the append-only LEDGER: one row per principal an
-- organization has ever admitted. A node is not a lifetime fact but a
-- CONCURRENCY one (master ruling, 2026-09-08): an ECS task or a Kubernetes pod
-- gets a fresh identity on every recreate, and a ledger that remembered every
-- one of them forever would read a routine redeploy as a second node. Nodes
-- therefore live in node_leases, the one table here on which UPDATE is
-- permitted: a node renews its lease every 30 seconds and the limit counts
-- leases that have not expired (NodeLeaseTTL in the admission package).
--
-- The limits are read from the SIGNED LICENCE through platform/agent/license's
-- one verified reader and enforced by platform/agent/license/admission, the
-- single package with the single Admit entry point. Unlimited tiers never
-- reach this table: Admit returns before any I/O when the limit is -1, so an
-- outage here cannot touch Enterprise traffic.
--
-- ════════════════════════════════════════════════════════════════════════════
-- WHY APPEND-ONLY, AND WHY THE PRIMARY KEY IS THE WHOLE IDENTITY
-- ════════════════════════════════════════════════════════════════════════════
--
-- The ruling (operator, 2026-09-07) is that a principal ALREADY SEEN keeps
-- working whatever happens to the ledger afterwards, and that only a principal
-- seen NOWHERE is refused - with a distinct reason - when the ledger cannot be
-- asked. "Seen" therefore has to be a fact that cannot be un-made by the
-- application role: a row here is written once and never updated or deleted.
--
-- The PRIMARY KEY (org_id, dimension, principal_id) is what makes a replay
-- idempotent by construction: admitting the same principal twice is ON
-- CONFLICT DO NOTHING, one row, one admission. Nothing has to remember whether
-- it already ran.
--
-- Append-only is enforced THREE ways, because each one alone has a hole:
--   1. the application roles are GRANTED SELECT and INSERT only, and the
--      UPDATE / DELETE / TRUNCATE that core/098's ALTER DEFAULT PRIVILEGES
--      would otherwise hand every new table are REVOKED explicitly;
--   2. a BEFORE UPDATE OR DELETE trigger raises, which also binds the table
--      OWNER (a privilege grant cannot bind the owner);
--   3. a BEFORE TRUNCATE trigger raises for the same reason.
-- platform/agent/admission_realpg_test.go PLANTS an UPDATE and a DELETE as
-- axonflow_app_role and asserts both are refused, and plants them as the
-- owner and asserts the trigger refuses those too.
--
-- ════════════════════════════════════════════════════════════════════════════
-- ROW LEVEL SECURITY
-- ════════════════════════════════════════════════════════════════════════════
--
-- ENABLE and FORCE, with the org-isolation policy on app.current_org_id, the
-- same shape as core/169. Every read and write the admission package makes is
-- wrapped in rls.WithOrgScope for the organization being admitted, and the
-- boot-time warm of the in-memory seen-set reads the deployment's own
-- organization(s) under the same scope. A GRANT is written here rather than
-- relied on from core/098's defaults for the reason core/170 documents (a
-- rotated migration credential leaves the defaults bound to the old owner).

BEGIN;

CREATE TABLE IF NOT EXISTS principal_admissions (
    org_id              VARCHAR(255) NOT NULL,
    dimension           VARCHAR(32)  NOT NULL,
    -- 512 to match identity_trust_realms.realm_id: the canonical principal
    -- wire form (platform/shared/identity) is bounded there, and a human
    -- principal's key is a canonical email, which is shorter still.
    principal_id        VARCHAR(512) NOT NULL,
    admitted_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- A fingerprint (SHA-256 hex) of the licence the deployment held when the
    -- row was written, for the operator reading a ledger after a licence
    -- change. NEVER the key itself. Empty when the deployment holds no key.
    licence_fingerprint VARCHAR(64)  NOT NULL DEFAULT '',
    CONSTRAINT principal_admissions_pkey PRIMARY KEY (org_id, dimension, principal_id),
    -- 'node' is deliberately NOT admitted here: nodes are leases, below.
    CONSTRAINT principal_admissions_dimension_chk
        CHECK (dimension IN ('human_principal', 'service_principal', 'org_root_policy')),
    CONSTRAINT principal_admissions_org_nonempty_chk       CHECK (btrim(org_id) <> ''),
    CONSTRAINT principal_admissions_principal_nonempty_chk CHECK (btrim(principal_id) <> '')
);

-- The boot-time warm reads the newest N rows per organization; the count the
-- admission decision makes is per (org_id, dimension) and is covered by the
-- primary key's leading columns.
CREATE INDEX IF NOT EXISTS idx_principal_admissions_org_dim_admitted
    ON principal_admissions (org_id, dimension, admitted_at DESC);

ALTER TABLE principal_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE principal_admissions FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS principal_admissions_org_isolation ON principal_admissions;
CREATE POLICY principal_admissions_org_isolation ON principal_admissions
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

-- Append-only, part 2 and 3: the triggers bind everyone, the owner included.
CREATE OR REPLACE FUNCTION principal_admissions_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'principal_admissions is append-only (#3593): % is not permitted; a principal once admitted stays admitted',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS principal_admissions_no_update_delete ON principal_admissions;
CREATE TRIGGER principal_admissions_no_update_delete
    BEFORE UPDATE OR DELETE ON principal_admissions
    FOR EACH ROW EXECUTE FUNCTION principal_admissions_append_only();

DROP TRIGGER IF EXISTS principal_admissions_no_truncate ON principal_admissions;
CREATE TRIGGER principal_admissions_no_truncate
    BEFORE TRUNCATE ON principal_admissions
    FOR EACH STATEMENT EXECUTE FUNCTION principal_admissions_append_only();

-- Append-only, part 1: the application roles hold SELECT and INSERT and
-- nothing else. The REVOKE is what matters - core/098's ALTER DEFAULT
-- PRIVILEGES has already granted UPDATE and DELETE to both roles by the time
-- this statement runs - and the GRANT restates the two privileges the ledger
-- needs so a deployment whose defaults did not follow (core/170's case) is
-- covered too. Guarded by role existence so local-dev chains without the v9
-- roles still apply.
-- WRITTEN AS LITERAL STATEMENTS, not as format(...%I...) inside a loop, and
-- that is a requirement rather than a style choice: the grant census in
-- platform/agent/migration_rls_grant_census_test.go reads the migration
-- SOURCE, and it recognises a literal `GRANT ... ON <table> TO <role>` and the
-- `format('GRANT ... ON %I TO %I')` loop shape only. A loop that interpolates
-- the ROLE but writes the table literally is invisible to it, so the table
-- reads as granted to nobody. Measured: the first version of this migration
-- used exactly that shape and the census reported both tables ungranted.
-- Shape copied from migrations/enterprise/149_proof_execution_record.sql.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON principal_admissions FROM axonflow_app_role;
        GRANT SELECT, INSERT ON principal_admissions TO axonflow_app_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON principal_admissions FROM axonflow_platform_admin;
        GRANT SELECT, INSERT ON principal_admissions TO axonflow_platform_admin;
    END IF;
END $$;

-- ════════════════════════════════════════════════════════════════════════════
-- node_leases - the concurrency table for the node dimension
-- ════════════════════════════════════════════════════════════════════════════
--
-- One row per node id an organization has seen. last_seen is renewed by the
-- node's heartbeat; a lease whose last_seen is older than the TTL is expired
-- and not counted. UPDATE is granted on THIS table only (the renewal is an
-- UPSERT); DELETE is granted so expired leases older than the retention the
-- package applies can be pruned. It carries no trigger: it is not append-only
-- and does not claim to be.
--
-- The refusal applies to a NEW node only: a node that holds a row renews it
-- whatever the count is (the same node restarting inside the TTL is one node),
-- and a node whose renewal fails keeps serving - the wiring logs the failure
-- and tries again at the next beat.

CREATE TABLE IF NOT EXISTS node_leases (
    org_id     VARCHAR(255) NOT NULL,
    node_id    VARCHAR(255) NOT NULL,
    first_seen TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT node_leases_pkey PRIMARY KEY (org_id, node_id),
    CONSTRAINT node_leases_org_nonempty_chk  CHECK (btrim(org_id) <> ''),
    CONSTRAINT node_leases_node_nonempty_chk CHECK (btrim(node_id) <> ''),
    CONSTRAINT node_leases_seen_order_chk    CHECK (last_seen >= first_seen)
);

CREATE INDEX IF NOT EXISTS idx_node_leases_org_last_seen ON node_leases (org_id, last_seen DESC);

ALTER TABLE node_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE node_leases FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS node_leases_org_isolation ON node_leases;
CREATE POLICY node_leases_org_isolation ON node_leases
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

-- Literal for the same reason as the block above. node_leases takes the full
-- set: a lease is RENEWED (UPDATE) and an expired one is pruned (DELETE), so
-- unlike the ledger this table is not append-only and does not claim to be.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON node_leases TO axonflow_app_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON node_leases TO axonflow_platform_admin;
    END IF;
END $$;

-- Self-verification: every property the admission package relies on, checked
-- before COMMIT so a partial apply cannot report success.
DO $$
DECLARE
    forced   boolean;
    enabled  boolean;
    r        text;
BEGIN
    IF to_regclass('principal_admissions') IS NULL THEN
        RAISE EXCEPTION 'Migration 171 failed: principal_admissions does not exist';
    END IF;
    SELECT relrowsecurity, relforcerowsecurity INTO enabled, forced
      FROM pg_class WHERE oid = 'principal_admissions'::regclass;
    IF NOT enabled OR NOT forced THEN
        RAISE EXCEPTION 'Migration 171 failed: RLS not ENABLEd + FORCEd on principal_admissions';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'principal_admissions'
                   AND policyname = 'principal_admissions_org_isolation') THEN
        RAISE EXCEPTION 'Migration 171 failed: isolation policy missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'principal_admissions_no_update_delete') THEN
        RAISE EXCEPTION 'Migration 171 failed: append-only row trigger missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'principal_admissions_no_truncate') THEN
        RAISE EXCEPTION 'Migration 171 failed: append-only truncate trigger missing';
    END IF;
    FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
        CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
        IF has_table_privilege(r, 'principal_admissions', 'UPDATE')
           OR has_table_privilege(r, 'principal_admissions', 'DELETE')
           OR has_table_privilege(r, 'principal_admissions', 'TRUNCATE') THEN
            RAISE EXCEPTION 'Migration 171 failed: % still holds UPDATE/DELETE/TRUNCATE on principal_admissions', r;
        END IF;
        IF NOT has_table_privilege(r, 'principal_admissions', 'SELECT')
           OR NOT has_table_privilege(r, 'principal_admissions', 'INSERT') THEN
            RAISE EXCEPTION 'Migration 171 failed: % lacks SELECT/INSERT on principal_admissions', r;
        END IF;
    END LOOP;
    IF to_regclass('node_leases') IS NULL THEN
        RAISE EXCEPTION 'Migration 171 failed: node_leases does not exist';
    END IF;
    SELECT relrowsecurity, relforcerowsecurity INTO enabled, forced
      FROM pg_class WHERE oid = 'node_leases'::regclass;
    IF NOT enabled OR NOT forced THEN
        RAISE EXCEPTION 'Migration 171 failed: RLS not ENABLEd + FORCEd on node_leases';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'node_leases'
                   AND policyname = 'node_leases_org_isolation') THEN
        RAISE EXCEPTION 'Migration 171 failed: node_leases isolation policy missing';
    END IF;
    RAISE NOTICE 'Migration 171 verified: principal_admissions present, RLS enabled+FORCED, isolation policy installed, append-only (roles hold SELECT+INSERT only; UPDATE/DELETE/TRUNCATE triggers installed); node_leases present, RLS enabled+FORCED, isolation policy installed, UPDATE permitted';
END $$;

COMMIT;
