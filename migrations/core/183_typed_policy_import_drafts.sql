-- Migration 183: typed_policy_import_drafts, the once-only import of legacy per-policy overrides into an unpublished draft
-- Date: 2026-09-13
-- Purpose: Record, once per organization, the typed draft its legacy
--          policy_overrides rows translate into (PRD v11 §1.5), with every row
--          that could not be carried and why; and create the function the
--          agent's boot step reads those rows through.
-- Related: #3746 (W3-I item 9), PRD v11 §1.5, migrations/core/030 (policy_overrides),
--          platform/agent/policy_override_import.go (the boot step that writes the rows).
--
-- EDITION: COMMUNITY (mirrored). policy_overrides ships on every edition, so the
-- record is kept on every edition; the Enterprise portal's editor reads it.
--
-- ---------------------------------------------------------------------------
-- WHAT THIS IS
-- ---------------------------------------------------------------------------
--
-- v11 controls the shipped set through the organization's typed document: its
-- system_controls section leaves a shipped control out or gives it another
-- action (PRD v11 §1.5). policy_overrides is read by no enforcing engine; it is
-- kept for ADR-044 break-glass, and its handlers refuse a write. A deployment
-- upgrading from v10 may carry customer settings in it, so the agent translates
-- them ONCE into an UNPUBLISHED draft per organization and records it here.
-- Nothing is published or activated: the organization reviews the draft in the
-- editor and publishes it, under separation of duties, like any document it
-- wrote.
--
-- ONE ROW PER ORGANIZATION THAT HAS ANY policy_overrides ROW. The row is also
-- the once-only marker: the boot step inserts with ON CONFLICT DO NOTHING, and a
-- trigger refuses a delete, so a dismissed draft keeps its row and boot never
-- imports again. An organization none of whose rows could be carried still gets
-- its row, with no draft, so the editor can say why.
--
-- The legacy tables are read by typed_policy_import_candidates() below, not by
-- Go: the one reader of static_policies and dynamic_policies this adds is a
-- migration's, which is where a one-time upgrade read belongs.

BEGIN;

CREATE TABLE IF NOT EXISTS typed_policy_import_drafts (
    org_id           VARCHAR(255) PRIMARY KEY,
    imported_at      TIMESTAMPTZ  NOT NULL,
    actor            VARCHAR(64)  NOT NULL,
    source_row_count INTEGER      NOT NULL,
    imported_count   INTEGER      NOT NULL,
    skipped          JSONB        NOT NULL DEFAULT '[]'::jsonb,
    draft            JSONB,
    draft_digest     VARCHAR(128),
    dismissed_at     TIMESTAMPTZ,
    CONSTRAINT typed_policy_import_drafts_org_nonempty_chk CHECK (org_id <> ''),
    CONSTRAINT typed_policy_import_drafts_actor_chk        CHECK (actor = 'system:upgrade-import'),
    CONSTRAINT typed_policy_import_drafts_counts_chk
        CHECK (source_row_count >= 1 AND imported_count >= 0 AND imported_count <= source_row_count),
    CONSTRAINT typed_policy_import_drafts_skipped_form_chk CHECK (jsonb_typeof(skipped) = 'array'),
    -- The draft and its digest exist together, and exactly when a row was
    -- carried into it: "nothing could be imported" is a row with no draft.
    CONSTRAINT typed_policy_import_drafts_draft_pair_chk   CHECK ((draft IS NULL) = (draft_digest IS NULL)),
    CONSTRAINT typed_policy_import_drafts_draft_count_chk  CHECK ((draft IS NULL) = (imported_count = 0)),
    CONSTRAINT typed_policy_import_drafts_draft_form_chk   CHECK (draft IS NULL OR jsonb_typeof(draft) = 'object'),
    CONSTRAINT typed_policy_import_drafts_digest_form_chk  CHECK (draft_digest IS NULL OR draft_digest LIKE 'sha256:%')
);

COMMENT ON TABLE typed_policy_import_drafts IS
    'The once-only import of an organization''s legacy policy_overrides rows into an unpublished typed draft (PRD v11 §1.5). One row per organization; only dismissed_at ever changes, once.';

-- ---------------------------------------------------------------------------
-- Row-level security, the shape of core/176 and core/181
-- ---------------------------------------------------------------------------

ALTER TABLE typed_policy_import_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE typed_policy_import_drafts FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS typed_policy_import_drafts_org_isolation ON typed_policy_import_drafts;
CREATE POLICY typed_policy_import_drafts_org_isolation ON typed_policy_import_drafts
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

-- ---------------------------------------------------------------------------
-- The record guard
--
-- The row records what was imported, so the one change it admits is dismissing
-- the draft, once. A delete is refused because a missing row imports again at
-- the next boot. The grants below bind the application roles; the trigger binds
-- the table OWNER too, which is why both exist.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION typed_policy_import_drafts_guard() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.dismissed_at IS NULL AND NEW.dismissed_at IS NOT NULL
       AND (NEW.org_id, NEW.imported_at, NEW.actor, NEW.source_row_count, NEW.imported_count, NEW.skipped, NEW.draft, NEW.draft_digest)
           IS NOT DISTINCT FROM
           (OLD.org_id, OLD.imported_at, OLD.actor, OLD.source_row_count, OLD.imported_count, OLD.skipped, OLD.draft, OLD.draft_digest) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION
        'Table % records an import: % is refused. The only change it admits is dismissing its draft, once, and a missing row would import again at the next boot (PRD v11 §1.5).',
        TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS typed_policy_import_drafts_record_guard ON typed_policy_import_drafts;
CREATE TRIGGER typed_policy_import_drafts_record_guard
    BEFORE UPDATE OR DELETE ON typed_policy_import_drafts
    FOR EACH ROW EXECUTE FUNCTION typed_policy_import_drafts_guard();

DROP TRIGGER IF EXISTS typed_policy_import_drafts_no_truncate ON typed_policy_import_drafts;
CREATE TRIGGER typed_policy_import_drafts_no_truncate
    BEFORE TRUNCATE ON typed_policy_import_drafts
    FOR EACH STATEMENT EXECUTE FUNCTION typed_policy_import_drafts_guard();

-- ---------------------------------------------------------------------------
-- Grants: the application roles read, and the portal's role dismisses. Only
-- the boot step, on the owner connection, writes a row.
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON typed_policy_import_drafts FROM axonflow_app_role;
        GRANT SELECT ON typed_policy_import_drafts TO axonflow_app_role;
        GRANT UPDATE (dismissed_at) ON typed_policy_import_drafts TO axonflow_app_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON typed_policy_import_drafts FROM axonflow_platform_admin;
        GRANT SELECT ON typed_policy_import_drafts TO axonflow_platform_admin;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- The rows the boot step reads, every organization's.
--
-- policy_overrides.policy_id is the UUID of a static_policies or
-- dynamic_policies row, so the legacy text id the corpus keys on is joined in
-- here. policy_overrides and both legacy tables ENABLE row-level security
-- without forcing it (core/018, core/030), so the owner connection the boot step
-- calls this on reads every organization. Nobody else may call it.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION typed_policy_import_candidates()
RETURNS TABLE (
    override_id      TEXT,
    org_id           TEXT,
    tenant_id        TEXT,
    policy_table     TEXT,
    policy_id        TEXT,
    enabled_override BOOLEAN,
    action_override  TEXT,
    revoked          BOOLEAN,
    expired          BOOLEAN,
    break_glass      BOOLEAN
)
LANGUAGE sql STABLE
SET search_path = public, pg_temp
AS $$
    SELECT po.id::text,
           po.org_id::text,
           po.tenant_id::text,
           CASE po.policy_type WHEN 'static' THEN 'static_policies' ELSE 'dynamic_policies' END,
           COALESCE(sp.policy_id, dp.policy_id, '')::text,
           po.enabled_override,
           po.action_override::text,
           po.revoked_at IS NOT NULL,
           po.expires_at IS NOT NULL AND po.expires_at <= now(),
           po.tool_signature IS NOT NULL
    FROM policy_overrides po
    LEFT JOIN static_policies  sp ON po.policy_type = 'static'  AND sp.id = po.policy_id
    LEFT JOIN dynamic_policies dp ON po.policy_type = 'dynamic' AND dp.id = po.policy_id
    ORDER BY po.org_id, po.id
$$;

REVOKE EXECUTE ON FUNCTION typed_policy_import_candidates() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Self-verification BEFORE COMMIT, the pattern of core/176 and core/181
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    r TEXT;
    n INTEGER;
BEGIN
    IF to_regclass('typed_policy_import_drafts') IS NULL THEN
        RAISE EXCEPTION 'migration 183 self-verification: typed_policy_import_drafts was not created';
    END IF;

    SELECT COUNT(*) INTO n
    FROM pg_catalog.pg_class c
    WHERE c.oid = to_regclass('typed_policy_import_drafts') AND c.relrowsecurity AND c.relforcerowsecurity;
    IF n <> 1 THEN
        RAISE EXCEPTION 'migration 183 self-verification: typed_policy_import_drafts does not have ENABLE + FORCE ROW LEVEL SECURITY';
    END IF;

    SELECT COUNT(*) INTO n FROM pg_catalog.pg_policies
    WHERE schemaname = 'public' AND tablename = 'typed_policy_import_drafts'
      AND policyname = 'typed_policy_import_drafts_org_isolation';
    IF n <> 1 THEN
        RAISE EXCEPTION 'migration 183 self-verification: typed_policy_import_drafts is missing its org-isolation policy';
    END IF;

    SELECT COUNT(*) INTO n FROM pg_catalog.pg_trigger
    WHERE tgrelid = to_regclass('typed_policy_import_drafts') AND NOT tgisinternal;
    IF n <> 2 THEN
        RAISE EXCEPTION 'migration 183 self-verification: typed_policy_import_drafts carries % guard triggers, expected 2', n;
    END IF;

    IF to_regprocedure('public.typed_policy_import_candidates()') IS NULL THEN
        RAISE EXCEPTION 'migration 183 self-verification: typed_policy_import_candidates() was not created';
    END IF;

    FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
        CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
        IF NOT has_table_privilege(r, 'typed_policy_import_drafts', 'SELECT') THEN
            RAISE EXCEPTION 'migration 183 self-verification: % cannot read typed_policy_import_drafts', r;
        END IF;
        IF has_table_privilege(r, 'typed_policy_import_drafts', 'INSERT')
           OR has_table_privilege(r, 'typed_policy_import_drafts', 'DELETE')
           OR has_table_privilege(r, 'typed_policy_import_drafts', 'TRUNCATE')
           OR has_column_privilege(r, 'typed_policy_import_drafts', 'draft', 'UPDATE') THEN
            RAISE EXCEPTION 'migration 183 self-verification: % can write typed_policy_import_drafts beyond dismissing a draft', r;
        END IF;
        IF has_function_privilege(r, 'typed_policy_import_candidates()', 'EXECUTE') THEN
            RAISE EXCEPTION 'migration 183 self-verification: % can call typed_policy_import_candidates()', r;
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role')
       AND NOT has_column_privilege('axonflow_app_role', 'typed_policy_import_drafts', 'dismissed_at', 'UPDATE') THEN
        RAISE EXCEPTION 'migration 183 self-verification: axonflow_app_role cannot dismiss a draft';
    END IF;

    RAISE NOTICE 'Migration 183 verified: typed_policy_import_drafts is org-isolated, FORCE-RLS, and only dismissable; its candidates function is the owner''s.';
END $$;

COMMIT;
